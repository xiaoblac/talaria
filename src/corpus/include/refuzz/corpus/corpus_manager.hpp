#pragma once

#include "refuzz/core/engine_handle.hpp"
#include "refuzz/corpus/inbox.hpp"
#include "refuzz/corpus/signal_ownership_index.hpp"  // [coverage-ownership bound] 语料边界机制
#include "refuzz/fuzzer/feedback_verdict.hpp"   // Verdict（feedback 产出，corpus 据此 admit）
#include "refuzz/fuzzer/interfaces.hpp"
#include "refuzz/fuzzer/metrics/fuzzer_metrics.hpp"
#include "refuzz/program/seed_metadata.hpp"     // SeedSource（OfferVerdict 建 Seed 时盖章）
#include "refuzz/scheduler/scheduler_engine.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace refuzz::fuzzer {

// [6b-3 — 当前版本] LoopStats 字段已移除, corpus 计数改由 FuzzerMetrics 承载
struct CorpusContext {
    const ICorpusStore& store;
};

struct ICorpusFilter {
    virtual ~ICorpusFilter() = default;
    virtual bool Test(const Seed& seed, const CorpusContext& ctx) const = 0;
    // [v2 SubT-D] admit 成功 / store bootstrap 时通知 filter,允许 mutate
    // 内部 state(eg. ContentHashDedupFilter 的 hash set)。默认空实现 — 无
    // state filter 不需 override。
    // 实现注意:若内部 state 跨线程访问,自行加 mutex(corpus admit 单 Tick
    // 线程,但 bootstrap 调用时机不一定单线程)。
    virtual void OnSeedAdded(const Seed& /*seed*/) {}
    // [syz corpus.go:140 merge parity] 若本 seed 是某 live corpus seed 的
    // content-duplicate,返回那个 seed_id。CorpusManager 据此把新 signal MERGE
    // 进既有 seed(而非 reject-and-lose)。默认 nullopt(non-dedup filter 不参与)。
    virtual std::optional<uint64_t> DuplicateOf(const Seed& /*seed*/,
                                                const CorpusContext& /*ctx*/) const {
        return std::nullopt;
    }
    // [syz progsMap delete parity] seed 被 sweep 驱逐时通知 filter erase 其 state,
    // 否则 dedup set 永不收缩 → 驱逐过的 program 永久拉黑、无法 re-admit。默认空。
    virtual void OnSeedRemoved(std::uint64_t /*seed_id*/) {}
};

struct FilterSelection {
    std::vector<const ICorpusFilter*> filters;
};

struct ICorpusAdmissionPolicy {
    virtual ~ICorpusAdmissionPolicy() = default;
    virtual FilterSelection SelectFilters(
        const std::vector<std::unique_ptr<ICorpusFilter>>& registry,
        const Seed& seed,
        const CorpusContext& ctx) const = 0;
    virtual void OnActivated(const CorpusContext& /*ctx*/) const {}
};






class NonEmptyPayloadFilter final : public ICorpusFilter {
public:
    bool Test(const Seed& seed, const CorpusContext& ctx) const override;
};

// [v2 SubT-D / G8] payload-content dedup filter:
//   - Test(): 算 FNV-1a 64-bit(seed.payload),若已在 seen_hashes_ → reject
//   - OnSeedAdded(): 算 hash 入 set
// 当前 MVP 选 payload SHA-256 替代选项已审定为 FNV-1a 64-bit(无加密需求,
// FNV-1a 64-bit collision 概率对 100K seed 约 10^-9,无依赖)。Future:若需
// artifact-level 等价 dedup,前置加 ProgramArtifact::ContentHash() 后升级。
// 详 docs/admit-pipeline-alignment/200_batch2_framework_primitives.md §3.D。
class ContentHashDedupFilter final : public ICorpusFilter {
public:
    ContentHashDedupFilter();
    ~ContentHashDedupFilter() override;
    // Test 恒放行 —— content-dup 不再 reject,改由 CorpusManager 经 DuplicateOf
    // MERGE(syz corpus.go:140)。空 payload 交 NonEmptyPayloadFilter。
    bool Test(const Seed& seed, const CorpusContext& ctx) const override;
    void OnSeedAdded(const Seed& seed) override;
    std::optional<uint64_t> DuplicateOf(const Seed& seed,
                                        const CorpusContext& ctx) const override;
    void OnSeedRemoved(std::uint64_t seed_id) override;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;  // pimpl 隔离 hash↔id 双 map + shared_mutex 头依赖
};






class AllFiltersPolicy final : public ICorpusAdmissionPolicy {
public:
    FilterSelection SelectFilters(
        const std::vector<std::unique_ptr<ICorpusFilter>>& registry,
        const Seed& seed,
        const CorpusContext& ctx) const override;
};

class NoFilterPolicy final : public ICorpusAdmissionPolicy {
public:
    FilterSelection SelectFilters(
        const std::vector<std::unique_ptr<ICorpusFilter>>& registry,
        const Seed& seed,
        const CorpusContext& ctx) const override;
};








// [verdict 重构] corpus 拥有的准入模式 —— feedback 只给 Verdict,corpus 自己据此
// 决定收不收。三值对应旧的 3 个 feedback dispatcher:
//   kInteresting  = 旧 corpus_admit     (admit iff verdict.interesting)
//   kAlways       = 旧 corpus_admit_all (admit 任何非 crash/timeout/exec_error)
//   kNever        = 旧 shadow_only      (从不 admit;仅观测)
enum class AdmitMode : std::uint8_t { kInteresting, kAlways, kNever };

// OfferVerdict 的结果:
//   built_seed       —— 仅在 (should_admit && divert) 路径返回给 caller 路由到 PendingSeedMap;
//   admitted_to_inbox —— (should_admit && !divert) 且 TryPush 成功;
//   inbox_full_drop   —— (should_admit && !divert) 但 inbox 满 TryPush 失败(loop 据此 bump
//                        inbox_drop_result;与 should_admit=false 的"没尝试"区分开)。
struct OfferResult {
    std::optional<Seed> built_seed;
    bool                admitted_to_inbox = false;
    bool                inbox_full_drop   = false;
};

class CorpusManager {
public:
    // scheduler_handle 由 SchedulerManager::Handle() 提供,Corpus 内部仅用于
    // OnSeedAdded 时通知当前 active scheduler;acquire 读安全,engine 切换
    // 由 SchedulerManager 统一负责。
    // admit_mode:准入模式,见 AdmitMode。默认 kInteresting(放最后且有默认 →
    //   既有 5-arg 构造调用点(如 xiuos)无需改动)。
    CorpusManager(ICorpusStore& store,
                  const core::EngineHandle<ISchedulerEngine>& scheduler_handle,
                  CorpusInbox& inbox,
                  int max_drain,
                  // v2: metric bus,nullptr 时跳过发布
                  refuzz::fuzzer::metrics::FuzzerMetrics* metrics = nullptr,
                  AdmitMode admit_mode = AdmitMode::kInteresting);

    // [verdict 重构] 承接旧 dispatcher 的 Seed 构造 + 准入决策。control loop 在
    // feedback.Process(event) 拿到 verdict 后调用本方法,corpus 据 admit_mode_ 决定
    // 是否收;收则构造 Seed(canonical materialize payload + artifact + priority +
    // SeedSourceMetadata)。divert=true(triage_enabled)时构造好的 Seed 经
    // OfferResult.built_seed 返回给 caller 路由到 PendingSeedMap,不进 inbox。
    // next_seed_id:loop 持有的单调 seed-id 计数器(单 Tick 线程,无 atomic),建新
    //   seed 时 ++(承接旧 dispatcher 的 allocate_seed_id);作参数传入而非成员,免去
    //   既有构造调用点(xiuos/tests)的改动。
    OfferResult OfferVerdict(const std::vector<uint8_t>& program_payload,
                             const std::shared_ptr<const ::refuzz::program::ProgramArtifact>& artifact,
                             const Verdict& verdict,
                             SeedSource source,
                             bool divert_to_caller,
                             uint64_t& next_seed_id,
                             // [mab lineage Step A] caller-decided seed lineage:
                             // origin arm + parent corpus seed. Same contract as
                             // `source` above — corpus only STAMPS it onto the
                             // built Seed; the gen-vs-mut classification is
                             // control's job, not corpus's.
                             SeedOrigin origin = SeedOrigin::kBoot,
                             uint64_t parent_seed_id = 0);

    int RegisterFilter(std::string name, std::unique_ptr<ICorpusFilter> filter);
    int RegisterAdmissionPolicy(std::string name, std::unique_ptr<ICorpusAdmissionPolicy> policy);

    bool SwitchAdmissionPolicyByName(std::string_view name);
    void SwitchAdmissionPolicy(int idx);
    bool MaybeApplyPendingSwitch();
    std::string ActivePolicyName() const;
    void SetOnAdmit(std::function<void(const Seed&)> cb);
    // Called when a content-duplicate candidate is merged into an existing seed.
    // This is deliberately narrower than on_admit_: duplicate saves must update
    // corpus-wide coverage accounting like syzkaller Corpus.Save(), but must not
    // repeat new-seed side effects such as scheduler/mutator notifications.
    void SetOnCoverMerge(std::function<void(const Seed&)> cb);

    void Tick();
    bool SweepIfGrowthExceeds(std::uint64_t growth_pct);

    // [coverage-ownership bound] 用一次批量 best-owner 选举把当前 store 收敛成最小
    // 覆盖集,并据此(重)建 SignalOwnershipIndex —— "批量建" 部分。每条边选最优 owner
    // (per-edge prio 高 → 程序小 → seed_id 小,= syz signal.Minimize),拥有 0 边的
    // seed 被驱逐(RemoveSeed + scheduler InvalidateSeed)。覆盖 union 按构造保留。
    // 调用时机:首次 Tick lazy bootstrap(boot/续跑的 loaded corpus 不保证已最小)+
    // FuzzerLoop 60s wall-clock sweep + 关机前最终一次(落盘前一致)。
    // 仅用 signal_cover_hashes(EDGES,= 准入单元);无 CorpusCoverageMetadata 或空覆盖
    // 的 seed 视为覆盖未知,保留且不入索引。public 以便测试。
    void EstablishInvariantFromStore();

    // [v2 SubT-D] 让所有 stateful filter 用 store 当前 seed 集合 bootstrap state。
    // 调用时机:首次 Tick 内 lazy 触发(无需 orchestrator 主动调用)。public 以便
    // 测试显式 bootstrap。
    void BootstrapFiltersFromStore();

    // Publish current corpus-owned gauges from the actual store state. This is
    // intentionally separate from corpus_growth: growth is cumulative admits,
    // while size/bytes are the current post-prune corpus.
    void PublishMetrics();

private:
    bool TryAdmit(Seed candidate, const CorpusContext& ctx);
    // [syz corpus.go:140 parity] 把 candidate 的 stable signal/cover MERGE 进
    // 既有 seed(content-duplicate),而非 reject-and-lose。UpdateSeedMetadata
    // in-place union signal_cover_hashes(per-edge max prio)+ cover_hashes。
    // 所有权在下次 sweep(EstablishInvariantFromStore)按新 signal 重新选举。
    void MergeIntoExisting(std::uint64_t existing_seed_id, const Seed& candidate);
    void SyncPayloadBytesFromStore();

    ICorpusStore& store_;
    const core::EngineHandle<ISchedulerEngine>& scheduler_handle_;
    CorpusInbox& inbox_;
    int max_drain_;
    refuzz::fuzzer::metrics::FuzzerMetrics* metrics_ = nullptr;
    AdmitMode admit_mode_;            // [verdict 重构] 准入模式

    std::vector<std::unique_ptr<ICorpusFilter>> filter_registry_;
    std::unordered_map<std::string, int> filter_name_index_;
    std::vector<std::unique_ptr<ICorpusAdmissionPolicy>> admission_policy_registry_;
    std::unordered_map<std::string, int> admission_policy_name_index_;
    std::atomic<int> next_admission_policy_idx_{0};
    int admission_policy_idx_ = 0;
    std::function<void(const Seed&)> on_admit_;
    std::function<void(const Seed&)> on_cover_merge_;

    // Current corpus payload bytes. Initialized once from the boot-loaded store,
    // then maintained incrementally on admit/drop.
    int64_t running_payload_bytes_ = 0;
    bool payload_bytes_initialized_ = false;

    // [v2 SubT-D] filter bootstrap-from-store flag。首次 Tick lazy 触发,
    // ForEachSeed → 通知所有 filter OnSeedAdded,让 stateful filter
    // (eg. ContentHashDedupFilter)同步 store 已加载的 seed hash。
    bool filters_bootstrapped_ = false;

    // [coverage-ownership bound] 边-owner 快照 = 语料"最小覆盖集"这个覆盖事实。准入
    // 不门它(admit-all);它由 EstablishInvariantFromStore 在 boot 首次 Tick + FuzzerLoop
    // 60s 周期 sweep 重建,用于暴露 corpus_owned_edges 指标 + 给 sweep 提供 owner 表。
    SignalOwnershipIndex ownership_;
    bool ownership_bootstrapped_ = false;
    // 上次周期 sweep 时的语料大小;语料较此增长超阈值才再 sweep(摊销 O(corpus) 成本,
    // 镜像 syz manager.go lastMinCorpus 的增长门控)。
    std::size_t last_swept_size_ = 0;
};

} // namespace refuzz::fuzzer

#pragma once

#include "refuzz/scheduler/scheduler_engine.hpp"
#include "refuzz/scheduler/scheduling_policy.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <random>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace refuzz::fuzzer {

class ICorpusStore;  // refuzz/fuzzer/interfaces.hpp — for value-weighted policies
class SeedHorizon;   // refuzz/scheduler/horizon/seed_horizon.hpp — future(seed)
class SeedBand2;     // refuzz/scheduler/horizon/seed_band2.hpp — band-② shadow candidate
class StaticBeliefGraph;  // refuzz/scheduler/horizon/static_belief_graph.hpp — belief-graph prior

// 优先级调度 engine：持有 N 个 ISchedulingPolicy，按 policy 驱动
// ready_queue / boosted / cooled 三路状态做种子选取。
// 构造时 policy 由外部 (Assembler / 测试) 通过 RegisterPolicy 注入。
// [value-weighted policies] 可选注入 corpus_store:非空时 engine 在 OnSeedAdded
// 维护 per-seed cover + PC 计数(经 SchedulerContext 暴露给 size/rarity 加权
// policy);为空时退化为 coverage-blind(priority/round_robin/uniform 不受影响)。
class PrioritySchedulerEngine final : public ISchedulerEngine {
public:
    explicit PrioritySchedulerEngine(const ICorpusStore* corpus_store = nullptr);

    std::string Name() const override;
    std::optional<SeedSelection> NextSeedId() override;
    void OnFeedback(uint64_t seed_id, SeedDisposition disposition) override;
    void OnSeedAdded(uint64_t seed_id) override;
    bool SwitchPolicyByName(std::string_view name) override;
    std::string ActivePolicyName() const override;
    // [v2 batch 3 G6] 从 ready_queue_ / boosted_ / cooled_ / known_ 各 pool erase。
    // O(N) on ready_queue_(线性扫 + erase);其它 pool 是 set/deque,O(N) erase。
    // corpus_verify_consumer 调用频率低(只在 retry 达上限时一次),性能可接受。
    void InvalidateSeed(uint64_t seed_id) override;
    // [mab-stage-selection Step 2] 转发给 active policy(只有 mab_exp3ix 消费)。
    void OnSeedReward(uint64_t seed_id, double pr, double gamma,
                      double cov_gain, double task_time_s) override;
    // [seed-value signal A] Σ 1/pc_count over the seed's cached stable cover;
    // 0 if unknown / no corpus_store (seed_cover_ empty). See ISchedulerEngine.
    double SeedRarityScore(uint64_t seed_id) const override;
    // [seed-value signals shadow] forward to the active policy's per-seed Ĝ.
    double SeedMabGhat(uint64_t seed_id) const override;
    // [seed-value signal C target] Σ 1/pc_count over an arbitrary PC cover.
    double CoverRarityScore(const std::vector<std::uint64_t>& cover_pcs) const override;
    // [seed-future-value] future(seed) cached at OnSeedAdded; 0 if no SeedHorizon.
    double SeedFutureValue(uint64_t seed_id) const override;
    // [future_cht] masked call-transition horizon cached at OnSeedAdded; 0 if none.
    double SeedTransitionValue(uint64_t seed_id) const override;
    // [future_band2] band-② residual-per-call cached at OnSeedAdded; 0 if no SeedBand2.
    double SeedBand2Value(uint64_t seed_id) const override;
    // [belief-graph] static unlock-potential prior cached at OnSeedAdded; 0 if no graph.
    double SeedBeliefValue(uint64_t seed_id) const override;
    // [belief-graph Phase B] forward region-precise live calibration to the injected graph (no-op if null).
    void ObserveBelief(
        const std::unordered_set<std::string>& executed,
        const std::unordered_map<std::string, std::vector<std::uint64_t>>& new_by_variant) override;
    bool BeliefActive() const override { return belief_graph_ != nullptr; }
    void DumpBeliefPosterior(const std::string& path) const override;

    // 装配期：注册一个调度 policy。第一个注册的 policy 自动成为 active。
    int RegisterPolicy(std::string name, std::unique_ptr<ISchedulingPolicy> policy);

    // [seed-future-value] inject the (orchestrator-owned, non-owning) SeedHorizon.
    // Set before seeds are added; OnSeedAdded then caches future(seed). Null =
    // disabled (SeedFutureValue returns 0). Observation only.
    void SetSeedHorizon(SeedHorizon* horizon) { seed_horizon_ = horizon; }

    // [future_band2] inject the (orchestrator-owned, non-owning) SeedBand2. Set before
    // seeds are added; OnSeedAdded then caches band-②(seed). Null = disabled.
    void SetSeedBand2(SeedBand2* band2) { seed_band2_ = band2; }

    // [belief-graph] inject the (orchestrator-owned, non-owning) StaticBeliefGraph. Set
    // before seeds are added; OnSeedAdded then caches belief(seed). Null = disabled.
    void SetBeliefGraph(StaticBeliefGraph* graph) { belief_graph_ = graph; }

private:
    // 被 NextSeedId / OnFeedback / OnSeedAdded 在入口调用;完成后 policy_idx_ 已稳定。
    bool ApplyPendingSwitchIfAny();

    // 构造一个 SchedulerContext,把三路 id 池 + value-weighted 输入(seed_cover_/
    // pc_count_/rng_)的指针填好。NextSeedId / OnFeedback 共用,避免重复填字段。
    SchedulerContext MakeContext();

    std::vector<std::unique_ptr<ISchedulingPolicy>> policy_registry_;
    std::unordered_map<std::string, int> policy_name_index_;

    std::vector<uint64_t> ready_queue_;
    std::deque<uint64_t> boosted_;
    std::unordered_set<uint64_t> cooled_;
    std::unordered_set<uint64_t> known_;
    size_t cursor_ = 0;

    std::atomic<int> next_policy_idx_{-1};
    int policy_idx_ = -1;

    // [value-weighted policies] 覆盖价值数据,仅在 corpus_store_ 非空时维护。
    const ICorpusStore* corpus_store_ = nullptr;
    std::unordered_map<uint64_t, std::vector<uint64_t>> seed_cover_;  // id -> cover PCs
    std::unordered_map<uint64_t, std::uint32_t>         pc_count_;    // PC -> #seeds
    std::mt19937_64 rng_;  // 确定性默认 seed → 跨 run 可复现

    // [seed-future-value] non-owning; OnSeedAdded caches future(seed) here.
    SeedHorizon*                            seed_horizon_ = nullptr;
    std::unordered_map<uint64_t, double>    future_;  // seed id -> future(seed)
    std::unordered_map<uint64_t, double>    cht_;     // seed id -> future_cht (transition horizon)
    // [future_band2] non-owning band-② shadow candidate; cached at OnSeedAdded.
    SeedBand2*                              seed_band2_ = nullptr;
    std::unordered_map<uint64_t, double>    band2_;   // seed id -> band-② residual/call
    // [belief-graph] non-owning static belief-graph prior; cached at OnSeedAdded.
    StaticBeliefGraph*                      belief_graph_ = nullptr;
    std::unordered_map<uint64_t, double>    belief_;  // seed id -> static unlock-potential
};

} // namespace refuzz::fuzzer

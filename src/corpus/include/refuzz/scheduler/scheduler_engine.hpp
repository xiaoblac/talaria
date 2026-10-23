#pragma once

#include "refuzz/fuzzer/feedback_verdict.hpp"   // SeedDisposition（曾在 feedback/，已下沉 core/）
#include "refuzz/fuzzer/seed_selection.hpp"   // [mab] NextSeedId 返回 {seed,pr,γ}(core 共享词汇)

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace refuzz::fuzzer {

// 调度 engine 接口。每个 engine 是一种自治的调度范式，
// 内部可持有多个 policy 并支持运行时切换。
// Manager 持有 N 个 engine 做路由，不介入执行。
//
// policy 切换语义(v2):
//   * SwitchPolicyByName 任意线程调用,仅记录 pending;
//   * engine 在下一次 NextSeedId/OnFeedback/OnSeedAdded 入口 lazy apply;
//   * 接口不暴露"commit"操作,FuzzerLoop/Manager 不感知两阶段细节。
class ISchedulerEngine {
public:
    virtual ~ISchedulerEngine() = default;
    virtual std::string Name() const = 0;
    // [mab] 返回 {seed_id, pr, γ}:pr/γ 是该次抽样的重要性权重参数,作为数据沿 stage→loop
    // 流动,reward 回流时回传给无状态 OnSeedReward。非 MAB engine/policy 取中性默认 (1,0)。
    virtual std::optional<SeedSelection> NextSeedId() = 0;
    virtual void OnFeedback(uint64_t seed_id, SeedDisposition disposition) = 0;
    virtual void OnSeedAdded(uint64_t seed_id) = 0;
    virtual bool SwitchPolicyByName(std::string_view name) = 0;
    virtual std::string ActivePolicyName() const = 0;

    // [v2 batch 3 G6] 通知 scheduler 该 seed 不应再被 NextSeedId 选中。
    //   - boot load 时:`corpus_disk_io::LoadFromFiles` 对 inactive seed
    //     **不调 OnSeedAdded**(根本不进 pool),InvalidateSeed 用于运行时 deactivate。
    //   - 运行时:`corpus_verify_consumer_stage` 在 retry 达上限时调用。
    // 默认 no-op:legacy scheduler 不感知 invalidate(用户用其它 impl 时承担
    // "inactive 不被跳过" 风险);PrioritySchedulerEngine 实现端从各 pool erase。
    virtual void InvalidateSeed(uint64_t /*seed_id*/) {}

    // [mab-stage-selection Step 2] seed-MAB 数值 reward 通道。FuzzerLoop 在 mutation task
    // 回流时调用,engine 转发给 active policy(只有 mab_exp3ix 消费;其它 policy / engine
    // default no-op)。pr/γ=该次抽样的重要性权重参数(loop 从 exec_id 簿记取回);
    // cov_gain=该种子被变异这次的新覆盖,task_time_s=执行时延。
    virtual void OnSeedReward(uint64_t /*seed_id*/, double /*pr*/, double /*gamma*/,
                              double /*cov_gain*/, double /*task_time_s*/) {}

    // [seed-value signal A] 该 seed 的稀有度加权覆盖分(shadow 信号,
    // docs/plans/seed-value-signals.md §2.1):Σ_{pc∈cover} 1/pc_count(pc)。
    // 在选择时刻读,反映「此刻」corpus 频率(非平稳=设计的自动衰减)。
    // default 0 = engine 不维护覆盖价值数据(无 corpus_store / coverage-blind)。
    virtual double SeedRarityScore(uint64_t /*seed_id*/) const { return 0.0; }

    // [seed-value signal C target] rarity-weight an ARBITRARY raw-PC cover set
    // (Σ 1/pc_count over the given PCs). Used to score a mutation's full executed
    // footprint = rare_cov_gain (how rare the regions it reached are). Same
    // pc_count basis as SeedRarityScore. default 0 = no corpus frequency data.
    virtual double CoverRarityScore(
        const std::vector<std::uint64_t>& /*cover_pcs*/) const { return 0.0; }

    // [seed-value signals shadow] active policy 的 per-seed 学习值估计(MAB Ĝ)。
    // 仅作 shadow 离线分析的 baseline 控制(信号须预测 MAB 已知之外的产出)。
    // default 0 = 无 MAB / coverage-blind policy。
    virtual double SeedMabGhat(uint64_t /*seed_id*/) const { return 0.0; }

    // [seed-future-value] forward/structural E[mass] of the seed — the de-flattened
    // resource-precondition horizon (coverage-novelty masked), computed at admit
    // by the injected SeedHorizon. 0 = no SeedHorizon / non-syz seed. Shadow-read
    // beside SeedMabGhat to test whether future adds beyond backward.
    virtual double SeedFutureValue(uint64_t /*seed_id*/) const { return 0.0; }

    // [future_cht / Psyzkaller] novelty-masked static call-transition horizon:
    // Σ over the seed's calls of the static ChoiceTable successor prior toward
    // not-yet-exercised successors. Forward signal in the ORDER/transition stratum
    // (P_chT), orthogonal to SeedFutureValue's unordered resource horizon. 0 = no
    // horizon / no transition table. Shadow only.
    virtual double SeedTransitionValue(uint64_t /*seed_id*/) const { return 0.0; }

    // [future_band2 / kill-shot] band-② uncovered-handler-mass-per-call, the first
    // forward signal that supplements backward — SHADOW ONLY, a CANDIDATE not truth
    // (shallow-detonator biased, code mass != triggerable mass). 0 = no SeedBand2 /
    // no cover / non-syz. Validated against deep/long-horizon yield before it leads.
    virtual double SeedBand2Value(uint64_t /*seed_id*/) const { return 0.0; }
    // [belief-graph] static 8-mechanism unlock-potential prior, cached at OnSeedAdded.
    // 0 = no StaticBeliefGraph / non-syz. Observation only (shadow). See StaticBeliefGraph.
    virtual double SeedBeliefValue(uint64_t /*seed_id*/) const { return 0.0; }

    // [belief-graph Phase B] region-precise live calibration of the belief graph's per-edge (α,β) from
    // one execution. executed = variants whose calls ran (precondition A ran); new_by_variant = each
    // executed variant → the globally-new PCs ITS call produced (so the graph can test whether B's new
    // frontier landed in a specific edge's gated slice R). No-op when no StaticBeliefGraph. Calibrates
    // the posterior; does not drive selection (Phase C). See StaticBeliefGraph::Observe.
    virtual void ObserveBelief(
        const std::unordered_set<std::string>& /*executed*/,
        const std::unordered_map<std::string, std::vector<std::uint64_t>>& /*new_by_variant*/) {}
    // Cheap gate: true iff a StaticBeliefGraph is loaded, so the loop only builds the executed/frontier
    // sets when ObserveBelief will consume them.
    virtual bool BeliefActive() const { return false; }
    // Persist the calibrated (α,β) posterior at run end (so a campaign yields the frontier-corrected prior,
    // not just the static ρ0 in the shadow json). No-op when no StaticBeliefGraph.
    virtual void DumpBeliefPosterior(const std::string& /*path*/) const {}
};

} // namespace refuzz::fuzzer

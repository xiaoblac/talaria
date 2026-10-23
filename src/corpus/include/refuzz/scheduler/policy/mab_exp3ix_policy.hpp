#pragma once
// [mab-stage-selection Step 2] seed-selection MAB —— SyzVegas Algorithm 2(纯 Exp3-IX)。
// 详见 docs/plans/mab-stage-selection.md §5。
//
//   arm = corpus seed;reward = 该 seed 变异任务在 **completion** 时的 found 覆盖,经 SyzVegas
//   相对货币归一(g = c·(Tmut/Cmut) − t,x = tanh(g/2σ),累积 σ;本实例只见 mutation 任务,
//   故 bar 自动 = Tmut/Cmut = SyzVegas Eq 11);选择/更新 = Exp3-IX(η=2γ=θ·√(2lnK/K))。
//
// 架构:ISchedulingPolicy 方法 const(state 住 SchedulerContext)。但 MAB 的 per-seed Ĝ
// 是真·evolving 状态,不是 ctx 能表达的 → 用 mutable 成员持 core 的 refuzz::mab 原语
// (与 control 的 task-MAB 复用同一份算法)。arm 在 Next() 里对 ready 种子 lazy 注册
// (handle policy 切换 / boot-load 早于 activation);invalidate 的种子 arm 残留无害
// (Next 只在 ready_queue 里选,残留 arm 不会被选中)。

#include "refuzz/core/mab/exp3_bandit.hpp"
#include "refuzz/core/mab/mab_reward.hpp"
#include "refuzz/scheduler/scheduling_policy.hpp"

#include <cstdint>
#include <optional>

namespace refuzz::fuzzer {

class MabExp3IxPolicy final : public ISchedulingPolicy {
public:
    // [SyzVegas baseline] reward = 相对货币 tanh + 累积 σ,无窗口/分位旋钮(那是绝对覆盖塌缩才
    // 需要的补丁,已移除)。
    //
    // [seed-value signal A — cold-arm rarity prior] rarity_prior_alpha (α):
    //   α=0(默认)= 纯 SyzVegas 基线,新臂 Ĝ₀=0;
    //   α>0       = 新种子注册时给一点前瞻性 head-start Ĝ₀ = α·clamp(rarity/mean−1, 0, cap),
    //               稀有覆盖的冷种子更早被试,真实 reward 累积后自然淹过(decaying prior)。
    //   这是 "MAB 积累 + 一点前瞻预测" 的 treatment 臂;A/B 用 α=0 vs α>0 比覆盖/bug 轨迹。
    explicit MabExp3IxPolicy(double rarity_prior_alpha = 0.0);

    std::optional<uint64_t> Next(SchedulerContext& ctx) const override;
    void OnFeedback(SchedulerContext& ctx, uint64_t seed_id,
                    SeedDisposition disposition) const override;
    // [无状态 reward] (pr, γ) 由 control loop 从 exec_id 在途簿记回传(本 policy 不持 per-seed
    // 在途状态):x=Settle(cov,t) → bandit_.Update(seed_id, pr, γ, x)。
    void OnSeedReward(uint64_t seed_id, double pr, double gamma, double cov_gain,
                      double task_time_s) const override;
    // [seed-value signals shadow] expose the arm's Ĝ (0 if unseen). Baseline
    // control for the offline analysis; never affects selection.
    double SeedMabGhat(uint64_t seed_id) const override;

private:
    // [signal A prior] 新臂注册时算 cold-arm Ĝ₀(α=0 → 恒 0 = 基线)。用运行中的 rarity
    // 均值标准化(只读 ctx.seed_cover/pc_count,与 RarityWeightedPolicy 同源),先用**先前**
    // 均值算 boost 再计入当前(免自比);早期均值不稳 → boost≈0(中性)。
    double ColdArmPrior(SchedulerContext& ctx, uint64_t seed_id) const;

    // const 接口下的真实学习状态(见头注)。注意:**无** per-seed 在途快照——reward 回流的
    // (pr, γ) 由 control loop 持有并回传(无状态打分器),corpus 调度侧不感知 exec_id。
    mutable refuzz::mab::Exp3Bandit bandit_;   // kFixedTheta(Algorithm 2)
    mutable refuzz::mab::MabReward  reward_;    // SyzVegas 相对货币归一(完成时 found cov)
    // [signal A prior] α + 运行中的 rarity 均值(标准化 head-start 用)。
    const double          prior_alpha_;
    mutable double        rar_sum_ = 0.0;  // Σ rarity over registered (covered) arms
    mutable std::uint64_t rar_n_   = 0;    // count
};

} // namespace refuzz::fuzzer

#pragma once

#include "refuzz/fuzzer/feedback_verdict.hpp"   // SeedDisposition（曾在 feedback/，已下沉 core/）
#include "refuzz/scheduler/scheduling_context.hpp"

#include <optional>

namespace refuzz::fuzzer {

struct ISchedulingPolicy {
    virtual ~ISchedulingPolicy() = default;
    virtual std::optional<uint64_t> Next(SchedulerContext& ctx) const = 0;
    virtual void OnFeedback(SchedulerContext& ctx, uint64_t seed_id, SeedDisposition disposition) const = 0;
    virtual void OnActivated(SchedulerContext& /*ctx*/) const {}

    // [mab-stage-selection Step 2] seed-MAB 的数值 reward 通道(SeedDisposition 枚举喂不动
    // Exp3-IX)。**无状态纯函数**:reward 回流时 control loop 把该次抽样的 (pr, γ) 一并传回(它
    // 持有 exec_id→{seed,pr,γ} 的在途簿记),policy 自己不留任何 per-seed 在途状态。default
    // no-op:只有 MabExp3IxPolicy 消费,算 x=Settle(cov,t) 后 Ĝ_seed += x/(pr+γ)。
    virtual void OnSeedReward(uint64_t /*seed_id*/, double /*pr*/, double /*gamma*/,
                              double /*cov_gain*/, double /*task_time_s*/) const {}

    // [seed-value signals shadow] the policy's own learned value estimate for a
    // seed (MAB Ĝ). Used only as the baseline control in the offline shadow
    // analysis (a signal must predict yield BEYOND what the MAB already knows).
    // default 0 = policy has no per-seed value state (non-MAB policies).
    virtual double SeedMabGhat(uint64_t /*seed_id*/) const { return 0.0; }
};

} // namespace refuzz::fuzzer

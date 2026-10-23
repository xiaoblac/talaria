// [mab-stage-selection — SyzVegas baseline] MabTaskSelector —— task-MAB 决策协调器。
//
// 详见 docs/plans/mab-stage-selection.md §4。持 2-arm(gen/mut)Exp3Bandit(kEpoch)+ MabReward
// + inflight map(executor_id → {arm, pr, γ}:产出快照,供 completion 结算与 FOUND 诊断)。
// 不含 IO;FuzzerLoop 在 RunOnce / ProcessEventFeedback 调它。
//
// 时序(SyzVegas:**每个任务在 completion 结算一次**,reward = found coverage 的相对货币):
//   1. Select(elig, rng)        → 抽 arm,带回 (pr, γ)
//   2. 链产出 task → RecordProduced(executor_id, pick) → 记 inflight(executor_id → {arm, pr, γ})
//   3. completion event 回流 → OnEvent(executor_id, cov_gain, task_time_s) → **结算该次选择**:
//        g = cov_gain − t·R → x = tanh(g/2σ) → Ĝ_arm += x/(pr+γ);并记 FOUND 诊断。
//      miss(cov_gain=0)→ g=−t·R<0 → x<0 → Ĝ 回落(见 MabReward 头注;t=guest exec 窗,triage-immune)。
// **为什么 completion 而非 admission 结算**:SyzVegas 对每个任务(win + miss)结算一次,miss 的负
//   reward 正是让 Ĝ 回落、share 自然消退的机制。admission-only 只见 win → Ĝ 单调不降 → 冻结早期
//   领先(旧 anchored 路径的病根)。admission 现仅供 found-vs-admitted 诊断(RecordAdmitDiagnostic)。

#pragma once

#include "refuzz/core/mab/exp3_bandit.hpp"
#include "refuzz/control/mab/mab_arm.hpp"
#include "refuzz/core/mab/mab_reward.hpp"

#include <array>
#include <cstdint>
#include <mutex>
#include <optional>
#include <random>
#include <unordered_map>

namespace refuzz::control::mab {

// [mab core 迁移] 共享 MAB 原语已下沉 core(refuzz::mab)。control 侧沿用本地短名。
using refuzz::mab::Exp3Bandit;
using refuzz::mab::Exp3Config;
using refuzz::mab::MabReward;
using refuzz::mab::MabRewardConfig;

struct MabTaskConfig {
    double time_cap_s = 2.0;  // reward 任务时间成本 t(秒)的 outlier 截顶;真实 exec 时间下生效(~2s)
};

// 本 slot 哪些 arm 可被选(sleeping-bandit,§4.1)。generate 恒可选;mutate 需 corpus 非空;
// triage 需任一 triage-group follow-up(verify/reexec/minimize)有 pending。
struct ArmEligibility {
    bool generate = true;
    bool mutate   = false;
    bool triage   = false;
};

class MabTaskSelector {
public:
    explicit MabTaskSelector(MabTaskConfig cfg = {});

    // 抽样产物:选中的 arm + 抽样瞬间的 (pr, γ),供 deferred reward 归属。
    struct Pick {
        MabArm arm   = MabArm::kGenerate;
        double pr    = 0.0;
        double gamma = 0.0;
    };

    // 在 eligible arm 内按 Ĝ 抽一个。全不 eligible → nullopt(调用方本 slot 不投)。
    std::optional<Pick> Select(const ArmEligibility& elig, std::mt19937_64& rng);

    // 链已用本 Pick 产出 executor_id 的 task → 记 inflight(arm + 抽样快照 pr/γ,供 completion
    // 结算精确归属该次选择)。
    void RecordProduced(std::uint64_t executor_id, const Pick& pick);

    // producer-selection completion 回流:**结算该次选择**(每任务一次)。
    //   g = cov_gain − task_time_s·R → x = tanh(g/2σ) → Ĝ_arm += x/(pr+γ),pr/γ 取 inflight 快照。
    //   task_time_s = 该任务的 guest exec 窗(秒,triage-immune);并记 per-arm FOUND-coverage
    //   诊断(panel 辨 found vs admitted)。未跟踪的 executor_id(非 MAB 产出 / 已消费)→ no-op。
    void OnEvent(std::uint64_t executor_id, double cov_gain, double task_time_s);

    // [诊断,非 reward] corpus admission 时按 origin arm 记 admitted coverage,供 panel 的
    // found-vs-admitted 对照。**不**触 bandit(reward 由 completion 的 OnEvent 结算)。
    void RecordAdmitDiagnostic(MabArm arm, double admitted_cov);

    // 内省(metrics / 单测 / 运行时观测)。
    double        Ghat(MabArm a) const;
    std::uint32_t Epoch() const;
    std::size_t   InflightCount() const;
    std::uint64_t PickCount(MabArm a) const;
    std::uint64_t EventCount(MabArm a) const;
    double        CovSum(MabArm a) const;
    std::uint64_t CovHits(MabArm a) const;
    // [t-probe] per-arm 累计 guest exec 时间(秒,raw 未截顶)。avg=TimeSum/EventCount,
    // 裁决 reward 的 cost 项 t 是否真在区分 gen(长程序)vs mut(短程序)。
    double        TimeSum(MabArm a) const;
    // [t-probe] per-arm raw task_time 分布分位(ms)。mean 被慢尾(mount seed)污染→必须看 p50/p95/p99。
    double        TimePctlMs(MabArm a, double q) const;
    std::uint64_t AdmitEventCount(MabArm a) const;
    double        AdmitCovSum(MabArm a) const;

private:
    struct Inflight {
        MabArm arm   = MabArm::kGenerate;  // 产出该 task 的 arm
        double pr    = 0.0;                // 抽样瞬间 pr(Exp3-IX 权重)
        double gamma = 0.0;                // 抽样瞬间 γ
    };

    mutable std::mutex                             mu_;
    Exp3Bandit                                    bandit_;
    MabReward                                     reward_;
    std::unordered_map<std::uint64_t, Inflight>   inflight_;
    std::uint64_t                                 picks_[kMabArmCount] = {0, 0, 0};
    std::uint64_t                                 events_[kMabArmCount]   = {0, 0, 0};
    double                                        cov_sum_[kMabArmCount]  = {0.0, 0.0, 0.0};
    double                                        time_sum_[kMabArmCount] = {0.0, 0.0, 0.0};
    std::array<std::array<std::uint32_t, 64>, kMabArmCount> t_hist_{};  // [t-probe] log 桶(~1ms–6s)
    std::uint64_t                                 cov_hits_[kMabArmCount] = {0, 0, 0};
    std::uint64_t                                 admit_events_[kMabArmCount]  = {0, 0, 0};
    double                                        admit_cov_sum_[kMabArmCount] = {0.0, 0.0, 0.0};
};

} // namespace refuzz::control::mab

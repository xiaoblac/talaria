#pragma once

#include <cstdint>

namespace refuzz::fuzzer {

// [mab-stage-selection] 一次 seed 选择的完整结果 = seed_id + 该次抽样的 importance-weight
// 参数 (pr, γ)。pr/γ 是 MAB 量(调度词汇内),用于 reward 回流时算 Exp3-IX 的
// Ĝ += x/(pr+γ)。非 MAB policy 不做重要性加权 → 取中性默认 (pr=1, γ=0),其 OnSeedReward
// 是 no-op,这两个值不被消费。
//
// 住 core 的共享词汇(refuzz/fuzzer/,与 feedback_verdict.hpp 同层):core 的 SchedulerLike
// concept 约束 NextSeedId 的返回类型 = optional<SeedSelection>,corpus 的 scheduler 实现返回
// 它,control 的 loop 消费它。
//
// 设计:把 (pr, γ) 当**选择结果的数据**沿 NextSeedId → stage → loop 流动,policy 自身**不**
// 保留任何 per-seed 在途状态;在途生命周期(exec_id 簿记)归 control FuzzerLoop,corpus
// 调度侧完全不感知 exec_id。
struct SeedSelection {
    std::uint64_t seed_id = 0;
    double        pr      = 1.0;  // 选择概率(Exp3-IX 重要性权重分母的一项);非 MAB = 1
    double        gamma   = 0.0;  // 探索项 γ;非 MAB = 0
};

} // namespace refuzz::fuzzer

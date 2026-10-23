#pragma once

#include "refuzz/scheduler/scheduling_policy.hpp"

namespace refuzz::fuzzer {

// [value-weighted experiment] syzkaller chooseProgram 的忠实对位:
//   weight(seed) = len(cover)   (覆盖的 PC 数,最小 1,= syz prio = len(signal))
// 在 ready_queue(跳过 cooled)上按 weight **加权随机** —— 覆盖更多的种子被选
// 概率成正比更高。需 SchedulerContext.seed_cover + rng;缺数据时退化为 uniform。
class SizeWeightedPolicy final : public ISchedulingPolicy {
public:
    std::optional<uint64_t> Next(SchedulerContext& ctx) const override;
    void OnFeedback(SchedulerContext& ctx, uint64_t seed_id, SeedDisposition disposition) const override;
};

} // namespace refuzz::fuzzer

#pragma once

#include "refuzz/scheduler/scheduling_policy.hpp"

namespace refuzz::fuzzer {

// [value-weighted experiment] 稀有度加权(novel,非 syz 现有行为):
//   weight(seed) = Σ_{pc ∈ cover} 1 / pc_count(pc)
// 守稀有/近乎独占覆盖的种子权重高,纠正 size 加权"过度偏向大但与他人重叠的程序"
// 的偏差。需 SchedulerContext.seed_cover + pc_count + rng;缺数据时退化为 uniform。
class RarityWeightedPolicy final : public ISchedulingPolicy {
public:
    std::optional<uint64_t> Next(SchedulerContext& ctx) const override;
    void OnFeedback(SchedulerContext& ctx, uint64_t seed_id, SeedDisposition disposition) const override;
};

} // namespace refuzz::fuzzer

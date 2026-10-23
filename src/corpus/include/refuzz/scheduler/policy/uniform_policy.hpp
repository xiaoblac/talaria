#pragma once

#include "refuzz/scheduler/scheduling_policy.hpp"

namespace refuzz::fuzzer {

// [value-weighted experiment] Coverage-blind 基线:在 ready_queue 上(一次性跳过
// cooled)**均匀随机**选种子,不做 boost。用来隔离"按价值加权到底有没有用"——
// 任何加权 policy 要算改进,就得赢过它。需 SchedulerContext.rng;缺则退化取尾。
class UniformPolicy final : public ISchedulingPolicy {
public:
    std::optional<uint64_t> Next(SchedulerContext& ctx) const override;
    void OnFeedback(SchedulerContext& ctx, uint64_t seed_id, SeedDisposition disposition) const override;
};

} // namespace refuzz::fuzzer

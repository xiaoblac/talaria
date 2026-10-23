#pragma once

#include "refuzz/scheduler/scheduling_policy.hpp"

namespace refuzz::fuzzer {

class PriorityPolicy final : public ISchedulingPolicy {
public:
    std::optional<uint64_t> Next(SchedulerContext& ctx) const override;
    void OnFeedback(SchedulerContext& ctx, uint64_t seed_id, SeedDisposition disposition) const override;
};

} // namespace refuzz::fuzzer

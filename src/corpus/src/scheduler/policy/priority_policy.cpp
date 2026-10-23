#include "refuzz/scheduler/policy/priority_policy.hpp"

#include <optional>

namespace refuzz::fuzzer {

std::optional<uint64_t> PriorityPolicy::Next(SchedulerContext& ctx) const
{
    while (!ctx.boosted.empty()) {
        const uint64_t id = ctx.boosted.back();
        ctx.boosted.pop_back();
        if (ctx.cooled.erase(id) > 0) {
            continue;
        }
        return id;
    }

    if (ctx.ready_queue.empty()) {
        return std::nullopt;
    }

    for (size_t i = 0; i < ctx.ready_queue.size(); ++i) {
        const uint64_t id = ctx.ready_queue[ctx.ready_queue.size() - 1 - i];
        if (ctx.cooled.erase(id) > 0) {
            continue;
        }
        return id;
    }
    return std::nullopt;
}

void PriorityPolicy::OnFeedback(SchedulerContext& ctx,
                                 uint64_t seed_id,
                                 SeedDisposition disposition) const
{
    switch (disposition) {
    case SeedDisposition::kPromote:
        ctx.boosted.push_back(seed_id);
        ctx.boosted.push_back(seed_id);
        break;
    case SeedDisposition::kDemote:
        ctx.cooled.insert(seed_id);
        break;
    case SeedDisposition::kNeutral:
        break;
    }
}

} // namespace refuzz::fuzzer

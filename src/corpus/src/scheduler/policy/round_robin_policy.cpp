#include "refuzz/scheduler/policy/round_robin_policy.hpp"

#include <optional>

namespace refuzz::fuzzer {

std::optional<uint64_t> RoundRobinPolicy::Next(SchedulerContext& ctx) const
{
    while (!ctx.boosted.empty()) {
        const uint64_t id = ctx.boosted.front();
        ctx.boosted.pop_front();
        if (ctx.cooled.erase(id) > 0) {
            continue;
        }
        return id;
    }

    if (ctx.ready_queue.empty()) {
        return std::nullopt;
    }

    for (size_t i = 0; i < ctx.ready_queue.size(); ++i) {
        if (ctx.cursor >= ctx.ready_queue.size()) {
            ctx.cursor = 0;
        }
        const uint64_t id = ctx.ready_queue[ctx.cursor++];
        if (ctx.cooled.erase(id) > 0) {
            continue;
        }
        return id;
    }
    return std::nullopt;
}

void RoundRobinPolicy::OnFeedback(SchedulerContext& ctx,
                                   uint64_t seed_id,
                                   SeedDisposition disposition) const
{
    switch (disposition) {
    case SeedDisposition::kPromote:
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

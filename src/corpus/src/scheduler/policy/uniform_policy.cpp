#include "refuzz/scheduler/policy/uniform_policy.hpp"

#include <cstdint>
#include <random>
#include <vector>

namespace refuzz::fuzzer {

std::optional<uint64_t> UniformPolicy::Next(SchedulerContext& ctx) const
{
    if (ctx.ready_queue.empty()) {
        return std::nullopt;
    }
    // 收集未冷却候选;cooled 命中即一次性清(与 priority/round_robin 同语义:
    // 冷却只跳过一轮,下轮重新可选)。
    std::vector<uint64_t> cand;
    cand.reserve(ctx.ready_queue.size());
    for (const uint64_t id : ctx.ready_queue) {
        if (ctx.cooled.erase(id) > 0) {
            continue;
        }
        cand.push_back(id);
    }
    if (cand.empty()) {
        return std::nullopt;
    }
    if (ctx.rng == nullptr) {
        return cand.back();  // 防御:无 rng(不应发生)退化取尾
    }
    std::uniform_int_distribution<std::size_t> dist(0, cand.size() - 1);
    return cand[dist(*ctx.rng)];
}

void UniformPolicy::OnFeedback(SchedulerContext& ctx, uint64_t seed_id,
                               SeedDisposition disposition) const
{
    // 纯选择基线:不 boost(promote 无效);仅 demote(timeout/error)冷却,
    // 避免反复选已知坏种子。
    if (disposition == SeedDisposition::kDemote) {
        ctx.cooled.insert(seed_id);
    }
}

} // namespace refuzz::fuzzer

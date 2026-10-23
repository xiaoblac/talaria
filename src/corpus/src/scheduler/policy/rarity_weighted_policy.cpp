#include "refuzz/scheduler/policy/rarity_weighted_policy.hpp"

#include "refuzz/scheduler/rarity_score.hpp"  // shared Σ 1/pc_count formula

#include <cstdint>
#include <random>
#include <vector>

namespace refuzz::fuzzer {

std::optional<uint64_t> RarityWeightedPolicy::Next(SchedulerContext& ctx) const
{
    if (ctx.ready_queue.empty()) {
        return std::nullopt;
    }
    // 候选 + 权重 = Σ_{pc∈cover} 1/pc_count(pc)。守稀有覆盖的种子权重高。
    std::vector<uint64_t> ids;
    std::vector<double>    weights;
    double total = 0.0;
    ids.reserve(ctx.ready_queue.size());
    weights.reserve(ctx.ready_queue.size());
    for (const uint64_t id : ctx.ready_queue) {
        if (ctx.cooled.erase(id) > 0) {
            continue;
        }
        double weight = 1.0;  // floor: uncovered seeds keep baseline probability
        if (ctx.seed_cover != nullptr && ctx.pc_count != nullptr) {
            const auto it = ctx.seed_cover->find(id);
            if (it != ctx.seed_cover->end() && !it->second.empty()) {
                const double sum = RarityScore(it->second, *ctx.pc_count);
                if (sum > 0.0) {
                    weight = sum;
                }
            }
        }
        ids.push_back(id);
        weights.push_back(weight);
        total += weight;
    }
    if (ids.empty()) {
        return std::nullopt;
    }
    if (ctx.rng == nullptr || total <= 0.0) {
        return ids.back();  // 防御:无 rng / 无覆盖数据 → 退化取尾
    }
    std::uniform_real_distribution<double> dist(0.0, total);
    const double r = dist(*ctx.rng);
    double acc = 0.0;
    for (std::size_t i = 0; i < ids.size(); ++i) {
        acc += weights[i];
        if (r <= acc) {
            return ids[i];
        }
    }
    return ids.back();
}

void RarityWeightedPolicy::OnFeedback(SchedulerContext& ctx, uint64_t seed_id,
                                      SeedDisposition disposition) const
{
    if (disposition == SeedDisposition::kDemote) {
        ctx.cooled.insert(seed_id);
    }
}

} // namespace refuzz::fuzzer

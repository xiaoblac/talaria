#include "refuzz/scheduler/policy/size_weighted_policy.hpp"

#include <cstdint>
#include <random>
#include <vector>

namespace refuzz::fuzzer {

std::optional<uint64_t> SizeWeightedPolicy::Next(SchedulerContext& ctx) const
{
    if (ctx.ready_queue.empty()) {
        return std::nullopt;
    }
    // 候选 + 权重 = len(cover)(最小 1,= syz prio==0→1)。cooled 一次性跳过。
    std::vector<uint64_t> ids;
    std::vector<double>    weights;
    double total = 0.0;
    ids.reserve(ctx.ready_queue.size());
    weights.reserve(ctx.ready_queue.size());
    for (const uint64_t id : ctx.ready_queue) {
        if (ctx.cooled.erase(id) > 0) {
            continue;
        }
        double weight = 1.0;
        if (ctx.seed_cover != nullptr) {
            const auto it = ctx.seed_cover->find(id);
            if (it != ctx.seed_cover->end() && !it->second.empty()) {
                weight = static_cast<double>(it->second.size());
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
        return ids.back();  // 防御:无 rng / 无权重数据 → 退化取尾(≈ priority)
    }
    // 加权随机:在 [0,total) 取点,走累积权重(= syz accPrios 前缀和的线性版)。
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

void SizeWeightedPolicy::OnFeedback(SchedulerContext& ctx, uint64_t seed_id,
                                    SeedDisposition disposition) const
{
    // 纯加权:权重已反映覆盖价值,不另做 boost;仅 demote 冷却。
    if (disposition == SeedDisposition::kDemote) {
        ctx.cooled.insert(seed_id);
    }
}

} // namespace refuzz::fuzzer

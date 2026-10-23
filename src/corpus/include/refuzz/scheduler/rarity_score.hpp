// Signal A — rarity-weighted coverage score (docs/plans/seed-value-signals.md
// §2.1). Shared by RarityWeightedPolicy (selection weight) and
// PrioritySchedulerEngine::SeedRarityScore (shadow signal), so the formula has
// a single home.
//
//   RarityScore(cover) = Σ_{pc ∈ cover} 1 / max(pc_count(pc), 1)
//
// Rare PCs (covered by few corpus members) dominate the sum, so a seed guarding
// near-exclusive coverage scores high. Empty cover → 0.0 (no information).
// pc_count missing / 0 is treated as 1 (the seed itself covers it).
#pragma once

#include <cstdint>
#include <unordered_map>
#include <vector>

namespace refuzz::fuzzer {

inline double RarityScore(
    const std::vector<std::uint64_t>&                       cover,
    const std::unordered_map<std::uint64_t, std::uint32_t>& pc_count)
{
    double sum = 0.0;
    for (const std::uint64_t pc : cover) {
        const auto it = pc_count.find(pc);
        const std::uint32_t cnt =
            (it != pc_count.end() && it->second > 0) ? it->second : 1u;
        sum += 1.0 / static_cast<double>(cnt);
    }
    return sum;
}

} // namespace refuzz::fuzzer

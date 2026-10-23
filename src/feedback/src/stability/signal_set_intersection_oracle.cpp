// signal_set_intersection_oracle.cpp —— SubT-A / kernel IStabilityOracle impl.
// 算法详 hpp 头注释。

#include "refuzz/feedback/stability/signal_set_intersection_oracle.hpp"

#include <algorithm>
#include <iterator>
#include <utility>

namespace refuzz::fuzzer {

std::optional<std::vector<std::uint64_t>>
SignalSetIntersectionOracle::ExtractStable(
    const std::vector<std::vector<std::uint64_t>>& runs,
    int min_votes) const
{
    // 严格交集:始终要求所有 run 命中,忽略 min_votes(见 hpp 说明)。
    (void)min_votes;
    if (runs.empty()) {
        return std::nullopt;
    }

    // baseline = runs[0]。
    std::vector<std::uint64_t> baseline = runs[0];

    for (std::size_t i = 1; i < runs.size(); ++i) {
        std::vector<std::uint64_t> tmp;
        tmp.reserve(std::min(baseline.size(), runs[i].size()));
        std::set_intersection(
            baseline.begin(), baseline.end(),
            runs[i].begin(),  runs[i].end(),
            std::back_inserter(tmp));
        baseline = std::move(tmp);
        if (baseline.empty()) {
            // 一旦 intersection 空,后续 run 不可能让它非空 — early exit。
            return std::nullopt;
        }
    }

    if (baseline.empty()) {
        return std::nullopt;  // flaky
    }
    return baseline;
}

}  // namespace refuzz::fuzzer

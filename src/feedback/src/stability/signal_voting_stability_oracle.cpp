// signal_voting_stability_oracle.cpp —— k-of-n 投票式 IStabilityOracle impl。
// 算法详 hpp 头注释。

#include "refuzz/feedback/stability/signal_voting_stability_oracle.hpp"

#include <algorithm>
#include <cstddef>
#include <unordered_map>

namespace refuzz::fuzzer {

std::optional<std::vector<std::uint64_t>>
SignalVotingStabilityOracle::ExtractStable(
    const std::vector<std::vector<std::uint64_t>>& runs,
    int min_votes) const
{
    if (runs.empty()) {
        return std::nullopt;
    }

    const std::size_t n = runs.size();
    // clamp 到 [1, n]:<=0 或 >= n 都退化为严格交集(need == n,所有 run 都得命中)。
    std::size_t need = (min_votes <= 0) ? n : static_cast<std::size_t>(min_votes);
    if (need > n) {
        need = n;
    }

    // 计票:每个 hash 出现在多少个 run 里。runs[i] 已是 sorted+unique(EngineOutput
    // 保证),故每个 run 对同一 hash 至多贡献 1 票 —— 直接累加即「出现的 run 数」。
    std::unordered_map<std::uint64_t, std::size_t> votes;
    for (const auto& run : runs) {
        for (const std::uint64_t h : run) {
            ++votes[h];
        }
    }

    std::vector<std::uint64_t> stable;
    stable.reserve(votes.size());
    for (const auto& [h, count] : votes) {
        if (count >= need) {
            stable.push_back(h);
        }
    }
    if (stable.empty()) {
        return std::nullopt;  // 没有任何 hash 凑够 need 票 → flaky
    }
    // 与 SignalSetIntersectionOracle 输出契约一致:sorted + unique(计票天然 unique)。
    std::sort(stable.begin(), stable.end());
    return stable;
}

}  // namespace refuzz::fuzzer

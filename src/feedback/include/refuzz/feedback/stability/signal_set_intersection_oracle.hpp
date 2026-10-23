// signal_set_intersection_oracle.hpp —— SubT-A / kernel IStabilityOracle impl.
//
// strict set_intersection 算法(等价 syzkaller pkg/fuzzer/job.go:221-301 deflake
// 的 stable-signal 提取语义):
//   1. baseline = runs[0]
//   2. for i in 1..N: baseline = set_intersection(baseline, runs[i])
//   3. baseline empty → flaky(nullopt);baseline 非空 → stable
//
// 算法保证两侧 sorted + unique(CompositeFeedback EngineOutput.new_signal_hashes
// 已经 sort + unique,详 composite_feedback_engine.cpp:82-95)。
//
// 详 docs/admit-pipeline-alignment/200_batch2_framework_primitives.md §3.A。

#pragma once

#include "refuzz/feedback/stability_oracle.hpp"

namespace refuzz::fuzzer {

class SignalSetIntersectionOracle final : public IStabilityOracle {
public:
    // 严格交集 oracle:**要求所有 run 都命中**(等价 k-of-n 的 k==n)。min_votes
    // 形参仅为接口一致性接收,本 oracle 始终做严格交集(忽略其值)。需要 flaky 容错
    // 投票(k<n,如 corpus 候选 2/6)的 family 应改用 SignalVotingStabilityOracle。
    std::optional<std::vector<std::uint64_t>> ExtractStable(
        const std::vector<std::vector<std::uint64_t>>& runs,
        int min_votes) const override;
};

}  // namespace refuzz::fuzzer

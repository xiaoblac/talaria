// signal_voting_stability_oracle.hpp —— k-of-n 投票式 IStabilityOracle impl。
//
// 对齐 syzkaller deflake 的「common to k out of n runs」语义(pkg/fuzzer/job.go:
// 102-131 + 280-294 的 signals[] 阶梯)。一个 hash 只要出现在 **至少 min_votes 个**
// run 里,就算稳定信号 —— 不要求每个 run 都命中。这容忍内核 flaky:
//   - corpus 候选 2/6:80% 复现率的程序 ~99.9% 通过去抖(syz 注释的二项分布账)。
//   - 严格交集(SignalSetIntersectionOracle)= 本 oracle 在 min_votes==n 时的特例。
//
// min_votes 由调用方从 IRetryPolicy.MinStableVotes(source) 取并传入(boot 候选 2,
// 新 prog 取 n 即退化严格)。本 oracle 不感知 SeedSource —— 纯 k-of-n 计票,保持
// feedback 模块边界:阈值是「策略」(retry_policy 产),计票是「算法」(本 oracle)。
//
// 注:reFuzz 的 corpus_verify / triage 一次性投 n 个 reexec task 再批量判定,没有
// syzkaller 的自适应提前停(跑到信号稳定就停)。故 n 是固定的(=VerifyRuns),flaky
// 容错完全由 min_votes 阈值提供。自适应提前停是独立的吞吐优化,见 follow-up。

#pragma once

#include "refuzz/feedback/stability_oracle.hpp"

namespace refuzz::fuzzer {

class SignalVotingStabilityOracle final : public IStabilityOracle {
public:
    // 一个 hash 出现在 ≥ clamp(min_votes, 1, runs.size()) 个 run 里即视为稳定。
    // min_votes <= 0 或 >= runs.size() → 退化为严格交集(等价 SignalSetIntersectionOracle)。
    std::optional<std::vector<std::uint64_t>> ExtractStable(
        const std::vector<std::vector<std::uint64_t>>& runs,
        int min_votes) const override;
};

}  // namespace refuzz::fuzzer

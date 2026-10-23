// syzkaller_retry_policy.hpp —— SubT-B / kernel IRetryPolicy impl.
//
// syzkaller pkg/fuzzer/fuzzer.go:190-207 + job.go:221-301 等价语义:
//   MaxAttempts:
//     kBootCorpus + risky → 2 (candidate 重试上限)
//     kBootCorpus + safe  → 3
//     非 kBootCorpus      → 0 (新 prog 不 retry,首次失败即 drop)
//     Snapshot 模式       → 0 (本 impl 不 expose snapshot 语义,等 batch 3 G6 调用方决定)
//   VerifyRuns / MinStableVotes(= k-of-n 的 n / k,见 retry_policy.hpp):
//     kBootCorpus → n=boot_verify_runs_(默认 6)/ k=boot_min_votes_(默认 2)→ 2/6 容错
//     其它(新 prog)→ n=5 / k=3 → 3-of-5(= syzkaller deflakeMaxRuns/NeedRuns;容忍
//                    flaky-but-real 信号。旧 3/3 严格交集漏大量有用信号,见 .cpp MinStableVotes)
//   IsRisky:
//     本批次先返 false(所有 seed 视为 safe);批次 3 G6 实施时挂 onceCrashed metadata
//     再读取(SeedAuditMetadata 或新加 SeedRiskMetadata 决定)
//
// boot 的 (n, k) 走构造参数,让 profile 各自配置而不影响别的 family:kernel profile
// 传 (6, 2) 启用 2/6 容错(配 SignalVotingStabilityOracle);xiuos 用默认构造但其
// stability oracle 仍是严格 SignalSetIntersectionOracle,故 k 形同虚设、维持 n-of-n。
//
// 详 docs/admit-pipeline-alignment/200_batch2_framework_primitives.md §3.B。

#pragma once

#include "refuzz/feedback/retry_policy.hpp"

namespace refuzz::fuzzer {

class SyzkallerRetryPolicy final : public IRetryPolicy {
public:
    // boot_verify_runs:kBootCorpus 去抖的 n 上限;boot_min_votes:其 k(≥k 命中即稳定);
    // boot_min_runs:自适应初始并行批量(<=0 → = boot_verify_runs,即不自适应)。
    // 默认 (2, 2, 0) = 旧的严格固定 2/2(默认构造者如 xiuos 维持原状,且 xiuos 用严格
    // intersection oracle);kernel profile 显式传 (6, 2, 4) 启用 syzkaller 自适应 2/6:
    // 先并行投 4,clean 候选即停,flaky 逐个加投到 6。
    explicit SyzkallerRetryPolicy(int boot_verify_runs = 2,
                                  int boot_min_votes   = 2,
                                  int boot_min_runs    = 0);

    int  MaxAttempts   (std::uint8_t source, bool risky) const override;
    int  VerifyRuns    (std::uint8_t source) const override;
    int  MinVerifyRuns (std::uint8_t source) const override;
    int  MinStableVotes(std::uint8_t source) const override;
    bool IsRisky       (const Seed& seed) const override;

private:
    int boot_verify_runs_;
    int boot_min_votes_;
    int boot_min_runs_;
};

}  // namespace refuzz::fuzzer

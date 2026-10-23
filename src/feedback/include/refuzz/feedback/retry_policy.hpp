// retry_policy.hpp —— SubT-B / framework primitive: candidate retry policy.
//
// 目的:抽出"corpus seed verify retry / risky 判定 / verify run 次数"的策略层,
// 让不同 family 注入不同 retry 语义:
//   - kernel:syzkaller-style(SyzkallerRetryPolicy)— Snapshot=0 / Risky=2 / Safe=3,
//                                                   verify_runs candidate=2 / generated=3
//   - 其它 family (future):各自决定 retry 上限 + risky 判定(eg. AFL skeleton 可能没 retry)
//
// 本批次 SubT-B 仅搭骨架(interface + kernel impl + 装配 wire),**不接 caller**。
// 批次 3 G6 corpus_verify_stage 才 read 决策。
//
// Framework primitive injection pattern 沿用 SubT-A 7 步(详父 plan §2);
// **K5 同步抽 ProfileDefaults factory pattern**:profile.make_retry_policy lambda
// 决定哪个 impl,Assembler 走 profile.make_retry_policy() dispatch + fallback default。
//
// 详 docs/admit-pipeline-alignment/200_batch2_framework_primitives.md §3.B。

#pragma once

#include <cstdint>

namespace refuzz::fuzzer {

struct Seed;

// 设计选择:接口用 std::uint8_t 抽象 source 而非 `SeedSource` enum,**刻意**让
// framework primitive 头不 `#include "refuzz/program/seed_metadata.hpp"` —
// framework 跟 program/ 解耦,caller 自由决定是 cast 回 SeedSource enum 还是直接
// 传 magic number。
// 数值约定跟 program/seed_metadata.hpp `enum class SeedSource : uint8_t` 一一对齐:
//   0=kBootCorpus / 1=kMutation / 2=kReplayHistory / 3=kFaultHistory。
// 备注:技术上 enum class : uint8_t 在 C++11 后可 forward decl,本设计选 uint8_t
// 不是因为不能 fwd decl(L2 review fix 2026-05-09),而是上文 framework 解耦考量。
// kernel impl 内部 `static_cast<SeedSource>(source)` 处理。

class IRetryPolicy {
public:
    virtual ~IRetryPolicy() = default;

    // 该 SeedSource 下,risky seed 允许的最大 retry 次数(含首次执行)。
    //   syzkaller candidate (kBootCorpus) + risky → 2 / safe → 3 / snapshot → 0
    //   kMutation 等其它 source → kernel impl 各自决定(默认 0 不 retry,等 G6 真正用时再覆盖)
    virtual int MaxAttempts(std::uint8_t source, bool risky) const = 0;

    // verify (deflake) 阶段的 **最大** N-run 次数(= k-of-n 投票的 n 上限)。syzkaller:
    //   kBootCorpus  → 6 (deflakeMaxCorpusRuns;配合 MinStableVotes=2 → 2/6 容错窗口)
    //   kMutation    → 5 (deflakeMaxRuns;配合 MinStableVotes=3 → 3-of-5 容错)
    //   kReplay/Fault → 同 kMutation
    virtual int VerifyRuns(std::uint8_t source) const = 0;

    // verify 阶段的 **最小** N-run 次数(自适应去抖的初始并行批量 + 提前停下限)。
    // corpus_verify 先并行投 MinVerifyRuns 个;若此时还没凑出稳定信号且未达 VerifyRuns
    // 上限,再逐个加投(对齐 syzkaller deflake「跑到信号稳定就停,最多 maxRuns」)。
    //   kBootCorpus → 4 (deflakeMinCorpusRuns;clean 候选 4 次即 stable → 提前停)
    //   kMutation 等 → 3 (deflakeNeedRuns;先投 3,信号不稳再加投到 5 → 3-of-5 自适应)
    // 返回 <=0 或 > VerifyRuns 时,调用方按 = VerifyRuns 处理(退化为固定批量)。
    virtual int MinVerifyRuns(std::uint8_t source) const = 0;

    // deflake 判 stable 所需的最小「命中 run 数」(= k-of-n 投票的 k);交给
    // SignalVotingStabilityOracle.ExtractStable(runs, k)。与 VerifyRuns(n) 配对构成
    // 每 source 的稳定性策略。syzkaller:
    //   kBootCorpus  → 2 (deflakeNeedCorpusRuns;2/6,容忍 flaky corpus 候选)
    //   kMutation 等 → 3 (deflakeNeedRuns;与 n=5 = 3-of-5,容忍 flaky-but-real 的新 prog 信号;
    //                  旧 k=n=3 是 3/3 严格交集,把非确定性边按 p³ 丢 → 漏大量有用信号,见 .cpp)
    // 返回 <=0 时调用方按严格交集处理(k=n)。
    virtual int MinStableVotes(std::uint8_t source) const = 0;

    // 该 seed 是否 risky(影响 MaxAttempts)。
    //   kernel SyzkallerRetryPolicy:看 seed.metadata 里的 onceCrashed 标志(future 加)
    //   本批次先返 false(所有 seed 视为 safe),批次 3 G6 实施时挂 metadata 字段
    virtual bool IsRisky(const Seed& seed) const = 0;
};

}  // namespace refuzz::fuzzer

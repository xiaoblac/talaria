// syzkaller_retry_policy.cpp —— SubT-B / kernel IRetryPolicy impl.
// 详 hpp 头注释。

#include "refuzz/feedback/retry/syzkaller_retry_policy.hpp"

#include "refuzz/program/seed_metadata.hpp"  // SeedSource enum (uint8_t cast 检验)

namespace refuzz::fuzzer {

SyzkallerRetryPolicy::SyzkallerRetryPolicy(int boot_verify_runs,
                                           int boot_min_votes,
                                           int boot_min_runs)
    : boot_verify_runs_(boot_verify_runs > 0 ? boot_verify_runs : 1)
    , boot_min_votes_(boot_min_votes > 0 ? boot_min_votes : 1)
    , boot_min_runs_(boot_min_runs)  // <=0 → MinVerifyRuns 退化为 = boot_verify_runs_
{}

int SyzkallerRetryPolicy::MaxAttempts(std::uint8_t source, bool risky) const
{
    // syzkaller candidate (kBootCorpus) retry 上限:
    //   onceCrashed (risky) → 2  (1 首次 + 1 retry)
    //   safe                → 3  (1 首次 + 2 retries)
    // 其它 source 不 retry — 新 prog flaky 直接 drop。
    if (source == static_cast<std::uint8_t>(SeedSource::kBootCorpus)) {
        return risky ? 2 : 3;
    }
    return 0;
}

int SyzkallerRetryPolicy::VerifyRuns(std::uint8_t source) const
{
    // k-of-n 投票的 n(上限)。配 MinStableVotes 的 k:
    //   candidate (kBootCorpus) → boot_verify_runs_(默认 6)→ 配 k=2 得 2/6 容错
    //   新 prog                  → 5(= syzkaller deflakeMaxRuns)→ 配 k=3 得 **3-of-5**
    if (source == static_cast<std::uint8_t>(SeedSource::kBootCorpus)) {
        return boot_verify_runs_;
    }
    return 5;
}

int SyzkallerRetryPolicy::MinVerifyRuns(std::uint8_t source) const
{
    // 自适应去抖的初始并行批量 / 提前停下限(= k-of-n 的 n 下限)。
    //   kBootCorpus → boot_min_runs_(默认 0 → 退化 = boot_verify_runs_,不自适应);
    //                 kernel 传 4 → 先投 4,clean 候选即停,flaky 加投到 6。
    //   新 prog      → 3(= syzkaller deflakeNeedRuns)→ 先投 3,信号不稳再加投到 5(自适应)。
    if (source == static_cast<std::uint8_t>(SeedSource::kBootCorpus)) {
        const int mr = (boot_min_runs_ > 0 && boot_min_runs_ <= boot_verify_runs_)
                           ? boot_min_runs_
                           : boot_verify_runs_;
        return mr;
    }
    return 3;
}

int SyzkallerRetryPolicy::MinStableVotes(std::uint8_t source) const
{
    // k-of-n 投票的 k(见 retry_policy.hpp)。
    //   kBootCorpus → boot_min_votes_(默认 2)→ 与 n=6 组成 2/6 容错窗口
    //   新 prog      → 3(= syzkaller deflakeNeedRuns)→ 与 n=5 组成 **3-of-5**。
    //     对齐 syzkaller(job.go:111「programs reproduce with high, but not 100% probability;
    //     the triage algorithm must tolerate this」→ common to 3-of-5;80% 复现率 94% 通过)。
    //     旧值 k=n=3 是 3/3 严格交集,把任何非确定性边按 p³ 丢弃(p=0.8 只留 51%),对 gen/mut
    //     都丢了大量 flaky-but-real 的有用信号 —— 这才是修法,不是放松。
    if (source == static_cast<std::uint8_t>(SeedSource::kBootCorpus)) {
        return boot_min_votes_;
    }
    return 3;
}

bool SyzkallerRetryPolicy::IsRisky(const Seed& /*seed*/) const
{
    // 本批次先返 false(所有 seed 视为 safe;batch 3 G6 加 onceCrashed metadata 后挂)。
    return false;
}

}  // namespace refuzz::fuzzer

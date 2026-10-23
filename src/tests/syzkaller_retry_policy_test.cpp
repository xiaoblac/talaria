// syzkaller_retry_policy_test.cpp
//
// SubT-B unit test:验 SyzkallerRetryPolicy 数值匹配 syzkaller pkg/fuzzer 等价语义。
// 详 docs/admit-pipeline-alignment/200_batch2_framework_primitives.md §3.B。

#include "refuzz/feedback/retry/syzkaller_retry_policy.hpp"
#include "refuzz/program/seed.hpp"
#include "refuzz/program/seed_metadata.hpp"

#include <cstdio>
#include <cstdint>

namespace {

int tests_run = 0;
int tests_passed = 0;

#define CHECK(cond) do {                                                  \
    if (!(cond)) {                                                        \
        std::fprintf(stderr, "    CHECK failed: %s [line %d]\n",          \
                     #cond, __LINE__);                                    \
        return false;                                                     \
    }                                                                     \
} while (0)

#define RUN_TEST(fn) do {                                                 \
    ++tests_run;                                                          \
    std::fprintf(stdout, "  %-60s ", #fn);                                \
    std::fflush(stdout);                                                  \
    if (fn()) { ++tests_passed; std::fprintf(stdout, "PASS\n"); }         \
    else      { std::fprintf(stdout, "FAIL\n"); }                         \
} while (0)

using refuzz::fuzzer::Seed;
using refuzz::fuzzer::SeedSource;
using refuzz::fuzzer::SyzkallerRetryPolicy;

constexpr std::uint8_t kBoot     = static_cast<std::uint8_t>(SeedSource::kBootCorpus);
constexpr std::uint8_t kMut      = static_cast<std::uint8_t>(SeedSource::kMutation);
constexpr std::uint8_t kReplay   = static_cast<std::uint8_t>(SeedSource::kReplayHistory);
constexpr std::uint8_t kFault    = static_cast<std::uint8_t>(SeedSource::kFaultHistory);

bool TestMaxAttemptsBootCorpusRisky()
{
    SyzkallerRetryPolicy p;
    // syzkaller candidate + onceCrashed → 2(1 首次 + 1 retry)
    CHECK(p.MaxAttempts(kBoot, /*risky=*/true) == 2);
    return true;
}

bool TestMaxAttemptsBootCorpusSafe()
{
    SyzkallerRetryPolicy p;
    // syzkaller candidate + safe → 3(1 首次 + 2 retries)
    CHECK(p.MaxAttempts(kBoot, /*risky=*/false) == 3);
    return true;
}

bool TestMaxAttemptsNonBootCorpusNoRetry()
{
    SyzkallerRetryPolicy p;
    // 新 prog (kMutation) / replay / fault 都不 retry — 首次失败即 drop
    CHECK(p.MaxAttempts(kMut, /*risky=*/true)  == 0);
    CHECK(p.MaxAttempts(kMut, /*risky=*/false) == 0);
    CHECK(p.MaxAttempts(kReplay, /*risky=*/false) == 0);
    CHECK(p.MaxAttempts(kFault, /*risky=*/false) == 0);
    return true;
}

bool TestVerifyRunsBootCorpus()
{
    // 默认构造保留旧的严格 2/2(boot_verify_runs=2)——给默认构造者(如 xiuos)。
    SyzkallerRetryPolicy p;
    CHECK(p.VerifyRuns(kBoot) == 2);
    // kernel profile 显式传 (6,2) 启用 syzkaller 2/6 的 n=6。
    SyzkallerRetryPolicy kernel(/*boot_verify_runs=*/6, /*boot_min_votes=*/2);
    CHECK(kernel.VerifyRuns(kBoot) == 6);
    return true;
}

bool TestVerifyRunsNonBootCorpus()
{
    SyzkallerRetryPolicy p;
    // 新 prog deflake n=5(= syzkaller deflakeMaxRuns;配 k=3 → 3-of-5);构造参数只影响 boot。
    CHECK(p.VerifyRuns(kMut)    == 5);
    CHECK(p.VerifyRuns(kReplay) == 5);
    CHECK(p.VerifyRuns(kFault)  == 5);
    SyzkallerRetryPolicy kernel(6, 2);
    CHECK(kernel.VerifyRuns(kMut) == 5);
    return true;
}

bool TestMinStableVotesBootCorpus()
{
    // 默认 k=2;kernel (6,2) 也 k=2 → 与 n=6 组成 2/6 容错窗口。
    SyzkallerRetryPolicy p;
    CHECK(p.MinStableVotes(kBoot) == 2);
    SyzkallerRetryPolicy kernel(/*boot_verify_runs=*/6, /*boot_min_votes=*/2);
    CHECK(kernel.MinStableVotes(kBoot) == 2);
    // 自定义 boot_min_votes 透传。
    SyzkallerRetryPolicy custom(8, 3);
    CHECK(custom.MinStableVotes(kBoot) == 3);
    CHECK(custom.VerifyRuns(kBoot)     == 8);
    return true;
}

bool TestMinStableVotesNonBoot3of5()
{
    // 非 boot:k=3 与 n=5 组成 syzkaller 的 3-of-5(k < n,容忍 flaky-but-real 新 prog 信号)。
    SyzkallerRetryPolicy p;
    CHECK(p.MinStableVotes(kMut)    == 3);
    CHECK(p.MinStableVotes(kReplay) == 3);
    CHECK(p.MinStableVotes(kFault)  == 3);
    CHECK(p.MinStableVotes(kMut)    <  p.VerifyRuns(kMut));  // k<n,非 3/3 严格交集
    return true;
}

bool TestMinVerifyRunsAdaptiveWindow()
{
    // 默认 (2,2,0):boot_min_runs<=0 → MinVerifyRuns 退化 = VerifyRuns(min==max,不自适应)。
    SyzkallerRetryPolicy def;
    CHECK(def.MinVerifyRuns(kBoot) == def.VerifyRuns(kBoot));  // 2 == 2
    // kernel (6,2,4):boot 自适应窗口 [4,6],k=2。
    SyzkallerRetryPolicy kernel(/*boot_verify_runs=*/6, /*boot_min_votes=*/2,
                                /*boot_min_runs=*/4);
    CHECK(kernel.MinVerifyRuns(kBoot) == 4);
    CHECK(kernel.VerifyRuns(kBoot)    == 6);
    CHECK(kernel.MinStableVotes(kBoot) == 2);
    // 非 boot:自适应窗口 [3,5](先投 3,信号不稳加投到 5)= syzkaller 3-of-5。
    CHECK(kernel.MinVerifyRuns(kMut) == 3);
    CHECK(kernel.VerifyRuns(kMut)    == 5);
    CHECK(kernel.MinVerifyRuns(kMut) <  kernel.VerifyRuns(kMut));  // min<max,自适应
    // 越界 boot_min_runs(> max)被钳到 = max(不自适应)。
    SyzkallerRetryPolicy clamp(4, 2, 99);
    CHECK(clamp.MinVerifyRuns(kBoot) == clamp.VerifyRuns(kBoot));  // 4 == 4
    return true;
}

bool TestIsRiskyAlwaysFalseInThisBatch()
{
    SyzkallerRetryPolicy p;
    // 本批次先返 false(所有 seed 视为 safe);批次 3 G6 加 onceCrashed metadata
    // 后挂。这条 case 留作 contract guard — 批次 3 实施时把 false 改成基于
    // metadata,记得同步更新此 case。
    Seed s;
    s.seed_id = 42;
    s.payload = {0x01};
    CHECK(p.IsRisky(s) == false);
    return true;
}

}  // namespace

int main()
{
    std::fprintf(stdout, "Running syzkaller_retry_policy_test...\n");

    RUN_TEST(TestMaxAttemptsBootCorpusRisky);
    RUN_TEST(TestMaxAttemptsBootCorpusSafe);
    RUN_TEST(TestMaxAttemptsNonBootCorpusNoRetry);
    RUN_TEST(TestVerifyRunsBootCorpus);
    RUN_TEST(TestVerifyRunsNonBootCorpus);
    RUN_TEST(TestMinStableVotesBootCorpus);
    RUN_TEST(TestMinStableVotesNonBoot3of5);
    RUN_TEST(TestMinVerifyRunsAdaptiveWindow);
    RUN_TEST(TestIsRiskyAlwaysFalseInThisBatch);

    std::fprintf(stdout, "\nPassed %d/%d tests\n", tests_passed, tests_run);
    return (tests_run == tests_passed) ? 0 : 1;
}

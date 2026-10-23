// signal_voting_stability_oracle_test.cpp
//
// 验 SignalVotingStabilityOracle 的 k-of-n 投票语义,对齐 syzkaller deflake
// 「common to k out of n runs」(pkg/fuzzer/job.go:102-131 + 280-294)。
// 同时验「min_votes >= n / <= 0 → 退化严格交集」与 SignalSetIntersectionOracle 等价。

#include "refuzz/feedback/stability/signal_voting_stability_oracle.hpp"
#include "refuzz/feedback/stability/signal_set_intersection_oracle.hpp"

#include <cstdio>
#include <cstdint>
#include <optional>
#include <vector>

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
    std::fprintf(stdout, "  %-58s ", #fn);                                \
    std::fflush(stdout);                                                  \
    if (fn()) { ++tests_passed; std::fprintf(stdout, "PASS\n"); }         \
    else      { std::fprintf(stdout, "FAIL\n"); }                         \
} while (0)

using refuzz::fuzzer::SignalVotingStabilityOracle;
using refuzz::fuzzer::SignalSetIntersectionOracle;

using Runs = std::vector<std::vector<std::uint64_t>>;

bool eq(const std::optional<std::vector<std::uint64_t>>& got,
        const std::vector<std::uint64_t>& want)
{
    return got.has_value() && *got == want;  // oracle 输出契约:sorted + unique
}

// 2-of-6:命中 ≥2 个 run 的 hash 稳定;只命中 1 个的被丢。
bool TestTwoOfSix()
{
    SignalVotingStabilityOracle o;
    Runs runs = {
        {1, 2, 3},   // run0
        {1, 2},      // run1
        {1},         // run2
        {},          // run3 (失败/空)
        {2, 9},      // run4
        {1},         // run5
    };
    // 票数:1→4, 2→3, 3→1, 9→1。k=2 → {1,2}。
    auto got = o.ExtractStable(runs, /*min_votes=*/2);
    CHECK(eq(got, {1, 2}));
    return true;
}

// flaky:没有任何 hash 凑够 k 票 → nullopt。
bool TestAllFlakyBelowThreshold()
{
    SignalVotingStabilityOracle o;
    Runs runs = {{1}, {2}, {3}};  // 每个 hash 只 1 票
    CHECK(!o.ExtractStable(runs, /*min_votes=*/2).has_value());
    return true;
}

// 确定性程序(所有 run 相同):任何 k≤n 都返回全集。
bool TestDeterministicAllStable()
{
    SignalVotingStabilityOracle o;
    Runs runs = {{5, 7, 9}, {5, 7, 9}, {5, 7, 9}};
    CHECK(eq(o.ExtractStable(runs, 2), {5, 7, 9}));
    CHECK(eq(o.ExtractStable(runs, 3), {5, 7, 9}));  // = 严格交集
    return true;
}

// min_votes >= n 或 <= 0 → 退化严格交集(= 只有所有 run 都命中的 hash)。
bool TestDegradesToStrictIntersection()
{
    SignalVotingStabilityOracle voting;
    SignalSetIntersectionOracle strict;
    Runs runs = {
        {1, 2, 3},
        {2, 3, 4},
        {2, 3, 5},
    };
    // 严格交集 = {2,3}(三 run 都有)。
    const std::vector<std::uint64_t> want = {2, 3};
    CHECK(eq(strict.ExtractStable(runs, /*ignored*/2), want));
    CHECK(eq(voting.ExtractStable(runs, /*min_votes=*/3), want));   // k==n
    CHECK(eq(voting.ExtractStable(runs, /*min_votes=*/99), want));  // clamp 到 n
    CHECK(eq(voting.ExtractStable(runs, /*min_votes=*/0), want));   // <=0 → 严格
    CHECK(eq(voting.ExtractStable(runs, /*min_votes=*/-5), want));
    return true;
}

// k=2 比严格交集更宽容:留住只在 2/3 run 出现的 flaky-but-real 信号。
bool TestVotingKeepsMoreThanStrict()
{
    SignalVotingStabilityOracle voting;
    SignalSetIntersectionOracle strict;
    Runs runs = {
        {1, 2},
        {1, 3},   // 2 没在这,3 没在 run0/run2
        {1, 2},
    };
    // 严格交集 = {1};2 出现在 run0+run2(2 票),3 只 run1(1 票)。
    CHECK(eq(strict.ExtractStable(runs, 2), {1}));
    CHECK(eq(voting.ExtractStable(runs, /*min_votes=*/2), {1, 2}));  // 多留住 2
    return true;
}

// 边界:空 runs → nullopt;单 run → 该 run 自身(need clamp 到 1)。
bool TestEdgeCases()
{
    SignalVotingStabilityOracle o;
    CHECK(!o.ExtractStable({}, 2).has_value());          // 无 run
    CHECK(eq(o.ExtractStable({{4, 8}}, 2), {4, 8}));     // 单 run:need clamp 到 1
    CHECK(!o.ExtractStable({{}, {}}, 1).has_value());    // 都空 → 无信号
    return true;
}

}  // namespace

int main()
{
    std::fprintf(stdout, "Running signal_voting_stability_oracle_test...\n");

    RUN_TEST(TestTwoOfSix);
    RUN_TEST(TestAllFlakyBelowThreshold);
    RUN_TEST(TestDeterministicAllStable);
    RUN_TEST(TestDegradesToStrictIntersection);
    RUN_TEST(TestVotingKeepsMoreThanStrict);
    RUN_TEST(TestEdgeCases);

    std::fprintf(stdout, "\nPassed %d/%d tests\n", tests_passed, tests_run);
    return (tests_run == tests_passed) ? 0 : 1;
}

// job_arbitration_test.cpp
//
// Regression tests for the FuzzerLoop pull-point arbitration.  The task queue
// already has its own tier tests, but routed requests and emit requests are
// selected before they enter that queue.  These tests protect the bug where a
// permanent Explore job at jobs_[0] starved later Smash emit jobs.

#include "refuzz/control/job/job_arbitration.hpp"

#include <cstdint>
#include <cstdio>
#include <iterator>
#include <optional>
#include <vector>

namespace {

using refuzz::control::job::JobArbitrationState;
using refuzz::control::job::PendingJobView;
using refuzz::control::job::SelectNextReadyJobIndex;
using refuzz::queue::TaskTier;

int tests_run = 0;
int tests_passed = 0;

#define CHECK(cond) do {                                                        \
    if (!(cond)) {                                                              \
        std::fprintf(stderr,                                                    \
                     "    CHECK failed: %s [line %d]\n",                        \
                     #cond, __LINE__);                                          \
        return false;                                                           \
    }                                                                           \
} while (0)

#define RUN_TEST(fn) do {                                                       \
    ++tests_run;                                                                \
    std::fprintf(stdout, "  %-60s ", #fn);                                      \
    std::fflush(stdout);                                                        \
    if (fn()) {                                                                 \
        ++tests_passed;                                                         \
        std::fprintf(stdout, "PASS\n");                                         \
    } else {                                                                    \
        std::fprintf(stdout, "FAIL\n");                                        \
    }                                                                           \
} while (0)

PendingJobView Ready(TaskTier tier)
{
    return PendingJobView{tier};
}

PendingJobView NotReady()
{
    return PendingJobView{std::nullopt};
}

bool TestExploreAtIndexZeroDoesNotStarveSmash()
{
    std::vector<PendingJobView> jobs = {
        Ready(TaskTier::Explore),  // Permanent ExploreJob is spawned first.
        Ready(TaskTier::Smash),
    };
    JobArbitrationState state;

    const std::size_t expected[] = {1, 1, 0, 1, 1, 0};
    for (std::size_t i = 0; i < std::size(expected); ++i) {
        const auto idx = SelectNextReadyJobIndex(jobs, state);
        CHECK(idx.has_value());
        CHECK(*idx == expected[i]);
    }
    return true;
}

bool TestRoundRobinWithinTier()
{
    std::vector<PendingJobView> jobs = {
        Ready(TaskTier::Smash),
        Ready(TaskTier::Smash),
        Ready(TaskTier::Smash),
    };
    JobArbitrationState state;

    const std::size_t expected[] = {0, 1, 2, 0, 1, 2};
    for (std::size_t i = 0; i < std::size(expected); ++i) {
        const auto idx = SelectNextReadyJobIndex(jobs, state);
        CHECK(idx.has_value());
        CHECK(*idx == expected[i]);
    }
    return true;
}

bool TestStrictTierBeatsSmashExploreAndDoesNotAdvanceAlternate()
{
    std::vector<PendingJobView> jobs = {
        Ready(TaskTier::Explore),
        Ready(TaskTier::Smash),
        Ready(TaskTier::Triage),
    };
    JobArbitrationState state;

    auto idx = SelectNextReadyJobIndex(jobs, state);
    CHECK(idx.has_value());
    CHECK(*idx == 2);
    CHECK(state.smash_explore_alternate_seq == 0);

    jobs[2] = NotReady();
    idx = SelectNextReadyJobIndex(jobs, state);
    CHECK(idx.has_value());
    CHECK(*idx == 1);  // first Smash/Explore pull starts at Smash, not Explore.
    CHECK(state.smash_explore_alternate_seq == 1);
    return true;
}

bool TestStrictOrderAmongHighTiers()
{
    std::vector<PendingJobView> jobs = {
        Ready(TaskTier::Triage),
        Ready(TaskTier::Candidate),
        Ready(TaskTier::CandidateTriage),
        Ready(TaskTier::Smash),
        Ready(TaskTier::Explore),
    };
    JobArbitrationState state;

    auto idx = SelectNextReadyJobIndex(jobs, state);
    CHECK(idx.has_value());
    CHECK(*idx == 2);

    jobs[2] = NotReady();
    idx = SelectNextReadyJobIndex(jobs, state);
    CHECK(idx.has_value());
    CHECK(*idx == 1);

    jobs[1] = NotReady();
    idx = SelectNextReadyJobIndex(jobs, state);
    CHECK(idx.has_value());
    CHECK(*idx == 0);
    return true;
}

bool TestSmashOnlyNeverIdlesOnAlternateSkip()
{
    std::vector<PendingJobView> jobs = {
        Ready(TaskTier::Smash),
    };
    JobArbitrationState state;

    for (int i = 0; i < 6; ++i) {
        const auto idx = SelectNextReadyJobIndex(jobs, state);
        CHECK(idx.has_value());
        CHECK(*idx == 0);
    }
    return true;
}

bool TestNoReadyJob()
{
    std::vector<PendingJobView> jobs = {
        NotReady(),
        NotReady(),
    };
    JobArbitrationState state;
    CHECK(!SelectNextReadyJobIndex(jobs, state).has_value());
    return true;
}

} // namespace

int main()
{
    RUN_TEST(TestExploreAtIndexZeroDoesNotStarveSmash);
    RUN_TEST(TestRoundRobinWithinTier);
    RUN_TEST(TestStrictTierBeatsSmashExploreAndDoesNotAdvanceAlternate);
    RUN_TEST(TestStrictOrderAmongHighTiers);
    RUN_TEST(TestSmashOnlyNeverIdlesOnAlternateSkip);
    RUN_TEST(TestNoReadyJob);

    if (tests_run != tests_passed) {
        std::fprintf(stderr, "%d/%d tests passed\n", tests_passed, tests_run);
        return 1;
    }
    std::fprintf(stdout, "%d/%d tests passed\n", tests_passed, tests_run);
    return 0;
}

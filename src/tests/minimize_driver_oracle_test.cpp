#include "refuzz/control/stages/minimize_driver.hpp"

#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace {

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

using refuzz::control::MinimizeDriver;

refuzz::crash::CandidateTestInput Candidate(std::vector<std::uint8_t> payload,
                                            int call_index = -1)
{
    refuzz::crash::CandidateTestInput out;
    out.payload = std::move(payload);
    out.call_index = call_index;
    return out;
}

std::unique_ptr<MinimizeDriver> MakeDriver(
    std::vector<refuzz::crash::CandidateTestInput> candidates,
    int remapped_guilty_call_index);

std::unique_ptr<MinimizeDriver> MakeDriver(
    std::vector<refuzz::crash::CandidateTestInput> candidates)
{
    return MakeDriver(std::move(candidates), /*remapped_guilty_call_index=*/-1);
}

std::unique_ptr<MinimizeDriver> MakeDriver(
    std::vector<refuzz::crash::CandidateTestInput> candidates,
    int remapped_guilty_call_index)
{
    return std::make_unique<MinimizeDriver>(
        [candidates = std::move(candidates), remapped_guilty_call_index](
            const refuzz::program::ProgramArtifact&,
            refuzz::crash::CandidateTestFunc test_fn,
            refuzz::crash::StopFunc stop_fn,
            refuzz::crash::MinimizeMode,
            int) mutable {
            refuzz::crash::MinimizeResult result;
            result.success = true;
            result.remapped_guilty_call_index = remapped_guilty_call_index;
            for (const auto& candidate : candidates) {
                if (stop_fn && stop_fn()) break;
                ++result.minimize_attempts;
                auto [matched, title] = test_fn(candidate);
                (void)title;
                if (matched) {
                    result.payload = candidate.payload;
                    ++result.minimize_commits;
                    break;
                }
            }
            return result;
        });
}

// RunInline executes candidates synchronously on the job thread. exec_fn stands
// in for the job's ctx.exec and returns the candidate's signal snapshot.
bool TestRunInlineConvergesOnMatch()
{
    auto driver = MakeDriver({
        Candidate({0x01}),
        Candidate({0x02}),
    });

    MinimizeDriver::StartArgs args;
    args.target_signal_hashes = {1, 2};
    args.mode = refuzz::crash::MinimizeMode::kCallsOnly;

    int exec_calls = 0;
    auto exec_fn = [&](const MinimizeDriver::Candidate& cand)
        -> MinimizeDriver::ExecSignalSnapshot {
        ++exec_calls;
        MinimizeDriver::ExecSignalSnapshot snap;
        // args.guilty_call_index is left at its default (-1 = Extra target), so
        // ObservedTargetSignal reads extra_signal_hashes, not signal_hashes —
        // set both to keep this test's original convergence-loop intent (it is
        // not specifically exercising Extra semantics, just the no-per-call-
        // target fallback path).
        // 0x01 → partial {1} across all attempts (reject); 0x02 → full {1,2}
        // on the first attempt (match) + cover.
        if (!cand.exec_wire_payload.empty() && cand.exec_wire_payload[0] == 0x02) {
            snap.signal_hashes = {1, 2};
            snap.extra_signal_hashes = {1, 2};
            snap.per_call.push_back({
                .coverage_hashes = {100, 101},
                .errno_value = 0,
                .syscall_id = 0,
                .edge_hashes = {},
            });
        } else {
            snap.signal_hashes = {1};
            snap.extra_signal_hashes = {1};
        }
        return snap;
    };

    auto v = driver->RunInline(args, exec_fn, [] { return false; });
    CHECK(exec_calls == 4);
    CHECK((v.final_payload == std::vector<std::uint8_t>{0x02}));
    CHECK((v.final_cover == std::vector<std::uint64_t>{100, 101}));
    return true;
}

bool TestRunInlineMergesFlakyTargetAcrossAttempts()
{
    auto driver = MakeDriver({
        Candidate({0x01}, /*call_index=*/0),
    });

    MinimizeDriver::StartArgs args;
    args.target_signal_hashes = {10, 20};
    args.guilty_call_index = 0;
    args.target_syscall_id = 77;
    args.attempts = 3;
    args.mode = refuzz::crash::MinimizeMode::kCallsOnly;

    int exec_calls = 0;
    auto exec_fn = [&](const MinimizeDriver::Candidate&)
        -> MinimizeDriver::ExecSignalSnapshot {
        ++exec_calls;
        MinimizeDriver::ExecSignalSnapshot snap;
        snap.per_call.push_back({
            .coverage_hashes = exec_calls == 1
                             ? std::vector<std::uint64_t>{10}
                             : std::vector<std::uint64_t>{20},
            .errno_value = 0,
            .syscall_id = 77,
            .edge_hashes = {},
        });
        return snap;
    };

    auto v = driver->RunInline(args, exec_fn, [] { return false; });
    CHECK(exec_calls == 2);
    CHECK((v.final_payload == std::vector<std::uint8_t>{0x01}));
    return true;
}

bool TestRunInlineHonorsSignalPriority()
{
    auto driver = MakeDriver({
        Candidate({0x01}, /*call_index=*/0),
    });

    MinimizeDriver::StartArgs args;
    args.target_signal_hashes = {10};
    args.target_signal_prios = {2};
    args.guilty_call_index = 0;
    args.target_syscall_id = 77;
    args.attempts = 2;
    args.mode = refuzz::crash::MinimizeMode::kCallsOnly;

    int exec_calls = 0;
    auto exec_fn = [&](const MinimizeDriver::Candidate&)
        -> MinimizeDriver::ExecSignalSnapshot {
        ++exec_calls;
        MinimizeDriver::ExecSignalSnapshot snap;
        snap.per_call.push_back({
            .coverage_hashes = {10},
            .errno_value = 0,
            .syscall_id = 77,
            .edge_hashes = {},
            .signal_priority = static_cast<std::uint8_t>(exec_calls == 1 ? 1 : 2),
        });
        return snap;
    };

    auto v = driver->RunInline(args, exec_fn, [] { return false; });
    CHECK(exec_calls == 2);
    CHECK((v.final_payload == std::vector<std::uint8_t>{0x01}));
    return true;
}

bool TestRunInlinePropagatesRemappedGuiltyCall()
{
    auto driver = MakeDriver({
        Candidate({0x01}, /*call_index=*/2),
        Candidate({0x02}, /*call_index=*/0),
    }, /*remapped_guilty_call_index=*/0);

    MinimizeDriver::StartArgs args;
    args.target_signal_hashes = {7};
    args.guilty_call_index = 2;
    args.mode = refuzz::crash::MinimizeMode::kCallsOnly;

    auto exec_fn = [&](const MinimizeDriver::Candidate& cand)
        -> MinimizeDriver::ExecSignalSnapshot {
        MinimizeDriver::ExecSignalSnapshot snap;
        snap.signal_hashes = {7};
        snap.per_call.push_back({
            .coverage_hashes = {},
            .errno_value = 0,
            .syscall_id = 0,
            .edge_hashes = {},
        });
        snap.per_call.push_back({
            .coverage_hashes = {},
            .errno_value = 0,
            .syscall_id = 0,
            .edge_hashes = {},
        });
        snap.per_call.push_back({
            .coverage_hashes = {7},
            .errno_value = 0,
            .syscall_id = 0,
            .edge_hashes = {},
        });
        (void)cand;
        return snap;
    };

    auto v = driver->RunInline(args, exec_fn, [] { return false; });
    CHECK(v.remapped_guilty_call_index == 0);
    CHECK((v.final_payload == std::vector<std::uint8_t>{0x01}));
    return true;
}

bool TestRunInlineCancellationStopsExec()
{
    auto driver = MakeDriver({
        Candidate({0x01}),
        Candidate({0x02}),
        Candidate({0x03}),
    });

    MinimizeDriver::StartArgs args;
    args.target_signal_hashes = {1, 2};
    args.mode = refuzz::crash::MinimizeMode::kCallsOnly;

    int exec_calls = 0;
    bool cancelled = false;
    auto exec_fn = [&](const MinimizeDriver::Candidate&)
        -> MinimizeDriver::ExecSignalSnapshot {
        ++exec_calls;
        cancelled = true;                 // first exec "comes back cancelled"
        return {};                        // empty snapshot
    };
    auto cancelled_fn = [&] { return cancelled; };

    auto v = driver->RunInline(args, exec_fn, cancelled_fn);
    CHECK(exec_calls == 1);               // stop_fn bailed before a 2nd exec
    CHECK(v.final_payload.empty());       // nothing matched
    CHECK(v.final_cover.empty());
    return true;
}

bool TestRunInlineHardStopAbortsSearch()
{
    auto driver = MakeDriver({
        Candidate({0x01}),
        Candidate({0x02}),
    });

    MinimizeDriver::StartArgs args;
    args.target_signal_hashes = {42};
    args.attempts = 3;
    args.mode = refuzz::crash::MinimizeMode::kCallsOnly;

    int exec_calls = 0;
    auto exec_fn = [&](const MinimizeDriver::Candidate&)
        -> MinimizeDriver::ExecSignalSnapshot {
        ++exec_calls;
        MinimizeDriver::ExecSignalSnapshot snap;
        snap.hard_stop = true;
        return snap;
    };

    auto v = driver->RunInline(args, exec_fn, [] { return false; });
    CHECK(exec_calls == 1);
    CHECK(v.hard_stopped);
    CHECK(v.final_payload.empty());
    CHECK(v.final_cover.empty());
    return true;
}

} // namespace

int main()
{
    std::fprintf(stdout, "Running minimize_driver_oracle_test...\n");
    RUN_TEST(TestRunInlineConvergesOnMatch);
    RUN_TEST(TestRunInlineMergesFlakyTargetAcrossAttempts);
    RUN_TEST(TestRunInlineHonorsSignalPriority);
    RUN_TEST(TestRunInlinePropagatesRemappedGuiltyCall);
    RUN_TEST(TestRunInlineCancellationStopsExec);
    RUN_TEST(TestRunInlineHardStopAbortsSearch);
    std::fprintf(stdout, "Result: %d/%d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}

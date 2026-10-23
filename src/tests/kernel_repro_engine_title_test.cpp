#include "refuzz/crash/repro/engine/linuxkernel/syz_engine/syz_repro_engine.hpp"

#include <cstdio>
#include <string>
#include <unordered_set>
#include <vector>

namespace {

int tests_run = 0;
int tests_passed = 0;

#define CHECK(cond) do {                                                        \
    if (!(cond)) {                                                              \
        std::fprintf(stderr, "    CHECK failed: %s [line %d]\n", #cond, __LINE__); \
        return false;                                                           \
    }                                                                           \
} while (0)

#define RUN_TEST(fn) do {                                                       \
    ++tests_run;                                                                \
    std::fprintf(stdout, "  %-44s ", #fn);                                      \
    std::fflush(stdout);                                                        \
    if (fn()) {                                                                 \
        ++tests_passed;                                                         \
        std::fprintf(stdout, "PASS\n");                                         \
    } else {                                                                    \
        std::fprintf(stdout, "FAIL\n");                                         \
    }                                                                           \
} while (0)

std::string HungReport(const std::string& frame)
{
    return
        "INFO: task syz.0 blocked for more than 140 seconds.\n"
        "Call Trace:\n"
        " __schedule+0x10/0x20\n" +
        std::string(" ") + frame + "+0x20/0x30\n"
        " helper+0x30/0x40\n";
}

bool Match(const refuzz::crash::KernelReproEngine& engine,
           const refuzz::crash::RunResult& run,
           bool strict,
           const std::string& target,
           const std::unordered_set<std::string>& observed = {},
           const std::vector<std::string>& alt = {})
{
    return engine.MatchVerdict(
        run, refuzz::crash::VerdictParams{}, strict, target, observed, alt,
        refuzz::crash::CrashKind::kKernelCrash);
}

bool ParsedConsoleOverridesStaleRawTitle()
{
    refuzz::crash::KernelReproEngine engine;
    refuzz::crash::RunResult run;
    run.crashed = true;
    run.crash_kind = refuzz::crash::CrashKind::kKernelCrash;
    run.crash_title = "INFO: task hung in stale_frame";
    run.console_output = HungReport("actual_frame");

    CHECK(Match(engine, run, true, "INFO: task hung in actual_frame"));
    CHECK(!Match(engine, run, true, "INFO: task hung in stale_frame"));
    return true;
}

bool FallsBackToRawTitleWhenConsoleHasNoReport()
{
    refuzz::crash::KernelReproEngine engine;
    refuzz::crash::RunResult run;
    run.crashed = true;
    run.crash_kind = refuzz::crash::CrashKind::kKernelCrash;
    run.crash_title = "WARNING in fallback+0x10/0x20";
    run.console_output = "ordinary executor output\n";

    CHECK(Match(engine, run, true, "WARNING in fallback"));
    return true;
}

bool CandidateAltTitleParticipatesInIntersection()
{
    refuzz::crash::KernelReproEngine engine;
    refuzz::crash::RunResult run;
    run.crashed = true;
    run.crash_kind = refuzz::crash::CrashKind::kKernelCrash;
    run.console_output = HungReport("root_frame");

    CHECK(Match(engine, run, true, "hang in root_frame"));
    return true;
}

bool OriginalAltTitleParticipatesInIntersection()
{
    refuzz::crash::KernelReproEngine engine;
    refuzz::crash::RunResult run;
    run.crashed = true;
    run.crash_kind = refuzz::crash::CrashKind::kKernelCrash;
    run.console_output = HungReport("root_frame");

    CHECK(Match(engine, run, true, "different canonical", {},
                {"INFO: task hung in root_frame"}));
    return true;
}

bool NonStrictMinimizeVerdictAcceptsAnyCrash()
{
    refuzz::crash::KernelReproEngine engine;
    refuzz::crash::RunResult run;
    run.crashed = true;
    run.crash_kind = refuzz::crash::CrashKind::kKernelCrash;
    run.console_output = HungReport("different_frame");

    CHECK(Match(engine, run, false, "original_frame"));
    run.crashed = false;
    CHECK(!Match(engine, run, false, "original_frame"));
    return true;
}

} // namespace

int main()
{
    std::fprintf(stdout, "kernel_repro_engine_title_test\n");
    RUN_TEST(ParsedConsoleOverridesStaleRawTitle);
    RUN_TEST(FallsBackToRawTitleWhenConsoleHasNoReport);
    RUN_TEST(CandidateAltTitleParticipatesInIntersection);
    RUN_TEST(OriginalAltTitleParticipatesInIntersection);
    RUN_TEST(NonStrictMinimizeVerdictAcceptsAnyCrash);

    std::fprintf(stdout, "\n%d/%d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}

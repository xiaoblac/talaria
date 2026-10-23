#include "refuzz/crash/components/symbolizer/kernel_report_parser.hpp"

#include <algorithm>
#include <cstdio>
#include <string>
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
    std::fprintf(stdout, "  %-48s ", #fn);                                      \
    std::fflush(stdout);                                                        \
    if (fn()) {                                                                 \
        ++tests_passed;                                                         \
        std::fprintf(stdout, "PASS\n");                                         \
    } else {                                                                    \
        std::fprintf(stdout, "FAIL\n");                                         \
    }                                                                           \
} while (0)

std::string ValidKasanReport()
{
    return
        "[   10.000000][   T42] BUG: KASAN: use-after-free in vulnerable+0x10/0x20\n"
        "[   10.000001][   T42] Read of size 8 at addr ffff888012345678\n"
        "[   10.000002][   T42] Call Trace:\n"
        "[   10.000003][   T42]  vulnerable+0x10/0x20\n"
        "[   10.000004][   T42]  caller+0x20/0x40\n"
        "[   10.000005][   T42]  do_syscall_64+0x30/0x60\n";
}

bool Contains(const std::vector<std::string>& values,
              const std::string& expected)
{
    return std::find(values.begin(), values.end(), expected) != values.end();
}

bool ParsesCanonicalFieldsFromGeneratedOopsFormats()
{
    refuzz::crash::KernelReportParser parser;
    const auto report = parser.Parse(ValidKasanReport());

    CHECK(report.has_value());
    CHECK(report->raw_title ==
          "BUG: KASAN: use-after-free in vulnerable+0x10/0x20");
    CHECK(report->title == "KASAN: use-after-free Read in vulnerable");
    CHECK(report->alt_titles ==
          std::vector<std::string>{"bad-access in vulnerable"});
    CHECK(report->report_type == "KASAN-USE-AFTER-FREE-READ");
    CHECK(report->type == refuzz::channel::CrashType::kKasan);
    CHECK(report->guilty_function == "vulnerable");
    CHECK(!report->corrupted);
    CHECK(!report->frames.empty());
    return true;
}

bool ProducesCanonicalAndPartiallyStrippedAltTitles()
{
    const std::string log =
        "INFO: task syz.0 blocked for more than 140 seconds.\n"
        "Call Trace:\n"
        " __schedule+0x10/0x20\n"
        " __x64_root_cause+0x20/0x30\n"
        " helper+0x30/0x40\n";

    refuzz::crash::KernelReportParser parser;
    const auto report = parser.Parse(log);

    CHECK(report.has_value());
    CHECK(report->title == "INFO: task hung in root_cause");
    CHECK(report->guilty_function == "root_cause");
    CHECK(report->report_type == "HANG");
    CHECK(Contains(report->alt_titles, "hang in root_cause"));
    CHECK(Contains(report->alt_titles,
                   "INFO: task hung in __x64_root_cause"));
    CHECK(Contains(report->alt_titles, "hang in __x64_root_cause"));
    CHECK(!report->corrupted);
    return true;
}

bool FiltersForeignPrintkCallerContext()
{
    const std::string log =
        "[  700.000000][   T42] INFO: task syz.0 blocked for more than 140 seconds.\n"
        "[  700.000001][   T42] Call Trace:\n"
        "[  700.000002][   T42]  __schedule+0x10/0x20\n"
        "[  700.000003][   T99]  foreign_frame+0x20/0x30\n"
        "[  700.000004][   T42]  root_cause+0x30/0x40\n"
        "[  700.000005][   T42]  helper+0x40/0x50\n";

    refuzz::crash::KernelReportParser parser;
    const auto report = parser.Parse(log);

    CHECK(report.has_value());
    CHECK(report->title == "INFO: task hung in root_cause");
    CHECK(std::none_of(report->frames.begin(), report->frames.end(),
                       [](const refuzz::crash::StackFrame& frame) {
                           return frame.function == "foreign_frame";
                       }));
    return true;
}

bool UsesFirstUnscopedReportForDescription()
{
    const std::string log =
        "INFO: task first blocked for more than 140 seconds.\n"
        "Call Trace:\n"
        " first_root_site+0x10/0x20\n"
        " first_helper+0x20/0x30\n"
        " first_tail+0x30/0x40\n"
        "INFO: task second blocked for more than 140 seconds.\n"
        "Call Trace:\n"
        " second_root_site+0x10/0x20\n"
        " second_helper+0x20/0x30\n"
        " second_tail+0x30/0x40\n";

    refuzz::crash::KernelReportParser parser;
    const auto report = parser.Parse(log);

    CHECK(report.has_value());
    CHECK(report->title == "INFO: task hung in first_root_site");
    CHECK(report->guilty_function == "first_root_site");
    return true;
}

bool QuestionableOnlyFramesFollowCorruptedFrameContract()
{
    const std::string log =
        "[  861.152227] INFO: task syz-executor3:10976 blocked for more than 120 seconds.\n"
        "[  861.177810] Call Trace:\n"
        "[  861.180416]  __schedule+0x8eb/0x2060\n"
        "[  861.184145]  ? uncertain_root+0x20/0x40\n"
        "[  861.188302]  ? uncertain_tail+0x30/0x50\n";

    refuzz::crash::KernelReportParser parser;
    const auto report = parser.Parse(log);

    CHECK(report.has_value());
    CHECK(report->title == "INFO: task hung in corrupted");
    CHECK(report->guilty_function == "corrupted");
    CHECK(report->alt_titles ==
          std::vector<std::string>{"hang in corrupted"});
    CHECK(report->report_type == "HANG");
    CHECK(report->corrupted);
    CHECK(report->corrupted_reason == "extracted no frames");
    return true;
}

bool ChecksCorruptedTitleBeforeDynamicNormalization()
{
    refuzz::crash::KernelReportParser parser;
    const auto report = parser.Parse(
        "BUG: bogus [ 123.456] interleaving\n");

    CHECK(report.has_value());
    CHECK(report->title == "BUG: bogus [ NUM.NUM] interleaving");
    CHECK(report->corrupted);
    CHECK(report->corrupted_reason == "title matches corrupted regexp");
    CHECK(report->report_type == "UNKNOWN");
    return true;
}

bool NormalizesArmFrameBeforePublishingReportFrame()
{
    const std::string log =
        "INFO: task syz.0 blocked for more than 140 seconds.\n"
        "Backtrace:\n"
        " [<c0100000>] (arm_current.isra.0) from [<c0200000>] (arm_caller+0x20/0x30)\n"
        " [<c0200000>] (arm_tail) from [<c0300000>] (arm_end+0x20/0x30)\n";

    refuzz::crash::KernelReportParser parser;
    const auto report = parser.Parse(log);

    CHECK(report.has_value());
    CHECK(report->title == "INFO: task hung in arm_current.isra.NUM");
    CHECK(report->guilty_function == "arm_current");
    CHECK(!report->corrupted);
    return true;
}

bool AppliesReporterDynamicTitleReplacementTable()
{
    const std::string normalized =
        refuzz::crash::KernelReportParser::NormalizeTitle(
            "WARNING: syz-executor.123/45 at 0xffff888012345678 "
            "CPU#7 foo.c:123 task 42");
    CHECK(normalized ==
          "WARNING: syz-executor at ADDR CPU foo.c:LINE task NUM");
    return true;
}

bool SuppressesKnownBenignOopsLines()
{
    const std::string log =
        "WARNING: The mand mount option has been deprecated and ignored\n";
    refuzz::crash::KernelReportParser parser;
    CHECK(!refuzz::crash::ConsoleContainsRealCrash(log));
    CHECK(!parser.Parse(log).has_value());
    return true;
}

bool MarksSerialConsoleDisconnectAsCorrupted()
{
    refuzz::crash::KernelReportParser parser;
    const auto report = parser.Parse(
        ValidKasanReport() + "serialport: VM disconnected.\n");
    CHECK(report.has_value());
    CHECK(report->corrupted);
    return true;
}

bool ReturnsNulloptForNonCrashOutput()
{
    refuzz::crash::KernelReportParser parser;
    CHECK(!parser.Parse("worker ready\nexecution completed\n").has_value());
    return true;
}

} // namespace

int main()
{
    std::fprintf(stdout, "kernel_report_parser_test\n");
    RUN_TEST(ParsesCanonicalFieldsFromGeneratedOopsFormats);
    RUN_TEST(ProducesCanonicalAndPartiallyStrippedAltTitles);
    RUN_TEST(FiltersForeignPrintkCallerContext);
    RUN_TEST(UsesFirstUnscopedReportForDescription);
    RUN_TEST(QuestionableOnlyFramesFollowCorruptedFrameContract);
    RUN_TEST(ChecksCorruptedTitleBeforeDynamicNormalization);
    RUN_TEST(NormalizesArmFrameBeforePublishingReportFrame);
    RUN_TEST(AppliesReporterDynamicTitleReplacementTable);
    RUN_TEST(SuppressesKnownBenignOopsLines);
    RUN_TEST(MarksSerialConsoleDisconnectAsCorrupted);
    RUN_TEST(ReturnsNulloptForNonCrashOutput);

    std::fprintf(stdout, "\n%d/%d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}

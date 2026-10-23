// §3.11-D — EvidenceFragment / Incident 数据类型 smoke test。
//
// 仅验证类型构造 + variant 访问 + helper 行为。不接触 sensor /
// pipeline / analyzer —— D 阶段只是落地数据类型，行为接入在 E 阶段。

#include "refuzz/crash/incident/evidence_fragment.hpp"
#include "refuzz/crash/incident/incident.hpp"
#include "refuzz/program/prog_format.hpp"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <variant>

namespace {

#define CHECK(expr)                                                          \
    do {                                                                    \
        if (!(expr)) {                                                       \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,     \
                         #expr);                                             \
            std::abort();                                                    \
        }                                                                    \
    } while (0)

#define RUN_TEST(fn)                                                         \
    do {                                                                    \
        std::fprintf(stderr, "RUN  %s\n", #fn);                              \
        fn();                                                                \
        std::fprintf(stderr, "OK   %s\n", #fn);                              \
    } while (0)

namespace ic = refuzz::crash::incident;

void TestConsoleLinesPayload() {
    ic::CrashEvidenceFragment f;
    f.source         = ic::Source::kKernelConsole;
    f.program_format = refuzz::fuzzer::ProgFormat::kSyzProg;
    f.worker_id      = 3;
    f.captured_ts_us = 12345;
    f.sequence       = 1;
    f.confidence     = ic::Confidence::kHigh;
    f.checker_name   = "console";
    f.payload = ic::ConsoleLines{ {"BUG: KASAN", "Call Trace", "do_open"}, false };

    CHECK(std::holds_alternative<ic::ConsoleLines>(f.payload));
    const auto& cl = std::get<ic::ConsoleLines>(f.payload);
    CHECK(cl.lines.size() == 3);
    CHECK(cl.lines[0] == "BUG: KASAN");
}

void TestSignalInfoPayload() {
    ic::CrashEvidenceFragment f;
    f.source     = ic::Source::kSignal;
    f.confidence = ic::Confidence::kHigh;
    f.payload    = ic::SignalInfo{
        /*signum=*/11,
        /*fault_addr=*/0xdead000,
        /*signal_name=*/"SIGSEGV",
        /*stack_top=*/{"frame0", "frame1"}
    };
    const auto& s = std::get<ic::SignalInfo>(f.payload);
    CHECK(s.signum == 11);
    CHECK(s.signal_name == "SIGSEGV");
    CHECK(s.stack_top.size() == 2);
}

void TestDifferentialPayload() {
    ic::CrashEvidenceFragment f;
    f.source     = ic::Source::kDifferentialMismatch;
    f.confidence = ic::Confidence::kMedium;
    f.payload    = ic::DifferentialMismatchInfo{
        /*left_fingerprint=*/"clang-O0",
        /*right_fingerprint=*/"clang-O3",
        /*mismatch_type=*/"stdout",
        /*left_output_summary=*/{1,2,3},
        /*right_output_summary=*/{1,2,4},
        /*tolerance=*/0.0
    };
    const auto& d = std::get<ic::DifferentialMismatchInfo>(f.payload);
    CHECK(d.left_fingerprint == "clang-O0");
    CHECK(d.left_output_summary != d.right_output_summary);
}

void TestLargeBlobPayload() {
    ic::CrashEvidenceFragment f;
    f.source     = ic::Source::kCoreDump;
    f.confidence = ic::Confidence::kHigh;
    f.payload    = ic::LargeBlobInfo{
        /*blob_id=*/"sha256:abc123",
        /*size_bytes=*/1024 * 1024 * 12,
        /*mime_type=*/"application/x-minidump",
        /*human_summary=*/"renderer SIGSEGV @ v8::Compile"
    };
    const auto& b = std::get<ic::LargeBlobInfo>(f.payload);
    CHECK(b.size_bytes == 1024 * 1024 * 12);
    CHECK(b.mime_type == "application/x-minidump");
}

void TestIncidentAggregation_HighestConfidenceWins() {
    ic::CrashIncident incident;
    incident.incident_id          = 0xABCDEF;
    incident.program_format       = refuzz::fuzzer::ProgFormat::kSyzProg;
    incident.first_fragment_ts_us = 100;
    incident.last_fragment_ts_us  = 5'000;
    incident.correlation_keys     = {3 /*worker_id*/};

    // t=100 heartbeat (Low)
    ic::CrashEvidenceFragment hb;
    hb.source = ic::Source::kHeartbeat;
    hb.captured_ts_us = 100;
    hb.confidence = ic::Confidence::kLow;
    hb.payload = ic::HeartbeatGap{/*last_seen_us=*/0, /*gap_us=*/3000, /*miss=*/3};
    incident.fragments.push_back(std::move(hb));

    // t=2000 console panic (High)
    ic::CrashEvidenceFragment cp;
    cp.source = ic::Source::kKernelConsole;
    cp.captured_ts_us = 2000;
    cp.confidence = ic::Confidence::kHigh;
    cp.payload = ic::ConsoleLines{{"BUG: kernel panic"}, false};
    incident.fragments.push_back(std::move(cp));

    // t=5000 vm dead (Medium)
    ic::CrashEvidenceFragment vd;
    vd.source = ic::Source::kVmAlive;
    vd.captured_ts_us = 5000;
    vd.confidence = ic::Confidence::kMedium;
    vd.payload = ic::OpaqueText{"vm exit", "vm_alive_sensor"};
    incident.fragments.push_back(std::move(vd));

    const auto* top = ic::HighestConfidenceFragment(incident);
    CHECK(top != nullptr);
    CHECK(top->source == ic::Source::kKernelConsole);
    CHECK(top->confidence == ic::Confidence::kHigh);
}

void TestIncidentKindNames() {
    CHECK(std::string(ic::IncidentKindName(ic::IncidentKind::kCrash)) == "crash");
    CHECK(std::string(ic::IncidentKindName(ic::IncidentKind::kHang)) == "hang");
    CHECK(std::string(ic::IncidentKindName(ic::IncidentKind::kDifferential)) == "differential");
    CHECK(std::string(ic::IncidentKindName(ic::IncidentKind::kSanitizer)) == "sanitizer");
    CHECK(std::string(ic::IncidentKindName(ic::IncidentKind::kInfraFault)) == "infra_fault");
    CHECK(std::string(ic::IncidentKindName(ic::IncidentKind::kUnknown)) == "unknown");
}

} // namespace

int main() {
    RUN_TEST(TestConsoleLinesPayload);
    RUN_TEST(TestSignalInfoPayload);
    RUN_TEST(TestDifferentialPayload);
    RUN_TEST(TestLargeBlobPayload);
    RUN_TEST(TestIncidentAggregation_HighestConfidenceWins);
    RUN_TEST(TestIncidentKindNames);
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}

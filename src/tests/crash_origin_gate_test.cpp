// §3.11-A — Bug #1 fix verification: ParseAndClassifyOp must NOT
// coerce kWorkerDead → kKernelCrash unless the underlying sensor
// origin is `kSerialPattern`. Heartbeat- / VM-liveness- /
// internal-origin events that happen to have stale console buffer
// content must keep their original kind.
//
// Test surface: drive `BuildContextOp.Execute()` then
// `ParseAndClassifyOp.Execute()` directly with crafted
// `proto::CombinedCrashEvent` inputs, capture resulting CrashContext,
// inspect crash_kind.

#include "refuzz/channel/worker/mode.hpp"
#include "refuzz/crash/components/symbolizer/kernel_report_parser.hpp"
#include "refuzz/crash/infra/crash_context.hpp"
#include "refuzz/crash/pipeline/core/crash_pipeline_op.hpp"
#include "refuzz/crash/pipeline/ops/linuxkernel/syz_ops/syz_pipeline_ops.hpp"
#include "refuzz/proto_domain/combined_crash_event.hpp"
#include "refuzz/proto_domain/fault_event.hpp"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>

namespace {

#define CHECK(expr)                                                          \
    do {                                                                     \
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

namespace cr = refuzz::crash;
namespace pr = refuzz::proto;

// Reusable kernel panic console excerpt for stale-buffer simulation.
constexpr const char kKernelPanicConsole[] =
    "[  123.456] BUG: kernel panic - not syncing: out of memory\n"
    "[  123.457] CPU: 0 PID: 1 Comm: init Not tainted\n"
    "[  123.458] Call Trace:\n"
    "[  123.459]  ? do_exit+0x42/0x100\n";

// ----- Test scaffold -----

struct ClassifyResult {
    cr::CrashKind crash_kind  = cr::CrashKind::kUnknownIncident;
    pr::FaultOrigin fault_origin = pr::FaultOrigin::kUnknown;
    pr::FaultReason fault_reason = pr::FaultReason::kWorkerHeartbeatLost;
};

// Drive BuildContext + ParseAndClassify on a crafted FaultEvent, return
// the resulting CrashContext fields of interest.
ClassifyResult RunPipeline(pr::FaultReason reason,
                            pr::FaultOrigin origin,
                            const std::string& console_log,
                            const std::string& raw_title = "")
{
    pr::CombinedCrashEvent combined;
    combined.incident_id = 42;

    pr::FaultEvent fe;
    fe.incident_id   = 42;
    fe.channel_id    = 1;
    fe.slot_id       = 0;
    fe.generation    = 1;
    fe.reason        = reason;
    fe.source        = pr::FaultSource::kHealthMonitor;
    fe.origin        = origin;
    fe.crash_console = console_log;
    fe.crash_title   = raw_title;
    combined.fault_event = std::move(fe);

    cr::CrashContext ctx;
    cr::KernelReportParser parser;

    auto build_op   = cr::testing::MakeBuildContextOpForTest(
        refuzz::channel::worker::WorkerSanitizerMode::kNone);
    auto classify_op = cr::testing::MakeParseAndClassifyOpForTest(
        &parser, /*symbolizer=*/nullptr);

    cr::BuildContextParams      build_params{};
    cr::ParseAndClassifyParams  classify_params{};
    build_op->Execute(combined, ctx, build_params);
    classify_op->Execute(combined, ctx, classify_params);

    return ClassifyResult{ctx.crash_kind, ctx.fault_origin, ctx.fault_reason};
}

// ----- Tests -----

// Case 1 — origin=kSerialPattern + console has panic →
// coercion fires (kWorkerDead → kKernelCrash). This is the legitimate
// pre-existing behavior and must be preserved.
void TestSerialPattern_WithPanicConsole_CoercesToKernelCrash() {
    auto r = RunPipeline(pr::FaultReason::kWorkerHeartbeatLost,
                          pr::FaultOrigin::kSerialPattern,
                          kKernelPanicConsole);
    CHECK(r.fault_origin == pr::FaultOrigin::kSerialPattern);
    CHECK(r.crash_kind   == cr::CrashKind::kKernelCrash);  // ✓ coerced
}

// Case 2 — origin=kHeartbeat + same console (stale buffer) →
// coercion DOES NOT fire. Bug #1 fix: heartbeat-detected events
// must not inherit unrelated console evidence.
void TestHeartbeat_WithStaleConsole_DoesNotCoerce() {
    auto r = RunPipeline(pr::FaultReason::kWorkerHeartbeatLost,
                          pr::FaultOrigin::kHeartbeat,
                          kKernelPanicConsole);
    CHECK(r.fault_origin == pr::FaultOrigin::kHeartbeat);
    CHECK(r.crash_kind   == cr::CrashKind::kWorkerDead);    // ★ Bug #1 fix
}

// Case 3 — origin=kHeartbeat + raw_title only (legacy second
// coercion path) → no coercion.
void TestHeartbeat_WithRawTitleOnly_DoesNotCoerce() {
    auto r = RunPipeline(pr::FaultReason::kWorkerHeartbeatLost,
                          pr::FaultOrigin::kHeartbeat,
                          /*console_log=*/"",
                          /*raw_title=*/"BUG: KASAN: out-of-bounds");
    CHECK(r.fault_origin == pr::FaultOrigin::kHeartbeat);
    CHECK(r.crash_kind   == cr::CrashKind::kWorkerDead);    // ★ Bug #1 fix
}

// Case 4 — origin=kSerialPattern + raw_title only (parse failed
// but title preserved) → coercion fires.
void TestSerialPattern_WithRawTitleOnly_Coerces() {
    auto r = RunPipeline(pr::FaultReason::kWorkerHeartbeatLost,
                          pr::FaultOrigin::kSerialPattern,
                          /*console_log=*/"",
                          /*raw_title=*/"BUG: KASAN: out-of-bounds");
    CHECK(r.fault_origin == pr::FaultOrigin::kSerialPattern);
    CHECK(r.crash_kind   == cr::CrashKind::kKernelCrash);   // ✓ coerced
}

// Case 5 — origin=kVmLiveness + panic console → no coercion (vm-dead
// is its own classification, not derived from console pattern).
void TestVmLiveness_WithPanicConsole_DoesNotChangeKind() {
    auto r = RunPipeline(pr::FaultReason::kVmDead,
                          pr::FaultOrigin::kVmLiveness,
                          kKernelPanicConsole);
    CHECK(r.fault_origin == pr::FaultOrigin::kVmLiveness);
    // BuildContextOp set kVmDead from FaultReason; coercion gate also
    // skips because origin != kSerialPattern.
    CHECK(r.crash_kind == cr::CrashKind::kVmDead);
}

// Case 6 — origin=kUnknown (legacy / not propagated) + panic
// console → no coercion. Conservative default: only explicit
// SerialPattern origin is allowed to upgrade.
void TestUnknownOrigin_WithPanicConsole_DoesNotCoerce() {
    auto r = RunPipeline(pr::FaultReason::kWorkerHeartbeatLost,
                          pr::FaultOrigin::kUnknown,
                          kKernelPanicConsole);
    CHECK(r.fault_origin == pr::FaultOrigin::kUnknown);
    CHECK(r.crash_kind   == cr::CrashKind::kWorkerDead);   // safe default
}

} // namespace

int main() {
    RUN_TEST(TestSerialPattern_WithPanicConsole_CoercesToKernelCrash);
    RUN_TEST(TestHeartbeat_WithStaleConsole_DoesNotCoerce);
    RUN_TEST(TestHeartbeat_WithRawTitleOnly_DoesNotCoerce);
    RUN_TEST(TestSerialPattern_WithRawTitleOnly_Coerces);
    RUN_TEST(TestVmLiveness_WithPanicConsole_DoesNotChangeKind);
    RUN_TEST(TestUnknownOrigin_WithPanicConsole_DoesNotCoerce);
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}

// Dedup identity contract after syzkaller-compatible report parsing.
//
// Coverage:
//   1) Parsed kernel reports use exactly the canonical title.
//   2) Local fault reasons and raw frames do not split one canonical bug.
//   3) Infrastructure findings retain reason/signal discrimination.

#include "refuzz/crash/components/symbolizer/kernel_report_parser.hpp"
#include "refuzz/crash/infra/crash_context.hpp"
#include "refuzz/crash/pipeline/ops/linuxkernel/syz_ops/syz_pipeline_ops.hpp"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <string>

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

namespace cr = refuzz::crash;
namespace pr = refuzz::proto;

cr::CrashContext MakeCtx(cr::CrashKind kind,
                         pr::FaultReason reason,
                         std::string title,
                         std::vector<std::string> stack_funcs = {},
                         uint32_t signal = 0)
{
    cr::CrashContext ctx;
    ctx.crash_kind   = kind;
    ctx.fault_reason = reason;
    ctx.title        = std::move(title);
    ctx.crash_signal = signal;
    if (kind == cr::CrashKind::kKernelCrash && !ctx.title.empty()) {
        cr::ParsedCrashReport report;
        report.title = ctx.title;
        for (auto& f : stack_funcs) {
            cr::StackFrame frame;
            frame.function = std::move(f);
            report.frames.push_back(std::move(frame));
        }
        ctx.parsed_report = std::move(report);
    }
    return ctx;
}

void TestParsedKernelReportUsesCanonicalTitleOnly() {
    auto a = MakeCtx(cr::CrashKind::kKernelCrash,
                      pr::FaultReason::kKernelCrash,
                      "BUG: KASAN: out-of-bounds in foo",
                      {"foo", "bar", "baz"});
    auto b = MakeCtx(cr::CrashKind::kKernelCrash,
                      pr::FaultReason::kInflightStale,
                      "BUG: KASAN: out-of-bounds in foo",
                      {"different_raw_frame", "another_frame"});
    const auto desc_a = cr::testing::ComputeDedupDescriptionForTest(a);
    const auto desc_b = cr::testing::ComputeDedupDescriptionForTest(b);
    CHECK(desc_a == "BUG: KASAN: out-of-bounds in foo");
    CHECK(desc_a == desc_b);
}

void TestEmptyTitleDifferentReason_DifferentDescription() {
    // Bug #3 — 两个 worker_dead 事件，一个 reason=heartbeat、一个
    // reason=inflight_stale。Title 都空（heartbeat sensor 不抓 console
    // 当 ring buffer 没在用时）。旧逻辑下 description 都是
    // "worker_dead" → 同 hash → 错合并。
    auto heartbeat = MakeCtx(cr::CrashKind::kWorkerDead,
                              pr::FaultReason::kWorkerHeartbeatLost,
                              /*title=*/"");
    auto inflight  = MakeCtx(cr::CrashKind::kWorkerDead,
                              pr::FaultReason::kInflightStale,
                              /*title=*/"");
    auto desc_a = cr::testing::ComputeDedupDescriptionForTest(heartbeat);
    auto desc_b = cr::testing::ComputeDedupDescriptionForTest(inflight);
    std::fprintf(stderr, "  heartbeat desc='%s'\n  inflight  desc='%s'\n",
                 desc_a.c_str(), desc_b.c_str());
    CHECK(desc_a != desc_b);  // ★ Bug #3 fix
}

void TestDifferentCanonicalTitlesRemainDifferent() {
    auto a = MakeCtx(cr::CrashKind::kKernelCrash,
                      pr::FaultReason::kKernelCrash,
                      "BUG: KASAN: out-of-bounds in open_handler",
                      {"open_handler"});
    auto b = MakeCtx(cr::CrashKind::kKernelCrash,
                      pr::FaultReason::kKernelCrash,
                      "BUG: KASAN: out-of-bounds in close_handler",
                      {"close_handler"});
    auto desc_a = cr::testing::ComputeDedupDescriptionForTest(a);
    auto desc_b = cr::testing::ComputeDedupDescriptionForTest(b);
    CHECK(desc_a != desc_b);
}

void TestEmptyTitleSameReason_SameDescription() {
    // 真正同 bucket：两次 heartbeat-lost on worker_dead，没拿到 console。
    auto a = MakeCtx(cr::CrashKind::kWorkerDead,
                      pr::FaultReason::kWorkerHeartbeatLost,
                      "");
    auto b = MakeCtx(cr::CrashKind::kWorkerDead,
                      pr::FaultReason::kWorkerHeartbeatLost,
                      "");
    CHECK(cr::testing::ComputeDedupDescriptionForTest(a) ==
          cr::testing::ComputeDedupDescriptionForTest(b));
}

void TestSignalFallback_SameSignalSameReason_SameDescription() {
    auto a = MakeCtx(cr::CrashKind::kWorkerDead,
                      pr::FaultReason::kWorkerHeartbeatLost,
                      /*title=*/"",
                      /*stack=*/{},
                      /*signal=*/11 /*SIGSEGV*/);
    auto b = MakeCtx(cr::CrashKind::kWorkerDead,
                      pr::FaultReason::kWorkerHeartbeatLost,
                      /*title=*/"",
                      /*stack=*/{},
                      /*signal=*/11);
    CHECK(cr::testing::ComputeDedupDescriptionForTest(a) ==
          cr::testing::ComputeDedupDescriptionForTest(b));

    auto c = MakeCtx(cr::CrashKind::kWorkerDead,
                      pr::FaultReason::kWorkerHeartbeatLost,
                      /*title=*/"",
                      /*stack=*/{},
                      /*signal=*/9 /*SIGKILL*/);
    CHECK(cr::testing::ComputeDedupDescriptionForTest(a) !=
          cr::testing::ComputeDedupDescriptionForTest(c));
}

} // namespace

int main() {
    RUN_TEST(TestParsedKernelReportUsesCanonicalTitleOnly);
    RUN_TEST(TestEmptyTitleDifferentReason_DifferentDescription);
    RUN_TEST(TestDifferentCanonicalTitlesRemainDifferent);
    RUN_TEST(TestEmptyTitleSameReason_SameDescription);
    RUN_TEST(TestSignalFallback_SameSignalSameReason_SameDescription);
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}

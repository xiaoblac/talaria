// §3.11-B oracle #22 — 6-class dedup hash stability + v2 IR transition.
//
// Verifies the dedup hash algorithm's properties after the §3.11-B
// conditional-payload-fold change in DedupOp::Execute:
//
//   * STABLE: hash(ctx) is deterministic across repeats.
//   * KIND-DISJOINT: same description on different CrashKind →
//     different bucket (CrashKindName seeds the hash).
//   * TITLE-DRIVEN ALIGNS WITH SYZKALLER: a successfully parsed kernel
//     report uses only its canonical title and omits payload from the hash.
//   * INFRA-FAULT KEEPS PAYLOAD-FOLD: when there is no parsed report,
//     DedupOp folds payload
//     to differentiate distinct incidents that would otherwise collapse
//     into one super-bucket (the §3.11-C Bug #3 hazard).
//   * V1→V2 IR TRANSITION: same kernel bug on a v1-form payload vs
//     a v2-form payload (different bytes, same logical program) hashes
//     to the same bucket if they produce the same parsed title — so
//     no migration of stored hashes is needed at the v2 default flip.
//
// We exercise HashDiagnosticArtifact directly with the conditional-fold
// rule replicated from DedupOp to avoid pulling in DiagnosticStore I/O.
// The DedupDescription helper is exercised via ComputeDedupDescriptionForTest.

#include "refuzz/crash/infra/crash_context.hpp"
#include "refuzz/crash/infra/diagnostic_artifact.hpp"
#include "refuzz/crash/pipeline/ops/linuxkernel/syz_ops/syz_pipeline_ops.hpp"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

namespace {

#define CHECK(expr)                                                         \
    do {                                                                    \
        if (!(expr)) {                                                      \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,    \
                         #expr);                                            \
            std::abort();                                                   \
        }                                                                   \
    } while (0)

#define RUN_TEST(fn)                                                        \
    do {                                                                    \
        std::fprintf(stderr, "RUN  %s\n", #fn);                             \
        fn();                                                               \
        std::fprintf(stderr, "OK   %s\n", #fn);                             \
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

// Mirror the §3.11-B conditional-fold rule from DedupOp::Execute.
uint64_t HashCtx(const cr::CrashContext& ctx,
                 const std::vector<uint8_t>& payload = {},
                 const std::vector<uint8_t>& output = {})
{
    const std::string desc = cr::testing::ComputeDedupDescriptionForTest(ctx);
    const bool has_real_title = ctx.parsed_report.has_value() &&
                                !ctx.parsed_report->title.empty();
    const bool fold_payload = !has_real_title;
    return cr::HashDiagnosticArtifact(
        ctx.crash_kind,
        desc,
        fold_payload ? payload : std::vector<uint8_t>{},
        fold_payload ? output  : std::vector<uint8_t>{});
}

// ----- tests -----

// Property 1: hash is deterministic on repeat.
void TestHashIsStableOnRepeat() {
    auto ctx = MakeCtx(cr::CrashKind::kKernelCrash,
                       pr::FaultReason::kKernelCrash,
                       "BUG: KASAN: out-of-bounds in foo",
                       {"foo", "bar", "baz"});
    const std::vector<uint8_t> payload = {1, 2, 3, 4};
    const auto h1 = HashCtx(ctx, payload);
    const auto h2 = HashCtx(ctx, payload);
    const auto h3 = HashCtx(ctx, payload);
    CHECK(h1 == h2);
    CHECK(h2 == h3);
}

// Property 2: same description, different CrashKind → different bucket.
void TestKindIsolation() {
    CHECK(cr::HashDiagnosticArtifact(cr::CrashKind::kKernelCrash, "softlockup") !=
          cr::HashDiagnosticArtifact(cr::CrashKind::kWorkerDead, "softlockup"));
}

// Property 3: title-driven path aligns with syzkaller — same canonical title
// across DIFFERENT payloads collapses into one bucket.
//
// This is the §3.11-B alignment: kernel-oops dedup matches syzkaller's
// identity.
void TestTitleDrivenIgnoresPayload() {
    auto kc = MakeCtx(cr::CrashKind::kKernelCrash,
                      pr::FaultReason::kKernelCrash,
                      "BUG: KASAN: out-of-bounds in foo",
                      {"foo", "bar", "baz"});

    const std::vector<uint8_t> payload_v1 = {0x50, 0x59, 0x5A, 0x53};  // SYZP-ish
    const std::vector<uint8_t> payload_v2 = {'r', '0', ' ', '=', ' ', 'o', 'p', 'e'};
    const std::vector<uint8_t> output_a   = {0xAA};
    const std::vector<uint8_t> output_b   = {0xBB};

    const auto h1 = HashCtx(kc, payload_v1, output_a);
    const auto h2 = HashCtx(kc, payload_v2, output_b);
    CHECK(h1 == h2);  // payload differs but title-driven → same bucket

    auto different_observation = MakeCtx(
        cr::CrashKind::kKernelCrash,
        pr::FaultReason::kInflightStale,
        "BUG: KASAN: out-of-bounds in foo",
        {"unrelated_raw_frame"});
    CHECK(HashCtx(kc, payload_v1) == HashCtx(different_observation, payload_v2));
}

// Property 4: empty title (infra fault) preserves payload-fold so distinct
// incidents don't collapse into one super-bucket. Regression guard for
// §3.11-C Bug #3.
void TestInfraFaultKeepsPayloadDifferentiation() {
    auto wd_w0 = MakeCtx(cr::CrashKind::kWorkerDead,
                         pr::FaultReason::kWorkerHeartbeatLost,
                         /*title=*/"",
                         /*stack=*/{},
                         /*signal=*/0);
    auto wd_w5 = MakeCtx(cr::CrashKind::kWorkerDead,
                         pr::FaultReason::kWorkerHeartbeatLost,
                         /*title=*/"",
                         /*stack=*/{},
                         /*signal=*/0);

    // Same description (both fall back to "worker_dead|reason=...").
    CHECK(cr::testing::ComputeDedupDescriptionForTest(wd_w0) ==
          cr::testing::ComputeDedupDescriptionForTest(wd_w5));

    // Different worker payload → different buckets (payload-fold preserved
    // because title is empty).
    const std::vector<uint8_t> payload_w0 = {'w', '0', 'd', 'a', 't', 'a'};
    const std::vector<uint8_t> payload_w5 = {'w', '5', 'd', 'a', 't', 'a'};
    CHECK(HashCtx(wd_w0, payload_w0) != HashCtx(wd_w5, payload_w5));

    // Same payload → same bucket (true duplicate).
    CHECK(HashCtx(wd_w0, payload_w0) == HashCtx(wd_w5, payload_w0));
}

// Property 5: v1→v2 IR transition yields no bucket migration. A real
// kernel oops always has a non-empty parsed title; under the title-driven
// rule, the v1-form payload bytes and the v2-form payload bytes both
// hash to the same bucket since payload is not folded.
//
// (For infra faults — payload IS folded — v1 vs v2 payloads naturally
// hash differently. That's fine: infra faults are not deduplicated
// across IR versions because they correlate with specific worker/VM
// instances, not with a kernel-side bug class.)
void TestV1V2TitleDrivenSameBucket() {
    auto kc = MakeCtx(cr::CrashKind::kKernelCrash,
                      pr::FaultReason::kKernelCrash,
                      "general protection fault in baz",
                      {"baz", "qux", "quux"});

    // Simulate v1 wire bytes vs v2 canonical text — different bytes,
    // same logical program for the dedup purpose.
    const std::vector<uint8_t> v1_bytes = {0x50, 0x59, 0x5A, 0x50, 0x01, 0x00};
    const std::vector<uint8_t> v2_text  = {'b', 'a', 'z', '(', '0', ')', '\n'};
    CHECK(HashCtx(kc, v1_bytes) == HashCtx(kc, v2_text));
}

} // namespace

int main() {
    RUN_TEST(TestHashIsStableOnRepeat);
    RUN_TEST(TestKindIsolation);
    RUN_TEST(TestTitleDrivenIgnoresPayload);
    RUN_TEST(TestInfraFaultKeepsPayloadDifferentiation);
    RUN_TEST(TestV1V2TitleDrivenSameBucket);
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}

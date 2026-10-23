// xiuos_coverage_signal_test.cpp
//
// Phase 2 §C #16 — unit tests for the XiUOS coverage Feedback signal.
//
// [real-kcov v3] The worker now emits *sparse* edge coverage instead of a
// dense 256-byte bitmap. Wire layout of Completion.output (the coverage prefix,
// before the 32-byte state region read by XiuosStateCoverageSignal):
//
//     u16 n_hit                       // big-endian, number of hit edges
//     n_hit × { u16 idx; u8 cnt }     // idx in [0, XIUOS_COV_MAP_SIZE), big-endian; cnt = saturating count
//
// The host decodes each (idx, cnt) entry and applies the pinned AFL algorithm
// against a XIUOS_COV_MAP_SIZE (4096) accumulated bitmap:
//
//   bucketize(c) = 0 if c == 0 else 1 << (bit_width(c) - 1)
//   new_bits     = bucketize(c) & ~seen[idx]
//   interesting  = any new_bits != 0
//   magnitude    = # sparse entries contributing at least one new bit
//
// Tests below craft Completion events with synthetic sparse output to exercise
// each clause without touching QEMU/serial or any other reFuzz subsystem.

#include "refuzz/feedback/signal/xiuos_coverage_signal.hpp"

#include "refuzz/core/channel_contract.hpp"
#include "refuzz/proto_wire/xiuos_uart_protocol.h"

#include <array>
#include <cstdint>
#include <cstdio>
#include <utility>
#include <vector>

namespace cc     = refuzz::core::channel_contract;
namespace fuzzer = refuzz::fuzzer;

#define CHECK(cond)                                                                \
    do {                                                                           \
        if (!(cond)) {                                                             \
            std::fprintf(stderr, "CHECK failed: %s (line %d)\n", #cond, __LINE__); \
            return 1;                                                              \
        }                                                                          \
    } while (0)

namespace {

cc::ChannelEvent MakeCompletionEvent(std::vector<std::uint8_t> output,
                                     std::uint64_t executor_id = 1) {
    cc::ChannelEvent ev;
    ev.kind = cc::ChannelEvent::Kind::kCompletion;
    ev.event_id = 1;
    ev.channel_id = 1;
    ev.generation = 1;

    cc::Completion c;
    c.ctx.executor_id = executor_id;
    c.kind = cc::CompletionKind::kNormal;
    c.output = std::move(output);
    ev.payload = std::move(c);
    return ev;
}

// Encode a list of (idx, cnt) sparse hits into the v3 wire coverage prefix:
//   u16 n_hit (BE) + n_hit*(u16 idx BE, u8 cnt).
// The 32-byte state region is irrelevant for XiuosCoverageSignal (it only reads
// n_hit and the entries), so we don't append it here.
std::vector<std::uint8_t> MakeSparse(
    const std::vector<std::pair<std::uint16_t, std::uint8_t>>& hits) {
    std::vector<std::uint8_t> out;
    const std::uint16_t n = static_cast<std::uint16_t>(hits.size());
    out.push_back(static_cast<std::uint8_t>(n >> 8));
    out.push_back(static_cast<std::uint8_t>(n & 0xFF));
    for (const auto& h : hits) {
        out.push_back(static_cast<std::uint8_t>(h.first >> 8));
        out.push_back(static_cast<std::uint8_t>(h.first & 0xFF));
        out.push_back(h.second);
    }
    return out;
}

// Bucketize spec from 050 §Stage 6: 0, 1, 2, 4, 8, 16, 32, 64, 128.
int TestBucketizeKnownVectors() {
    CHECK(fuzzer::XiuosCoverageSignal::Bucketize(0)   == 0);
    CHECK(fuzzer::XiuosCoverageSignal::Bucketize(1)   == 1);
    CHECK(fuzzer::XiuosCoverageSignal::Bucketize(2)   == 2);
    CHECK(fuzzer::XiuosCoverageSignal::Bucketize(3)   == 2);
    CHECK(fuzzer::XiuosCoverageSignal::Bucketize(4)   == 4);
    CHECK(fuzzer::XiuosCoverageSignal::Bucketize(7)   == 4);
    CHECK(fuzzer::XiuosCoverageSignal::Bucketize(8)   == 8);
    CHECK(fuzzer::XiuosCoverageSignal::Bucketize(15)  == 8);
    CHECK(fuzzer::XiuosCoverageSignal::Bucketize(16)  == 16);
    CHECK(fuzzer::XiuosCoverageSignal::Bucketize(31)  == 16);
    CHECK(fuzzer::XiuosCoverageSignal::Bucketize(32)  == 32);
    CHECK(fuzzer::XiuosCoverageSignal::Bucketize(63)  == 32);
    CHECK(fuzzer::XiuosCoverageSignal::Bucketize(64)  == 64);
    CHECK(fuzzer::XiuosCoverageSignal::Bucketize(127) == 64);
    CHECK(fuzzer::XiuosCoverageSignal::Bucketize(128) == 128);
    CHECK(fuzzer::XiuosCoverageSignal::Bucketize(255) == 128);
    return 0;
}

// First non-zero coverage should be marked interesting; bitmap accumulates at
// the sparse indices (which can now span the full 4096-edge map).
int TestFirstHitsAreInteresting() {
    fuzzer::XiuosCoverageSignal signal;
    auto event = MakeCompletionEvent(MakeSparse({
        {0, 1},      // bucket 1
        {1, 5},      // bucket 4
        {2, 128},    // bucket 128
        {4095, 200}, // bucket 128, highest valid edge index
    }));
    auto contribution = signal.Sample(event);

    CHECK(contribution.id == "xiuos_coverage");
    CHECK(contribution.kind == fuzzer::SignalKind::kCoverage);
    CHECK(contribution.fired);
    CHECK(!contribution.malformed);
    CHECK(contribution.interesting);
    CHECK(contribution.magnitude == 4);  // 4 entries contributed new bits

    CHECK(signal.accumulated()[0]    == 1);
    CHECK(signal.accumulated()[1]    == 4);
    CHECK(signal.accumulated()[2]    == 128);
    CHECK(signal.accumulated()[4095] == 128);
    CHECK(signal.accumulated()[100]  == 0);  // untouched
    return 0;
}

// Replay the same coverage → no new bits; not interesting; magnitude 0.
int TestReplayingSameCoverageIsNotInteresting() {
    fuzzer::XiuosCoverageSignal signal;
    auto output = MakeSparse({{0, 5}, {1, 50}, {2, 200}});

    auto first = signal.Sample(MakeCompletionEvent(output));
    CHECK(first.fired);
    CHECK(first.interesting);
    CHECK(first.magnitude == 3);

    auto replay = signal.Sample(MakeCompletionEvent(output));
    CHECK(replay.fired);
    CHECK(!replay.interesting);
    CHECK(replay.magnitude == 0);
    return 0;
}

// A higher-bucket hit on an index that previously only had a lower bucket must
// be flagged as a new bit.
int TestHigherBucketOnSameIdxIsInteresting() {
    fuzzer::XiuosCoverageSignal signal;
    auto r1 = signal.Sample(MakeCompletionEvent(MakeSparse({{42, 1}})));  // bucket 1
    CHECK(r1.magnitude == 1);
    CHECK(signal.accumulated()[42] == 1);

    auto r2 = signal.Sample(MakeCompletionEvent(MakeSparse({{42, 100}})));  // bucket 64
    CHECK(r2.interesting);
    CHECK(r2.magnitude == 1);
    CHECK(signal.accumulated()[42] == (1 | 64));
    return 0;
}

// A different (lower) bucket on an index that already accumulated a higher
// bucket still sets a new discrete bucket bit (AFL semantics: each bucket is a
// distinct signal).
int TestDifferentBucketOnSameIdxAddsNewBit() {
    fuzzer::XiuosCoverageSignal signal;
    signal.Sample(MakeCompletionEvent(MakeSparse({{42, 200}})));  // bucket 128
    CHECK(signal.accumulated()[42] == 128);

    auto r2 = signal.Sample(MakeCompletionEvent(MakeSparse({{42, 3}})));  // bucket 2
    // 2 & ~128 = 2 ≠ 0 → new bit; the bitmap learns the lower bucket too.
    CHECK(r2.magnitude == 1);
    CHECK(signal.accumulated()[42] == (128 | 2));
    return 0;
}

// Empty coverage (n_hit == 0 — program executed but hit no instrumented edge in
// the window, e.g. a rejected program) — fired but no magnitude, not malformed.
int TestEmptyCoverageIsNotInteresting() {
    fuzzer::XiuosCoverageSignal signal;
    auto r = signal.Sample(MakeCompletionEvent(MakeSparse({})));  // n_hit = 0
    CHECK(r.fired);
    CHECK(!r.malformed);
    CHECK(!r.interesting);
    CHECK(r.magnitude == 0);
    return 0;
}

// Malformed frames → malformed flag set, bitmap unchanged.
int TestMalformedCoverage() {
    fuzzer::XiuosCoverageSignal signal;

    // (a) shorter than the 2-byte n_hit header.
    std::vector<std::uint8_t> one_byte{0xFF};
    auto r1 = signal.Sample(MakeCompletionEvent(one_byte));
    CHECK(r1.fired);
    CHECK(r1.malformed);
    CHECK(!r1.interesting);
    CHECK(r1.magnitude == 0);

    // (b) n_hit claims 3 entries but the entry bytes are truncated.
    std::vector<std::uint8_t> truncated{0x00, 0x03, /* only 1.x entries: */ 0x00, 0x05, 0x01, 0x00};
    auto r2 = signal.Sample(MakeCompletionEvent(truncated));
    CHECK(r2.malformed);
    CHECK(r2.magnitude == 0);

    // Bitmap should be entirely zero — no partial accumulation on malformed.
    for (auto b : signal.accumulated()) CHECK(b == 0);
    return 0;
}

// An out-of-range index (>= XIUOS_COV_MAP_SIZE) is defensively skipped, not
// counted and not treated as malformed; valid entries in the same frame still
// accumulate.
int TestOutOfRangeIdxIsSkipped() {
    fuzzer::XiuosCoverageSignal signal;
    auto r = signal.Sample(MakeCompletionEvent(MakeSparse({
        {7, 1},      // valid
        {5000, 200}, // out of range (>= 4096) → skipped
        {9, 1},      // valid
    })));
    CHECK(r.fired);
    CHECK(!r.malformed);
    CHECK(r.magnitude == 2);  // only the two in-range entries
    CHECK(signal.accumulated()[7] == 1);
    CHECK(signal.accumulated()[9] == 1);
    return 0;
}

// Non-Completion events (Abnormal / Fault) → fired = false; bitmap unchanged.
int TestNonCompletionEventDoesNothing() {
    fuzzer::XiuosCoverageSignal signal;

    cc::ChannelEvent abnormal;
    abnormal.kind = cc::ChannelEvent::Kind::kAbnormal;
    abnormal.event_id = 2;
    cc::AbnormalCompletion ac;
    ac.ctx.executor_id = 7;
    ac.kind = cc::AbnormalKind::kInfraFault;
    ac.output = MakeSparse({{0, 0xFF}, {1, 0xFF}});  // try to bait the signal
    abnormal.payload = std::move(ac);

    auto r = signal.Sample(abnormal);
    CHECK(!r.fired);
    CHECK(!r.interesting);
    for (auto b : signal.accumulated()) CHECK(b == 0);

    cc::ChannelEvent fault;
    fault.kind = cc::ChannelEvent::Kind::kFault;
    fault.event_id = 3;
    fault.payload = cc::Fault{};
    auto r2 = signal.Sample(fault);
    CHECK(!r2.fired);
    return 0;
}

// OnGenerationReset must clear the bitmap so a post-reboot worker observes
// "everything is new" again.
int TestGenerationResetClearsBitmap() {
    fuzzer::XiuosCoverageSignal signal;

    auto output = MakeSparse({{0, 5}, {1, 5}});
    auto r1 = signal.Sample(MakeCompletionEvent(output));
    CHECK(r1.magnitude == 2);

    signal.OnGenerationReset();
    for (auto b : signal.accumulated()) CHECK(b == 0);

    auto r2 = signal.Sample(MakeCompletionEvent(output));
    CHECK(r2.magnitude == 2);  // both indices appear new again post-reset
    CHECK(r2.interesting);
    return 0;
}

// Accumulation across many events: hit 100 distinct edges with bucket 1, then
// 50 of them with bucket 128. Magnitude per event reflects new bits, and the
// accumulated bitmap shows the union.
int TestAccumulationAcrossManyEvents() {
    fuzzer::XiuosCoverageSignal signal;

    std::vector<std::pair<std::uint16_t, std::uint8_t>> first;
    for (std::uint16_t i = 0; i < 100; ++i) first.push_back({i, 1});
    auto r1 = signal.Sample(MakeCompletionEvent(MakeSparse(first)));
    CHECK(r1.magnitude == 100);

    std::vector<std::pair<std::uint16_t, std::uint8_t>> second;
    for (std::uint16_t i = 0; i < 50; ++i) second.push_back({i, 200});  // bucket 128
    auto r2 = signal.Sample(MakeCompletionEvent(MakeSparse(second)));
    CHECK(r2.magnitude == 50);

    for (std::size_t i = 0; i < 50; ++i)   CHECK(signal.accumulated()[i] == (1 | 128));
    for (std::size_t i = 50; i < 100; ++i) CHECK(signal.accumulated()[i] == 1);
    CHECK(signal.accumulated()[100] == 0);  // untouched
    return 0;
}

}  // namespace

int main() {
    std::fprintf(stdout, "Running xiuos_coverage_signal_test...\n");
    int run = 0, ok = 0;
    auto exec = [&](auto fn, const char* name) {
        ++run;
        std::fprintf(stderr, "  [RUN] %s\n", name);
        if (fn() == 0) { ++ok; std::fprintf(stderr, "  [PASS] %s\n", name); }
        else            { std::fprintf(stderr, "  [FAIL] %s\n", name); }
    };

    exec(TestBucketizeKnownVectors,                  "BucketizeKnownVectors");
    exec(TestFirstHitsAreInteresting,                "FirstHitsAreInteresting");
    exec(TestReplayingSameCoverageIsNotInteresting,  "ReplayingSameCoverageIsNotInteresting");
    exec(TestHigherBucketOnSameIdxIsInteresting,     "HigherBucketOnSameIdxIsInteresting");
    exec(TestDifferentBucketOnSameIdxAddsNewBit,     "DifferentBucketOnSameIdxAddsNewBit");
    exec(TestEmptyCoverageIsNotInteresting,          "EmptyCoverageIsNotInteresting");
    exec(TestMalformedCoverage,                      "MalformedCoverage");
    exec(TestOutOfRangeIdxIsSkipped,                 "OutOfRangeIdxIsSkipped");
    exec(TestNonCompletionEventDoesNothing,          "NonCompletionEventDoesNothing");
    exec(TestGenerationResetClearsBitmap,            "GenerationResetClearsBitmap");
    exec(TestAccumulationAcrossManyEvents,           "AccumulationAcrossManyEvents");

    std::fprintf(stdout, "\nPassed %d/%d tests\n", ok, run);
    return (run == ok) ? 0 : 1;
}

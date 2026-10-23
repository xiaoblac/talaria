// kcov_cmp_signal_decode_test.cpp
//
// Epic 5 PR-5-B — KcovCmpSignal::Sample decode path ctest.
//
// Synthesizes a ChannelEvent.Completion with output buffer carrying a
// kCoverageKcovCmp wire region (built via AppendKcovCmpFeedbackRaw),
// constructs KcovCmpSignal with a real HashFeedbackStore, and asserts:
//   - SignalContribution.fired = true
//   - magnitude = number of decoded records (post upstream filters)
//   - hashes count matches decoded.cmp size
//   - decoded.cmp contains expected (pc, op1, op2, is_const) tuples
//   - PC-only payload (kCoverageKcov region) → fired=false (no cmp)
//   - empty payload → fired=false

#include "refuzz/core/channel_contract.hpp"
#include "refuzz/feedback/signal/hash_feedback_store.hpp"
#include "refuzz/feedback/signal/kcov_cmp_signal.hpp"
#include "refuzz/proto_domain/types.hpp"
#include "refuzz/proto_wire/feedback_wire.hpp"
#include "worker/coverage/coverage_collector.hpp"

#include <cstdint>
#include <cstdio>
#include <vector>

#define CHECK(cond)                                                                \
    do {                                                                           \
        if (!(cond)) {                                                             \
            std::fprintf(stderr, "CHECK failed: %s (line %d)\n", #cond, __LINE__); \
            return 1;                                                              \
        }                                                                          \
    } while (0)

namespace cc = refuzz::core::channel_contract;

namespace {

constexpr uint64_t kKcovCmpSize8 = 6;

cc::ChannelEvent MakeCompletionWithOutput(std::vector<uint8_t> output)
{
    cc::ChannelEvent ev;
    ev.kind = cc::ChannelEvent::Kind::kCompletion;
    cc::Completion c{};
    c.ctx.executor_id = 12345;
    c.output = std::move(output);
    ev.payload = std::move(c);
    return ev;
}

std::vector<uint8_t> BuildCmpRegion(const std::vector<uint64_t>& packed_records,
                                    uint32_t record_count)
{
    constexpr size_t kCap = 64 * 1024;
    std::vector<uint8_t> buf(kCap, 0);
    uint32_t buf_len = 0;
    const auto status = refuzz::worker::AppendKcovCmpFeedbackRaw(
        buf.data(), kCap, &buf_len,
        packed_records.data(),
        record_count);
    if (status != refuzz::worker::FeedbackAppendStatus::kOk) {
        return {};
    }
    buf.resize(buf_len);
    return buf;
}

int Case1_DecodeFiresOnHappyPath() {
    refuzz::fuzzer::HashFeedbackStore store;
    refuzz::fuzzer::KcovCmpSignal signal(&store);

    // 3 cmp records — none filtered out.
    std::vector<uint64_t> packed = {
        kKcovCmpSize8, 0x111, 0x222, 0x1000,
        kKcovCmpSize8, 0x333, 0x444, 0x2000,
        kKcovCmpSize8, 0x555, 0x666, 0x3000,
    };
    auto buf = BuildCmpRegion(packed, 3);
    CHECK(!buf.empty());

    auto ev = MakeCompletionWithOutput(std::move(buf));
    auto contrib = signal.Sample(ev);
    CHECK(contrib.fired);
    CHECK(!contrib.malformed);
    CHECK(contrib.decoded.cmp.size() == 3);
    // First record: kernel arg1=0x111 / arg2=0x222 → after swap op1=0x222/op2=0x111.
    CHECK(contrib.decoded.cmp[0].pc == 0x1000);
    CHECK(contrib.decoded.cmp[0].arg1 == 0x222);
    CHECK(contrib.decoded.cmp[0].arg2 == 0x111);
    CHECK(contrib.decoded.cmp[0].is_const == false);
    CHECK(contrib.magnitude == 3);
    CHECK(contrib.hashes.size() == 3);
    CHECK(contrib.interesting);
    return 0;
}

int Case2_NoiseFilteredAtDecode() {
    refuzz::fuzzer::HashFeedbackStore store;
    refuzz::fuzzer::KcovCmpSignal signal(&store);

    // 1 keep + 2 dropped (arg1==arg2 and noise rule).
    std::vector<uint64_t> packed = {
        kKcovCmpSize8, 0xaaaa, 0xbbbb, 0x1100, // keep
        kKcovCmpSize8, 0x55,   0x55,   0x1200, // arg1==arg2 → drop
        kKcovCmpSize8, 0,      0,      0x1300, // noise → drop
    };
    auto buf = BuildCmpRegion(packed, 3);
    auto ev = MakeCompletionWithOutput(std::move(buf));
    auto contrib = signal.Sample(ev);
    CHECK(contrib.fired);
    CHECK(contrib.decoded.cmp.size() == 1);
    CHECK(contrib.magnitude == 1);
    CHECK(contrib.decoded.cmp[0].pc == 0x1100);
    return 0;
}

int Case3_PCRegionDoesNotFireCmpSignal() {
    refuzz::fuzzer::HashFeedbackStore store;
    refuzz::fuzzer::KcovCmpSignal signal(&store);

    // Build a kCoverageKcov region (PC entries) — KcovCmpSignal must NOT fire.
    constexpr size_t kCap = 64 * 1024;
    std::vector<uint8_t> buf(kCap, 0);
    uint32_t buf_len = 0;
    std::vector<uint64_t> pcs = {0x1, 0x2, 0x3};
    const auto status = refuzz::worker::AppendCoverageFeedbackRaw(
        buf.data(), kCap, &buf_len,
        refuzz::proto::FeedbackKind::kCoverageKcov,
        pcs.data(), static_cast<uint32_t>(pcs.size()));
    CHECK(status == refuzz::worker::FeedbackAppendStatus::kOk);
    buf.resize(buf_len);

    auto ev = MakeCompletionWithOutput(std::move(buf));
    auto contrib = signal.Sample(ev);
    CHECK(!contrib.fired);                 // wrong kind → no cmp data
    CHECK(contrib.decoded.cmp.empty());
    CHECK(contrib.magnitude == 0);
    return 0;
}

int Case4_EmptyPayload() {
    refuzz::fuzzer::HashFeedbackStore store;
    refuzz::fuzzer::KcovCmpSignal signal(&store);
    auto ev = MakeCompletionWithOutput({});
    auto contrib = signal.Sample(ev);
    CHECK(!contrib.fired);
    CHECK(contrib.magnitude == 0);
    CHECK((contrib.decoded.flags & refuzz::proto::kFeedbackFlagEmptyCoverage) != 0);
    return 0;
}

int Case5_NullStoreDegradesGracefully() {
    refuzz::fuzzer::KcovCmpSignal signal(nullptr); // no dedupe store
    std::vector<uint64_t> packed = {kKcovCmpSize8, 0x77, 0x88, 0x4000};
    auto buf = BuildCmpRegion(packed, 1);
    auto ev = MakeCompletionWithOutput(std::move(buf));
    auto contrib = signal.Sample(ev);
    CHECK(contrib.fired);
    CHECK(contrib.magnitude == 0);
    CHECK(!contrib.interesting);
    return 0;
}

} // namespace

int main()
{
    int rc = 0;
    rc |= Case1_DecodeFiresOnHappyPath();
    rc |= Case2_NoiseFilteredAtDecode();
    rc |= Case3_PCRegionDoesNotFireCmpSignal();
    rc |= Case4_EmptyPayload();
    rc |= Case5_NullStoreDegradesGracefully();
    if (rc == 0) {
        std::printf("kcov_cmp_signal_decode_test PASSED\n");
    } else {
        std::printf("kcov_cmp_signal_decode_test FAILED rc=%d\n", rc);
    }
    return rc;
}

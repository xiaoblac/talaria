// kcov_cmp_signal_dedupe_test.cpp
//
// Epic 5 PR-5-B — KcovCmpSignal dedupe ctest.
//
// Validates that re-sampling the same cmp records returns gain=0 because
// the cmp HashFeedbackStore has already absorbed them.
//
// Cases:
//   1. First Sample → magnitude == record_count; second Sample with same
//      payload → magnitude == 0 (and store size unchanged).
//   2. New record on top of existing store → magnitude == 1.
//   3. is_const flip on otherwise-equal record → distinct hash → counted.

#include "refuzz/core/channel_contract.hpp"
#include "refuzz/feedback/signal/hash_feedback_store.hpp"
#include "refuzz/feedback/signal/kcov_cmp_signal.hpp"
#include "refuzz/proto_domain/types.hpp"
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
constexpr uint64_t kKcovCmpConst = 1;

cc::ChannelEvent MakeCompletionWithOutput(std::vector<uint8_t> output)
{
    cc::ChannelEvent ev;
    ev.kind = cc::ChannelEvent::Kind::kCompletion;
    cc::Completion c{};
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
        packed_records.data(), record_count);
    if (status != refuzz::worker::FeedbackAppendStatus::kOk) {
        return {};
    }
    buf.resize(buf_len);
    return buf;
}

int Case1_RepeatPayloadGainsZero() {
    refuzz::fuzzer::HashFeedbackStore store;
    refuzz::fuzzer::KcovCmpSignal signal(&store);

    std::vector<uint64_t> packed = {
        kKcovCmpSize8, 0x10, 0x20, 0xa00,
        kKcovCmpSize8, 0x30, 0x40, 0xb00,
    };
    auto first_buf = BuildCmpRegion(packed, 2);
    auto first_ev  = MakeCompletionWithOutput(std::move(first_buf));
    auto first     = signal.Sample(first_ev);
    CHECK(first.fired);
    CHECK(first.magnitude == 2);
    CHECK(store.Count() == 2);

    auto second_buf = BuildCmpRegion(packed, 2);
    auto second_ev  = MakeCompletionWithOutput(std::move(second_buf));
    auto second     = signal.Sample(second_ev);
    CHECK(second.fired);                  // wire shape valid
    CHECK(second.magnitude == 0);         // no new dedupe entries
    CHECK(!second.interesting);
    CHECK(store.Count() == 2);            // store size unchanged
    return 0;
}

int Case2_NewRecordCounted() {
    refuzz::fuzzer::HashFeedbackStore store;
    refuzz::fuzzer::KcovCmpSignal signal(&store);

    auto first_ev = MakeCompletionWithOutput(
        BuildCmpRegion({kKcovCmpSize8, 0xaa, 0xbb, 0x100}, 1));
    auto first    = signal.Sample(first_ev);
    CHECK(first.magnitude == 1);
    CHECK(store.Count() == 1);

    auto second_ev = MakeCompletionWithOutput(
        BuildCmpRegion({kKcovCmpSize8, 0xcc, 0xdd, 0x200}, 1));
    auto second    = signal.Sample(second_ev);
    CHECK(second.magnitude == 1);
    CHECK(store.Count() == 2);
    return 0;
}

int Case3_IsConstFlipDistinct() {
    refuzz::fuzzer::HashFeedbackStore store;
    refuzz::fuzzer::KcovCmpSignal signal(&store);

    auto baseline_ev = MakeCompletionWithOutput(
        BuildCmpRegion({kKcovCmpSize8, 0x42, 0x84, 0x300}, 1));
    auto baseline    = signal.Sample(baseline_ev);
    CHECK(baseline.magnitude == 1);

    // Same operands+pc but is_const flipped (CONST | SIZE8 type).
    auto const_ev = MakeCompletionWithOutput(
        BuildCmpRegion({kKcovCmpConst | kKcovCmpSize8, 0x42, 0x84, 0x300}, 1));
    auto const_  = signal.Sample(const_ev);
    CHECK(const_.magnitude == 1);    // is_const=true → different hash → counted
    CHECK(store.Count() == 2);
    return 0;
}

} // namespace

int main()
{
    int rc = 0;
    rc |= Case1_RepeatPayloadGainsZero();
    rc |= Case2_NewRecordCounted();
    rc |= Case3_IsConstFlipDistinct();
    if (rc == 0) {
        std::printf("kcov_cmp_signal_dedupe_test PASSED\n");
    } else {
        std::printf("kcov_cmp_signal_dedupe_test FAILED rc=%d\n", rc);
    }
    return rc;
}

// feedback_cmp_wire_round_trip_test.cpp
//
// Epic 5 PR-5-A — round-trip ctest for KCOV_CMP wire format.
//
// Validates that AppendKcovCmpFeedbackRaw + CoverageFeedbackCodec.Extract
// preserve the upstream ComparisonRaw tuple (pc, op1, op2, is_const)
// and apply upstream kernel filter rules at decode time:
//   - drop type > (KCOV_CMP_CONST | KCOV_CMP_SIZE_MASK)        [malformed]
//   - drop arg1==0 && (arg2==0 || is_const)                     [noise]
//   - drop arg1==arg2                                           [success]
//   - sign-extend arg1/arg2 to comparison width per type & SIZE_MASK
//   - swap kernel operands so op1 is the value that may come from input
//
// Cases:
//   1. Single happy-path record decodes losslessly.
//   2. Multiple records preserve order in result.
//   3. KCOV_CMP_CONST bit lifts into is_const.
//   4. Size-mask sign-extends wide arg1/arg2 and swaps operands.
//   5. Malformed type (out-of-range) is dropped silently.
//   6. Noise-rule (arg1==0 && (arg2==0 || const)) drops record.
//   7. Successful comparison (arg1==arg2) drops record.
//   8. Empty record vector -> kSkippedNoCoverage on append; codec
//      called on PC region payload sees kCoverageKcov path
//      (mutual-exclusion preserved — cmp parsing only fires on
//      kCoverageKcovCmp kind).
//   9. AppendKcovCmpFeedbackRaw rejects nullptr / zero count
//      gracefully without writing.
//  10. Decoder handles a cmp region appended after an existing prefix
//      byte without relying on uint64 alignment.

#include "refuzz/feedback/feedback_codec.hpp"
#include "refuzz/proto_domain/types.hpp"
#include "refuzz/proto_wire/feedback_wire.hpp"
#include "worker/coverage/coverage_collector.hpp"

#include <cstdio>
#include <cstdint>
#include <vector>

#define CHECK(cond)                                                                \
    do {                                                                           \
        if (!(cond)) {                                                             \
            std::fprintf(stderr, "CHECK failed: %s (line %d)\n", #cond, __LINE__); \
            return 1;                                                              \
        }                                                                          \
    } while (0)

namespace {

constexpr uint64_t kKcovCmpConst    = 1;
constexpr uint64_t kKcovCmpSize1    = 0;
constexpr uint64_t kKcovCmpSize2    = 2;
constexpr uint64_t kKcovCmpSize4    = 4;
constexpr uint64_t kKcovCmpSize8    = 6;
constexpr uint64_t kKcovCmpSizeMask = 6;

struct WireRecord { uint64_t type, arg1, arg2, pc; };

// Pack records into a flat uint64 stream in upstream kernel order.
std::vector<uint64_t> Pack(const std::vector<WireRecord>& records) {
    std::vector<uint64_t> out;
    out.reserve(records.size() * 4);
    for (const auto& r : records) {
        out.push_back(r.type);
        out.push_back(r.arg1);
        out.push_back(r.arg2);
        out.push_back(r.pc);
    }
    return out;
}

// Append + decode round-trip helper.
int RoundTrip(const std::vector<WireRecord>& wire,
              std::vector<refuzz::proto::CmpRecord>* out_decoded) {
    constexpr size_t kCap = 64 * 1024;
    std::vector<uint8_t> buf(kCap, 0);
    uint32_t buf_len = 0;

    const auto packed = Pack(wire);
    const auto status = refuzz::worker::AppendKcovCmpFeedbackRaw(
        buf.data(), kCap, &buf_len,
        packed.data(),
        static_cast<uint32_t>(wire.size()));
    CHECK(status == refuzz::worker::FeedbackAppendStatus::kOk);
    CHECK(buf_len > 0);

    buf.resize(buf_len);
    refuzz::proto::FeedbackDelta feedback;
    refuzz::fuzzer::CoverageFeedbackCodec codec;
    const auto parse_status = codec.Extract(&buf, &feedback);
    CHECK(parse_status == refuzz::fuzzer::ParseFeedbackStatus::kOk);

    *out_decoded = std::move(feedback.cmp);
    return 0;
}

int Case1_SingleHappyPath() {
    std::vector<WireRecord> wire = {
        // type=SIZE8 (=6), arg1=0xdeadbeef, arg2=0xcafebabe, pc=0x100
        { kKcovCmpSize8, 0xdeadbeef, 0xcafebabe, 0x100 },
    };
    std::vector<refuzz::proto::CmpRecord> got;
    if (RoundTrip(wire, &got) != 0) return 1;
    CHECK(got.size() == 1);
    CHECK(got[0].pc       == 0x100);
    CHECK(got[0].arg1     == 0xcafebabe);
    CHECK(got[0].arg2     == 0xdeadbeef);
    CHECK(got[0].is_const == false);
    return 0;
}

int Case2_OrderPreserved() {
    std::vector<WireRecord> wire = {
        { kKcovCmpSize8, 0xaaa, 0xbbb, 0x10 },
        { kKcovCmpSize8, 0xccc, 0xddd, 0x20 },
        { kKcovCmpSize8, 0xeee, 0xfff, 0x30 },
    };
    std::vector<refuzz::proto::CmpRecord> got;
    if (RoundTrip(wire, &got) != 0) return 1;
    CHECK(got.size() == 3);
    CHECK(got[0].pc == 0x10);
    CHECK(got[1].pc == 0x20);
    CHECK(got[2].pc == 0x30);
    CHECK(got[0].arg1 == 0xbbb);
    CHECK(got[1].arg2 == 0xccc);
    return 0;
}

int Case3_ConstBit() {
    std::vector<WireRecord> wire = {
        // CONST | SIZE8 → is_const=true, no truncation
        { kKcovCmpConst | kKcovCmpSize8, 0x1234, 0xabcd, 0x200 },
    };
    std::vector<refuzz::proto::CmpRecord> got;
    if (RoundTrip(wire, &got) != 0) return 1;
    CHECK(got.size() == 1);
    CHECK(got[0].is_const == true);
    CHECK(got[0].arg1 == 0xabcd);
    CHECK(got[0].arg2 == 0x1234);
    return 0;
}

int Case4_SizeSignExtensionAndSwap() {
    // SIZE1/2/4 are sign-extended after KCOV width selection, then
    // operands are swapped to match upstream ComparisonRaw.
    std::vector<WireRecord> wire = {
        { kKcovCmpSize1, 0xfeull,       0x7full,       0x300 },
        { kKcovCmpSize2, 0xff80ull,     0x1234ull,     0x400 },
        { kKcovCmpSize4, 0xffffff00ull, 0x76543210ull, 0x500 },
    };
    std::vector<refuzz::proto::CmpRecord> got;
    if (RoundTrip(wire, &got) != 0) return 1;
    CHECK(got.size() == 3);
    CHECK(got[0].arg1 == 0x7f);
    CHECK(got[0].arg2 == 0xfffffffffffffffeull);
    CHECK(got[1].arg1 == 0x1234);
    CHECK(got[1].arg2 == 0xffffffffffffff80ull);
    CHECK(got[2].arg1 == 0x76543210ull);
    CHECK(got[2].arg2 == 0xffffffffffffff00ull);
    return 0;
}

int Case5_MalformedTypeDropped() {
    std::vector<WireRecord> wire = {
        { kKcovCmpSize8, 0x1, 0x2, 0x600 },                        // good
        { (kKcovCmpConst | kKcovCmpSizeMask) + 1, 0x3, 0x4, 0x700 }, // type out of range → drop
        { kKcovCmpSize8, 0x5, 0x6, 0x800 },                        // good
    };
    std::vector<refuzz::proto::CmpRecord> got;
    if (RoundTrip(wire, &got) != 0) return 1;
    CHECK(got.size() == 2);
    CHECK(got[0].pc == 0x600);
    CHECK(got[1].pc == 0x800);
    return 0;
}

int Case6_NoiseDropped() {
    std::vector<WireRecord> wire = {
        { kKcovCmpSize8,                 0, 0, 0x900 },           // arg1==0, arg2==0     → drop
        { kKcovCmpConst | kKcovCmpSize8, 0, 0xff, 0xa00 },        // arg1==0 && is_const → drop
        { kKcovCmpSize8,                 0, 0xff, 0xb00 },        // arg1==0 && !is_const → KEEP
        { kKcovCmpSize8,                 0xaa, 0xbb, 0xc00 },     // happy path           → KEEP
    };
    std::vector<refuzz::proto::CmpRecord> got;
    if (RoundTrip(wire, &got) != 0) return 1;
    CHECK(got.size() == 2);
    CHECK(got[0].pc == 0xb00);
    CHECK(got[1].pc == 0xc00);
    return 0;
}

int Case7_SuccessfulComparisonDropped() {
    std::vector<WireRecord> wire = {
        { kKcovCmpSize8, 0x55, 0x55, 0xd00 }, // successful comparison -> drop
        { kKcovCmpSize8, 0x11, 0x22, 0xe00 }, // keep, decoded as op1=0x22/op2=0x11
    };
    std::vector<refuzz::proto::CmpRecord> got;
    if (RoundTrip(wire, &got) != 0) return 1;
    CHECK(got.size() == 1);
    CHECK(got[0].pc == 0xe00);
    CHECK(got[0].arg1 == 0x22);
    CHECK(got[0].arg2 == 0x11);
    return 0;
}

int Case8_NullCmpKindNotConfusedWithPc() {
    // Build a PC region (kCoverageKcov) and verify codec parses it as
    // cov_hashes, NOT as cmp. Mutual-exclusion contract: a single
    // ChannelEvent.output carries one region; codec dispatches on kind.
    constexpr size_t kCap = 64 * 1024;
    std::vector<uint8_t> buf(kCap, 0);
    uint32_t buf_len = 0;
    std::vector<uint64_t> pcs = {0xaaaa, 0xbbbb, 0xcccc};
    const auto status = refuzz::worker::AppendCoverageFeedbackRaw(
        buf.data(), kCap, &buf_len,
        refuzz::proto::FeedbackKind::kCoverageKcov,
        pcs.data(), static_cast<uint32_t>(pcs.size()));
    CHECK(status == refuzz::worker::FeedbackAppendStatus::kOk);
    buf.resize(buf_len);

    refuzz::proto::FeedbackDelta feedback;
    refuzz::fuzzer::CoverageFeedbackCodec codec;
    const auto parse_status = codec.Extract(&buf, &feedback);
    CHECK(parse_status == refuzz::fuzzer::ParseFeedbackStatus::kOk);
    CHECK(feedback.cmp.empty());                  // no cmp parsed
    CHECK(!feedback.cov_hashes.empty());          // PC parsed
    return 0;
}

int Case9_AppendRejectsBadInput() {
    constexpr size_t kCap = 64 * 1024;
    std::vector<uint8_t> buf(kCap, 0);
    uint32_t buf_len = 0;
    std::vector<uint64_t> empty;

    // null records ptr.
    auto s1 = refuzz::worker::AppendKcovCmpFeedbackRaw(
        buf.data(), kCap, &buf_len, /*records=*/nullptr, 1);
    CHECK(s1 == refuzz::worker::FeedbackAppendStatus::kSkippedNoCoverage);
    CHECK(buf_len == 0);

    // zero count.
    uint64_t scratch = 0;
    auto s2 = refuzz::worker::AppendKcovCmpFeedbackRaw(
        buf.data(), kCap, &buf_len, &scratch, 0);
    CHECK(s2 == refuzz::worker::FeedbackAppendStatus::kSkippedNoCoverage);
    CHECK(buf_len == 0);

    // out=null.
    auto s3 = refuzz::worker::AppendKcovCmpFeedbackRaw(
        nullptr, kCap, &buf_len, &scratch, 1);
    CHECK(s3 == refuzz::worker::FeedbackAppendStatus::kSkippedNoCoverage);
    return 0;
}

int Case10_UnalignedPrefixRoundTrip() {
    constexpr size_t kCap = 64 * 1024;
    std::vector<uint8_t> buf(kCap, 0);
    uint32_t buf_len = 1;
    buf[0] = 0xee;

    const auto packed = Pack({{ kKcovCmpSize8, 0x123, 0x456, 0xabc }});
    const auto status = refuzz::worker::AppendKcovCmpFeedbackRaw(
        buf.data(), kCap, &buf_len,
        packed.data(),
        1);
    CHECK(status == refuzz::worker::FeedbackAppendStatus::kOk);
    buf.resize(buf_len);

    refuzz::proto::FeedbackDelta feedback;
    refuzz::fuzzer::CoverageFeedbackCodec codec;
    const auto parse_status = codec.Extract(&buf, &feedback);
    CHECK(parse_status == refuzz::fuzzer::ParseFeedbackStatus::kOk);
    CHECK(buf.size() == 1);
    CHECK(buf[0] == 0xee);
    CHECK(feedback.cmp.size() == 1);
    CHECK(feedback.cmp[0].pc == 0xabc);
    CHECK(feedback.cmp[0].arg1 == 0x456);
    CHECK(feedback.cmp[0].arg2 == 0x123);
    return 0;
}

} // namespace

int main()
{
    int rc = 0;
    rc |= Case1_SingleHappyPath();
    rc |= Case2_OrderPreserved();
    rc |= Case3_ConstBit();
    rc |= Case4_SizeSignExtensionAndSwap();
    rc |= Case5_MalformedTypeDropped();
    rc |= Case6_NoiseDropped();
    rc |= Case7_SuccessfulComparisonDropped();
    rc |= Case8_NullCmpKindNotConfusedWithPc();
    rc |= Case9_AppendRejectsBadInput();
    rc |= Case10_UnalignedPrefixRoundTrip();
    if (rc == 0) {
        std::printf("feedback_cmp_wire_round_trip_test PASSED\n");
    } else {
        std::printf("feedback_cmp_wire_round_trip_test FAILED rc=%d\n", rc);
    }
    return rc;
}

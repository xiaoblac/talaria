// kcov_cmp_worker_filter_test.cpp
//
// Epic 5 PR-5-B fix #1 — worker-local cmp record filters ctest.
//
// Validates `FilterCmpRecordsByOutputBuffer` (the pre-append filter that
// mirrors upstream executor.cc:1841-1849). Without this filter, cmp
// records whose operands happen to equal a worker output-buffer address
// would leak through to host hint mutators and let the fuzzer corrupt
// its own output region.
//
// Cases:
//   1. All-clear records pass through unchanged.
//   2. Record with arg1 inside [out_start, out_end] is dropped.
//   3. Record with arg2 inside [out_start, out_end] is dropped.
//   4. Record with both arg1 and arg2 inside is dropped (single drop, not
//      double-counted).
//   5. Boundary inclusivity matches upstream (>= start && <= end).
//   6. Empty input + zero count → no output.
//   7. nullptr in/out gracefully degrade to 0 kept.

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

namespace {

constexpr uint64_t kKcovCmpSize8 = 6;

// Pack one record: type, arg1, arg2, pc.
void Push(std::vector<uint64_t>* out, uint64_t type, uint64_t arg1, uint64_t arg2, uint64_t pc) {
    out->push_back(type);
    out->push_back(arg1);
    out->push_back(arg2);
    out->push_back(pc);
}

int Case1_AllClearPassThrough() {
    constexpr uint64_t kBufStart = 0x10000000ull;
    constexpr uint64_t kBufEnd   = 0x10010000ull;
    std::vector<uint64_t> in;
    Push(&in, kKcovCmpSize8, 0x111, 0x222, 0xa00);
    Push(&in, kKcovCmpSize8, 0x333, 0x444, 0xb00);

    std::vector<uint64_t> out;
    const uint32_t kept = refuzz::worker::FilterCmpRecordsByOutputBuffer(
        in.data(), 2, kBufStart, kBufEnd, &out);
    CHECK(kept == 2);
    CHECK(out.size() == 8);  // 2 records × 4 uint64
    // Order preserved verbatim.
    for (size_t i = 0; i < in.size(); ++i) {
        CHECK(out[i] == in[i]);
    }
    return 0;
}

int Case2_Arg1InRangeDropped() {
    constexpr uint64_t kBufStart = 0x40000000ull;
    constexpr uint64_t kBufEnd   = 0x40020000ull;
    std::vector<uint64_t> in;
    Push(&in, kKcovCmpSize8, 0x40010000ull, 0x222, 0xa00); // arg1 IN buf → drop
    Push(&in, kKcovCmpSize8, 0x300,         0x400, 0xb00); // clean → keep

    std::vector<uint64_t> out;
    const uint32_t kept = refuzz::worker::FilterCmpRecordsByOutputBuffer(
        in.data(), 2, kBufStart, kBufEnd, &out);
    CHECK(kept == 1);
    CHECK(out.size() == 4);
    CHECK(out[3] == 0xb00);  // pc of surviving record
    return 0;
}

int Case3_Arg2InRangeDropped() {
    constexpr uint64_t kBufStart = 0x80000000ull;
    constexpr uint64_t kBufEnd   = 0x80100000ull;
    std::vector<uint64_t> in;
    Push(&in, kKcovCmpSize8, 0x500, 0x80050000ull, 0xc00); // arg2 IN buf → drop
    Push(&in, kKcovCmpSize8, 0x600, 0x700,         0xd00); // clean → keep

    std::vector<uint64_t> out;
    const uint32_t kept = refuzz::worker::FilterCmpRecordsByOutputBuffer(
        in.data(), 2, kBufStart, kBufEnd, &out);
    CHECK(kept == 1);
    CHECK(out[3] == 0xd00);
    return 0;
}

int Case4_BothInRangeDroppedOnce() {
    constexpr uint64_t kBufStart = 0xb0000000ull;
    constexpr uint64_t kBufEnd   = 0xb0010000ull;
    std::vector<uint64_t> in;
    Push(&in, kKcovCmpSize8, 0xb0001000ull, 0xb0002000ull, 0xe00); // both IN
    Push(&in, kKcovCmpSize8, 0x111,         0x222,         0xf00); // keep

    std::vector<uint64_t> out;
    const uint32_t kept = refuzz::worker::FilterCmpRecordsByOutputBuffer(
        in.data(), 2, kBufStart, kBufEnd, &out);
    CHECK(kept == 1);
    CHECK(out[3] == 0xf00);
    CHECK(out.size() == 4);  // exactly one record retained, not double-dropped
    return 0;
}

int Case5_BoundaryInclusivity() {
    // Upstream: arg >= out_start && arg <= out_end (both inclusive).
    constexpr uint64_t kBufStart = 0x1000ull;
    constexpr uint64_t kBufEnd   = 0x2000ull;
    std::vector<uint64_t> in;
    Push(&in, kKcovCmpSize8, 0x1000, 0x9999, 0x100);  // arg1 == start → drop
    Push(&in, kKcovCmpSize8, 0x9999, 0x2000, 0x200);  // arg2 == end   → drop
    Push(&in, kKcovCmpSize8, 0x0fff, 0x9999, 0x300);  // arg1 == start-1 → keep
    Push(&in, kKcovCmpSize8, 0x9999, 0x2001, 0x400);  // arg2 == end+1   → keep

    std::vector<uint64_t> out;
    const uint32_t kept = refuzz::worker::FilterCmpRecordsByOutputBuffer(
        in.data(), 4, kBufStart, kBufEnd, &out);
    CHECK(kept == 2);
    CHECK(out.size() == 8);
    CHECK(out[3] == 0x300);
    CHECK(out[7] == 0x400);
    return 0;
}

int Case6_EmptyInput() {
    std::vector<uint64_t> out{0xdead}; // pre-populate to verify clear() runs
    const uint32_t kept = refuzz::worker::FilterCmpRecordsByOutputBuffer(
        nullptr, 0, 0, 0, &out);
    CHECK(kept == 0);
    CHECK(out.empty());
    return 0;
}

int Case7_NullArgsDegrade() {
    // null in_records with non-zero count.
    std::vector<uint64_t> out;
    CHECK(refuzz::worker::FilterCmpRecordsByOutputBuffer(
              nullptr, 5, 0, 0, &out) == 0);
    CHECK(out.empty());

    // null out — must not crash; returns 0.
    std::vector<uint64_t> in;
    Push(&in, kKcovCmpSize8, 0x1, 0x2, 0x3);
    CHECK(refuzz::worker::FilterCmpRecordsByOutputBuffer(
              in.data(), 1, 0, 0, /*out_records=*/nullptr) == 0);
    return 0;
}

} // namespace

int main()
{
    int rc = 0;
    rc |= Case1_AllClearPassThrough();
    rc |= Case2_Arg1InRangeDropped();
    rc |= Case3_Arg2InRangeDropped();
    rc |= Case4_BothInRangeDroppedOnce();
    rc |= Case5_BoundaryInclusivity();
    rc |= Case6_EmptyInput();
    rc |= Case7_NullArgsDegrade();
    if (rc == 0) {
        std::printf("kcov_cmp_worker_filter_test PASSED\n");
    } else {
        std::printf("kcov_cmp_worker_filter_test FAILED rc=%d\n", rc);
    }
    return rc;
}

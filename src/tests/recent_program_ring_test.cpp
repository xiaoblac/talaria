// recent_program_ring_test.cpp
//
// Unit tests for the Layer-2 crash-history ring (per-worker count-bounded ring of
// recently completed programs). See docs/plans/crash-execution-history-ring.md.
// Bare assert harness (repo convention, no gtest).

#include "refuzz/channel/internal/recent_program_ring.hpp"

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <unordered_set>
#include <vector>

namespace {

using refuzz::channel::RecentProgramRecord;
using refuzz::channel::RecentProgramRing;

RecentProgramRecord Rec(uint64_t exec_id, uint64_t ts, uint8_t tag = 0) {
    RecentProgramRecord r;
    r.executor_id  = exec_id;
    r.seed_id      = exec_id;
    r.submit_ts_us = ts;
    r.payload      = {tag};
    return r;
}

void TestDisabledByZeroDepth() {
    RecentProgramRing ring{/*worker_count=*/4, /*depth=*/0};
    assert(!ring.enabled());
    ring.Note(0, Rec(1, 100));
    ring.NoteHanged(Rec(2, 200));
    assert(ring.Collect({}).empty());
    // default-constructed is also disabled
    RecentProgramRing def;
    assert(!def.enabled());
    std::fprintf(stdout, "  [ok] depth=0 disables (zero-overhead fallback)\n");
}

void TestRingBoundPerWorker() {
    RecentProgramRing ring{/*worker_count=*/2, /*depth=*/3};
    assert(ring.enabled());
    // worker 0: push 5, only last 3 (ts 30,40,50) survive
    for (uint64_t i = 1; i <= 5; ++i) ring.Note(0, Rec(i, i * 10));
    auto all = ring.Collect({});
    assert(all.size() == 3);
    assert(all[0].submit_ts_us == 30);
    assert(all[1].submit_ts_us == 40);
    assert(all[2].submit_ts_us == 50);
    std::fprintf(stdout, "  [ok] per-worker ring bounded by depth (evict oldest)\n");
}

void TestCollectTimeSortedAcrossWorkers() {
    RecentProgramRing ring{/*worker_count=*/2, /*depth=*/4};
    // interleave out-of-order across two workers
    ring.Note(0, Rec(10, 500));
    ring.Note(1, Rec(11, 100));
    ring.Note(0, Rec(12, 300));
    ring.Note(1, Rec(13, 200));
    auto all = ring.Collect({});
    assert(all.size() == 4);
    // ascending by submit_ts_us regardless of worker
    assert(all[0].submit_ts_us == 100);
    assert(all[1].submit_ts_us == 200);
    assert(all[2].submit_ts_us == 300);
    assert(all[3].submit_ts_us == 500);
    std::fprintf(stdout, "  [ok] Collect merges workers, time-sorted ascending\n");
}

void TestExcludeInflight() {
    RecentProgramRing ring{/*worker_count=*/1, /*depth=*/8};
    for (uint64_t i = 1; i <= 4; ++i) ring.Note(0, Rec(i, i * 10));
    // exclude executor_ids 2 and 4 (still in the in-flight Layer-1 snapshot)
    std::unordered_set<uint64_t> exclude{2, 4};
    auto all = ring.Collect(exclude);
    assert(all.size() == 2);
    assert(all[0].executor_id == 1);
    assert(all[1].executor_id == 3);
    std::fprintf(stdout, "  [ok] Collect excludes in-flight executor_ids (no double-count)\n");
}

void TestHangedKeptBeyondRing() {
    RecentProgramRing ring{/*worker_count=*/1, /*depth=*/2};
    ring.NoteHanged(Rec(99, 5));  // hanged at ts=5
    // flood the ring; hanged must NOT be evicted
    for (uint64_t i = 1; i <= 10; ++i) ring.Note(0, Rec(i, 100 + i));
    auto all = ring.Collect({});
    // 2 from the ring + 1 hanged
    assert(all.size() == 3);
    assert(all[0].executor_id == 99);   // hanged is oldest (ts=5) -> first
    assert(all[0].submit_ts_us == 5);
    std::fprintf(stdout, "  [ok] hanged program retained beyond ring eviction\n");
}

void TestResetClears() {
    RecentProgramRing ring{/*worker_count=*/2, /*depth=*/4};
    ring.Note(0, Rec(1, 10));
    ring.NoteHanged(Rec(2, 20));
    assert(ring.Collect({}).size() == 2);
    ring.Reset();
    assert(ring.Collect({}).empty());
    // usable after reset
    ring.Note(1, Rec(3, 30));
    assert(ring.Collect({}).size() == 1);
    std::fprintf(stdout, "  [ok] Reset clears ring + hanged (reboot generation)\n");
}

void TestOutOfRangeSlotNoOp() {
    RecentProgramRing ring{/*worker_count=*/2, /*depth=*/4};
    ring.Note(5, Rec(1, 10));  // slot 5 out of range -> no-op, no crash
    assert(ring.Collect({}).empty());
    std::fprintf(stdout, "  [ok] out-of-range worker slot is a no-op\n");
}

} // namespace

int main() {
    std::fprintf(stdout, "Running recent_program_ring_test...\n");
    TestDisabledByZeroDepth();
    TestRingBoundPerWorker();
    TestCollectTimeSortedAcrossWorkers();
    TestExcludeInflight();
    TestHangedKeptBeyondRing();
    TestResetClears();
    TestOutOfRangeSlotNoOp();
    std::fprintf(stdout, "recent_program_ring_test: ALL PASS\n");
    return 0;
}

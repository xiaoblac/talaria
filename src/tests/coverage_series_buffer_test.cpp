// coverage_series_buffer_test.cpp
//
// PR-K-A — Substrate ctest for the coverage series ring buffer +
// RunStateStore series surface (kcov-coverage-curve.md §5.4).
//
// Cases:
//   * Buffer.Push / Latest / Snapshot — empty / partial / full / wrap
//   * Buffer.DroppedTotal — increments only on overflow
//   * RunStateStore.RegisterCoverageSeries — throws on duplicate id
//   * RunStateStore.{Latest,Snapshot}SeriesPoint — empty for unknown id
//   * RunStateStore.RecordCoveragePoint — silently drops for unknown id
//   * RunStateStore — config-aware ctor uses coverage_series_capacity

#include "refuzz/telemetry/observation/coverage_series.hpp"
#include "refuzz/telemetry/observation/run_state_store.hpp"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <vector>

using refuzz::telemetry::CoverageSamplePoint;
using refuzz::telemetry::CoverageSeriesBuffer;
using refuzz::telemetry::CoverageSeriesDescriptor;
using refuzz::telemetry::CoverageSeriesId;
using refuzz::telemetry::RunStateStore;
using refuzz::telemetry::RunStateStoreConfig;

#define CHECK(cond)                                                             \
    do {                                                                        \
        if (!(cond)) {                                                          \
            std::fprintf(stderr, "CHECK failed: %s (line %d)\n",                \
                         #cond, __LINE__);                                      \
            return 1;                                                           \
        }                                                                       \
    } while (0)

#define RUN_TEST(fn)                                                            \
    do {                                                                        \
        std::fprintf(stderr, "  [RUN] %s\n", #fn);                              \
        int rc = fn();                                                          \
        if (rc != 0) {                                                          \
            std::fprintf(stderr, "  [FAIL] %s\n", #fn);                         \
            return rc;                                                          \
        }                                                                       \
        std::fprintf(stderr, "  [PASS] %s\n", #fn);                             \
    } while (0)

static CoverageSamplePoint MakePoint(uint64_t tick, uint64_t total)
{
    CoverageSamplePoint p;
    p.tick_index   = tick;
    p.ts_steady_ns = static_cast<int64_t>(tick * 1000000);
    p.value_total  = total;
    p.value_delta  = (tick == 0) ? 0 : 1;
    p.unique_total = total;
    return p;
}

// Buffer is empty by construction; Latest=nullptr, Snapshot=empty,
// DroppedTotal=0, Size=0.
static int Test_BufferEmpty()
{
    CoverageSeriesBuffer buf(8);
    CHECK(buf.Empty());
    CHECK(buf.Size() == 0);
    CHECK(buf.Capacity() == 8);
    CHECK(buf.Latest() == nullptr);
    CHECK(buf.Snapshot(10).empty());
    CHECK(buf.Snapshot(0).empty());
    CHECK(buf.DroppedTotal() == 0);
    return 0;
}

// Push fewer than capacity → no drop, Snapshot returns insertion order
// oldest-first, Latest is the newest.
static int Test_BufferPartialFill()
{
    CoverageSeriesBuffer buf(8);
    for (uint64_t i = 0; i < 5; ++i) {
        buf.Push(MakePoint(i, i * 10));
    }
    CHECK(buf.Size() == 5);
    CHECK(!buf.Empty());
    CHECK(buf.DroppedTotal() == 0);

    auto snap = buf.Snapshot(100);
    CHECK(snap.size() == 5);
    for (uint64_t i = 0; i < snap.size(); ++i) {
        CHECK(snap[i].tick_index == i);
        CHECK(snap[i].value_total == i * 10);
    }

    const auto* latest = buf.Latest();
    CHECK(latest != nullptr);
    CHECK(latest->tick_index == 4);
    CHECK(latest->value_total == 40);

    // max_n cap honored
    auto snap3 = buf.Snapshot(3);
    CHECK(snap3.size() == 3);
    CHECK(snap3.front().tick_index == 2);
    CHECK(snap3.back().tick_index == 4);
    return 0;
}

// Push more than capacity → oldest dropped; Size pinned at capacity;
// DroppedTotal = (pushed - capacity); Snapshot still oldest-first within
// the live window.
static int Test_BufferWrap()
{
    constexpr size_t kCap = 4;
    CoverageSeriesBuffer buf(kCap);
    for (uint64_t i = 0; i < 10; ++i) {
        buf.Push(MakePoint(i, i));
    }
    CHECK(buf.Size() == kCap);
    CHECK(buf.DroppedTotal() == 10 - kCap);

    auto snap = buf.Snapshot(100);
    CHECK(snap.size() == kCap);
    // Live window is the last 4 pushes: ticks 6,7,8,9
    CHECK(snap[0].tick_index == 6);
    CHECK(snap[1].tick_index == 7);
    CHECK(snap[2].tick_index == 8);
    CHECK(snap[3].tick_index == 9);

    CHECK(buf.Latest()->tick_index == 9);
    return 0;
}

// 0-capacity argument is normalized to kDefaultCapacity (defensive).
static int Test_BufferZeroCapacityNormalized()
{
    CoverageSeriesBuffer buf(0);
    CHECK(buf.Capacity() == CoverageSeriesBuffer::kDefaultCapacity);
    return 0;
}

// RegisterCoverageSeries throws on duplicate id (fail-closed §3 D-7).
static int Test_StoreRegisterDuplicate()
{
    RunStateStore store(RunStateStoreConfig{});
    CoverageSeriesDescriptor d;
    d.id           = CoverageSeriesId{"kcov_pc"};
    d.display_name = "KCOV PC";
    d.unit         = "edges";
    store.RegisterCoverageSeries(d);

    bool threw = false;
    try {
        store.RegisterCoverageSeries(d);
    } catch (const std::runtime_error&) {
        threw = true;
    }
    CHECK(threw);

    auto registered = store.RegisteredSeries();
    CHECK(registered.size() == 1);
    CHECK(registered.front().id.value == "kcov_pc");
    return 0;
}

// Read accessors return empty for unknown ids; RecordCoveragePoint
// silently drops unknown id.
static int Test_StoreUnknownIdReadDrop()
{
    RunStateStore store(RunStateStoreConfig{});
    CoverageSeriesId unknown{"nope"};

    CHECK(!store.LatestSeriesPoint(unknown).has_value());
    CHECK(store.SeriesSnapshot(unknown, 10).empty());
    // Should not throw / not register the id under the hood.
    store.RecordCoveragePoint(unknown, MakePoint(0, 0));
    CHECK(!store.LatestSeriesPoint(unknown).has_value());
    CHECK(store.RegisteredSeries().empty());
    return 0;
}

// End-to-end: register one series, push N > capacity, verify wrap +
// LatestSeriesPoint + SeriesSnapshot match buffer semantics, and
// the per-store coverage_series_capacity_ from RunStateStoreConfig
// is honored.
static int Test_StoreEndToEndWithConfigCapacity()
{
    constexpr size_t kCap = 3;
    RunStateStoreConfig cfg;
    cfg.coverage_series_capacity = kCap;
    RunStateStore store(cfg);

    CoverageSeriesDescriptor d;
    d.id           = CoverageSeriesId{"kcov_pc"};
    d.display_name = "KCOV PC";
    d.unit         = "edges";
    store.RegisterCoverageSeries(d);

    for (uint64_t i = 0; i < 7; ++i) {
        store.RecordCoveragePoint(d.id, MakePoint(i, i * 100));
    }

    auto latest = store.LatestSeriesPoint(d.id);
    CHECK(latest.has_value());
    CHECK(latest->tick_index == 6);
    CHECK(latest->value_total == 600);

    // capacity=3, so live window is ticks 4,5,6
    auto snap = store.SeriesSnapshot(d.id, 100);
    CHECK(snap.size() == kCap);
    CHECK(snap.front().tick_index == 4);
    CHECK(snap.back().tick_index == 6);

    auto snap1 = store.SeriesSnapshot(d.id, 1);
    CHECK(snap1.size() == 1);
    CHECK(snap1.front().tick_index == 6);

    return 0;
}

int main()
{
    RUN_TEST(Test_BufferEmpty);
    RUN_TEST(Test_BufferPartialFill);
    RUN_TEST(Test_BufferWrap);
    RUN_TEST(Test_BufferZeroCapacityNormalized);
    RUN_TEST(Test_StoreRegisterDuplicate);
    RUN_TEST(Test_StoreUnknownIdReadDrop);
    RUN_TEST(Test_StoreEndToEndWithConfigCapacity);
    std::fprintf(stderr, "coverage_series_buffer_test: ALL PASS\n");
    return 0;
}

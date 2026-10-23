// coverage_series_concurrent_test.cpp
//
// PR-K-A — Substrate ctest for concurrent access to the
// RunStateStore coverage series surface (kcov-coverage-curve.md §5.4).
//
// Per §3 D-2: writer = projector thread; readers = renderer / sink
// threads. They share the existing RunStateStore::mu_, no second
// mutex. This test runs a writer + reader concurrently for N
// iterations and asserts:
//   * No torn read: every observed tick_index <= max written tick.
//   * Snapshot length always <= buffer capacity.
//   * No crash / no deadlock — ctest will SIGKILL on timeout.
//
// The test is deterministic in the contract sense (no race-tolerant
// asserts beyond bounds checks) — TSan validation is operator-driven
// per the plan, not a hard ctest gate.

#include "refuzz/telemetry/observation/coverage_series.hpp"
#include "refuzz/telemetry/observation/run_state_store.hpp"

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <thread>
#include <vector>

using refuzz::telemetry::CoverageSamplePoint;
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

static int RunConcurrent()
{
    constexpr size_t   kCap   = 256;
    constexpr uint64_t kIters = 1000;

    RunStateStoreConfig cfg;
    cfg.coverage_series_capacity = kCap;
    RunStateStore store(cfg);

    CoverageSeriesDescriptor d;
    d.id           = CoverageSeriesId{"kcov_pc"};
    d.display_name = "KCOV PC";
    d.unit         = "edges";
    store.RegisterCoverageSeries(d);

    std::atomic<uint64_t> last_written_tick{0};
    std::atomic<bool>     reader_failed{false};
    std::atomic<bool>     writer_done{false};

    // Writer: projector-style. Pushes monotonically increasing tick.
    // Publishes the bound `last_written_tick` BEFORE the store write so
    // the reader's invariant `latest <= bound` holds at all times: in
    // the window between bound-publish and store-write, store still has
    // the previous tick (which is < the new bound).
    std::thread writer([&]() {
        for (uint64_t i = 0; i < kIters; ++i) {
            last_written_tick.store(i, std::memory_order_release);
            CoverageSamplePoint p;
            p.tick_index   = i;
            p.ts_steady_ns = static_cast<int64_t>(i * 1000);
            p.value_total  = i * 7;
            p.value_delta  = 7;
            p.unique_total = i * 3;
            store.RecordCoveragePoint(d.id, p);
        }
        writer_done.store(true, std::memory_order_release);
    });

    // Reader: renderer-style. Reads Latest + Snapshot in a loop.
    // Reads `latest` BEFORE `bound` so the invariant `latest <= bound`
    // holds: anything visible in the store at time T must have had its
    // bound published before T (writer publishes bound first, then
    // writes), and bound is monotonically non-decreasing, so the bound
    // sampled after the store read is >= bound-at-store-read >= latest.
    std::thread reader([&]() {
        while (!writer_done.load(std::memory_order_acquire)) {
            auto latest = store.LatestSeriesPoint(d.id);
            const uint64_t bound = last_written_tick.load(std::memory_order_acquire);
            if (latest.has_value()) {
                if (latest->tick_index > bound) {
                    reader_failed.store(true, std::memory_order_release);
                    return;
                }
            }
            auto snap = store.SeriesSnapshot(d.id, 64);
            if (snap.size() > 64 || snap.size() > kCap) {
                reader_failed.store(true, std::memory_order_release);
                return;
            }
            for (size_t i = 1; i < snap.size(); ++i) {
                // Snapshot is oldest-first within live window; ticks
                // must be strictly increasing.
                if (snap[i].tick_index <= snap[i - 1].tick_index) {
                    reader_failed.store(true, std::memory_order_release);
                    return;
                }
            }
        }
    });

    writer.join();
    reader.join();

    CHECK(!reader_failed.load(std::memory_order_acquire));

    // Final state assertion: latest is the very last written tick.
    auto latest = store.LatestSeriesPoint(d.id);
    CHECK(latest.has_value());
    CHECK(latest->tick_index == kIters - 1);
    CHECK(latest->value_total == (kIters - 1) * 7);

    auto snap = store.SeriesSnapshot(d.id, kCap * 2);
    CHECK(snap.size() == kCap);  // exactly capacity after kIters > kCap pushes
    CHECK(snap.back().tick_index == kIters - 1);

    return 0;
}

int main()
{
    std::fprintf(stderr, "  [RUN] coverage_series_concurrent_test\n");
    int rc = RunConcurrent();
    if (rc != 0) {
        std::fprintf(stderr, "  [FAIL] coverage_series_concurrent_test\n");
        return rc;
    }
    std::fprintf(stderr, "  [PASS] coverage_series_concurrent_test: ALL PASS\n");
    return 0;
}

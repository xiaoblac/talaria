// Copyright 2026 reFuzz project author -------youngkk.
//
// Coverage series substrate (PR-K-A) — types + ring buffer used by
// telemetry to record a 1 Hz time-series of coverage counters. The
// surface here is owned by `telemetry/`; nothing outside this layer
// (per docs/plans/kcov-coverage-curve.md §1.2 Rule B + Corollary D #2)
// constructs a CoverageSeriesId, a CoverageSeriesDescriptor, or a
// CoverageSamplePoint.
//
// A series is registered once at projector construction (PR-K-A) and
// then populated tick-by-tick from MetricRegistry samples. The terminal
// renderer reads this bounded in-memory history; disk metric logs bypass it.

#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <string>
#include <vector>

namespace refuzz::telemetry {

// CoverageSeriesId — typed wrapper around std::string. Equality + hash
// are required so it can key an unordered_map. Per §3 D-1 this is the
// only handle that renderer / sink code uses; they never read the
// underlying MetricRegistry counter name.
struct CoverageSeriesId {
    std::string value;

    bool operator==(const CoverageSeriesId& other) const noexcept {
        return value == other.value;
    }
    bool operator!=(const CoverageSeriesId& other) const noexcept {
        return !(*this == other);
    }
    bool operator<(const CoverageSeriesId& other) const noexcept {
        return value < other.value;
    }
};

// Display metadata for a series. `display_name` is the human label
// (terminal scalar + sparkline title in PR-K-B); `unit` is the axis
// label used by the terminal renderer. Per §1.2 Rule B, this
// struct is the only series-specific knowledge a renderer ever holds.
struct CoverageSeriesDescriptor {
    CoverageSeriesId id;
    std::string display_name;
    std::string unit;
};

// One sample of a series, written by ObservabilityProjector once per
// tick. Field semantics per §3 D-2:
//   * tick_index    : projector-monotonic counter (0-based)
//   * ts_steady_ns  : chrono::steady_clock at sample time, ns
//   * value_total   : cumulative coverage count this tick
//                     (e.g. fuzzer.cov.new_total)
//   * value_delta   : signed delta vs previous tick's value_total
//                     (signed for safety; should not go negative in
//                     practice but a registry restart could expose it)
//   * unique_total  : companion counter (e.g. fuzzer.cov.unique store
//                     size); 0 for kcov_cmp until Epic 5 PR-5-B
struct CoverageSamplePoint {
    uint64_t tick_index   = 0;
    int64_t  ts_steady_ns = 0;
    uint64_t value_total  = 0;
    int64_t  value_delta  = 0;
    uint64_t unique_total = 0;
};

// FIFO ring buffer for CoverageSamplePoint. Bounded by `capacity`;
// when full, the oldest sample is dropped. Disk logs are sampled directly
// from MetricRegistry and do not drain this buffer.
// dropped_total counts total drops since construction — exposed for
// tests + future JSON metadata, **not** as a registered MetricRegistry
// counter (per §3 D-7 telemetry.* metric names are not reserved).
//
// Concurrency: this class is *not* thread-safe on its own.
// RunStateStore owns one buffer per series under its existing mu_;
// concurrent readers/writers must hold that lock. Per §3 D-2 ("reuse,
// do not introduce a second mutex").
class CoverageSeriesBuffer {
public:
    static constexpr size_t kDefaultCapacity = 4096;

    explicit CoverageSeriesBuffer(size_t capacity = kDefaultCapacity);

    void Push(CoverageSamplePoint point);

    // Pointer to the most-recently-pushed sample, or nullptr if the
    // buffer is empty. Pointer is invalidated on the next Push.
    const CoverageSamplePoint* Latest() const;

    // Snapshot of up to the last `max_n` samples, oldest-first.
    // Returns at most min(Size(), max_n) entries; empty if buffer is
    // empty or max_n == 0.
    std::vector<CoverageSamplePoint> Snapshot(size_t max_n) const;

    size_t Size()         const { return points_.size(); }
    size_t Capacity()     const { return capacity_; }
    size_t DroppedTotal() const { return dropped_total_; }
    bool   Empty()        const { return points_.empty(); }

private:
    size_t                          capacity_;
    std::deque<CoverageSamplePoint> points_;
    size_t                          dropped_total_ = 0;
};

} // namespace refuzz::telemetry

namespace std {
template <>
struct hash<::refuzz::telemetry::CoverageSeriesId> {
    size_t operator()(const ::refuzz::telemetry::CoverageSeriesId& id) const noexcept {
        return std::hash<std::string>{}(id.value);
    }
};
} // namespace std

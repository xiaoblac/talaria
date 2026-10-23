// coverage_series_render_test.cpp
//
// PR-K-B — Descriptor-driven coverage render ctest. Verifies that
// RenderCoverageBlock(store) iterates registered descriptors and
// formats each per the §6.1 D-3 contract.
//
// 4 deterministic cases (plan §6.1):
//   1. Empty buffer → "  <display_name> (no coverage data)"
//   2. Partial fill (3 of spark_width) → exact "#-_" sparkline
//   3. Full window (60+ points) → 60-char sparkline
//   4. Two-series multi-line render — both display_names appear in
//      registration order with their independent sparklines.

#include "refuzz/telemetry/observation/coverage_series.hpp"
#include "refuzz/telemetry/observation/run_state_renderer.hpp"
#include "refuzz/telemetry/observation/run_state_store.hpp"

#include <cstdint>
#include <cstdio>
#include <string>

using refuzz::telemetry::CoverageSamplePoint;
using refuzz::telemetry::CoverageSeriesDescriptor;
using refuzz::telemetry::CoverageSeriesId;
using refuzz::telemetry::RenderCoverageBlock;
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

#define CHECK_EQ_STR(actual, expected)                                          \
    do {                                                                        \
        const std::string& _a = (actual);                                       \
        const std::string& _e = (expected);                                     \
        if (_a != _e) {                                                         \
            std::fprintf(stderr,                                                \
                "CHECK_EQ_STR failed (line %d):\n  expected=[%s]\n  actual  =[%s]\n", \
                __LINE__, _e.c_str(), _a.c_str());                              \
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

static CoverageSamplePoint MakePoint(uint64_t tick,
                                     uint64_t total,
                                     int64_t  delta)
{
    CoverageSamplePoint p;
    p.tick_index   = tick;
    p.ts_steady_ns = static_cast<int64_t>(tick * 1000000);
    p.value_total  = total;
    p.value_delta  = delta;
    p.unique_total = total;
    return p;
}

static CoverageSeriesDescriptor MakeDescriptor(const char* id,
                                               const char* display_name,
                                               const char* unit)
{
    CoverageSeriesDescriptor d;
    d.id           = CoverageSeriesId{id};
    d.display_name = display_name;
    d.unit         = unit;
    return d;
}

// Test 1: empty buffer — descriptor registered but no points pushed
// → "(no coverage data)" line, no total/Δ tokens.
static int Test_RenderEmpty()
{
    RunStateStore store{RunStateStoreConfig{}};
    store.RegisterCoverageSeries(MakeDescriptor("kcov_pc", "KCOV PC", "edges"));
    const auto out = RenderCoverageBlock(store);
    CHECK_EQ_STR(out, std::string("\n  KCOV PC (no coverage data)"));
    return 0;
}

// Test 2: partial fill — 3 points with deltas [10, 5, 2]; max_delta=10.
// Levels (oldest-first): 10*7/10=7 ('#'), 5*7/10=3 ('-'), 2*7/10=1 ('_').
// Sparkline = "#-_". Latest is the 3rd push: total=17, delta=2.
static int Test_RenderPartial()
{
    RunStateStore store{RunStateStoreConfig{}};
    store.RegisterCoverageSeries(MakeDescriptor("kcov_pc", "KCOV PC", "edges"));
    store.RecordCoveragePoint(CoverageSeriesId{"kcov_pc"}, MakePoint(0, 10, 10));
    store.RecordCoveragePoint(CoverageSeriesId{"kcov_pc"}, MakePoint(1, 15, 5));
    store.RecordCoveragePoint(CoverageSeriesId{"kcov_pc"}, MakePoint(2, 17, 2));

    const auto out = RenderCoverageBlock(store, /*spark_width=*/60);
    CHECK_EQ_STR(out, std::string("\n  KCOV PC total=17 Δ=2 #-_"));
    return 0;
}

// Test 3: full window — push 70 points, capacity is default (4096), but
// spark_width=60 caps the sparkline. All deltas=1, max_delta=1, all
// levels=7 → 60 '#' chars. Latest is tick=69 with total=70, delta=1.
static int Test_RenderFullWindow()
{
    RunStateStore store{RunStateStoreConfig{}};
    store.RegisterCoverageSeries(MakeDescriptor("kcov_pc", "KCOV PC", "edges"));
    for (uint64_t t = 0; t < 70; ++t) {
        store.RecordCoveragePoint(CoverageSeriesId{"kcov_pc"},
                                  MakePoint(t, t + 1, 1));
    }
    const auto out = RenderCoverageBlock(store, /*spark_width=*/60);
    std::string expected = "\n  KCOV PC total=70 Δ=1 ";
    expected.append(60, '#');
    CHECK_EQ_STR(out, expected);
    return 0;
}

// Test 4: multi-series — 2 descriptors registered in order. Each series
// gets its own line; max_delta + sparkline are independent per buffer.
//   kcov_pc: deltas [3, 1], max_delta=3 → levels [7, 2] → "#:"; latest total=4 delta=1
//   kcov_cmp: deltas [10, 5], max_delta=10 → levels [7, 3] → "#-"; latest total=15 delta=5
// Output preserves registration order: kcov_pc first, then kcov_cmp.
static int Test_RenderMultiSeries()
{
    RunStateStore store{RunStateStoreConfig{}};
    store.RegisterCoverageSeries(MakeDescriptor("kcov_pc",  "KCOV PC",  "edges"));
    store.RegisterCoverageSeries(MakeDescriptor("kcov_cmp", "KCOV CMP", "comparisons"));

    store.RecordCoveragePoint(CoverageSeriesId{"kcov_pc"},  MakePoint(0, 3, 3));
    store.RecordCoveragePoint(CoverageSeriesId{"kcov_pc"},  MakePoint(1, 4, 1));

    store.RecordCoveragePoint(CoverageSeriesId{"kcov_cmp"}, MakePoint(0, 10, 10));
    store.RecordCoveragePoint(CoverageSeriesId{"kcov_cmp"}, MakePoint(1, 15, 5));

    const auto out = RenderCoverageBlock(store, /*spark_width=*/60);
    const std::string expected =
        std::string("\n  KCOV PC total=4 Δ=1 #:")
      + std::string("\n  KCOV CMP total=15 Δ=5 #-");
    CHECK_EQ_STR(out, expected);
    return 0;
}

int main()
{
    RUN_TEST(Test_RenderEmpty);
    RUN_TEST(Test_RenderPartial);
    RUN_TEST(Test_RenderFullWindow);
    RUN_TEST(Test_RenderMultiSeries);
    std::fprintf(stderr, "coverage_series_render_test: ALL PASS\n");
    return 0;
}

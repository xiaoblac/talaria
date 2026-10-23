// coverage_series_register_two_test.cpp
//
// PR-K-D / PR-K-E1 — End-to-end ctest verifying that
// ObservabilityProjector auto-registers BOTH kcov_pc + kcov_cmp builtin
// series (plan §3 D-1 + §6.3) and drives them per-tick from MetricRegistry
// counters.
//
// Cases:
//   1. Both series auto-registered at projector ctor —
//      RegisteredSeries() returns exactly 2 entries in registration
//      order with correct display_name / unit metadata.
//   2. ≥5 ticks → both buffers grow at the same length; kcov_pc has at
//      least one non-zero delta (its counters are populated); kcov_cmp
//      has all-zero points (Epic 5 PR-5-B counters not yet emitting).
//
// Disk output is covered separately by periodic_metric_sink_test; this test
// only verifies the in-memory dashboard series.

#include "refuzz/core/broadcast_bus.hpp"
#include "refuzz/core/channel_contract.hpp"
#include "refuzz/core/metrics/metric_registry.hpp"
#include "refuzz/telemetry/observation/coverage_series.hpp"
#include "refuzz/telemetry/observation/observability_projector.hpp"
#include "refuzz/telemetry/observation/run_state_store.hpp"

#include <chrono>
#include <cstdio>
#include <string>
#include <thread>

namespace cc = refuzz::core::channel_contract;
using refuzz::core::BroadcastBus;
using refuzz::core::metrics::MetricRegistry;
using refuzz::telemetry::CoverageSamplePoint;
using refuzz::telemetry::CoverageSeriesId;
using refuzz::telemetry::ObservabilityConfig;
using refuzz::telemetry::ObservabilityProjector;
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

// Test 1: ObservabilityProjector ctor auto-registers BOTH kcov_pc and
// kcov_cmp. RegisteredSeries() returns them in registration order with
// the expected display metadata.
static int Test_BothSeriesAutoRegistered()
{
    BroadcastBus<cc::ChannelObserveEvent> bus;
    RunStateStore store;
    MetricRegistry registry;
    ObservabilityConfig cfg;
    cfg.pull_interval = std::chrono::milliseconds{1000};  // not started; cadence irrelevant

    ObservabilityProjector projector(
        store, bus.Subscribe(), cfg,
        /*policy_engine=*/nullptr,
        &registry,
        std::chrono::steady_clock::now(),
        std::chrono::system_clock::now(),
        /*logs_dir=*/"");

    auto descriptors = store.RegisteredSeries();
    // [Task A] corpus_pc series 无条件注册(syz_corpus_cover 类比);corpus_edge 仅
    // edge_series_enabled 才注册(默认关,本 test 用默认 cfg)→ 默认注册 3 个。
    CHECK(descriptors.size() == 3);
    CHECK(descriptors[0].id.value     == "kcov_pc");
    CHECK(descriptors[0].display_name == "KCOV PC");
    CHECK(descriptors[0].unit         == "pcs");
    CHECK(descriptors[1].id.value     == "kcov_cmp");
    CHECK(descriptors[1].display_name == "KCOV CMP");
    CHECK(descriptors[1].unit         == "comparisons");
    CHECK(descriptors[2].id.value     == "corpus_pc");
    CHECK(descriptors[2].display_name == "Corpus PC");
    CHECK(descriptors[2].unit         == "pcs");
    return 0;
}

// Test 2: ≥5 ticks → both buffers grow with same length. kcov_pc has
// ≥1 non-zero delta (its fuzzer.cov.{new_total,unique} counters are
// populated); kcov_cmp's points are all-zero (Epic 5 PR-5-B counters
// fuzzer.cov.cmp.* are absent in this rev — verified zero-fill behavior
// per §3 D-7).
static int Test_FiveTicksGrowBothBuffers()
{
    BroadcastBus<cc::ChannelObserveEvent> bus;
    RunStateStore store;
    MetricRegistry registry;

    auto& all_pc = registry.GaugeOf("fuzzer.cov.all_pc", {});

    ObservabilityConfig cfg;
    cfg.pull_interval = std::chrono::milliseconds{20};  // tick fast

    ObservabilityProjector projector(
        store, bus.Subscribe(), cfg,
        /*policy_engine=*/nullptr,
        &registry,
        std::chrono::steady_clock::now(),
        std::chrono::system_clock::now(),
        /*logs_dir=*/"");

    projector.Start();
    // 6 increments × 40 ms ≈ 240 ms of wall time → projector hits
    // ≥10 ticks at 20 ms cadence. We assert ≥5 below to keep the
    // bound loose against scheduler jitter.
    for (int i = 0; i < 6; ++i) {
        all_pc.Add(10);
        std::this_thread::sleep_for(std::chrono::milliseconds{40});
    }
    projector.Stop();

    const auto pc_snap  = store.SeriesSnapshot(CoverageSeriesId{"kcov_pc"},  4096);
    const auto cmp_snap = store.SeriesSnapshot(CoverageSeriesId{"kcov_cmp"}, 4096);
    CHECK(pc_snap.size() >= 5);
    // Both buffers tick in the same projector pass → identical lengths.
    CHECK(cmp_snap.size() == pc_snap.size());

    // kcov_pc: at least one tick observed a counter increment between
    // its previous tick and this one → non-zero delta.
    bool pc_has_nonzero_delta = false;
    for (const auto& p : pc_snap) {
        if (p.value_delta > 0) { pc_has_nonzero_delta = true; break; }
    }
    CHECK(pc_has_nonzero_delta);

    // kcov_cmp: all zero (counters absent → SamplesCounterValue returns 0).
    for (const auto& p : cmp_snap) {
        CHECK(p.value_total  == 0);
        CHECK(p.value_delta  == 0);
        CHECK(p.unique_total == 0);
    }
    return 0;
}

int main()
{
    RUN_TEST(Test_BothSeriesAutoRegistered);
    RUN_TEST(Test_FiveTicksGrowBothBuffers);
    std::fprintf(stderr, "coverage_series_register_two_test: ALL PASS\n");
    return 0;
}

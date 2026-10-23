// kcov_cmp_two_series_active_test.cpp
//
// Epic 5 PR-5-B — extends PR-K-D coverage_series_register_two_test
// to verify that, with PR-5-B's counter publication active, BOTH
// kcov_pc AND kcov_cmp series fill non-zero deltas.
//
// Forward-compat pinky promise from kcov-coverage-curve.md App B is
// asserted here: PR-K-D pre-registered the kcov_cmp series binding
// with `fuzzer.cov.cmp.{new_total,unique}` as source counters; PR-5-B
// publishes those counters; this test exercises that the curve infra
// auto-fills WITHOUT any change to telemetry/.
//
// Cases:
//   1. Manually bind fuzzer.cov.cmp.{new_total,unique} in MetricRegistry
//      AND fuzzer.cov.{new_total,unique}; tick the projector; both
//      kcov_pc AND kcov_cmp snapshots show ≥1 non-zero delta.
//   2. Only PC counters present (fuzzer.cov.cmp.* absent) → kcov_pc fills,
//      kcov_cmp all-zero (regression check matches PR-K-D behavior).

#include "refuzz/core/broadcast_bus.hpp"
#include "refuzz/core/channel_contract.hpp"
#include "refuzz/core/metrics/metric_registry.hpp"
#include "refuzz/telemetry/observation/coverage_series.hpp"
#include "refuzz/telemetry/observation/observability_projector.hpp"
#include "refuzz/telemetry/observation/run_state_store.hpp"

#include <chrono>
#include <cstdio>
#include <thread>

namespace cc = refuzz::core::channel_contract;
using refuzz::core::BroadcastBus;
using refuzz::core::metrics::MetricRegistry;
using refuzz::telemetry::CoverageSeriesId;
using refuzz::telemetry::ObservabilityConfig;
using refuzz::telemetry::ObservabilityProjector;
using refuzz::telemetry::RunStateStore;

#define CHECK(cond)                                                                \
    do {                                                                           \
        if (!(cond)) {                                                             \
            std::fprintf(stderr, "CHECK failed: %s (line %d)\n", #cond, __LINE__); \
            return 1;                                                              \
        }                                                                          \
    } while (0)

namespace {

int Case1_BothCountersFillBothSeries()
{
    BroadcastBus<cc::ChannelObserveEvent> bus;
    RunStateStore store;
    MetricRegistry registry;

    // Bind ALL four counters that the projector binds to in production.
    auto& all_pc    = registry.GaugeOf  ("fuzzer.cov.all_pc",         {});
    auto& cmp_total = registry.CounterOf("fuzzer.cov.cmp.new_total",  {});
    auto& cmp_unique= registry.GaugeOf  ("fuzzer.cov.cmp.unique",     {});

    ObservabilityConfig cfg;
    cfg.pull_interval = std::chrono::milliseconds{20};

    ObservabilityProjector projector(
        store, bus.Subscribe(), cfg,
        /*policy_engine=*/nullptr,
        &registry,
        std::chrono::steady_clock::now(),
        std::chrono::system_clock::now(),
        /*logs_dir=*/"");

    projector.Start();
    for (int i = 0; i < 6; ++i) {
        all_pc.Add(7);
        cmp_total.Inc(3);
        cmp_unique.Add(1);
        std::this_thread::sleep_for(std::chrono::milliseconds{40});
    }
    projector.Stop();

    const auto pc_snap  = store.SeriesSnapshot(CoverageSeriesId{"kcov_pc"},  4096);
    const auto cmp_snap = store.SeriesSnapshot(CoverageSeriesId{"kcov_cmp"}, 4096);
    CHECK(pc_snap.size()  >= 5);
    CHECK(cmp_snap.size() == pc_snap.size());

    bool pc_nonzero  = false;
    bool cmp_nonzero = false;
    for (const auto& p : pc_snap)  if (p.value_delta > 0) { pc_nonzero  = true; break; }
    for (const auto& p : cmp_snap) if (p.value_delta > 0) { cmp_nonzero = true; break; }
    CHECK(pc_nonzero);
    CHECK(cmp_nonzero);   // PR-5-B effect: cmp counters publish → series fills.
    return 0;
}

int Case2_OnlyPCKeepsCmpZero()
{
    BroadcastBus<cc::ChannelObserveEvent> bus;
    RunStateStore store;
    MetricRegistry registry;

    auto& all_pc = registry.GaugeOf("fuzzer.cov.all_pc", {});
    // No cmp counters bound — pre-PR-5-B regression behavior.

    ObservabilityConfig cfg;
    cfg.pull_interval = std::chrono::milliseconds{20};

    ObservabilityProjector projector(
        store, bus.Subscribe(), cfg,
        /*policy_engine=*/nullptr,
        &registry,
        std::chrono::steady_clock::now(),
        std::chrono::system_clock::now(),
        /*logs_dir=*/"");

    projector.Start();
    for (int i = 0; i < 4; ++i) {
        all_pc.Add(5);
        std::this_thread::sleep_for(std::chrono::milliseconds{40});
    }
    projector.Stop();

    const auto cmp_snap = store.SeriesSnapshot(CoverageSeriesId{"kcov_cmp"}, 4096);
    for (const auto& p : cmp_snap) {
        CHECK(p.value_total  == 0);
        CHECK(p.value_delta  == 0);
        CHECK(p.unique_total == 0);
    }
    return 0;
}

} // namespace

int main()
{
    int rc = 0;
    rc |= Case1_BothCountersFillBothSeries();
    rc |= Case2_OnlyPCKeepsCmpZero();
    if (rc == 0) {
        std::printf("kcov_cmp_two_series_active_test PASSED\n");
    } else {
        std::printf("kcov_cmp_two_series_active_test FAILED rc=%d\n", rc);
    }
    return rc;
}

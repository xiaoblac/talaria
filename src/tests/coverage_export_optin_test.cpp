// coverage_export_optin_test.cpp
//
// PR-K-E1 — Verifies the disk-export opt-in gate.
//
// coverage_series.log is written only when
// (`ObservabilityConfig::coverage_export_enabled == true` OR
//  `edge_series_enabled == true`) AND a non-empty logs_dir is provided.
// Both export gates false → no sink object exists, no IO, no file on disk.
// (These cases keep coverage_export_enabled as the toggle; edge stays default
// false, so the pair reduces to the single coverage_export_enabled gate.)
//
// Cases:
//   1. flag=false + non-empty logs_dir → no coverage log after Stop.
//   2. flag=true  + non-empty logs_dir → coverage log written at Stop.
//   3. flag=true  + empty   logs_dir   → no coverage log (no destination).

#include "refuzz/core/broadcast_bus.hpp"
#include "refuzz/core/channel_contract.hpp"
#include "refuzz/core/metrics/metric_registry.hpp"
#include "refuzz/telemetry/observation/observability_projector.hpp"
#include "refuzz/telemetry/observation/run_state_store.hpp"

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <string>
#include <thread>
#include <unistd.h>

namespace cc = refuzz::core::channel_contract;
using refuzz::core::BroadcastBus;
using refuzz::core::metrics::MetricRegistry;
using refuzz::telemetry::ObservabilityConfig;
using refuzz::telemetry::ObservabilityProjector;
using refuzz::telemetry::RunStateStore;

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

namespace {

std::filesystem::path MakeUniqueTmpDir(const char* tag)
{
    static int counter = 0;
    auto dir = std::filesystem::temp_directory_path() /
               ("refuzz_optin_" + std::string(tag) + "_" +
                std::to_string(::getpid()) + "_" + std::to_string(++counter));
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    return dir;
}

// Run a projector for a few ticks with distinct-set gauges changing.
void DriveProjectorBriefly(ObservabilityProjector& projector,
                           MetricRegistry& registry)
{
    auto& all_pc = registry.GaugeOf("fuzzer.cov.all_pc", {});
    auto& corpus_pc = registry.GaugeOf("fuzzer.cov.corpus_pc", {});
    projector.Start();
    for (int i = 0; i < 3; ++i) {
        all_pc.Add(10);
        corpus_pc.Add(1);
        std::this_thread::sleep_for(std::chrono::milliseconds{40});
    }
    projector.Stop();
}

} // namespace

// Case 1: opt-in flag false + valid logs_dir → no PC metric log. This is the
// production default path; no coverage-export IO unless operator enables.
static int Test_FlagFalseNoFile()
{
    const auto dir = MakeUniqueTmpDir("flag_false");
    BroadcastBus<cc::ChannelObserveEvent> bus;
    RunStateStore store;
    MetricRegistry registry;

    ObservabilityConfig cfg;
    cfg.pull_interval = std::chrono::milliseconds{20};
    cfg.coverage_export_enabled = false;  // explicit default

    ObservabilityProjector projector(
        store, bus.Subscribe(), cfg,
        /*policy_engine=*/nullptr,
        &registry,
        std::chrono::steady_clock::now(),
        std::chrono::system_clock::now(),
        /*logs_dir=*/dir.string());

    DriveProjectorBriefly(projector, registry);

    const auto log_path = dir / "coverage_series.log";
    CHECK(!std::filesystem::exists(log_path));

    std::filesystem::remove_all(dir);
    return 0;
}

// Case 2: opt-in flag true + valid logs_dir → coverage metric log exists with
// at least the header line (zero-skip may suppress all-zero rows but
// the header always lands on a non-empty first batch).
static int Test_FlagTrueFileExists()
{
    const auto dir = MakeUniqueTmpDir("flag_true");
    BroadcastBus<cc::ChannelObserveEvent> bus;
    RunStateStore store;
    MetricRegistry registry;

    ObservabilityConfig cfg;
    cfg.pull_interval = std::chrono::milliseconds{20};
    cfg.coverage_export_enabled = true;

    ObservabilityProjector projector(
        store, bus.Subscribe(), cfg,
        /*policy_engine=*/nullptr,
        &registry,
        std::chrono::steady_clock::now(),
        std::chrono::system_clock::now(),
        /*logs_dir=*/dir.string());

    DriveProjectorBriefly(projector, registry);

    const auto log_path = dir / "coverage_series.log";
    CHECK(std::filesystem::exists(log_path));
    CHECK(std::filesystem::file_size(log_path) > 0);

    std::filesystem::remove_all(dir);
    return 0;
}

// Case 3: opt-in flag true but empty logs_dir → still no sink (no
// destination), no file. Both gates must be true to construct the sink.
static int Test_FlagTrueEmptyLogsDirNoSink()
{
    BroadcastBus<cc::ChannelObserveEvent> bus;
    RunStateStore store;
    MetricRegistry registry;

    ObservabilityConfig cfg;
    cfg.pull_interval = std::chrono::milliseconds{20};
    cfg.coverage_export_enabled = true;

    ObservabilityProjector projector(
        store, bus.Subscribe(), cfg,
        /*policy_engine=*/nullptr,
        &registry,
        std::chrono::steady_clock::now(),
        std::chrono::system_clock::now(),
        /*logs_dir=*/"");

    // No exception expected; ctor + Start/Stop succeed trivially.
    DriveProjectorBriefly(projector, registry);
    return 0;
}

int main()
{
    RUN_TEST(Test_FlagFalseNoFile);
    RUN_TEST(Test_FlagTrueFileExists);
    RUN_TEST(Test_FlagTrueEmptyLogsDirNoSink);
    std::fprintf(stderr, "coverage_export_optin_test: ALL PASS\n");
    return 0;
}

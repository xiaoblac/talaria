#pragma once

#include "refuzz/core/broadcast_bus.hpp"
#include "refuzz/core/channel_contract.hpp"
#include "refuzz/core/runtime_state.hpp"
// [v2 metric bus — 当前版本] DeriveAndRecordCoveragePoints uses
// MetricRegistry::Sample (a nested type), so the full header is required
// here — forward declaration is no longer sufficient.
#include "refuzz/core/metrics/metric_registry.hpp"
// [v2 PR-K-A] coverage series substrate, see kcov-coverage-curve.md §5.2
#include "refuzz/telemetry/observation/coverage_series.hpp"
// [fixed request stream] ObservabilityConfig carries SummaryRunMode.
#include "refuzz/telemetry/observation/run_summary.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace refuzz::telemetry {

class CoverageMetricsSink;
class FuzzerStatsSink;
class PolicyEngine;
class RunStateStore;

struct ObservabilityConfig {
    std::chrono::milliseconds pull_interval{1000};
    // [v2 run_summary redesign] final tick 时是否跑 RunSummary invariants。
    bool enable_summary_invariants = true;
    // PC metric-log export opt-in. The in-memory series and terminal renderer
    // remain active regardless; enabled writes coverage_PC_series.log at 10s.
    bool coverage_export_enabled = false;
    // [edge-over-time] Dedicated corpus-EDGE time-series export, INDEPENDENT of
    // Independent edge metric-log gate. Enabled writes all_edge/corpus_edge to
    // coverage_edge_series.log at the same 10s cadence as the PC file.
    bool edge_series_enabled = false;
    // [fixed request stream] Workload source for this run. Selects which
    // invariant set the final RunSummary is assembled against, and is recorded
    // in run_summary.json so a reader can tell a measured zero from a field
    // that does not exist in this mode. See SummaryRunMode.
    SummaryRunMode run_mode = SummaryRunMode::kFuzzing;
};

// [v2 PR-K-A] Binding between a CoverageSeriesDescriptor and the two
// MetricRegistry counters that drive its samples. Per §3 D-4
// (adapter pattern, not abstraction down): the projector owns this
// binding; feedback / control / mutator / executor never see series
// types. Per §3 D-7 missing metrics are treated as 0 (so PR-K-D's
// kcov_cmp slot stays valid before Epic 5 PR-5-B publishes its
// counters).
struct CoverageSeriesBinding {
    CoverageSeriesDescriptor descriptor;
    std::string total_metric;    // counter name for value_total
    std::string unique_metric;   // counter name for unique_total (optional; "" → skip)
};

// [6b-3 — 当前版本] Projector 瘦身为单订阅:
//   channel_event_sub (BroadcastBus) — 事件投递到 RunStateStore
// Fuzzer/Executor/ChannelSnapshot 三个数据流已由 MetricRegistry 承担,
// Projector 不再聚合 RuntimeSnapshot 数据, 只保留事件 fan-in 与 policy tick。
//
// [v2 run_summary redesign] 每 tick 调 ComputeRunSummary 投影 samples → RunSummary
// 写回 store;Stop() 在 join 后跑一次同步 final tick,保证 JsonSink 读到 is_final=true。
class ObservabilityProjector {
public:
    using ChannelEventSubscription =
        refuzz::core::BroadcastBus<refuzz::core::channel_contract::ChannelObserveEvent>::Subscription;

    // session_start_steady / session_start_wall 由 orchestrator 在 Build/Run 时确定,
    // 供 ComputeRunSummary 计算 elapsed_ms / exec_s / 墙钟 iso 时间。
    ObservabilityProjector(RunStateStore& store,
                           ChannelEventSubscription channel_event_sub,
                           ObservabilityConfig config = {},
                           PolicyEngine* policy_engine = nullptr,
                           refuzz::core::metrics::MetricRegistry* registry = nullptr,
                           std::chrono::steady_clock::time_point session_start_steady = {},
                           std::chrono::system_clock::time_point session_start_wall = {},
                           // Coverage metric logs are created only when their
                           // corresponding config gate is enabled and logs_dir
                           // is non-empty.
                           std::string logs_dir = "");
    ~ObservabilityProjector();

    void Start();
    void Stop();

    // [v2 PR-K-A] Register a coverage series. Must be called BEFORE Start();
    // also calls store_.RegisterCoverageSeries which throws on duplicate id
    // (fail-closed per §3 D-7). Series order in subsequent ticks follows
    // registration order.
    void RegisterCoverageSeries(CoverageSeriesBinding binding);

private:
    void ProjectLoop();
    bool DrainInputs();
    void EmitObserveEvent(const refuzz::core::channel_contract::ChannelObserveEvent& event);
    void EmitGapEvent(const char* subject, size_t dropped);
    // [v2 run_summary redesign] compute+write RunSummary 到 store;nullptr registry 直接返回。
    void ComputeAndStoreSummary(bool is_final);
    // [v2 PR-K-A] Helper called from ComputeAndStoreSummary to derive
    // CoverageSamplePoint for each registered binding from the same
    // `samples` vector that ComputeRunSummary consumed (so a single
    // CollectAllPrefixes call drives both run_summary + series, per §5.2).
    void DeriveAndRecordCoveragePoints(
        const std::vector<refuzz::core::metrics::MetricRegistry::Sample>& samples,
        std::uint64_t tick);
    // [v2 PR-K-A] Builtin coverage-series registry. Called once from the
    // ctor to register the kcov_pc binding (the only active series in
    // PR-K-A; PR-K-D extends this method with the kcov_cmp empty-slot).
    // Lives inside projector — control/ is barred from RegisterCoverageSeries
    // refs by §1.2 Corollary D #2 (PR-K-D lint).
    void RegisterBuiltinCoverageSeries();

    RunStateStore& store_;
    ChannelEventSubscription channel_event_sub_;
    ObservabilityConfig config_{};
    PolicyEngine* policy_engine_ = nullptr;
    refuzz::core::metrics::MetricRegistry* registry_ = nullptr;
    // [v2 run_summary redesign]
    std::chrono::steady_clock::time_point session_start_steady_{};
    std::chrono::system_clock::time_point session_start_wall_{};

    // [v2 PR-K-A] Registered coverage series + per-series last_total
    // for delta computation. tick_index_ is projector-monotonic across
    // every coverage tick (incremented once per ComputeAndStoreSummary
    // pass that has at least one binding).
    std::vector<CoverageSeriesBinding>             series_bindings_;
    std::unordered_map<CoverageSeriesId, uint64_t> last_total_;
    uint64_t                                       coverage_tick_index_ = 0;

    // Direct metric exporter for coverage_PC_series.log and
    // coverage_edge_series.log. It reads the same registry snapshot as summary.
    std::unique_ptr<CoverageMetricsSink>           coverage_metrics_sink_;
    // Default completed-stats export. Created whenever logs_dir is non-empty;
    // writes <logs_dir>/stats.txt every 60s plus one final shutdown row.
    std::unique_ptr<FuzzerStatsSink>                stats_sink_;
    std::mutex wait_mu_;
    std::condition_variable wait_cv_;
    std::thread thread_;
    std::atomic<bool> running_{false};
};

} // namespace refuzz::telemetry

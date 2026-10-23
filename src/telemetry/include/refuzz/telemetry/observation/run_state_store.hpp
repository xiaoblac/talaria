#pragma once

#include "refuzz/core/runtime_state.hpp"
// [v2 metric bus — 当前版本]
#include "refuzz/core/metrics/metric_registry.hpp"
#include "refuzz/telemetry/observation/run_summary.hpp"
// [v2 PR-K-A] coverage series substrate, see kcov-coverage-curve.md §5.2
#include "refuzz/telemetry/observation/coverage_series.hpp"
// [v2 G5 follow-up] LibAFL `afl_exec_sec` 等价 windowed exec/sec tracker。
#include "refuzz/telemetry/observation/rate_window_tracker.hpp"

#include <cstddef>
#include <deque>
#include <fstream>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace refuzz::telemetry {

// [v2 PR-K-A] Constructor config — preserves the existing
// RunStateStore(size_t) shim used by current call sites; the new
// ctor sets coverage_series_capacity_ from `coverage_series_capacity`.
struct RunStateStoreConfig {
    size_t max_events                 = 1024;
    size_t coverage_series_capacity   = CoverageSeriesBuffer::kDefaultCapacity;
};

class RunStateStore {
public:
    // [v2 metric bus — 当前版本]
    using SampleKey = std::pair<std::string, refuzz::core::metrics::Labels>;
    using SampleMap = std::map<SampleKey, refuzz::core::metrics::MetricRegistry::Sample>;

    explicit RunStateStore(size_t max_events = 1024);
    // [v2 PR-K-A] Config-aware ctor, see plan §5.2. Both ctors land in
    // the same final state; existing call sites stay on the size_t shim.
    explicit RunStateStore(RunStateStoreConfig config);

    // [diag] 打开 debug event 持久化日志文件；Append 模式。
    //   path 为空则关闭已有 sink。典型路径 <layout.logs_dir>/debugEvent.txt。
    //   与 PushEvent 串行（共用 mu_），失败只记状态不抛；写入含完整 detail 不截断。
    void EnableDebugEventLog(const std::string& path);

    void UpdateSnapshot(refuzz::core::RuntimeSnapshot snap);
    void PushEvent(refuzz::core::RuntimeEvent event);

    // [v2 metric bus — 当前版本]
    void UpdateMetricSamples(std::vector<refuzz::core::metrics::MetricRegistry::Sample> samples);
    SampleMap MetricSamples() const;

    refuzz::core::RuntimeSnapshot LatestSnapshot() const;
    std::vector<refuzz::core::RuntimeEvent> RecentEvents(size_t max_count = 100) const;

    // [v2 run_summary redesign] 由 ObservabilityProjector 每 tick 写入;
    // Renderer/JsonSink 从这里读已算好的 RunSummary,不再各自重投影。
    void UpdateRunSummary(RunSummary summary);
    std::optional<RunSummary> LatestRunSummary() const;

    // [v2 G5 follow-up] windowed exec/sec — LibAFL `afl_exec_sec` 等价。
    // ObserveExecRate(ts_us, terminal) 由 status thread 每 tick 调
    // (orchestrator status loop,5s 一次)。返 smoothed rate 给 renderer + summary。
    // 跟现有 `execs_per_sec = terminal/exec_fuzz_s` 累计平均并存,不替代。
    void   ObserveExecRate(std::uint64_t ts_us, std::uint64_t terminal);
    double WindowedExecsPerSec() const;

    // [v2 PR-K-A] Coverage series surface (see kcov-coverage-curve.md
    // §3 D-1/D-2 + §5.2). All 5 methods take `mu_` so they share the
    // existing concurrency contract — no second mutex.
    //
    // RegisterCoverageSeries: throws std::runtime_error on id collision
    //   (fail-closed per §3 D-7). Called once per series at projector
    //   startup; never on the hot path.
    // RecordCoveragePoint: silently drops if id is unknown (defensive;
    //   projector should not call with an unregistered id).
    // RegisteredSeries: insertion-ordered copy of all registered
    //   descriptors — renderer iterates this to drive its loop.
    // LatestSeriesPoint / SeriesSnapshot: read accessors used by
    //   PR-K-B renderer + PR-K-C sink.
    void RegisterCoverageSeries(CoverageSeriesDescriptor descriptor);
    void RecordCoveragePoint(const CoverageSeriesId& id, CoverageSamplePoint point);
    std::vector<CoverageSeriesDescriptor> RegisteredSeries() const;
    std::optional<CoverageSamplePoint> LatestSeriesPoint(const CoverageSeriesId& id) const;
    std::vector<CoverageSamplePoint> SeriesSnapshot(const CoverageSeriesId& id, size_t max_n) const;

private:
    // [diag] 持久化 event 的辅助；已持 mu_ 时调用。
    void AppendDebugEventLocked_(const refuzz::core::RuntimeEvent& event);

    mutable std::mutex mu_;
    refuzz::core::RuntimeSnapshot snapshot_;
    std::deque<refuzz::core::RuntimeEvent> events_;
    size_t max_events_ = 1024;
    // [v2 metric bus — 当前版本]
    SampleMap metric_samples_;
    // [v2 run_summary redesign]
    std::optional<RunSummary> run_summary_;

    // [v2 PR-K-A] Coverage series storage (under mu_). Insertion-ordered
    // descriptor list lets RegisteredSeries() return registration order
    // (renderer iterates in registration order in PR-K-B).
    size_t                                                       coverage_series_capacity_ =
        CoverageSeriesBuffer::kDefaultCapacity;
    std::unordered_map<CoverageSeriesId, CoverageSeriesBuffer>   coverage_series_;
    std::vector<CoverageSeriesDescriptor>                        series_descriptors_;

    // [diag] debug event sink：受 mu_ 保护，PushEvent 同步 append
    std::ofstream debug_event_log_;
    std::string   debug_event_log_path_;

    // [v2 G5 follow-up] windowed exec/sec tracker — 自带 mutex,跟 store mu_
    // 独立(避免 dashboard render 持 mu_ 时 query rate 嵌套锁)。
    RateWindowTracker exec_rate_tracker_;
};

} // namespace refuzz::telemetry

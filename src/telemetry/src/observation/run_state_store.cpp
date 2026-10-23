#include "refuzz/telemetry/observation/run_state_store.hpp"

#include "refuzz/logging/host_logger.hpp"  // [diag] sink 打开/失败日志

#include <stdexcept>
#include <utility>

namespace refuzz::telemetry {
using refuzz::core::RuntimeEvent;
using refuzz::core::RuntimeSnapshot;
// [v2 metric bus — 当前版本]
using refuzz::core::metrics::MetricRegistry;

namespace {

const char* EventKindName(RuntimeEvent::Kind kind)
{
    switch (kind) {
    case RuntimeEvent::Kind::kFault:              return "fault";
    case RuntimeEvent::Kind::kRecoveryBegin:      return "recovery_begin";
    case RuntimeEvent::Kind::kRecoveryComplete:   return "recovery_complete";
    case RuntimeEvent::Kind::kPolicySwitch:       return "policy_switch";
    case RuntimeEvent::Kind::kChannelStateChange: return "channel_state_change";
    }
    return "unknown";
}

} // namespace

RunStateStore::RunStateStore(size_t max_events)
    : max_events_(max_events)
{}

// [v2 PR-K-A] Config-aware ctor (kcov-coverage-curve.md §5.2).
RunStateStore::RunStateStore(RunStateStoreConfig config)
    : max_events_(config.max_events)
    , coverage_series_capacity_(config.coverage_series_capacity == 0
                                    ? CoverageSeriesBuffer::kDefaultCapacity
                                    : config.coverage_series_capacity)
{}

void RunStateStore::EnableDebugEventLog(const std::string& path)
{
    std::lock_guard<std::mutex> lock(mu_);
    if (debug_event_log_.is_open()) debug_event_log_.close();
    debug_event_log_path_ = path;
    if (path.empty()) return;
    debug_event_log_.open(path, std::ios::out | std::ios::app);
    if (!debug_event_log_.is_open()) {
        refuzz::logging::HostLogger::Instance().Log(
            "RunStateStore", "debug_event_log_open_failed",
            {refuzz::logging::Field("path", path)});
        return;
    }
    debug_event_log_ << "# debugEvent.txt opened (append mode); full event stream, no detail truncation\n";
    debug_event_log_.flush();
    refuzz::logging::HostLogger::Instance().Log(
        "RunStateStore", "debug_event_log_opened",
        {refuzz::logging::Field("path", path)});
}

void RunStateStore::AppendDebugEventLocked_(const RuntimeEvent& event)
{
    if (!debug_event_log_.is_open()) return;
    // 和 run_state_renderer 的 event 行格式对齐，但 detail 不截断
    debug_event_log_ << "event ts_us=" << event.ts_us
                     << " kind=" << EventKindName(event.kind)
                     << " channel=" << event.channel_id
                     << " incident=" << event.incident_id;
    if (!event.subject.empty())    debug_event_log_ << " subject=" << event.subject;
    if (!event.from_state.empty()) debug_event_log_ << " from="    << event.from_state;
    if (!event.to_state.empty())   debug_event_log_ << " to="      << event.to_state;
    if (!event.detail.empty())     debug_event_log_ << " detail="  << event.detail;
    debug_event_log_ << '\n';
    debug_event_log_.flush();
}

void RunStateStore::UpdateSnapshot(RuntimeSnapshot snap)
{
    std::lock_guard<std::mutex> lock(mu_);
    snapshot_ = std::move(snap);
}

void RunStateStore::PushEvent(RuntimeEvent event)
{
    std::lock_guard<std::mutex> lock(mu_);
    AppendDebugEventLocked_(event);     // [diag] 先写文件（带完整 detail）
    events_.push_back(std::move(event));
    while (events_.size() > max_events_) {
        events_.pop_front();
    }
}

RuntimeSnapshot RunStateStore::LatestSnapshot() const
{
    std::lock_guard<std::mutex> lock(mu_);
    return snapshot_;
}

std::vector<RuntimeEvent> RunStateStore::RecentEvents(size_t max_count) const
{
    std::lock_guard<std::mutex> lock(mu_);
    const size_t count = std::min(max_count, events_.size());
    std::vector<RuntimeEvent> out;
    out.reserve(count);
    const size_t begin = events_.size() > count ? events_.size() - count : 0;
    for (size_t idx = begin; idx < events_.size(); ++idx) {
        out.push_back(events_[idx]);
    }
    return out;
}

// [v2 metric bus — 当前版本]
void RunStateStore::UpdateMetricSamples(
    std::vector<MetricRegistry::Sample> samples)
{
    std::lock_guard<std::mutex> lock(mu_);
    metric_samples_.clear();
    for (auto& s : samples) {
        SampleKey key{s.name, s.labels};
        metric_samples_.emplace(std::move(key), std::move(s));
    }
}

// [v2 metric bus — 当前版本]
RunStateStore::SampleMap RunStateStore::MetricSamples() const
{
    std::lock_guard<std::mutex> lock(mu_);
    return metric_samples_;
}

// [v2 run_summary redesign]
void RunStateStore::UpdateRunSummary(RunSummary summary)
{
    std::lock_guard<std::mutex> lock(mu_);
    run_summary_ = std::move(summary);
}

std::optional<RunSummary> RunStateStore::LatestRunSummary() const
{
    std::lock_guard<std::mutex> lock(mu_);
    return run_summary_;
}

// [v2 G5 follow-up] windowed exec/sec tracking — LibAFL `afl_exec_sec` 等价。
// tracker 自带 mutex,跟 store mu_ 独立,避免 dashboard render 嵌套锁。
void RunStateStore::ObserveExecRate(std::uint64_t ts_us, std::uint64_t terminal)
{
    exec_rate_tracker_.Observe(ts_us, terminal);
}

double RunStateStore::WindowedExecsPerSec() const
{
    return exec_rate_tracker_.SmoothedRate();
}

// [v2 PR-K-A] Coverage series methods (kcov-coverage-curve.md §3 D-1/D-2).
void RunStateStore::RegisterCoverageSeries(CoverageSeriesDescriptor descriptor)
{
    std::lock_guard<std::mutex> lock(mu_);
    auto [it, inserted] = coverage_series_.try_emplace(
        descriptor.id, coverage_series_capacity_);
    if (!inserted) {
        throw std::runtime_error(
            "RunStateStore::RegisterCoverageSeries: duplicate series id: " +
            descriptor.id.value);
    }
    series_descriptors_.push_back(std::move(descriptor));
}

void RunStateStore::RecordCoveragePoint(const CoverageSeriesId& id,
                                        CoverageSamplePoint point)
{
    std::lock_guard<std::mutex> lock(mu_);
    auto it = coverage_series_.find(id);
    if (it == coverage_series_.end()) {
        return;  // unknown id — projector should not reach this branch
    }
    it->second.Push(point);
}

std::vector<CoverageSeriesDescriptor> RunStateStore::RegisteredSeries() const
{
    std::lock_guard<std::mutex> lock(mu_);
    return series_descriptors_;
}

std::optional<CoverageSamplePoint>
RunStateStore::LatestSeriesPoint(const CoverageSeriesId& id) const
{
    std::lock_guard<std::mutex> lock(mu_);
    auto it = coverage_series_.find(id);
    if (it == coverage_series_.end()) {
        return std::nullopt;
    }
    const CoverageSamplePoint* p = it->second.Latest();
    if (p == nullptr) {
        return std::nullopt;
    }
    return *p;
}

std::vector<CoverageSamplePoint>
RunStateStore::SeriesSnapshot(const CoverageSeriesId& id, size_t max_n) const
{
    std::lock_guard<std::mutex> lock(mu_);
    auto it = coverage_series_.find(id);
    if (it == coverage_series_.end()) {
        return {};
    }
    return it->second.Snapshot(max_n);
}

} // namespace refuzz::telemetry

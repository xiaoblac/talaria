#include "refuzz/telemetry/observation/observability_projector.hpp"

#include "refuzz/core/channel_contract.hpp"
// [v2 metric bus — 当前版本]
#include "refuzz/core/metrics/metric_registry.hpp"
#include "refuzz/telemetry/policy/policy_engine.hpp"
#include "refuzz/telemetry/observation/run_state_store.hpp"
// [v2 run_summary redesign]
#include "refuzz/telemetry/observation/run_summary_computer.hpp"
#include "refuzz/telemetry/observation/coverage_metrics_sink.hpp"
#include "refuzz/telemetry/observation/fuzzer_stats_sink.hpp"

#include <chrono>
#include <iterator>
#include <string>
#include <utility>
#include <vector>

namespace refuzz::telemetry {
namespace cc = refuzz::core::channel_contract;
using refuzz::core::RuntimeEvent;
using refuzz::core::RuntimeSnapshot;

namespace {

uint64_t NowUs()
{
    const auto now = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(now).count());
}

// [v2 run_summary redesign] 合并 fuzzer./executor./channel./perf. samples。
std::vector<refuzz::core::metrics::MetricRegistry::Sample>
CollectAllPrefixes(const refuzz::core::metrics::MetricRegistry& registry)
{
    auto samples = registry.CollectPrefix("fuzzer.");
    auto exec_samples = registry.CollectPrefix("executor.");
    auto chan_samples = registry.CollectPrefix("channel.");
    auto perf_samples = registry.CollectPrefix("perf.");
    samples.insert(samples.end(),
                   std::make_move_iterator(exec_samples.begin()),
                   std::make_move_iterator(exec_samples.end()));
    samples.insert(samples.end(),
                   std::make_move_iterator(chan_samples.begin()),
                   std::make_move_iterator(chan_samples.end()));
    samples.insert(samples.end(),
                   std::make_move_iterator(perf_samples.begin()),
                   std::make_move_iterator(perf_samples.end()));
    return samples;
}

// [v2 PR-K-A] Linear lookup for a counter by name (no labels). Coverage
// counters are unlabeled today (fuzzer.cov.new_total / fuzzer.cov.unique).
// Returns 0 when missing — per §3 D-7 (Epic 5 PR-5-B has not yet
// published kcov_cmp counters; the slot fills with 0-valued points
// until then, which is the intended PR-K-D demonstration).
uint64_t SamplesCounterValue(
    const std::vector<refuzz::core::metrics::MetricRegistry::Sample>& samples,
    const std::string& name)
{
    if (name.empty()) {
        return 0;
    }
    for (const auto& s : samples) {
        if (s.name == name && s.labels.empty()) {
            return static_cast<uint64_t>(s.value);
        }
    }
    return 0;
}

} // namespace

ObservabilityProjector::ObservabilityProjector(
    RunStateStore& store,
    ChannelEventSubscription channel_event_sub,
    ObservabilityConfig config,
    PolicyEngine* policy_engine,
    refuzz::core::metrics::MetricRegistry* registry,
    std::chrono::steady_clock::time_point session_start_steady,
    std::chrono::system_clock::time_point session_start_wall,
    std::string logs_dir)
    : store_(store)
    , channel_event_sub_(std::move(channel_event_sub))
    , config_(std::move(config))
    , policy_engine_(policy_engine)
    , registry_(registry)
    , session_start_steady_(session_start_steady == std::chrono::steady_clock::time_point{}
                                ? std::chrono::steady_clock::now()
                                : session_start_steady)
    , session_start_wall_(session_start_wall == std::chrono::system_clock::time_point{}
                              ? std::chrono::system_clock::now()
                              : session_start_wall)
{
    // [v2 PR-K-A] Auto-register builtin coverage series. Per plan §3 D-1,
    // kcov_pc is "active in PR-K-A"; PR-K-D adds kcov_cmp here later.
    // Lives in ctor (telemetry/) so control/ stays clean of series refs
    // (§1.2 Corollary D #2 lint, lands in PR-K-D).
    RegisterBuiltinCoverageSeries();
    if ((config_.coverage_export_enabled || config_.edge_series_enabled) &&
        !logs_dir.empty()) {
        coverage_metrics_sink_ = std::make_unique<CoverageMetricsSink>(
            std::filesystem::path{logs_dir}, session_start_steady_,
            std::chrono::seconds{10});
    }
    if (!logs_dir.empty()) {
        stats_sink_ = std::make_unique<FuzzerStatsSink>(
            std::filesystem::path{logs_dir}, session_start_steady_);
    }
}

ObservabilityProjector::~ObservabilityProjector()
{
    Stop();
}

void ObservabilityProjector::Start()
{
    if (running_.exchange(true, std::memory_order_acq_rel)) {
        return;
    }
    thread_ = std::thread([this]() { ProjectLoop(); });
}

void ObservabilityProjector::Stop()
{
    if (!running_.exchange(false, std::memory_order_acq_rel)) {
        return;
    }
    wait_cv_.notify_one();
    if (thread_.joinable()) {
        thread_.join();
    }
    // [v2 run_summary redesign] 最后一次同步 tick(is_final=true),在调用线程跑,
    // 与 JsonSink::WriteFinal 无并发;保证 Store 里落的是 final summary。
    ComputeAndStoreSummary(/*is_final=*/true);
}

void ObservabilityProjector::EmitGapEvent(const char* subject, size_t dropped)
{
    store_.PushEvent(RuntimeEvent{
        .ts_us = NowUs(),
        .kind = RuntimeEvent::Kind::kChannelStateChange,
        .subject = subject,
        .detail = "dropped=" + std::to_string(dropped),
    });
}

void ObservabilityProjector::EmitObserveEvent(const cc::ChannelObserveEvent& event)
{
    const uint64_t ts_us = event.ts_us != 0 ? event.ts_us : NowUs();
    switch (event.kind) {
    case cc::ChannelObserveEventKind::kLifecycleChanged:
        store_.PushEvent(RuntimeEvent{
            .ts_us = ts_us,
            .kind = RuntimeEvent::Kind::kChannelStateChange,
            .channel_id = event.channel_id,
            .incident_id = event.event_id,
            .subject = "channel_lifecycle",
            .from_state = cc::ChannelLifecycleStateName(event.old_lifecycle_state),
            .to_state = cc::ChannelLifecycleStateName(event.new_lifecycle_state),
            .detail = "generation=" + std::to_string(event.generation),
        });
        break;
    case cc::ChannelObserveEventKind::kFaultDetected:
        store_.PushEvent(RuntimeEvent{
            .ts_us = ts_us,
            .kind = RuntimeEvent::Kind::kFault,
            .channel_id = event.channel_id,
            .incident_id = event.event_id,
            .subject = "channel_fault",
            .from_state = cc::FaultKindName(event.fault_kind),
            .to_state = cc::ChannelFaultReasonName(event.fault_reason),
            .detail = "generation=" + std::to_string(event.generation),
        });
        break;
    case cc::ChannelObserveEventKind::kRecoveryStarted:
        store_.PushEvent(RuntimeEvent{
            .ts_us = ts_us,
            .kind = RuntimeEvent::Kind::kRecoveryBegin,
            .channel_id = event.channel_id,
            .incident_id = event.event_id,
            .subject = "channel_recovery",
            .from_state = cc::ChannelFaultReasonName(event.fault_reason),
            .to_state = cc::RecoveryActionName(event.recovery_action),
            .detail = "generation=" + std::to_string(event.generation),
        });
        break;
    case cc::ChannelObserveEventKind::kRecoveryCompleted: {
        std::string detail = "reason=" + std::string(
            cc::ChannelFaultReasonName(event.fault_reason));
        if (!event.recovery_success && !event.error_message.empty()) {
            detail += " err=" + event.error_message;
        }
        store_.PushEvent(RuntimeEvent{
            .ts_us = ts_us,
            .kind = RuntimeEvent::Kind::kRecoveryComplete,
            .channel_id = event.channel_id,
            .incident_id = event.event_id,
            .subject = "channel_recovery",
            .from_state = cc::RecoveryActionName(event.recovery_action),
            .to_state = event.recovery_success ? "success" : "failed",
            .detail = std::move(detail),
        });
        break;
    }
    case cc::ChannelObserveEventKind::kGenerationReset:
        store_.PushEvent(RuntimeEvent{
            .ts_us = ts_us,
            .kind = RuntimeEvent::Kind::kChannelStateChange,
            .channel_id = event.channel_id,
            .incident_id = event.event_id,
            .subject = "channel_generation",
            .from_state = std::to_string(event.old_generation),
            .to_state = std::to_string(event.new_generation),
            .detail = "generation=" + std::to_string(event.generation),
        });
        break;
    }
}

// [v2 run_summary redesign + PR-K-A] same `samples` vector now drives
// both ComputeRunSummary (existing) and DeriveAndRecordCoveragePoints
// (new) before being moved into the store. Single CollectAllPrefixes
// call per tick; no extra registry traversal.
void ObservabilityProjector::ComputeAndStoreSummary(bool is_final)
{
    if (registry_ == nullptr) {
        return;
    }
    auto samples = CollectAllPrefixes(*registry_);
    const auto now_steady = std::chrono::steady_clock::now();
    auto summary = ComputeRunSummary(samples,
                                     session_start_steady_,
                                     now_steady,
                                     session_start_wall_,
                                     std::chrono::system_clock::now(),
                                     is_final,
                                     config_.enable_summary_invariants,
                                     config_.run_mode);

    // [v2 G5 follow-up] windowed exec/sec — push current terminal counter into
    // RateWindowTracker(LibAFL `afl_exec_sec` 等价)。terminal = completion +
    // abnormal(跟 run_summary "terminal" field 同公式;详 run_summary.cpp:212)。
    // tracker 自带 mutex,跟 store mu_ 独立,projector tick(5s)频率推一次足够。
    {
        std::uint64_t terminal_count = 0;
        for (const auto& s : samples) {
            if (s.name != "fuzzer.results") continue;
            for (const auto& kv : s.labels) {
                if (kv.first == "kind" &&
                    (kv.second == "completion" || kv.second == "abnormal")) {
                    terminal_count += static_cast<std::uint64_t>(s.value);
                    break;
                }
            }
        }
        const auto now_us = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                now_steady.time_since_epoch()).count());
        store_.ObserveExecRate(now_us, terminal_count);
    }

    // [v2 G5 follow-up] 把 windowed exec/sec 注入 summary.fields 末尾,让 JSON
    // consumer / phase5_metrics.log / dashboard 都能读到。schema-driven extractor
    // 拿不到 store ref,这里 projector 作为聚合点手动 push 一个 SummaryField
    // (跟 plan D3=A 一致 — 加 windowed,不改名 execs_per_sec)。
    summary.fields.emplace_back(
        "execs_per_sec_windowed",
        SummaryValue::Double(store_.WindowedExecsPerSec()));

    const std::uint64_t tick = coverage_tick_index_++;
    DeriveAndRecordCoveragePoints(samples, tick);
    // 覆盖 log 的 t 字段用墙钟本地时间(HH:MM:SS)。间隔判定在 sink 内仍走 steady_clock,
    // 这里只提供采样时刻的显示用墙钟。
    const auto now_wall = std::chrono::system_clock::now();
    if (is_final) {
        if (coverage_metrics_sink_) {
            coverage_metrics_sink_->FlushFinal(now_wall, tick, samples);
        }
        if (stats_sink_) {
            stats_sink_->FlushFinal(now_steady, now_wall, samples);
        }
    } else {
        if (coverage_metrics_sink_) {
            coverage_metrics_sink_->MaybeFlush(now_steady, now_wall, tick, samples);
        }
        if (stats_sink_) {
            stats_sink_->MaybeFlush(now_steady, now_wall, samples);
        }
    }
    store_.UpdateMetricSamples(std::move(samples));
    store_.UpdateRunSummary(std::move(summary));
}

// [v2 PR-K-A] Register binding + delegate to RunStateStore::RegisterCoverageSeries.
// Throws std::runtime_error if id duplicates an already-registered series
// (fail-closed per §3 D-7).
//
// Order matters for exception safety: the store call goes FIRST so that a
// duplicate-id throw leaves projector state (series_bindings_, last_total_)
// untouched. Otherwise a caller that catches the throw would leave stale
// projector entries that record duplicate points each subsequent tick.
void ObservabilityProjector::RegisterCoverageSeries(CoverageSeriesBinding binding)
{
    store_.RegisterCoverageSeries(binding.descriptor);   // throw point — copies descriptor
    last_total_[binding.descriptor.id] = 0;
    series_bindings_.push_back(std::move(binding));
}

// [v2 PR-K-A] Hardcoded builtin coverage series.
// [v2 PR-K-D] Extended with kcov_cmp empty-slot for Epic 5 PR-5-B.
//
// Registration order = render/sink order. kcov_pc first (active in
// PR-K-A), kcov_cmp second (counters absent until Epic 5 PR-5-B
// publishes fuzzer.cov.cmp.{new_total,unique}; until then the buffer
// fills with zero-valued points — intentional per plan §1 R-3, §3 D-7).
void ObservabilityProjector::RegisterBuiltinCoverageSeries()
{
    CoverageSeriesBinding kcov_pc;
    kcov_pc.descriptor.id           = CoverageSeriesId{"kcov_pc"};
    kcov_pc.descriptor.display_name = "KCOV PC";
    kcov_pc.descriptor.unit         = "pcs";
    kcov_pc.total_metric  = "fuzzer.cov.all_pc";
    kcov_pc.unique_metric = "fuzzer.cov.all_pc";
    RegisterCoverageSeries(std::move(kcov_pc));

    // [v2 PR-K-D — kcov_cmp empty slot, plan §6.3]
    CoverageSeriesBinding kcov_cmp;
    kcov_cmp.descriptor.id           = CoverageSeriesId{"kcov_cmp"};
    kcov_cmp.descriptor.display_name = "KCOV CMP";
    kcov_cmp.descriptor.unit         = "comparisons";
    kcov_cmp.total_metric  = "fuzzer.cov.cmp.new_total";
    kcov_cmp.unique_metric = "fuzzer.cov.cmp.unique";
    RegisterCoverageSeries(std::move(kcov_cmp));

    // Corpus-admitted raw-PC history for the terminal dashboard.
    CoverageSeriesBinding corpus_pc;
    corpus_pc.descriptor.id           = CoverageSeriesId{"corpus_pc"};
    corpus_pc.descriptor.display_name = "Corpus PC";
    corpus_pc.descriptor.unit         = "pcs";
    corpus_pc.total_metric  = "fuzzer.cov.corpus_pc";
    corpus_pc.unique_metric = "fuzzer.cov.corpus_pc";
    RegisterCoverageSeries(std::move(corpus_pc));

    // Corpus-edge history for the terminal dashboard. Disk output reads the
    // same Gauge directly through CoverageMetricsSink.
    if (config_.edge_series_enabled) {
        CoverageSeriesBinding corpus_edge;
        corpus_edge.descriptor.id           = CoverageSeriesId{"corpus_edge"};
        corpus_edge.descriptor.display_name = "Corpus Edge";
        corpus_edge.descriptor.unit         = "edges";
        corpus_edge.total_metric  = "fuzzer.cov.corpus_edge";
        corpus_edge.unique_metric = "fuzzer.cov.corpus_edge";
        RegisterCoverageSeries(std::move(corpus_edge));
    }
}

// [v2 PR-K-A] For each registered binding, look up total/unique counter
// values in `samples`, compute delta vs last tick, push a CoverageSamplePoint
// to the store. Missing metric → 0 (D-7).
void ObservabilityProjector::DeriveAndRecordCoveragePoints(
    const std::vector<refuzz::core::metrics::MetricRegistry::Sample>& samples,
    std::uint64_t tick)
{
    if (series_bindings_.empty()) {
        return;
    }
    const int64_t  now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    for (const auto& binding : series_bindings_) {
        const uint64_t total  = SamplesCounterValue(samples, binding.total_metric);
        const uint64_t unique = SamplesCounterValue(samples, binding.unique_metric);
        const uint64_t prev   = last_total_[binding.descriptor.id];
        const int64_t  delta  =
            static_cast<int64_t>(total) - static_cast<int64_t>(prev);
        last_total_[binding.descriptor.id] = total;

        CoverageSamplePoint point;
        point.tick_index   = tick;
        point.ts_steady_ns = now_ns;
        point.value_total  = total;
        point.value_delta  = delta;
        point.unique_total = unique;
        store_.RecordCoveragePoint(binding.descriptor.id, point);
    }
}

bool ObservabilityProjector::DrainInputs()
{
    bool changed = false;

    std::vector<cc::ChannelObserveEvent> observe_events;
    const auto event_stats = channel_event_sub_.Drain(observe_events);
    if (event_stats.dropped > 0) {
        EmitGapEvent("channel_event_gap", event_stats.dropped);
    }
    for (const auto& event : observe_events) {
        EmitObserveEvent(event);
        changed = true;
    }

    return changed;
}

void ObservabilityProjector::ProjectLoop()
{
    while (running_.load(std::memory_order_acquire)) {
        const bool events_changed = DrainInputs();

        RuntimeSnapshot snapshot;
        snapshot.ts_us = NowUs();
        if (policy_engine_ != nullptr) {
            // [v2 6b-1 — 当前版本] Evaluate() 无参,直接读 registry
            policy_engine_->Evaluate();
            snapshot.policy_phase = SystemPhaseName(policy_engine_->CurrentPhase());
            snapshot.policy_switch_count = policy_engine_->SwitchCount();
        }

        // [v2 run_summary redesign] samples 收集 + ComputeRunSummary 一次性完成,
        // UpdateMetricSamples 先于 UpdateRunSummary/UpdateSnapshot,保证读者顺序一致。
        ComputeAndStoreSummary(/*is_final=*/false);
        store_.UpdateSnapshot(std::move(snapshot));
        (void)events_changed;
        std::unique_lock<std::mutex> lock(wait_mu_);
        wait_cv_.wait_for(lock, config_.pull_interval, [this]() {
            return !running_.load(std::memory_order_acquire);
        });
    }
}

} // namespace refuzz::telemetry

// Copyright 2026 reFuzz project author -------youngkk.

#include "refuzz/orchestrator/orchestrator.hpp"
#include "refuzz/orchestrator/builtins.hpp"
#include "refuzz/orchestrator/profile_registry.hpp"
#include "refuzz/profile/builtin_profiles.hpp"

#include "refuzz/assembler/assemble_context.hpp"
#include "refuzz/assembler/assembled_bundle.hpp"
#include "refuzz/assembler/assembler.hpp"
#include "refuzz/config_parser/parse_config_from_json.hpp"
#include "refuzz/crash/pipeline/manager/crash_pipeline_manager.hpp"
#include "refuzz/crash/target_toolkit_catalog.hpp"
#include "refuzz/crash/repro/ops/linuxkernel/syz_ops/adapter/repro_channel.hpp"
#include "refuzz/crash/repro/ops/linuxkernel/syz_ops/channel_exec_ops.hpp"
#include "refuzz/crash/repro/ops/xiuos/xiuos_repro_exec_ops.hpp"
#include "refuzz/crash/repro/manager/repro_manager.hpp"
#include "refuzz/crash/repro/manager/repro_worker.hpp"
#include "refuzz/crash/repro/core/repro_queue.hpp"
#include "refuzz/crash/repro/repro_worker_service.hpp"
#include "refuzz/crash/components/symbolizer/addr2line_symbolizer.hpp"
#include "refuzz/crash/components/symbolizer/kernel_report_parser.hpp"  // ConsoleContainsRealCrash
#include "refuzz/crash/infra/diagnostic_store.hpp"
#include "refuzz/corpus/corpus_disk_io.hpp"
#include "refuzz/control/loop/pending_seed_map.hpp"  // [Step 6] PendingSeedMap(候选区)
#include "refuzz/program/seed_metadata.hpp"  // [Task A / F2] CorpusCoverageMetadata
#include "refuzz/corpus/corpus_store.hpp"
#include "refuzz/program/artifact_materializer.hpp"   // §3.10 follow-up — registry / MakeRegistryMaterializer
#include "refuzz/program/syz/target.hpp"               // syz::Target::linux_amd64() for ProgramTargetKey
#include "refuzz/program/syz/prog.hpp"                  // [machine-check] As<syz::Prog> for corpus filter
#include "refuzz/control/support/machine_check/machine_check.hpp"  // [C4.6 ③] machine-check phase
#include "refuzz/feedback/signal/hash_feedback_store.hpp"
#include "refuzz/resolver/builtin_catalog_bundle.hpp"
#include "refuzz/resolver/catalog_set.hpp"
#include "refuzz/resolver/resolved_plan.hpp"
#include "refuzz/resolver/resolver.hpp"
#include "refuzz/startup/launch_plan.hpp"

#include "channeldispatcher.hpp"
#include "refuzz/channel/channel.hpp"
#include "refuzz/channel/channel_impl.hpp"
#include "refuzz/channel/worker/mode.hpp"
#include "refuzz/control/fuzzer_loop.hpp"
#include "refuzz/control/request_stream_reader.hpp"  // [fixed request stream, Step 4]
#include "refuzz/core/broadcast_bus.hpp"
#include "refuzz/core/metrics/metric_lookup.hpp"
#include "refuzz/core/metrics/metric_registry.hpp"
#include "refuzz/core/service_registry.hpp"
#include "refuzz/core/watch_bus.hpp"
#include "refuzz/executor/channel_service.hpp"
#include "refuzz/executor/health_monitor_service.hpp"
#include "refuzz/logging/host_logger.hpp"
#include "refuzz/queue/event_queue.hpp"
#include "refuzz/queue/lifecycle_queue.hpp"
#include "refuzz/queue/task_queue.hpp"
#include "refuzz/telemetry/observation/observability_projector.hpp"
#include "refuzz/telemetry/observation/run_state_renderer.hpp"
#include "refuzz/telemetry/observation/run_state_store.hpp"
#include "refuzz/telemetry/observation/run_summary_json_sink.hpp"
#include "refuzz/telemetry/observation/terminal_dashboard.hpp"
#include "refuzz/telemetry/policy/policy_engine.hpp"
#include "refuzz/telemetry/telemetry_service.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace refuzz::orchestrator {
namespace {

// [v2 run_summary redesign] OrcCounterValue/OrcGaugeValue 已上提到
// core/metrics/metric_lookup.hpp,同款 helper(CounterValue/GaugeValue)
// 与 PolicyMonitor::Tick 共用。本 TU 直接 using 复用。
using refuzz::core::metrics::Labels;
using refuzz::core::metrics::MetricRegistry;
using refuzz::core::metrics::CounterValue;
using refuzz::core::metrics::GaugeValue;

bool CoverageModeEnabled(CoverageMode mode)
{
    return mode == CoverageMode::kKcov;
}

bool ShouldContinueByRunLimit(const OrchestratorConfig& cfg,
                              uint64_t generated_tasks,
                              uint64_t reexec_tasks,
                              std::chrono::steady_clock::time_point now,
                              std::chrono::steady_clock::time_point end_at)
{
    // [verdict/triage 重构] kTaskCount 预算改为 work-aware:generated + reexec 合计。
    // 否则纯 triage(corpus_verify reexec)期 generated_tasks 恒 0 → kTaskCount 永不
    // 触发 → triage 永不终止。triage 与 fuzz 交织后,任一来源的执行都计入预算,三种
    // 模式都保证终止(kRuntime 按墙钟,kTaskCount 按合计执行数,kBoth 取先到)。
    const uint64_t executed = generated_tasks + reexec_tasks;
    switch (cfg.run_limit_mode) {
    case RunLimitMode::kTaskCount:
        return executed < cfg.total_tasks;
    case RunLimitMode::kRuntime:
        return now < end_at;
    case RunLimitMode::kBoth:
    default:
        return now < end_at && executed < cfg.total_tasks;
    }
}

// [fixed request stream] Publish "quiesced, VM still alive" and block until an
// external driver releases teardown (or the backstop expires). Called from
// Stop() only, after the fuzzer thread has joined -- see the call site and
// ReplayConfig for why this cannot live outside the process.
//
// Failure to create the marker is NOT fatal: the run's own results are already
// complete at this point, so refusing to tear the VM down would trade a
// finished run for a hang. Log and proceed instead.
//
// `fully_drained` distinguishes the two ways the fuzzer thread can exit: the
// producer's on_fully_drained (every record emitted AND completed) versus the
// ordinary run-limit backstop. Both reach here, so the marker's CONTENT -- not its
// mere existence -- is what tells the driver whether the measurement covers the
// whole stream. Writing "incomplete" lets the driver reject a truncated run instead
// of silently reporting it as a full one.
void HoldForGuestProbeFetch(const ReplayConfig& replay, bool fully_drained)
{
    std::error_code ec;
    {
        std::ofstream marker(replay.drained_marker_path, std::ios::binary | std::ios::trunc);
        if (!marker) {
            refuzz::logging::HostLineBuilder("Orchestrator", "replay_hold_marker_failed")
                << replay.drained_marker_path << "; proceeding to teardown\n";
            return;
        }
        marker << (fully_drained ? "drained\n" : "incomplete\n");
    }
    if (!fully_drained) {
        refuzz::logging::HostLineBuilder("Orchestrator", "replay_drain_incomplete")
            << "fuzzer thread exited WITHOUT the producer signalling full drain -- "
               "run-limit backstop or lost completions; the replay does not cover "
               "the whole stream and its throughput/CPU numbers are truncated\n";
    }
    if (replay.release_path.empty()) {
        refuzz::logging::HostLineBuilder("Orchestrator", "replay_hold_no_release_path")
            << "drained marker published but no release_path configured; "
               "proceeding to teardown\n";
        return;
    }

    const auto began = std::chrono::steady_clock::now();
    refuzz::logging::HostLineBuilder("Orchestrator", "replay_hold_begin")
        << "quiesced; VM held for guest probe fetch, waiting on "
        << replay.release_path << " (timeout "
        << replay.hold_timeout_s << "s, 0=forever)\n";

    while (!std::filesystem::exists(replay.release_path, ec)) {
        if (replay.hold_timeout_s != 0) {
            const auto waited = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - began).count();
            if (waited >= static_cast<long long>(replay.hold_timeout_s)) {
                refuzz::logging::HostLineBuilder("Orchestrator", "replay_hold_timeout")
                    << "no release after " << replay.hold_timeout_s
                    << "s; proceeding to teardown (guest probe data may be lost)\n";
                return;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    const auto held_s = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - began).count();
    refuzz::logging::HostLineBuilder("Orchestrator", "replay_hold_released")
        << "released after " << held_s << "s; proceeding to teardown\n";
}

} // namespace

// Pimpl：持有所有子系统实例，生命周期由 Orchestrator 管理。
struct Orchestrator::Impl {
    // ── 装配层资源(最先声明 = 最后析构)──────────────────
    // 注:Orchestrator 的运行时组件(executor/loop/telemetry/crash_pipeline/
    //    repro_manager/repro_worker)持有 bundle 内成员的 raw pointer,必须
    //    在 bundle 之后析构 → 故 bundle/resolved/profile_registry/catalog_bundle
    //    放在 Impl 最前面,让它们最后析构。
    // 注 2:resolved.config 被 Build/Start/Stop 广泛 alias 使用(c = resolved.config),
    //       生命周期必须覆盖整个 Orchestrator。
    //
    // ProfileRegistry 存 move-only 的 ProfileDefaults,不可整库拷贝;nullptr
    // 分支用 owned_profile_registry,否则 active_profile_registry 指向调用方注入实例。
    std::unique_ptr<ProfileRegistry> owned_profile_registry;
    ProfileRegistry*               active_profile_registry = nullptr;

    resolver::BuiltinCatalogBundle catalog_bundle;
    resolver::ResolvedPlan         resolved;

    // v2 metric bus:声明必须先于所有缓存 Counter*/Gauge* 的组件
    // (executor / loop / channel / ...),保证 registry 析构顺序最靠后;否则
    // 组件析构期访问已释放的 Counter/Gauge 会触发 malloc 堆损坏。
    // 特别注意:bundle 内的 ChannelMetrics 缓存 Counter*/Gauge*,因此 metric_registry
    // 必须先于 bundle 声明(C++ 成员按声明反序析构)。
    refuzz::core::metrics::MetricRegistry                metric_registry;
    assembler::AssembledBundle       bundle;

    // ── 编排层(ServiceRegistry + buses)────────────────────
    refuzz::core::ServiceRegistry                                             registry;
    std::vector<std::string>                                                  channel_dep_name_storage;
    // [6b-3 — 当前版本] fuzzer/executor/channel_snapshot 三个 WatchBus/BroadcastBus
    // 已随 LoopStats/FuzzerRuntimeSnapshot/ExecutorSnapshot 删除;
    // projector 只剩 channel_event_bus 一个订阅源。
    refuzz::core::BroadcastBus<refuzz::core::channel_contract::ChannelObserveEvent> channel_event_bus{1024};

    std::unique_ptr<channeldispatcher::Executor>         executor;
    std::unique_ptr<queue::InMemoryTaskQueue>            task_queue;
    std::unique_ptr<queue::InMemoryEventQueue>           event_queue;
    // [request-window] pull/window 生命周期队列;Executor(submit 线程 Push)与 FuzzerLoop
    //   (控制线程 DrainAll → MarkAccepted)共用同一实例。生命周期同 task_queue/event_queue。
    std::unique_ptr<queue::InMemoryLifecycleQueue>       lifecycle_queue;

    std::unique_ptr<control::FuzzerLoop>                 loop;
    // [fixed request stream] validated in Build() before any VM/channel boot
    // when config.run_mode == RunMode::kReplay; empty otherwise. Owns the
    // stream for the FixedInputProducerJob, which only holds a non-owning
    // pointer to it.
    std::optional<refuzz::request_stream::RequestStream> replay_stream;

    std::unique_ptr<telemetry::RunStateStore>            state_store;
    std::unique_ptr<telemetry::PolicyEngine>             policy_engine;
    std::unique_ptr<telemetry::ObservabilityProjector>   projector;
    std::unique_ptr<telemetry::TerminalDashboard>        dashboard;

    std::unique_ptr<crash::DiagnosticStore>              diagnostic_store;
    std::unique_ptr<crash::IDiagnosticAttachmentProvider> diagnostic_provider;
    std::unique_ptr<crash::CrashPipelineManager>         crash_pipeline;

    // Repro manager 子系统(repro_channels 已在 bundle.repro_channels)
    std::unique_ptr<crash::Addr2lineSymbolizer>          symbolizer;
    std::unique_ptr<crash::ICrashAnalysisEngine>         analysis_engine;
    std::unique_ptr<crash::IReproEngine>                 repro_engine;
    std::unique_ptr<crash::InMemoryReproQueue>           repro_queue;
    std::unique_ptr<crash::ReproChannel>                 repro_channel_adapter;
    std::unique_ptr<crash::IExecAdapter>                 repro_exec_ops;
    std::unique_ptr<crash::ReproManager>                 repro_manager;
    std::unique_ptr<crash::ReproWorker>                  repro_worker;

    // 线程
    std::thread fuzzer_thread;
    std::thread status_thread;

    std::atomic<bool> stop_requested{false};
    // [fixed request stream] true only if the producer's on_fully_drained actually
    // fired, i.e. every emitted record's completion was observed. The fuzzer thread
    // ALSO exits on the ordinary run-limit backstop, which makes a truncated replay
    // indistinguishable from a complete one to any external driver -- so the drained
    // marker records which of the two happened instead of just existing.
    std::atomic<bool> replay_fully_drained{false};
    std::atomic<bool> initial_corpus_triaged{false};
    bool initial_candidate_phase_required = false;

    std::mutex status_mtx;

    // [harness-fatal 语义修正] 全局终止的唯一通道侧来源：main channel 真正进入
    // kFailed（recovery 策略在预算耗尽后裁决 kFailChannel）。历史实现用
    // FuzzerLoop::HarnessFatalLatched() 当退出条件，第一次任务级 error 14 就
    // 停掉整轮，即使 channel 的 restart_single_worker/reboot_vm 恢复仍可能成功。
    bool ChannelFailed() const
    {
        if (bundle.main_channel == nullptr) {
            return false;
        }
        return bundle.main_channel->ObserveSnapshot().lifecycle_state ==
               refuzz::core::channel_contract::ChannelLifecycleState::kFailed;
    }
    std::condition_variable status_cv;
    std::atomic<bool> status_stop{false};

    std::chrono::steady_clock::time_point started_at;
    // [v2 run_summary redesign] 与 started_at 同一时刻的 wall clock;JsonSink 产出 ISO 时间串用。
    std::chrono::system_clock::time_point started_at_wall;
    std::chrono::steady_clock::time_point end_at;
    bool dashboard_active = false;

    // [v2 run_summary redesign]
    std::unique_ptr<telemetry::RunSummaryJsonSink> run_summary_json_sink;
    telemetry::JsonWriteStatus final_summary_status =
        telemetry::JsonWriteStatus::kOk;

    void PublishInitialCorpusTriaged()
    {
        bool expected = false;
        if (!initial_corpus_triaged.compare_exchange_strong(
                expected, true, std::memory_order_acq_rel)) {
            return;
        }
        if (bundle.main_channel) {
            bundle.main_channel->PublishInitialCorpusTriaged();
        }
        for (auto& channel : bundle.additional_fuzz_channels) {
            if (channel) {
                channel->PublishInitialCorpusTriaged();
            }
        }
    }

    void MaybePublishInitialCorpusTriaged()
    {
        if (initial_corpus_triaged.load(std::memory_order_acquire)) {
            return;
        }
        if (!initial_candidate_phase_required || !bundle.pending_seed_map ||
            bundle.pending_seed_map->Size() == 0) {
            PublishInitialCorpusTriaged();
        }
    }

    // 关闭所有 channel(从 bundle 取)
    void CloseChannels()
    {
        if (bundle.main_channel) {
            bundle.main_channel->Close();
        }
        for (auto& ch : bundle.additional_fuzz_channels) {
            if (ch) {
                ch->Close();
            }
        }
        for (auto& ch : bundle.repro_channels) {
            if (ch) {
                ch->Close();
            }
        }
    }

    void LogShutdownState(const char* tag) const
    {
        // [6b-3 — 当前版本] ExecutorSnapshot 已删除,改读 MetricRegistry。
        const int64_t channels_total = GaugeValue(metric_registry, "executor.channels.total");
        const int64_t pending_tasks  = GaugeValue(metric_registry, "executor.dispatch.pending");
        const int64_t stop_req       = GaugeValue(metric_registry, "executor.stop_requested");
        const uint64_t events_fwd    = CounterValue(metric_registry, "executor.events_forwarded");
        const uint64_t tasks_sub     = CounterValue(metric_registry, "executor.tasks_submitted");
        refuzz::logging::HostLineBuilder("Orchestrator", "shutdown_state") << tag
                  << " pending=" << loop->PendingCount()
                  << " task_queue_depth=" << task_queue->PendingSize()
                  << " event_queue_depth=" << (event_queue ? event_queue->PendingSize() : 0)
                  << " channels=" << channels_total
                  << " pending_tasks=" << pending_tasks
                  << " stop_requested=" << stop_req
                  << " events_forwarded=" << events_fwd
                  << " tasks_submitted=" << tasks_sub
                  << "\n";
        // per-channel id 日志: 从 registry 扫 channel.* 样本集起所有 channel_id。
        {
            std::set<uint32_t> ids;
            const auto samples = metric_registry.CollectPrefix("channel.");
            for (const auto& s : samples) {
                for (const auto& [k, v] : s.labels) {
                    if (k == "channel_id") {
                        try { ids.insert(static_cast<uint32_t>(std::stoul(v))); } catch (...) {}
                        break;
                    }
                }
            }
            for (uint32_t cid : ids) {
                refuzz::logging::HostLineBuilder("Orchestrator", "shutdown_channel")
                    << "channel=" << cid << "\n";
            }
        }
        refuzz::logging::HostLineBuilder("Orchestrator", "runtime_panel") << telemetry::RenderRuntimePanel(
            *state_store, "ShutdownPanel", resolved.config.dashboard.max_events);
    }

    bool PipelineDrained() const
    {
        return loop->PendingCount() == 0
            && task_queue->PendingSize() == 0
            && (event_queue == nullptr || event_queue->PendingSize() == 0);
    }

    // Build() 重入时 unique_ptr 会先析构旧 Impl;须在此关闭 channel,避免
    // ~Channel 在 BroadcastBus 已销毁后仍 Publish。
    ~Impl() { CloseChannels(); }
};

Orchestrator::Orchestrator() = default;
Orchestrator::~Orchestrator() = default;

bool Orchestrator::Build(refuzz::startup::LaunchPlan plan,
                         std::optional<fuzzer::FeedbackEngineSpec> spec,
                         ProfileRegistry* profile_reg,
                         resolver::ResolveOptions resolve_opts)
{
    impl_ = std::make_unique<Impl>();

    if (profile_reg != nullptr) {
        impl_->active_profile_registry = profile_reg;
    } else {
        impl_->owned_profile_registry = std::make_unique<ProfileRegistry>();
        profile::RegisterBuiltinProfiles(*impl_->owned_profile_registry);
        impl_->active_profile_registry = impl_->owned_profile_registry.get();
    }

    impl_->catalog_bundle.RegisterBuiltins();

    refuzz::logging::HostLogger::Instance().Initialize(
        refuzz::logging::HostLoggerConfig{
            .enabled = plan.config.logging.enable,
            .stream_to_stdout = plan.config.logging.stream,
            .path = plan.config.logging.path,
            .flush_interval = plan.config.logging.flush_interval,
            .console_summary = plan.config.logging.console_summary,
            .hot_path_sample_rate = plan.config.logging.hot_path_sample_rate,
            .task_trace_sample_rate = plan.config.logging.task_trace_sample_rate,
        });

    if (spec.has_value()) {
        resolve_opts.ad_hoc_feedback_spec = std::move(spec);
    }
    auto resolved = resolver::Resolver::Resolve(
        std::move(plan),
        *impl_->active_profile_registry,
        impl_->catalog_bundle.View(),
        resolve_opts);
    if (!resolved) {
        refuzz::logging::HostLineBuilder("Orchestrator", "resolve_failed")
            << resolved.error().message << "\n";
        impl_.reset();
        return false;
    }
    impl_->resolved = std::move(*resolved);
    auto& c = impl_->resolved.config;

    refuzz::logging::HostLogger::Instance().Log(
        "Orchestrator", "build_begin",
        {refuzz::logging::Field("profile", impl_->resolved.profile),
         refuzz::logging::Field("session_root", c.layout.root),
         refuzz::logging::Field("host_log_path", c.logging.path)});
    refuzz::logging::HostLineBuilder("Config", "effective_summary")
        << DumpConfigSummary(c) << "\n";

    if (!std::filesystem::exists(c.worker_bin_host_path)) {
        refuzz::logging::HostLineBuilder("Orchestrator", "worker_binary_missing")
            << c.worker_bin_host_path << "\n";
        impl_.reset();
        return false;
    }

    // [fixed request stream] Validate + load the WHOLE stream now, before any
    // channel/VM boot below (Gate 4: "reader 完整校验 stream 后才启动
    // VM/measurement"). A bad stream fails Build() closed, exactly like the
    // worker-binary check above -- never surfaced as a fake program result.
    if (c.run_mode == RunMode::kReplay) {
        auto parsed = refuzz::request_stream::ReadFile(c.replay.stream_path);
        if (!parsed.has_value()) {
            refuzz::logging::HostLineBuilder("Orchestrator", "replay_stream_invalid")
                << c.replay.stream_path << ": " << parsed.error() << "\n";
            impl_.reset();
            return false;
        }
        impl_->replay_stream = std::move(*parsed);
        refuzz::logging::HostLineBuilder("Orchestrator", "replay_stream_loaded")
            << c.replay.stream_path << ": "
            << impl_->replay_stream->records.size() << " records\n";
    }


    // [Task2 syz-parity suppression] linux-kernel target：把"console 是否真崩"判定注入
    //   channel config。Channel::HandleFault 对 kKernelCrash 先过 crash 子系统的 suppression
    //   (benign deprecation/notice WARNING 如 mand-mount 不 reboot)。判定数据(suppression
    //   表)属 crash/(linux report parser);orchestrator 是唯一同时握有 crash 子系统 +
    //   channel config 的层。非 linux backend 不注入 → 谓词空 → 旧行为(kKernelCrash 全按真崩)。
    if (impl_->resolved.config.channel_common.backend_id == "qemu_ivshmem_linux") {
        impl_->resolved.config.channel_common.is_real_kernel_crash =
            [](const std::string& s) { return refuzz::crash::ConsoleContainsRealCrash(s); };
    }

    assembler::AssembleContext asm_ctx;
    asm_ctx.profile_registry = impl_->active_profile_registry;

    // [v2 metric bus — Step 5a] 传入 registry 供 Assembler 在 Bind 时使用
    asm_ctx.metric_registry  = &impl_->metric_registry;
    auto bundle = assembler::Assembler::Assemble(
        impl_->resolved, impl_->catalog_bundle.View(), asm_ctx);
    if (!bundle) {
        refuzz::logging::HostLineBuilder("Orchestrator", "assemble_failed")
            << bundle.error().message << "\n";
        impl_.reset();
        return false;
    }
    impl_->bundle = std::move(*bundle);

    impl_->executor = std::make_unique<channeldispatcher::Executor>(c.executor, &impl_->metric_registry);
    // [6b-3 — 当前版本] executor_snapshot_bus 已删除, 数据流走 MetricRegistry。

    auto* main_ch = impl_->bundle.main_channel.get();
    if (main_ch == nullptr) {
        refuzz::logging::HostLineBuilder("Orchestrator", "no_main_channel")
            << impl_->resolved.profile << "\n";
        impl_.reset();
        return false;
    }
    // [6b-3 — 当前版本] channel_snapshot_bus 订阅者已消失 → 传 nullptr;
    // Channel 仍通过 MetricRegistry 和 channel_event_bus 发布观测。
    main_ch->AttachObservabilityPublishers(
        nullptr, &impl_->channel_event_bus,
        &impl_->bundle.main_channel_metrics, &impl_->metric_registry);

    std::vector<refuzz::channel::IChannel*> fuzz_channels;
    fuzz_channels.reserve(1 + impl_->bundle.additional_fuzz_channels.size());
    fuzz_channels.push_back(main_ch);
    for (size_t i = 0; i < impl_->bundle.additional_fuzz_channels.size(); ++i) {
        auto& ch = impl_->bundle.additional_fuzz_channels[i];
        if (ch) {
            refuzz::core::metrics::ChannelMetrics* metrics =
                (i < impl_->bundle.additional_fuzz_channel_metrics.size())
                ? &impl_->bundle.additional_fuzz_channel_metrics[i]
                : nullptr;
            ch->AttachObservabilityPublishers(
                nullptr, &impl_->channel_event_bus,
                metrics, &impl_->metric_registry);
            fuzz_channels.push_back(ch.get());
        }
    }

    for (size_t i = 0; i < impl_->bundle.repro_channels.size(); ++i) {
        auto& ch = impl_->bundle.repro_channels[i];
        if (ch) {
            refuzz::core::metrics::ChannelMetrics* repro_metrics =
                (i < impl_->bundle.repro_channel_metrics.size())
                ? &impl_->bundle.repro_channel_metrics[i]
                : nullptr;
            ch->AttachObservabilityPublishers(
                nullptr, &impl_->channel_event_bus,
                repro_metrics, &impl_->metric_registry);
        }
    }
    for (auto* ch : fuzz_channels) {
        impl_->executor->AddChannel(ch);
    }

    impl_->task_queue = std::make_unique<queue::InMemoryTaskQueue>();
    impl_->event_queue = std::make_unique<queue::InMemoryEventQueue>();
    impl_->lifecycle_queue = std::make_unique<queue::InMemoryLifecycleQueue>();
    impl_->executor->SetLoopContext(
        impl_->task_queue.get(), impl_->event_queue.get(),
        c.pop_timeout, c.poll_timeout);
    // [request-window] Executor submit 线程经此发 accepted/rejected;FuzzerLoop 排干后
    //   MarkAccepted 释放 dispatch 窗口 credit(下方 loop 构造后再 SetLifecycleQueue 到同一实例)。
    impl_->executor->SetLifecycleQueue(impl_->lifecycle_queue.get());

    if (CoverageModeEnabled(c.target.coverage_mode)
        && c.coverage_persist_enable
        && c.coverage_load_on_start) {
        const size_t before = impl_->bundle.feedback_store->Count();
        if (!impl_->bundle.feedback_store->LoadFromFile(c.coverage_persist_path)) {
            refuzz::logging::HostLineBuilder("Orchestrator", "coverage_load_warn")
                << c.coverage_persist_path << "\n";
        } else {
            const size_t loaded = impl_->bundle.feedback_store->Count() - before;
            refuzz::logging::HostLineBuilder("Orchestrator", "coverage_loaded")
                << loaded << " coverage hashes\n";
        }
        // [v2 Epic 5 PR-5-B] cmp dedupe store resume — same load discipline,
        // separate path. Missing file is benign (first run with cmp engine).
        if (impl_->bundle.cmp_feedback_store) {
            const std::string cmp_path = c.coverage_persist_path + ".cmp";
            const size_t cmp_before = impl_->bundle.cmp_feedback_store->Count();
            if (!impl_->bundle.cmp_feedback_store->LoadFromFile(cmp_path)) {
                refuzz::logging::HostLineBuilder("Orchestrator", "coverage_cmp_load_warn")
                    << cmp_path << "\n";
            } else {
                const size_t cmp_loaded = impl_->bundle.cmp_feedback_store->Count() - cmp_before;
                refuzz::logging::HostLineBuilder("Orchestrator", "coverage_cmp_loaded")
                    << cmp_loaded << " cmp hashes\n";
            }
        }
    }

    auto& boot_scheduler = impl_->bundle.scheduler_manager->Handle().Get();



    // [v2 PR2 — Corpus Generation Adaptation 当前版本]
    // 不再硬编码 (kSyzProg, linux-amd64) + StrictTyped；改由 active profile 自报：
    //   profile.corpus_prep.build_decoder(c) → ArtifactMaterializerFn
    //   profile.corpus_prep.load_policy      → CorpusLoadPolicy
    // 缺失的 profile 字段（未注册 / 老 profile）取 LenientBytes 默认（兼容）。
    const ::refuzz::profile::ProfileDefaults* active_profile =
        impl_->active_profile_registry->Find(impl_->resolved.profile);
    if (active_profile == nullptr) {
        refuzz::logging::HostLineBuilder("Orchestrator", "active_profile_missing")
            << "profile not found in registry: " << impl_->resolved.profile << "\n";
        impl_->CloseChannels();
        impl_.reset();
        return false;
    }
    ::refuzz::program::ArtifactMaterializerFn corpus_materializer;
    if (active_profile->corpus_prep.build_decoder) {
        corpus_materializer = active_profile->corpus_prep.build_decoder(c);
    }
    const auto corpus_load_policy = active_profile->corpus_prep.load_policy;



    // [v2 PR2 — Corpus Generation Adaptation 当前版本]
    //   - decoder 与 load_policy 全部由 active_profile.corpus_prep 自报；
    //     orch 不再硬编码 syz materializer 或 StrictTyped。
    //   - bootstrap 块整段已删除（见下方）；空 corpus 由 ExploreJob 接管（genFuzz
    //     never-empty supply，control/src/job/explore_job.cpp）。
    size_t corpus_loaded = 0;
    if (c.corpus_persist_enable && c.corpus_load_on_start) {
        // [candidate-model gate] 只有 profile **真选了** candidate 模型(stage 链里
        // 有 corpus_verify/minimize,corpus_prep.boot_corpus_via_candidates=true)才
        // 把 boot corpus 物化成 candidate 放进 PendingSeedMap,经 verify→minimize→
        // admit 入 corpus(corpus 从 ~0 长起,与 syz 同构)。否则(无 verify 链的
        // profile,如 xiuos)**直接 admit 进 active corpus** —— 否则种子被塞进候选区
        // 却无任何 stage 取走 → 永不 admit → active corpus 恒 0 → producer 零产出。
        // 旧逻辑只判 stage_shared_state!=null(=staged profile),错误地假设
        // "staged ⇒ 有 verify";xiuos 是 staged 但无 verify,被它坑住。
        const bool via_candidates =
            active_profile->corpus_prep.boot_corpus_via_candidates &&
            impl_->bundle.pending_seed_map != nullptr;
        impl_->initial_candidate_phase_required = via_candidates;
        if (via_candidates) {
            auto candidates = fuzzer::CorpusDiskIO::LoadAllAsSeeds(
                c.corpus_persist_dir, *impl_->bundle.seed_id_alloc,
                corpus_materializer, corpus_load_policy);
            auto pending = impl_->bundle.pending_seed_map;
            for (auto& seed : candidates) {
                pending->Put(std::move(seed));
            }
            corpus_loaded = candidates.size();
            refuzz::logging::HostLineBuilder("Orchestrator", "corpus_loaded")
                << corpus_loaded
                << " corpus seeds -> pending candidates (verify->minimize->admit"
                   " before entering corpus)\n";
        } else {
            // [direct-admit] 无 candidate 模型 → boot corpus 直接入 active corpus,
            // mut_p 立即可变异(LoadAll 同时通知 scheduler)。
            corpus_loaded = fuzzer::CorpusDiskIO::LoadAll(
                *impl_->bundle.corpus_store, boot_scheduler,
                c.corpus_persist_dir, *impl_->bundle.seed_id_alloc,
                corpus_materializer, corpus_load_policy);
            refuzz::logging::HostLineBuilder("Orchestrator", "corpus_loaded")
                << corpus_loaded
                << " corpus seeds -> admitted directly into corpus"
                   " (no candidate model)\n";
        }
    }

    if (c.crash_repros_as_seeds) {
        const size_t repros = fuzzer::CorpusDiskIO::LoadCrashRepros(
            *impl_->bundle.corpus_store, boot_scheduler,
            c.layout.diagnostics_dir, *impl_->bundle.seed_id_alloc,
            corpus_materializer,
            corpus_load_policy);
        refuzz::logging::HostLineBuilder("Orchestrator", "repros_loaded")
            << repros << " crash repros as seeds\n";
    }

    const bool collect_pc_coverage =
        c.coverage_export_enabled || !c.coverage_export_corpus_pc_path.empty();
    const bool collect_edge_coverage =
        c.coverage_export_edge_series_enabled ||
        !c.coverage_export_corpus_signal_path.empty() ||
        !c.coverage_export_all_signal_path.empty();

    // [Task A / F2] Backfill the corpus-cover store from loaded seeds that
    // carry persisted CorpusCoverageMetadata, so corpus_pc reflects the FULL
    // current corpus (syz_corpus_cover semantics) across restarts — not only
    // seeds admitted in THIS process. Seeds with no cover metadata (e.g.
    // externally-sourced seed corpora never run through reFuzz triage)
    // contribute nothing until re-executed — a documented residual gap
    // (syzkaller re-triages corpus on load to derive their cover).
    if (collect_pc_coverage && impl_->bundle.corpus_pc_feedback_store &&
        impl_->bundle.corpus_store) {
        size_t backfilled = 0;
        impl_->bundle.corpus_store->ForEachSeed(
            [&](const refuzz::fuzzer::Seed& seed) {
                if (const auto* cc =
                        seed.metadata.Get<refuzz::fuzzer::CorpusCoverageMetadata>();
                    cc != nullptr && !cc->cover_hashes.empty()) {
                    impl_->bundle.corpus_pc_feedback_store->MergeCoverage(
                        cc->cover_hashes, 0);
                    ++backfilled;
                }
            });
        if (backfilled > 0) {
            refuzz::logging::HostLineBuilder("Orchestrator", "corpus_cover_backfilled")
                << backfilled << " seeds -> "
                << impl_->bundle.corpus_pc_feedback_store->Count()
                << " distinct PCs\n";
        }
    }
    // [coverage-compare export] same boot backfill for the corpus ADMISSION-signal
    // store (signal_cover_hashes) so it includes boot-loaded seeds. Only when its
    // export path is set (else the store is never dumped → skip the work).
    if (collect_edge_coverage && impl_->bundle.corpus_edge_feedback_store &&
        impl_->bundle.corpus_store) {
        impl_->bundle.corpus_store->ForEachSeed(
            [&](const refuzz::fuzzer::Seed& seed) {
                if (const auto* cc =
                        seed.metadata.Get<refuzz::fuzzer::CorpusCoverageMetadata>();
                    cc != nullptr && cc->signal_hashes_are_edges &&
                    !cc->signal_cover_hashes.empty()) {
                    impl_->bundle.corpus_edge_feedback_store->MergeCoverage(
                        cc->signal_cover_hashes, 0);
                }
            });
    }



    // [v2 PR2 — Corpus Generation Adaptation 当前版本]
    // bootstrap canonical seed 整段删除：
    //   - syzkaller 也无 bootstrap，corpus-independent generation 由 ExploreJob
    //     在 fuzz loop 稳态接管（control/src/job/explore_job.cpp）：空 corpus 时
    //     ArmEligibility.mutate=false 让 MAB 选不出 mutate 臂，加上 genFuzz
    //     never-empty supply 兜底，二者共同保证空 corpus 100% 强制 generate；
    //     非空时由 MAB 在 generate/mutate 间自适应选择（不是固定概率）；
    //   - target_toolkit 已删 build_seed_payload 字段；
    //   - corpus 启动后允许 0 seed 状态合法。
    if (impl_->bundle.corpus_store->Size() == 0) {
        refuzz::logging::HostLineBuilder("Orchestrator", "corpus_empty_start")
            << "starting with empty corpus; ExploreJob will produce "
            << "fresh programs from ChoiceTable\n";
    }

    // [coverage-ownership bound] 旧的 "corpus-capacity frozen" 守护已删除:固定容量
    // 冻结这一行为不复存在,语料大小由 SignalOwnershipIndex(覆盖所有权不变量)常驻
    // 维护,加载再大的 corpus 也不会拒收新发现。

    c.fuzzer.initial_seed_id = impl_->bundle.seed_id_alloc->Peek();
    if (c.corpus_persist_enable) {
        c.fuzzer.corpus_persist_dir = c.corpus_persist_dir;
    } else {
        c.fuzzer.corpus_persist_dir.clear();
    }
    // [choice-table feedback shadow] run logs dir → enables the per-target
    // syscall novelty persistence TSV (choice_table_persist.tsv). Same dir as
    // debugEvent.txt / run_summary.json.
    c.fuzzer.logs_dir = c.layout.logs_dir;
    // [v2 V1 fallback capability-gated — 当前版本] 把 active_profile 自报的
    // capability 拷贝到 FuzzerLoopConfig。kernel/syz profile 默认 false(严格
    // typed/artifact-first);raw/AFL 等 family profile 添加时显式 true。
    c.fuzzer.accept_bytes_only_fallback =
        active_profile->capabilities.accept_bytes_only_fallback;
    // [Step 1 catch-all 迁 loop] triage divert 闸:mut_c 退出 consumer_chain 后,catch-all
    // 由 FuzzerLoop 承接;profile 报 triage_enabled → loop catch-all 对 NewCov seed 走 divert
    // + push "triage" follow-up(kernel=true,XiUOS/无 triage 链=false)。
    c.fuzzer.catch_all_triage_enabled = active_profile->capabilities.triage_enabled;
    // [fixed request stream] plan §6.2: "禁止启动正常 ExploreJob/program
    // generator" + "禁止从 replay completion 派生新的 triage、smash、retry 或
    // mutation task" -- force both regardless of profile. catch_all_triage_enabled
    // gates ALL THREE completion-derived cascades (candidate retry, core-path
    // triage/deflake/minimize, and their smash/fault/hints followups), so this one
    // flag is sufficient; suppress_default_producer stops the ExploreJob supply.
    if (c.run_mode == RunMode::kReplay) {
        c.fuzzer.catch_all_triage_enabled = false;
        c.fuzzer.suppress_default_producer = true;
        // [request-stream capture] Capturing a replay would re-emit the stream it
        // was handed, minus whatever failed to decode -- a lossy copy that looks
        // like a fresh capture. The point of the sink is to record what reFuzz
        // GENERATES, which only a normal fuzz run does. Dropped loudly rather than
        // silently: a run configured for both was configured by mistake.
        if (!c.fuzzer.request_stream_capture_path.empty()) {
            refuzz::logging::HostLogger::Instance().Log(
                "Orchestrator", "request_stream_capture_ignored",
                {refuzz::logging::Field("reason", std::string("run_mode=replay")),
                 refuzz::logging::Field("path", c.fuzzer.request_stream_capture_path)});
            c.fuzzer.request_stream_capture_path.clear();
        }
    }
    // [Step 6 stage 清场] jobs-only 默认模式:ExploreJob 的 gen/mut/collide 三臂恒可用(无 flag
    //   判据)→ 不再从 bundle.producer_chain 派生 MAB 臂可用集(chain 已随 stage framework 物删)。
    if (!c.mutator_policy.empty()) {
        c.policy_engine.normal.mutation_policy = c.mutator_policy;
    }
    // [config-selected scheduling policy] 与 mutator_policy 同构:config 的
    // fuzzer.scheduling_policy → PolicyEngine normal profile。PolicyEngine 是 active
    // policy 的真正权威(运行时驱动 SwitchSchedulingPolicy);直接在 FuzzerLoop ctor
    // 切会被它覆盖成 normal 默认(round_robin)。空 = 保持 PolicyEngine 默认。
    if (!c.fuzzer.scheduling_policy.empty()) {
        c.policy_engine.normal.scheduling_policy = c.fuzzer.scheduling_policy;
    }
    // [v2 exectime split — 当前版本] started_at 提到 FuzzerLoop 构造之前 lock,
    //   并把 started_at 传进 FuzzerLoop ctor 作为 fuzz phase 偏移的锚。
    //   语义变化:elapsed_ms 现在多包含 PolicyEngine + Projector 等几微秒构造,可忽略;
    //   收益:FuzzerLoop 能算出"首次 produce 距 session_start 的偏移",
    //        用于 run_summary 派生 elapsed_fuzz_ms / exec_fuzz_s。
    impl_->started_at = std::chrono::steady_clock::now();
    impl_->started_at_wall = std::chrono::system_clock::now();

    // [Step 6 stage 清场] FuzzerLoop 已删除 producer/consumer chain + follow_up_dispatcher 参数
    //   (stage framework 物删,jobs-only loop 仅经 job_scheduler 表达运行时工作)。logger 走
    //   HostLogger::Instance()。末参 session_start = started_at。
    impl_->loop = std::make_unique<control::FuzzerLoop>(
        *impl_->task_queue, *impl_->event_queue,
        *impl_->bundle.corpus_store,
        impl_->bundle.mutator_manager->Handle(),
        impl_->bundle.scheduler_manager->Handle(),
        impl_->bundle.feedback_manager->Handle(),
        refuzz::logging::HostLogger::Instance(),
        c.fuzzer,
        &impl_->metric_registry,
        impl_->started_at);
    // [6b-3 — 当前版本] SetRuntimeSnapshotBus 已随 FuzzerRuntimeSnapshot 一起删除。
    // [request-window] 与 Executor 同一 lifecycle 队列:RunOnce 排干 → JobScheduler::MarkAccepted。
    impl_->loop->SetLifecycleQueue(impl_->lifecycle_queue.get());
    impl_->loop->SetFeedbackStore(impl_->bundle.feedback_store.get());
    // [v2 Epic 5 PR-5-B] cmp dedupe store — published to FuzzerLoop so the
    // periodic cov_cmp_unique gauge update has a source.
    impl_->loop->SetCmpFeedbackStore(impl_->bundle.cmp_feedback_store.get());
    if (collect_pc_coverage) {
        impl_->loop->SetAllPcFeedbackStore(
            impl_->bundle.all_pc_feedback_store.get());
        impl_->loop->SetCorpusPcFeedbackStore(
            impl_->bundle.corpus_pc_feedback_store.get());
    }
    if (collect_edge_coverage) {
        impl_->loop->SetAllEdgeFeedbackStore(
            impl_->bundle.all_edge_feedback_store.get());
        impl_->loop->SetCorpusEdgeFeedbackStore(
            impl_->bundle.corpus_edge_feedback_store.get());
    }
    // [mab — candidate drain] 候选区探针:从 bundle 的 PendingSeedMap(boot corpus 加载
    // 进的候选区,与 corpus_verify/triage 共用那份)注入。task-MAB 开启时,FuzzerLoop 在
    // 候选非空期间优先 drain(验证+admit 加载的 corpus),drain 完才进 steady-state ——
    // 让 MAB-on 对比和 syz 喂同一份 corpus(否则 MAB 只看 corpus.Size()=0 把它架空)。
    if (impl_->bundle.pending_seed_map) {
        auto pending = impl_->bundle.pending_seed_map;
        impl_->loop->SetMabCandidateProbe(
            [pending]() { return pending->Size(); });
        // [Step 1 catch-all 迁 loop] 同一份 PendingSeedMap 注入 loop 的 catch-all triage
        // trampoline(= 旧 mut_c 的 pending_,与 triage/minimize/corpus_verify 共用)。
        impl_->loop->SetCatchAllPending(pending);
    }
    // [fixed request stream] the ONE task source for this run (plan §6.2).
    // on_fully_drained reuses RequestStop() -- the same signal-safe atomic store a
    // SIGINT would trigger -- so shutdown after the last completion is identical
    // to a normal graceful stop (PipelineDrained() polling in Stop() trivially
    // sees "already drained" since on_fully_drained only fires once every emitted
    // request's completion has actually been observed).
    if (c.run_mode == RunMode::kReplay) {
        impl_->loop->SpawnFixedInputProducerJob(*impl_->replay_stream, [this]() {
            impl_->replay_fully_drained.store(true, std::memory_order_release);
            RequestStop();
        });
    }
    // [v2 SubT-A] framework primitive — signal stability oracle。bundle 长寿命 →
    // raw ptr 在 fuzzer_loop 生命周期稳定。triage_stage 通过 deps.stability_oracle 调用。
    impl_->loop->SetStabilityOracle(impl_->bundle.stability_oracle.get());
    // [v2 SubT-B] 同上 pattern,IRetryPolicy。本批次仅搭骨架,批次 3 G6 才 read。
    impl_->loop->SetRetryPolicy(impl_->bundle.retry_policy.get());
    // [v2 batch 3 PR-Y] 同上 pattern,IPriorityCalculator。当前 stage 无 caller,
    // KcovCoverageSignal 经 SignalTraits::BuildContext 直接拿;字段保 7 步 canon。
    impl_->loop->SetPriorityCalculator(impl_->bundle.priority_calculator.get());
    // [v2 batch 3 G5] 同上 pattern,ISaturationFilter。
    impl_->loop->SetSaturationFilter(impl_->bundle.saturation_filter.get());

    impl_->state_store = std::make_unique<telemetry::RunStateStore>();
    // [diag] 把 recent_events 全量 + 不截断 detail 持久化到 <logs>/debugEvent.txt
    if (!c.layout.logs_dir.empty()) {
        impl_->state_store->EnableDebugEventLog(c.layout.logs_dir + "/debugEvent.txt");
    }
    // [v2 6b-1 — 当前版本] pass metric_registry as third parameter
    impl_->policy_engine = std::make_unique<telemetry::PolicyEngine>(
        *impl_->loop, impl_->state_store.get(),
        impl_->metric_registry, c.policy_engine);


    auto obs_cfg = c.observability;
    obs_cfg.coverage_export_enabled = c.coverage_export_enabled;
    obs_cfg.edge_series_enabled = c.coverage_export_edge_series_enabled;
    // [fixed request stream] telemetry 层有自己的 SummaryRunMode(不 include
    // orchestrator 头文件),这里做一次显式映射。run_summary 的 invariant 组装按它
    // 分流:replay 下 ExploreJob 不启动,generated 结构性为 0,拿 fuzzing 那套判
    // progress 会把一次 100% 成功的 replay 判成失败。
    obs_cfg.run_mode = (c.run_mode == RunMode::kReplay)
        ? telemetry::SummaryRunMode::kReplay
        : telemetry::SummaryRunMode::kFuzzing;
    impl_->projector = std::make_unique<telemetry::ObservabilityProjector>(
        *impl_->state_store,
        impl_->channel_event_bus.Subscribe(),
        obs_cfg,
        impl_->policy_engine.get(),
        &impl_->metric_registry,
        impl_->started_at,
        impl_->started_at_wall,
        // Destination for the opt-in coverage metric logs.
        c.layout.logs_dir);
    // [v2 run_summary redesign] JsonSink 不持有 registry,只读 Store;必须在 Projector 之后构造。
    impl_->run_summary_json_sink = std::make_unique<telemetry::RunSummaryJsonSink>(
        telemetry::RunSummaryJsonSinkConfig{c.layout.logs_dir},
        *impl_->state_store);
    impl_->dashboard = std::make_unique<telemetry::TerminalDashboard>(
        *impl_->state_store, c.dashboard);

    impl_->diagnostic_store = std::make_unique<crash::DiagnosticStore>(
        c.layout.diagnostics_dir);
    if (impl_->bundle.target_toolkit->create_diagnostic_provider) {
        impl_->diagnostic_provider =
            impl_->bundle.target_toolkit->create_diagnostic_provider(main_ch);
    }

    crash::Addr2lineSymbolizer* symbolizer_ptr = nullptr;
    if (!c.repro.vmlinux_path.empty()) {
        refuzz::logging::HostLineBuilder("Orchestrator", "repro_symbolizer_create")
            << c.repro.vmlinux_path << "\n";
        crash::Addr2lineConfig sym_cfg;
        sym_cfg.vmlinux_path     = c.repro.vmlinux_path;
        sym_cfg.addr2line_binary = c.repro.addr2line_binary;
        impl_->symbolizer = std::make_unique<crash::Addr2lineSymbolizer>(sym_cfg);
        symbolizer_ptr = impl_->symbolizer.get();
        refuzz::logging::HostLineBuilder("Orchestrator", "repro_symbolizer_created")
            << "Addr2lineSymbolizer created\n";
    }

    crash::TargetToolkitBuildArgs toolkit_args;
    switch (c.target.sanitizer_mode) {
    case SanitizerMode::kKasan:
        toolkit_args.sanitizer_mode = channel::worker::WorkerSanitizerMode::kKasan;
        break;
    case SanitizerMode::kKcsan:
        toolkit_args.sanitizer_mode = channel::worker::WorkerSanitizerMode::kKcsan;
        break;
    case SanitizerMode::kUbsan:
        toolkit_args.sanitizer_mode = channel::worker::WorkerSanitizerMode::kUbsan;
        break;
    case SanitizerMode::kNone:
    default:
        toolkit_args.sanitizer_mode = channel::worker::WorkerSanitizerMode::kNone;
        break;
    }
    if (impl_->bundle.target_toolkit->create_analysis_engine) {
        impl_->analysis_engine = impl_->bundle.target_toolkit->create_analysis_engine(
            toolkit_args, symbolizer_ptr);
    }

    crash::IReproQueue* repro_queue_ptr = nullptr;
    if (c.repro.enable) {
        impl_->repro_queue = std::make_unique<crash::InMemoryReproQueue>(
            c.repro.repro_queue_capacity);
        repro_queue_ptr = impl_->repro_queue.get();
        refuzz::logging::HostLineBuilder("Orchestrator", "repro_queue_created")
            << c.repro.repro_queue_capacity << "\n";
    }

    impl_->crash_pipeline = std::make_unique<crash::CrashPipelineManager>(
        impl_->analysis_engine.get(),
        impl_->diagnostic_store.get(),
        repro_queue_ptr);
    // Crash-pipeline triage policy (config-driven). XiUOS sets "actionable" so
    // wedge/worker-dead incidents (not only kKernelCrash) are enqueued for repro;
    // empty keeps the manager default ("all_unique").
    if (!c.repro.triage_policy.empty()) {
        impl_->crash_pipeline->SwitchTriagePolicyByName(c.repro.triage_policy);
    }
    impl_->loop->SetCrashPipeline(impl_->crash_pipeline.get());

    refuzz::channel::IChannel* active_repro_ch = nullptr;
    if (c.repro.enable && c.repro.dedicated_vm_count > 0
        && !impl_->bundle.repro_channels.empty()) {
        active_repro_ch = impl_->bundle.repro_channels.front().get();
        refuzz::logging::HostLineBuilder("Orchestrator", "repro_channel_configured")
            << "repro channel will boot with channel group\n";
        if (impl_->bundle.target_toolkit->create_repro_engine) {
            impl_->repro_engine = impl_->bundle.target_toolkit->create_repro_engine(
                toolkit_args, symbolizer_ptr);
        }
        impl_->repro_channel_adapter = std::make_unique<crash::ReproChannel>(
            active_repro_ch, c.repro.execute_timeout);
        // Exec adapter: targets whose findings wedge/kill the worker (the engine
        // declares RequiresHardRebootBetweenRuns) get the self-healing XiUOS
        // adapter, which reboots the dedicated repro VM before any candidate that
        // follows a poisoning run — otherwise a forever-wedge would make every
        // later minimize candidate time out and the program would over-collapse.
        if (impl_->repro_engine &&
            impl_->repro_engine->RequiresHardRebootBetweenRuns()) {
            impl_->repro_exec_ops = std::make_unique<crash::XiuosReproExecOps>(
                *impl_->repro_channel_adapter, *active_repro_ch);
        } else {
            impl_->repro_exec_ops = std::make_unique<crash::ChannelExecOps>(
                *impl_->repro_channel_adapter);
        }
        impl_->repro_manager = std::make_unique<crash::ReproManager>(
            impl_->repro_engine.get(), *impl_->repro_exec_ops);
        // [async-crash-reproduction Phase 3] Enable the C reproducer stage so a
        // reproduced crash emits repro.c (the upstream deliverable). Source-only
        // (try_compile stays off — no in-orchestrator toolchain assumption); the
        // typed minimized artifact needed for csource is now available for history/
        // bisect/concat extracts too (Phase 1/1.5).
        crash::ReproConfig rc = c.repro;
        rc.produce_c_reproducer = true;
        impl_->repro_manager->SetReproConfig(rc);
        // Reliability policy (config-driven). XiUOS defaults to "fast_triage" since
        // its crashes reproduce in extract but are restart-bound; empty keeps "full".
        if (!c.repro.policy.empty()) {
            impl_->repro_manager->SwitchPolicyByName(c.repro.policy);
        }
        impl_->repro_worker = std::make_unique<crash::ReproWorker>(
            *impl_->repro_queue, *impl_->repro_manager,
            c.repros_persist_dir);
        refuzz::logging::HostLogger::Instance().Log(
            "Orchestrator", "repro_initialized",
            {refuzz::logging::Field("channels", impl_->bundle.repro_channels.size())});
        if (c.logging.console_summary) {
            refuzz::logging::HostLineBuilder("Orchestrator", "repro_initialized_summary")
                << impl_->bundle.repro_channels.size() << " dedicated channel(s)\n";
        }
    }

    if (!c.mutator_policy.empty()) {
        impl_->loop->SwitchMutationPolicy(c.mutator_policy);
        refuzz::logging::HostLogger::Instance().Log(
            "Orchestrator", "mutator_policy",
            {refuzz::logging::Field("policy", c.mutator_policy)});
        if (c.logging.console_summary) {
            refuzz::logging::HostLineBuilder("Orchestrator", "mutator_policy_summary")
                << c.mutator_policy << "\n";
        }
    }

    impl_->channel_dep_name_storage.clear();
    const size_t required_channel_service_count = fuzz_channels.size();
    impl_->channel_dep_name_storage.reserve(required_channel_service_count);
    for (size_t i = 0; i < fuzz_channels.size(); ++i) {
        impl_->channel_dep_name_storage.push_back(
            "channel_" + std::to_string(i));
    }

    std::vector<std::string_view> exec_dep_views;
    exec_dep_views.reserve(impl_->channel_dep_name_storage.size());
    for (const auto& name : impl_->channel_dep_name_storage) {
        exec_dep_views.push_back(name);
    }

    std::vector<std::unique_ptr<refuzz::executor::ChannelService>> required_channel_svcs;
    required_channel_svcs.reserve(required_channel_service_count);
    for (size_t i = 0; i < fuzz_channels.size(); ++i) {
        required_channel_svcs.push_back(std::make_unique<refuzz::executor::ChannelService>(
            impl_->channel_dep_name_storage[i], fuzz_channels[i]));
    }
    std::vector<std::unique_ptr<refuzz::executor::ChannelService>> optional_channel_svcs;
    if (active_repro_ch != nullptr) {
        optional_channel_svcs.push_back(std::make_unique<refuzz::executor::ChannelService>(
            "repro_channel_0", active_repro_ch));
    }

    std::unique_ptr<refuzz::executor::HealthMonitorService> health_svc;
    if (auto* concrete = dynamic_cast<refuzz::channel::Channel*>(main_ch)) {
        health_svc = std::make_unique<refuzz::executor::HealthMonitorService>(concrete);
    }

    auto tele_svc = std::make_unique<refuzz::telemetry::TelemetryService>(
        impl_->projector.get(), impl_->dashboard.get());

    std::unique_ptr<refuzz::crash::ReproWorkerService> repro_svc;
    if (impl_->repro_worker) {
        auto repro_channel_can_start = [active_repro_ch]() {
            if (active_repro_ch == nullptr) {
                return false;
            }
            const auto snapshot = active_repro_ch->ObserveSnapshot();
            return snapshot.lifecycle_state
                       == refuzz::core::channel_contract::ChannelLifecycleState::kRunning
                   || snapshot.lifecycle_state
                       == refuzz::core::channel_contract::ChannelLifecycleState::kRecovering;
        };
        repro_svc = std::make_unique<refuzz::crash::ReproWorkerService>(
            impl_->repro_worker.get(), std::move(repro_channel_can_start));
    }

    refuzz::orchestrator::RegisterBuiltinServices(
        impl_->registry,
        required_channel_svcs,
        optional_channel_svcs,
        *impl_->executor,
        exec_dep_views,
        std::move(health_svc),
        std::move(repro_svc),
        std::move(tele_svc));

    if (!impl_->registry.TopologicalOrder().has_value()) {
        refuzz::logging::HostLineBuilder("Orchestrator", "service_registry_cycle")
            << "circular dependency\n";
        impl_->CloseChannels();
        impl_.reset();
        return false;
    }

    if (auto init_r = impl_->registry.InitAll(); !init_r) {
        refuzz::logging::HostLineBuilder("Orchestrator", "service_init_failed")
            << init_r.error().message << "\n";
        impl_->CloseChannels();
        impl_.reset();
        return false;
    }

    return true;
}

bool Orchestrator::Start()
{
    if (!impl_) {
        refuzz::logging::HostLineBuilder("Orchestrator", "start_before_build") << "Orchestrator::Start() called before Build()\n";
        return false;
    }
    auto& c = impl_->resolved.config;

    // [v2 run_summary redesign] started_at 已在 Build() 锁定,Run() 只算 end_at。
    impl_->end_at = impl_->started_at + c.runtime;

    if (auto start_r = impl_->registry.StartAll(); !start_r) {
        refuzz::logging::HostLineBuilder("Orchestrator", "service_start_failed")
            << start_r.error().message << "\n";
        impl_->CloseChannels();
        return false;
    }

    // [machine-check C4.6 ③] Host-driven machine-check phase. The channel is
    // booted + workers ready (StartAll) and the Executor forwards completions,
    // but the fuzz loop has NOT started (its thread is launched below), so this
    // thread exclusively owns the data plane: probe the candidate syscalls,
    // resolve the supported enabled set, and apply it to the mutator before any
    // generation. Linux kernel-syscall targets only; best-effort (a failure logs
    // and leaves the startup/static enabled set in place rather than aborting).
    if (c.target.execution_mode == ::refuzz::orchestrator::ExecutionMode::kKernelSyscall &&
        impl_->bundle.main_channel && impl_->task_queue && impl_->event_queue &&
        impl_->bundle.mutator_manager) {
        namespace mc = ::refuzz::control::support::machine_check;
        namespace cs = ::refuzz::control::support;
        const auto& tgt = ::refuzz::program::syz::Target::linux_amd64();

        // Env facts: worker-0 publishes EnvFeatures BEFORE signalling ready, so by
        // now (post-StartAll) a SINGLE read is guaranteed to observe it (the
        // publish release happens-before the ready signal the host acquired). No
        // poll / timeout. A miss (non-ivshmem transport) → static (sandbox-only)
        // env; the trial-exec still runs, only the probed narrowing is skipped.
        cs::SupportEnv env;
        env.sandbox_is_none =
            c.target.sandbox_mode == ::refuzz::orchestrator::SandboxMode::kNone;
        bool probed = false;
        {
            ::EnvFeatures ef;
            if (impl_->bundle.main_channel->ReadGuestEnvFeatures(&ef)) {
                env    = mc::EnvFeaturesToSupportEnv(ef, env.sandbox_is_none);
                probed = true;
            }
        }

        mc::MachineCheckConfig mc_cfg;
        mc_cfg.enable  = c.target.enable_syscalls;
        mc_cfg.disable = c.target.disable_syscalls;
        mc_cfg.env     = std::move(env);

        const mc::MachineCheckResult res =
            mc::RunMachineCheck(tgt, mc_cfg, *impl_->task_queue, *impl_->event_queue);

        if (res.enabled.ok && !res.enabled.mask.empty()) {
            impl_->bundle.mutator_manager->SetEnabledCalls(res.enabled.mask);

            // [machine-check] Filter the boot corpus by the PROBED enabled set.
            // Decode already succeeded in Build() (all candidates loaded into
            // PendingSeedMap with the base materializer); this is the SEPARATE
            // allow-list filter — drop candidates that use a non-enabled syscall,
            // before the fuzz loop consumes the pending map (mirrors syz dropping
            // disabled-call corpus). Decode ≠ filter.
            if (impl_->bundle.pending_seed_map != nullptr) {
                auto pending = impl_->bundle.pending_seed_map;
                const std::vector<std::uint8_t>& mask = res.enabled.mask;
                std::vector<std::uint64_t> drop_ids;
                pending->ForEach([&](const refuzz::fuzzer::Seed& s) {
                    if (!s.artifact) return;  // no typed view → can't inspect → keep
                    auto prog = s.artifact->As<::refuzz::program::syz::Prog>();
                    if (prog == nullptr) return;
                    for (const auto& call : prog->calls()) {
                        const auto* m = call->meta();
                        if (m == nullptr) continue;
                        const std::uint64_t id = m->id();
                        if (id >= mask.size() || mask[id] == 0) {
                            drop_ids.push_back(s.seed_id);  // uses a disabled call
                            return;
                        }
                    }
                });
                for (const std::uint64_t id : drop_ids) pending->Erase(id);
                if (!drop_ids.empty()) {
                    refuzz::logging::HostLineBuilder("Orchestrator", "corpus_filtered")
                        << "boot corpus: filtered " << drop_ids.size()
                        << " candidate(s) using non-enabled syscalls; "
                        << pending->Size() << " remain\n";
                }
            }

            std::size_t enabled_count = 0;
            for (const std::uint8_t v : res.enabled.mask) {
                if (v) ++enabled_count;
            }
            // ONE structured summary record (the per-syscall detail goes to a
            // clean report FILE, not the event log — a syscall list with a
            // seq/wall/mono/tid prefix per line is unreadable noise).
            std::ostringstream summary;
            summary << "machine check: env=" << (probed ? "probed" : "static")
                    << " enabled=" << enabled_count << "/" << res.enabled.mask.size()
                    << " probed_calls=" << res.probe_calls
                    << " executed=" << res.probe_executed
                    << " enosys=" << res.probe_enosys
                    << " programs=" << res.programs_returned << "/" << res.probe_programs
                    << " disabled=" << res.disabled.size()
                    << " not_executed=" << res.probe_not_executed.size();
            refuzz::logging::HostLineBuilder("Orchestrator", "machine_check")
                << summary.str();

            // [machine-check] Clean categorized report → <logdir>/
            // machine_check_report.txt, syz printMachineCheck style: a header per
            // category, one syscall per line, sorted by name, NO structured
            // prefix. Two disabled sections split by reason shape (a transitive
            // reason is "<resource> [ctor ...]", carries '['; a direct reason —
            // ENOSYS / socket: … / failed to open … / <lsm> is not enabled — never
            // does) + the not-executed list (no errno evidence ⇒ kept). Overwritten
            // each run; best-effort.
            try {
                if (!c.logging.path.empty()) {
                    const std::filesystem::path report =
                        std::filesystem::path(c.logging.path).parent_path() /
                        "machine_check_report.txt";
                    std::vector<std::string> direct;
                    std::vector<std::string> transitive;
                    for (const auto& d : res.disabled) {
                        std::string line =
                            d.call != nullptr ? d.call->name() : std::string("?");
                        if (line.size() < 44) line.append(44 - line.size(), ' ');
                        line += ": ";
                        line += d.reason;
                        (d.reason.find('[') == std::string::npos ? direct : transitive)
                            .push_back(std::move(line));
                    }
                    std::sort(direct.begin(), direct.end());
                    std::sort(transitive.begin(), transitive.end());
                    std::ofstream out(report, std::ios::trunc);
                    out << summary.str() << "\n\n";
                    out << "disabled the following syscalls: (" << direct.size()
                        << ")\n";
                    for (const auto& l : direct) out << "  " << l << "\n";
                    out << "\ntransitively disabled the following syscalls "
                           "(missing resource [creating syscalls]): ("
                        << transitive.size() << ")\n";
                    for (const auto& l : transitive) out << "  " << l << "\n";
                    out << "\nnot executed (no errno evidence; kept): ("
                        << res.probe_not_executed.size() << ")\n";
                    for (const auto& n : res.probe_not_executed) out << "  " << n << "\n";
                    refuzz::logging::HostLineBuilder("Orchestrator",
                                                     "machine_check_report")
                        << "machine-check report: " << report.string();
                }
            } catch (...) {
                // report is best-effort diagnostics; never fail the run over it.
            }
        } else {
            refuzz::logging::HostLineBuilder("Orchestrator", "machine_check_skipped")
                << "machine check produced empty/!ok enabled set ('"
                << res.enabled.error << "'); keeping startup enabled set\n";
        }
    }

    impl_->MaybePublishInitialCorpusTriaged();

    impl_->dashboard_active = impl_->dashboard->Active();
    if (!impl_->dashboard_active && c.dashboard.enable) {
        refuzz::logging::HostLogger::Instance().Log(
            "Orchestrator",
            "dashboard_fallback",
            {refuzz::logging::Field("reason", "interactive_terminal_unavailable")});
        if (c.logging.console_summary) {
            refuzz::logging::HostLineBuilder("Orchestrator", "dashboard_fallback_summary") << "interactive terminal unavailable; using periodic log panel\n";
        }
    }

    impl_->fuzzer_thread = std::thread([this]() {
        auto& d = *impl_;
        while (!d.stop_requested.load(std::memory_order_acquire)
            && !d.executor->StopRequested()
            && !d.ChannelFailed()) {
            const auto now = std::chrono::steady_clock::now();
            const auto generated_tasks = CounterValue(d.metric_registry, "fuzzer.generated_tasks");
            // [triage 重构] reexec(corpus_verify/triage/smash/fault)也计入 work-aware 预算。
            const auto reexec_tasks    = CounterValue(d.metric_registry, "fuzzer.reexec_tasks");
            if (!ShouldContinueByRunLimit(d.resolved.config, generated_tasks, reexec_tasks, now, d.end_at)) {
                break;
            }
            d.loop->RunOnce(d.resolved.config.pop_timeout);
            d.MaybePublishInitialCorpusTriaged();
        }
    });

    if (!impl_->dashboard_active) {
        impl_->status_thread = std::thread([this]() {
            auto& d = *impl_;
            std::unique_lock<std::mutex> lk(d.status_mtx);
            while (!d.status_stop.load(std::memory_order_acquire)) {
                const bool stopping = d.status_cv.wait_for(lk, std::chrono::seconds(5), [&]() {
                    return d.status_stop.load(std::memory_order_acquire);
                });
                if (stopping) {
                    break;
                }
                refuzz::logging::HostLineBuilder("Orchestrator", "runtime_panel") << telemetry::RenderRuntimePanel(
                    *d.state_store, "RuntimePanel", d.resolved.config.dashboard.max_events);
            }
        });
    }
    return true;
}

void Orchestrator::WaitForCompletion()
{
    if (!impl_ || !impl_->fuzzer_thread.joinable()) {
        return;
    }
    impl_->fuzzer_thread.join();
}

// [v2 PR-K-E2 — graceful shutdown 当前版本]
// 仅 lock-free atomic store,signal-safe;在 SIGINT handler 内直调安全。
// 不 join 任何线程、不取 mutex、不做 IO ——所有收尾留给主线程的 Stop()。
void Orchestrator::RequestStop()
{
    if (!impl_) {
        return;
    }
    impl_->stop_requested.store(true, std::memory_order_release);
}

int Orchestrator::Stop()
{
    if (!impl_) {
        return 1;
    }
    auto& d = *impl_;
    auto& c = d.resolved.config;

    d.stop_requested.store(true, std::memory_order_release);

    if (d.fuzzer_thread.joinable()) {
        d.fuzzer_thread.join();
    }

    // [fixed request stream] Hold here, if configured: the fuzzer thread has
    // joined (normally because every request completed; see the marker's
    // drained/incomplete content for the case where it did not) but registry.StopAll()
    // -- which destroys the VM -- is still further down. This is the only point
    // in the process where "all work is done" and "the guest is still alive"
    // are both true, so it is the only place an external driver can be let in
    // to stop and fetch a guest-side probe (perf record). See ReplayConfig for
    // why polling from outside cannot substitute for this.
    if (c.run_mode == RunMode::kReplay && !c.replay.drained_marker_path.empty()) {
        HoldForGuestProbeFetch(c.replay,
                               d.replay_fully_drained.load(std::memory_order_acquire));
    }

    // [corpus-pc-export] speed-compare D: dump the corpus-admitted PC set (raw KCOV
    // PC, sorted) HERE — right after the fuzzer thread joins (corpus_pc_feedback_store
    // now has no concurrent writer) and BEFORE registry.StopAll() + the VM/pipeline
    // drains, which can hang under SIGINT and otherwise force-exit before the later
    // coverage-save block runs. Gated on coverage.export.corpus_pc_path (default
    // empty). corpus_pc_feedback_store = reFuzz analog of syz corpus.cover.
    if (!c.coverage_export_corpus_pc_path.empty() && d.bundle.corpus_pc_feedback_store) {
        if (d.bundle.corpus_pc_feedback_store->DumpPCsToFile(
                c.coverage_export_corpus_pc_path)) {
            refuzz::logging::HostLineBuilder("Orchestrator", "corpus_pc_export")
                << d.bundle.corpus_pc_feedback_store->Count() << " corpus PCs -> "
                << c.coverage_export_corpus_pc_path << "\n";
        } else {
            refuzz::logging::HostLineBuilder("Orchestrator", "corpus_pc_export_warn")
                << c.coverage_export_corpus_pc_path << "\n";
        }
    }
    // [coverage-compare export] corpus ADMISSION-signal + all-exec signal sets
    // (edges in cover_edges mode / raw PCs otherwise), dumped here alongside
    // corpus_pc. Each gated on its own path (default empty = off).
    if (!c.coverage_export_corpus_signal_path.empty() &&
        d.bundle.corpus_edge_feedback_store) {
        if (d.bundle.corpus_edge_feedback_store->DumpPCsToFile(
                c.coverage_export_corpus_signal_path)) {
            refuzz::logging::HostLineBuilder("Orchestrator", "corpus_signal_export")
                << d.bundle.corpus_edge_feedback_store->Count() << " corpus edges -> "
                << c.coverage_export_corpus_signal_path << "\n";
        } else {
            refuzz::logging::HostLineBuilder("Orchestrator", "corpus_signal_export_warn")
                << c.coverage_export_corpus_signal_path << "\n";
        }
    }
    if (!c.coverage_export_all_signal_path.empty() &&
        d.bundle.all_edge_feedback_store) {
        if (d.bundle.all_edge_feedback_store->DumpPCsToFile(
                c.coverage_export_all_signal_path)) {
            refuzz::logging::HostLineBuilder("Orchestrator", "all_signal_export")
                << d.bundle.all_edge_feedback_store->Count() << " all-exec edges -> "
                << c.coverage_export_all_signal_path << "\n";
        } else {
            refuzz::logging::HostLineBuilder("Orchestrator", "all_signal_export_warn")
                << c.coverage_export_all_signal_path << "\n";
        }
    }

    const auto task_drain_deadline =
        std::chrono::steady_clock::now() +
        std::chrono::milliseconds(c.shutdown_grace_ms);
    while (d.task_queue->PendingSize() > 0 &&
           std::chrono::steady_clock::now() < task_drain_deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
        d.loop->Drain(std::chrono::milliseconds{0}, 8);
    }

    // Final corpus minimization must happen before telemetry StopAll(), because
    // the projector computes run_summary.json during StopAll().
    d.loop->FinalizeCorpusForShutdown();

    if (auto stop_r = d.registry.StopAll(); !stop_r) {
        refuzz::logging::HostLineBuilder("Orchestrator", "service_stop_failed")
            << stop_r.error().message << "\n";
    }

    const auto post_stop_drain_deadline =
        std::chrono::steady_clock::now() +
        std::chrono::milliseconds(c.shutdown_grace_ms > 3000U ? 3000U : c.shutdown_grace_ms);
    while (!d.PipelineDrained() && std::chrono::steady_clock::now() < post_stop_drain_deadline) {
        d.loop->Drain(std::chrono::milliseconds{0}, 8);
    }
    if (!d.PipelineDrained()) {
        d.LogShutdownState("residual work after executor stop");
    }
    if (d.status_thread.joinable()) {
        {
            std::lock_guard<std::mutex> lk(d.status_mtx);
            d.status_stop.store(true, std::memory_order_release);
        }
        d.status_cv.notify_one();
        d.status_thread.join();
    }

    // [v2 PR-K-0 — coverage_thread 已删除;coverage_output_dir 现由
    //  HashFeedbackStore::SaveToFile 同步写出 (双输出语义见 §3 D-5)]
    if (CoverageModeEnabled(c.target.coverage_mode)) {
        const std::string out_path = c.coverage_output_dir + "/coverage_hashes.bin";
        if (d.bundle.feedback_store->SaveToFile(out_path)) {
            refuzz::logging::HostLineBuilder("Orchestrator", "coverage_output_saved")
                << d.bundle.feedback_store->Count() << " hashes -> " << out_path << "\n";
        } else {
            refuzz::logging::HostLineBuilder("Orchestrator", "coverage_output_save_warn")
                << out_path << "\n";
        }
        // [v2 Epic 5 PR-5-B] cmp dedupe two-output Stop write (Q3 decision).
        // Empty store on PC-only runs writes a zero-count .cmp.bin; harmless.
        if (d.bundle.cmp_feedback_store) {
            const std::string cmp_out_path =
                c.coverage_output_dir + "/coverage_hashes_cmp.bin";
            if (d.bundle.cmp_feedback_store->SaveToFile(cmp_out_path)) {
                refuzz::logging::HostLineBuilder("Orchestrator", "coverage_cmp_output_saved")
                    << d.bundle.cmp_feedback_store->Count()
                    << " cmp hashes -> " << cmp_out_path << "\n";
            } else {
                refuzz::logging::HostLineBuilder("Orchestrator", "coverage_cmp_output_save_warn")
                    << cmp_out_path << "\n";
            }
        }
    }
    if (CoverageModeEnabled(c.target.coverage_mode) && c.coverage_persist_enable) {
        if (d.bundle.feedback_store->SaveToFile(c.coverage_persist_path)) {
            refuzz::logging::HostLineBuilder("Orchestrator", "coverage_saved") << d.bundle.feedback_store->Count() << " coverage hashes\n";
        } else {
            refuzz::logging::HostLineBuilder("Orchestrator", "coverage_save_warn") << c.coverage_persist_path << "\n";
        }
        // [v2 Epic 5 PR-5-B] cmp dedupe canonical resume path (alongside PC).
        if (d.bundle.cmp_feedback_store) {
            const std::string cmp_path = c.coverage_persist_path + ".cmp";
            if (d.bundle.cmp_feedback_store->SaveToFile(cmp_path)) {
                refuzz::logging::HostLineBuilder("Orchestrator", "coverage_cmp_saved")
                    << d.bundle.cmp_feedback_store->Count() << " cmp hashes\n";
            } else {
                refuzz::logging::HostLineBuilder("Orchestrator", "coverage_cmp_save_warn")
                    << cmp_path << "\n";
            }
        }
    }

    // [v2 run_summary redesign] service_registry.StopAll() 已经跑完 Projector::Stop(),
    // 其中执行了 ComputeAndStoreSummary(is_final=true),Store 里此刻是最终 summary。
    // 这里做两件事:
    //   1. 把 final summary 写成 run_summary.json(仅 final 一次,过程不写)
    //   2. 从 Store 读出 has_progress 判定用的 5 个值 + stop_complete 日志字段
    d.final_summary_status = d.run_summary_json_sink
        ? d.run_summary_json_sink->WriteFinal()
        : telemetry::JsonWriteStatus::kSkipped;

    const auto& reg = d.metric_registry;
    const uint64_t generated_tasks    = CounterValue(reg, "fuzzer.generated_tasks");
    // [triage 重构] reexec(corpus_verify/triage/smash/fault)产生的执行,用于 phase-aware 进展判定。
    const uint64_t reexec_tasks       = CounterValue(reg, "fuzzer.reexec_tasks");
    const uint64_t completion_results = CounterValue(reg, "fuzzer.results", {{"kind", "completion"}});
    const uint64_t partial_completion_results =
        CounterValue(reg, "fuzzer.results", {{"kind", "partial_completion"}});
    const uint64_t abnormal_results   = CounterValue(reg, "fuzzer.results", {{"kind", "abnormal"}});
    const uint64_t fault_events       = CounterValue(reg, "fuzzer.results", {{"kind", "fault"}});
    const uint64_t harness_fatal      = CounterValue(reg, "fuzzer.results", {{"kind", "harness_fatal"}});
    const uint64_t terminal_results   = completion_results + abnormal_results;

    // has_progress:fuzz 进展(生成 task 且有 terminal),或 reexec 进展(triage/verify/
    //   smash/fault 产生了 reexec 工作)。后者避免"只跑了 triage 的短 run"被误判 no-progress
    //   → exit 1。result 计数(completion/abnormal)只由 catch-all mutational consumer(fuzz
    //   phase)写,故是 fuzz 进展;reexec 进展用 reexec_tasks>0 表征。
    //   不把 fault 算进来:fault 不意味着 task 实际执行过。
    const bool fuzz_progress   = generated_tasks > 0 && terminal_results > 0;
    const bool reexec_progress = reexec_tasks > 0;
    const bool has_progress = fuzz_progress || reexec_progress;

    if (d.repro_worker) {
        refuzz::logging::HostLogger::Instance().Log(
            "Orchestrator",
            "repro_summary",
            {refuzz::logging::Field("processed", d.repro_worker->ProcessedCount()),
             refuzz::logging::Field("reproduced", d.repro_worker->ReproducedCount())});
        if (c.logging.console_summary) {
            refuzz::logging::HostLineBuilder("Orchestrator", "repro_summary_text") << d.repro_worker->ProcessedCount() << " reproduced=" << d.repro_worker->ReproducedCount() << "\n";
        }
    }
    for (auto& ch : d.bundle.repro_channels) {
        if (ch) {
            ch->Close();
        }
    }

    d.CloseChannels();

    if (!has_progress) {
        refuzz::logging::HostLogger::Instance().Log(
            "Orchestrator",
            "stop_complete",
            {refuzz::logging::Field("has_progress", false),
             refuzz::logging::Field("generated", generated_tasks),
             refuzz::logging::Field("completion", completion_results),
             refuzz::logging::Field("partial_completion", partial_completion_results),
             refuzz::logging::Field("abnormal", abnormal_results),
             refuzz::logging::Field("fault", fault_events),
             refuzz::logging::Field("harness_fatal", harness_fatal),
             refuzz::logging::Field("terminal", terminal_results)});
        refuzz::logging::HostLogger::Instance().Shutdown();
        refuzz::logging::HostLineBuilder("Orchestrator", "no_progress") << "orchestrator: fuzzer loop did not make progress\n";
        return 1;
    }

    refuzz::logging::HostLogger::Instance().Log(
        "Orchestrator",
        "stop_complete",
        {refuzz::logging::Field("has_progress", true),
         refuzz::logging::Field("generated", generated_tasks),
         refuzz::logging::Field("completion", completion_results),
         refuzz::logging::Field("partial_completion", partial_completion_results),
         refuzz::logging::Field("abnormal", abnormal_results),
         refuzz::logging::Field("fault", fault_events),
         refuzz::logging::Field("harness_fatal", harness_fatal),
         refuzz::logging::Field("terminal", terminal_results),
         refuzz::logging::Field("run_summary_status",
             telemetry::JsonWriteStatusName(d.final_summary_status))});
    refuzz::logging::HostLogger::Instance().Shutdown();
    std::cout << "orchestrator: completed successfully\n";

    // [v2 run_summary redesign] 退出码反映 final json 写盘 & invariant 结果。
    //   kOk/kSkipped/kDisabled 视作成功(0);kInvariantFailed → 3;kIoError → 4。
    switch (d.final_summary_status) {
    case telemetry::JsonWriteStatus::kInvariantFailed: return 3;
    case telemetry::JsonWriteStatus::kIoError:         return 4;
    case telemetry::JsonWriteStatus::kOk:
    case telemetry::JsonWriteStatus::kSkipped:
    default:                                           return 0;
    }
}

} // namespace refuzz::orchestrator

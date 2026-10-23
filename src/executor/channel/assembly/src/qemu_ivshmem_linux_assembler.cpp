// QemuIvshmemLinuxAssembler 实现（v3.5 Phase D/E 完整装配）
//
// 本文件是整个"组件拼装"的集中点：
//   - 所有具体实现类（Runtime / IvshmemControlPlane / IvshmemDataPlane / UnixSerialConsoleSource
//     / IvshmemStepEventSource / HealthMonitor + 三个 Sensor / Recovery）只在本文件里构造；
//   - Channel / Builder 只看到 ChannelComponents 里的抽象接口。
//
// Phase 设计来源：docs/channel-redesign/v3.5/140_phase_E_assembler.md

#include "refuzz/channel/factory/qemu_ivshmem_linux_assembler.hpp"
#include "refuzz/channel/factory/channel_builder.hpp"
#include "refuzz/channel/factory/qemu_ivshmem_linux_profile.hpp"
#include "refuzz/channel/channel_impl.hpp"   // IChannel 完整类型 (unique_ptr 析构需要)

#include "refuzz/channel/control/ivshmem_control_plane.hpp"
#include "refuzz/channel/data/ivshmem_data_plane.hpp"
#include "refuzz/channel/evidence/unix_serial_console_source.hpp"
#include "refuzz/channel/evidence/ivshmem_step_event_source.hpp"
#include "refuzz/channel/health/health_monitor.hpp"
#include "refuzz/channel/health/heartbeat_sensor.hpp"
#include "refuzz/channel/health/console_sensor.hpp"
#include "refuzz/channel/health/vm_alive_sensor.hpp"
#include "refuzz/channel/infra/shm_infra.hpp"
#include "refuzz/channel/recovery/recovery.hpp"
#include "refuzz/channel/runtime/runtime.hpp"

#include <algorithm>
#include <memory>
#include <filesystem>
#include <string>
#include <utility>

namespace refuzz::channel {

std::string_view QemuIvshmemLinuxAssembler::Id() const
{
    return "qemu_ivshmem_linux";
}

Result<ChannelComponents> QemuIvshmemLinuxAssembler::Assemble(
    const ChannelBuildContext& ctx)
{
    // 两段式配置：neutral ChannelConfig + dynamic_cast 到本后端 Profile。
    if (ctx.backend_profile == nullptr) {
        return Error{
            ErrorKind::kConfig,
            "QemuIvshmemLinuxAssembler: ctx.backend_profile is null"};
    }

    const auto* prof = dynamic_cast<const factory::QemuIvshmemLinuxProfile*>(
        ctx.backend_profile);
    if (prof == nullptr) {
        return Error{
            ErrorKind::kConfig,
            std::string{"QemuIvshmemLinuxAssembler requires QemuIvshmemLinuxProfile, got backend_id="} +
                std::string{ctx.backend_profile->BackendId()}};
    }

    const ChannelConfig& cfg = ctx.channel_cfg;

    // 1) 轻量校验：workers 数量一致性（profile.infra.n_workers == cfg.n_workers）
    if (prof->infra.n_workers != cfg.n_workers) {
        return Error{
            ErrorKind::kConfig,
            "QemuIvshmemLinuxAssembler: profile.infra.n_workers (" +
                std::to_string(prof->infra.n_workers) + ") != ctx.channel_cfg.n_workers (" +
                std::to_string(cfg.n_workers) + ")"};
    }

    // 1.1) Orchestrator 必须通过 ctx.vm_workdir 指定本 VM 的工作目录；
    //      Assembler 不从 profile 里读 workdir（profile.runtime.instance.workdir
    //      在 yaml 解析期留空），也不拼接 vm-<index>。
    if (ctx.vm_workdir.empty()) {
        return Error{
            ErrorKind::kConfig,
            "QemuIvshmemLinuxAssembler: ctx.vm_workdir is empty "
            "(orchestrator must fill it from SessionLayout)"};
    }

    ChannelComponents out;

    // 2) Shm / Infra：shared_ptr 形式，CP/DP/Steps 共享
    auto shm = std::make_shared<infra::ShmInfra>(prof->infra);
    auto r_shm = shm->Init();
    if (!r_shm.ok()) {
        return Error{ErrorKind::kInfra, "Infra.Init failed: " + r_shm.error().message};
    }
    out.shm = shm;

    // 3) Substrate（Runtime 实现 ISubstrate）；ivshmem_bytes 从 shm 反写回 runtime_cfg
    auto runtime_cfg = prof->runtime;
    runtime_cfg.instance.ivshmem_bytes = shm->total_size();
    // workdir 由 orchestrator 通过 ctx 下发（SessionLayout.vm_dir(i)
    // / repro_dir(i)），在此处填入 RuntimeInstanceConfig。
    runtime_cfg.instance.workdir       = ctx.vm_workdir;
    runtime_cfg.instance.index         = ctx.vm_index;
    // serial_log_path 留空 → 默认 <vm_workdir>/serial.log；yaml 若显式指定则沿用。
    if (runtime_cfg.instance.serial_log_path.empty()) {
        runtime_cfg.instance.serial_log_path = ctx.vm_workdir + "/serial.log";
    if (runtime_cfg.instance.worker_log_path.empty())
        runtime_cfg.instance.worker_log_path = ctx.vm_workdir + "/worker.log";
    }

    auto rt_result = runtime::Runtime::Create(
        runtime_cfg,
        runtime::MakeVmSubstratePoolOps(runtime_cfg.instance),
        prof->worker);
    if (!rt_result.ok()) {
        return Error{ErrorKind::kConfig,
                     "Runtime.Create failed: " + rt_result.error().message};
    }
    out.substrate = std::move(rt_result.value());
    runtime::ISubstrate* substrate_raw = out.substrate.get();  // Recovery 走 ISubstrate

    // 4) ControlPlane：Ivshmem 具体实现；从 shm.Backbone() 拿共享 mmap
    auto backbone = shm->Backbone();
    if (!backbone) {
        return Error{ErrorKind::kInfra, "IvshmemBackbone not ready after Infra.Init"};
    }

    // wait_ready_timeout 从 ChannelConfig（中性）读取；
    // wait_ready_poll_us 仍为后端专属，保留在 TransportConfig。
    control::SessionTiming timing;
    timing.wait_ready_timeout_us =
        std::chrono::duration_cast<std::chrono::microseconds>(cfg.wait_ready_timeout);
    timing.wait_ready_poll_us = prof->transport.wait_ready_poll_us;

    auto cp_concrete = std::make_unique<control::IvshmemControlPlane>(
        backbone, shm.get(), timing);
    control::IvshmemControlPlane* cp_raw = cp_concrete.get();

    // 5) DataPlane
    data::IvshmemDataPlaneOptions dopt;
    dopt.shm_path             = prof->infra.shm_path;
    dopt.doorbell_socket_path = prof->transport.doorbell_socket_path;
    dopt.use_doorbell         = prof->transport.use_doorbell;
    dopt.poll_sleep_us        = prof->transport.poll_sleep_us;

    auto dp_concrete = std::make_unique<data::IvshmemDataPlane>(
        backbone,
        shm.get(),
        cp_raw->GetSendabilityView(),
        cp_raw->GetRegistrationHook(),
        std::move(dopt));

    out.control = std::move(cp_concrete);
    out.data    = std::move(dp_concrete);

    // 6) Evidence：Console（延后到 Boot 再 Open，因为需要 StartVM 后的 socket 路径）
    out.console = std::make_unique<evidence::UnixSerialConsoleSource>();

    //    Step-event 源（直接基于 shm）
    auto step_concrete = std::make_unique<evidence::IvshmemStepEventSource>(*shm);
    evidence::IvshmemStepEventSource* step_raw = step_concrete.get();
    out.steps = std::move(step_concrete);

    // 7) HealthMonitor：view 留空（Channel::Boot 里 BindChannelSignals 再填）
    auto health_cfg = prof->health_monitor;
    health_cfg.expected_worker_count = shm->n_workers();
    auto hm = std::make_unique<health::HealthMonitor>(
        health::HealthMonitorView{/* 空 view：Boot 时再 Bind */},
        health_cfg);

    // §3.11-B — 共享 console ring buffer（ConsoleSensor 写、HeartbeatSensor
    // 读）。先创建后 raw-ptr 注入两个 sensor；持有于 ChannelComponents 让
    // 生命周期跟 Channel 对齐（晚于 sensor，避免 Sensor::Stop 之后才析构）。
    out.console_ring = std::make_unique<evidence::ConsoleRingBuffer>(
        /*max_lines=*/200);
    auto* ring_raw = out.console_ring.get();

    // 聚合前进时钟（检测器 A/B 的中立信号）。和 console_ring 同样的注入模式：先创建、
    //   raw-ptr 注入写读两方（HeartbeatSensor 写+读，VmAliveSensor 读），unique_ptr
    //   持有于 ChannelComponents 让生命周期跟 Channel 对齐。
    out.progress_clock = std::make_unique<evidence::ProgressClock>();
    auto* progress_raw = out.progress_clock.get();

    // 7.1 HeartbeatSensor
    {
        health::HeartbeatSensorConfig hc;
        hc.poll_interval      = prof->health_monitor.heartbeat.poll_interval;
        hc.miss_threshold     = prof->health_monitor.heartbeat.miss_threshold;
        hc.workers_per_round  = prof->health_monitor.heartbeat.workers_per_round;
        hc.worker_count       = shm->n_workers();
        hc.capture_step_events = prof->health_monitor.heartbeat.capture_step_events;
        hm->AddSensor(std::make_unique<health::HeartbeatSensor>(
            cp_raw, step_raw, hc, ring_raw, progress_raw));
    }
    // 7.2 ConsoleSensor
    {
        health::ConsoleSensorConfig cc_cfg;
        cc_cfg.pre_context_lines  = prof->health_monitor.serial_watcher.pre_context_lines;
        cc_cfg.post_context_lines = prof->health_monitor.serial_watcher.post_context_lines;
        cc_cfg.capture_step_events = prof->health_monitor.serial_watcher.capture_step_events;
        hm->AddSensor(std::make_unique<health::ConsoleSensor>(
            out.console.get(), step_raw, cc_cfg, ring_raw));
    }
    // 7.3 VmAliveSensor（闭包捕 ISubstrate*；Channel 生命周期保证早于 sensor）
    {
        health::VmAliveSensorConfig vc;
        vc.check_interval  = prof->health_monitor.vm_liveness.check_interval;
        vc.vm_dead_timeout = prof->health_monitor.vm_liveness.vm_dead_timeout;  // 检测器 A 阈值
        auto* sub_raw = out.substrate.get();
        hm->AddSensor(std::make_unique<health::VmAliveSensor>(
            [sub_raw] { return sub_raw && sub_raw->IsVMAlive(0); }, vc, progress_raw));
    }

    // 7.4 HealthMonitor 挂回 components
    health::HealthMonitor* hm_raw = hm.get();
    out.health = std::move(hm);

    // 8) ChannelConfig 直接透传：ctx.channel_cfg 已由 orchestrator 填好中性字段。
    //    Assembler 只负责 backend_id 的权威设置 + wire 级 payload 上限同步。
    out.channel_cfg                  = cfg;
    out.channel_cfg.backend_id       = "qemu_ivshmem_linux";
    // Decouple Channel::Submit from `shm_->MaxInput()`: publish the same
    // upper bound through the neutral ChannelConfig so the orchestrator
    // path no longer dereferences shm_ on the hot path. Behavior is
    // bit-identical (ShmInfra::MaxInput returns MAX_INPUT_SIZE constant);
    // the fallback in channel.cpp keeps any caller that left this 0 working.
    out.channel_cfg.max_payload_size = static_cast<std::size_t>(shm->MaxInput());

    // 8.1 DeployBundle 兜底：若 ctx.channel_cfg.deploy_bundle 为空，从 worker profile
    //     派生一个最小 bundle。必须在 Recovery::Create 之前完成：Recovery 会把
    //     bundle 透传给 RecoveryExe 用于 Reboot 后 re-deploy。
    if (out.channel_cfg.deploy_bundle.artifacts.empty() &&
        out.channel_cfg.deploy_bundle.worker_start_cmd.empty()) {
        out.channel_cfg.deploy_bundle.artifacts.push_back(runtime::DeployArtifact{
            /* .local_path  = */ prof->worker.worker_binary_host_path,
            /* .remote_path = */ prof->worker.worker_remote_path,
            /* .mode        = */ 0755,
        });
        const std::filesystem::path worker_host_path(
            prof->worker.worker_binary_host_path);
        const std::filesystem::path worker_remote_path(
            prof->worker.worker_remote_path);
        out.channel_cfg.deploy_bundle.artifacts.push_back(runtime::DeployArtifact{
            /* .local_path  = */
                (worker_host_path.parent_path() / "refuzz_executor").string(),
            /* .remote_path = */
                (worker_remote_path.parent_path() / "refuzz_executor").string(),
            /* .mode        = */ 0755,
        });
        out.channel_cfg.deploy_bundle.deploy_timeout = prof->worker.deploy_timeout;
    }

    // ExecDoubleFork resolves refuzz_executor next to /proc/self/exe. Custom
    // bundles must satisfy the same deployment contract as the fallback.
    const std::filesystem::path executor_host_path =
        std::filesystem::path(prof->worker.worker_binary_host_path)
            .parent_path() / "refuzz_executor";
    const std::filesystem::path executor_remote_path =
        std::filesystem::path(prof->worker.worker_remote_path)
            .parent_path() / "refuzz_executor";
    const bool executor_already_deployed = std::any_of(
        out.channel_cfg.deploy_bundle.artifacts.begin(),
        out.channel_cfg.deploy_bundle.artifacts.end(),
        [&](const runtime::DeployArtifact& artifact) {
            return artifact.remote_path == executor_remote_path.string();
        });
    if (!executor_already_deployed) {
        out.channel_cfg.deploy_bundle.artifacts.push_back(runtime::DeployArtifact{
            /* .local_path  = */ executor_host_path.string(),
            /* .remote_path = */ executor_remote_path.string(),
            /* .mode        = */ 0755,
        });
    }

    // 9) Recovery：[v4.0 Phase K] 走 ISubstrate*；透传 deploy_bundle 给 RecoveryExe
    //    用于 Reboot 路径里的 re-deploy。
    auto rec_r = recovery::Recovery::Create(
        prof->recovery_config,
        substrate_raw,
        out.channel_cfg.deploy_bundle,
        cp_raw,
        out.data.get(),
        hm_raw,
        out.channel_cfg.wait_ready_timeout,
        out.console.get());  // [console-drain-before-workers] Reboot 路径 worker 启动前重开新 serial
    if (!rec_r.ok()) {
        return Error{ErrorKind::kConfig,
                     "Recovery.Create failed: " + rec_r.error().message};
    }
    out.recovery = std::move(rec_r.value());

    return Result<ChannelComponents>::Ok(std::move(out));
}

Result<std::unique_ptr<IChannel>> QemuIvshmemLinuxAssembler::AssembleAndBuild(
    const ChannelBuildContext& ctx)
{
    auto comps_r = QemuIvshmemLinuxAssembler{}.Assemble(ctx);
    if (!comps_r.ok()) {
        return Error{comps_r.error().kind, comps_r.error().message};
    }
    auto built_r = ChannelBuilder::Build(std::move(comps_r.value()));
    if (!built_r.ok()) {
        return Error{built_r.error().kind, built_r.error().message};
    }
    return Result<std::unique_ptr<IChannel>>::Ok(std::move(built_r.value()));
}

} // namespace refuzz::channel

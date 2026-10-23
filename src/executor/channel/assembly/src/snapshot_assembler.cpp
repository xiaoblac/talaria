// SnapshotAssembler 实现 —— 见 header + docs/plans/snapshot-session-integration.md。
// 结构镜像 QemuIvshmemLinuxAssembler;只在 substrate(强制 snapshot_fuzzing)、
// data(包 SnapshotDataPlane)、health(Noop)三处不同。

#include "refuzz/channel/factory/snapshot_assembler.hpp"
#include "refuzz/channel/factory/channel_builder.hpp"
#include "refuzz/channel/factory/channel_catalog.hpp"
#include "refuzz/channel/factory/qemu_ivshmem_linux_profile.hpp"
#include "refuzz/channel/channel_impl.hpp"

#include "refuzz/channel/control/ivshmem_control_plane.hpp"
#include "refuzz/channel/control/session_timing.hpp"
#include "refuzz/channel/data/ivshmem_data_plane.hpp"
#include "refuzz/channel/data/snapshot_data_plane.hpp"
#include "refuzz/channel/evidence/unix_serial_console_source.hpp"
#include "refuzz/channel/evidence/ivshmem_step_event_source.hpp"
#include "refuzz/channel/health/health_monitor.hpp"
#include "refuzz/channel/health/console_sensor.hpp"
#include "refuzz/channel/health/vm_alive_sensor.hpp"
#include "refuzz/channel/health/wedge_relay_sensor.hpp"
#include "refuzz/channel/infra/shm_infra.hpp"
#include "refuzz/channel/recovery/snapshot_recovery.hpp"
#include "refuzz/channel/runtime/runtime.hpp"

#include <chrono>
#include <memory>
#include <string>
#include <utility>

namespace refuzz::channel {

std::string_view SnapshotAssembler::Id() const
{
    return channel_backend_id::kQemuIvshmemSnapshotLinux;
}

Result<ChannelComponents> SnapshotAssembler::Assemble(const ChannelBuildContext& ctx)
{
    if (ctx.backend_profile == nullptr) {
        return Error{ErrorKind::kConfig, "SnapshotAssembler: ctx.backend_profile is null"};
    }
    // snapshot 复用 QemuIvshmemLinuxProfile(config parser 不另建 profile 类型)。
    const auto* prof = dynamic_cast<const factory::QemuIvshmemLinuxProfile*>(
        ctx.backend_profile);
    if (prof == nullptr) {
        return Error{ErrorKind::kConfig,
                     "SnapshotAssembler requires QemuIvshmemLinuxProfile, got backend_id=" +
                         std::string{ctx.backend_profile->BackendId()}};
    }
    const ChannelConfig& cfg = ctx.channel_cfg;

    // 全局 1-in-flight: loadvm 回滚整台 VM,v1 强制单 worker。
    if (cfg.n_workers != 1) {
        return Error{ErrorKind::kConfig,
                     "snapshot backend requires n_workers=1 (whole-VM loadvm = 1 in-flight); got " +
                         std::to_string(cfg.n_workers)};
    }
    if (prof->infra.n_workers != cfg.n_workers) {
        return Error{ErrorKind::kConfig, "snapshot: profile.infra.n_workers != channel_cfg.n_workers"};
    }
    if (ctx.vm_workdir.empty()) {
        return Error{ErrorKind::kConfig, "SnapshotAssembler: ctx.vm_workdir is empty"};
    }

    ChannelComponents out;

    // 2) Shm / Infra
    auto shm = std::make_shared<infra::ShmInfra>(prof->infra);
    if (auto r = shm->Init(); !r.ok())
        return Error{ErrorKind::kInfra, "Infra.Init failed: " + r.error().message};
    out.shm = shm;

    // 3) Substrate(Runtime) —— 强制 snapshot_fuzzing;捕获 Runtime* 给 QMP provider。
    auto runtime_cfg = prof->runtime;
    runtime_cfg.instance.ivshmem_bytes    = shm->total_size();
    runtime_cfg.instance.workdir          = ctx.vm_workdir;
    runtime_cfg.instance.index            = ctx.vm_index;
    runtime_cfg.instance.snapshot_fuzzing = true;   // qcow2 overlay + ivshmem master=on + 去 -snapshot
    runtime_cfg.instance.ivshmem_mode     = "plain"; // doorbell eventfd 过不了 savevm
    if (runtime_cfg.instance.serial_log_path.empty())
        runtime_cfg.instance.serial_log_path = ctx.vm_workdir + "/serial.log";
    if (runtime_cfg.instance.worker_log_path.empty())
        runtime_cfg.instance.worker_log_path = ctx.vm_workdir + "/worker.log";

    auto rt_result = runtime::Runtime::Create(
        runtime_cfg, runtime::MakeVmSubstratePoolOps(runtime_cfg.instance), prof->worker);
    if (!rt_result.ok())
        return Error{ErrorKind::kConfig, "Runtime.Create failed: " + rt_result.error().message};
    runtime::Runtime* runtime_raw = rt_result.value().get();  // MonitorEndpoint 是 Runtime 专属
    out.substrate = std::move(rt_result.value());

    // 4) ControlPlane(复用)
    auto backbone = shm->Backbone();
    if (!backbone)
        return Error{ErrorKind::kInfra, "IvshmemBackbone not ready after Infra.Init"};
    control::SessionTiming timing;
    timing.wait_ready_timeout_us =
        std::chrono::duration_cast<std::chrono::microseconds>(cfg.wait_ready_timeout);
    timing.wait_ready_poll_us = prof->transport.wait_ready_poll_us;
    auto cp_concrete = std::make_unique<control::IvshmemControlPlane>(
        backbone, shm.get(), timing);
    control::IvshmemControlPlane* cp_raw = cp_concrete.get();

    // 5) DataPlane —— 内层 IvshmemDataPlane(强制 plain),外面包 SnapshotDataPlane。
    data::IvshmemDataPlaneOptions dopt;
    dopt.shm_path             = prof->infra.shm_path;
    dopt.doorbell_socket_path = prof->transport.doorbell_socket_path;
    dopt.use_doorbell         = false;  // snapshot 必须 plain
    dopt.poll_sleep_us        = prof->transport.poll_sleep_us;
    auto inner_dp = std::make_unique<data::IvshmemDataPlane>(
        backbone, shm.get(), cp_raw->GetSendabilityView(),
        cp_raw->GetRegistrationHook(), std::move(dopt));
    // [Brick 4a step 3] VMI-on-wedge: derive vmlinux (for System.map + addr2line)
    // from the kernel bzImage path — vmlinux + System.map live in the kernel build
    // dir alongside arch/<a>/boot/bzImage. If the layout differs, the data plane
    // disables printk-ring VMI but PC-on-wedge still works (raw RIP).
    std::string vmlinux_path;
    {
        const std::string& kpath = runtime_cfg.instance.kernel;
        const auto arch_pos = kpath.find("/arch/");
        if (arch_pos != std::string::npos) {
            vmlinux_path = kpath.substr(0, arch_pos) + "/vmlinux";
        }
    }
    // A program normally completes in ~loadvm(1.5s)+exec; a wedge is far past
    // that. 8s >> the ~1.76s steady-state and the 5s exec timeout + loadvm.
    // A program normally completes in ~220ms of post-loadvm exec; a silent wedge
    // never completes. 8s >> normal, so VMI fires only on a genuine hang.
    constexpr uint32_t kWedgeThresholdMs = 8000;
    auto snap_dp = std::make_unique<data::SnapshotDataPlane>(
        std::move(inner_dp),
        [runtime_raw] { return runtime_raw->MonitorEndpoint(0); },
        /*snapshot_tag=*/"S0",
        vmlinux_path,
        kWedgeThresholdMs);

    data::SnapshotDataPlane* snap_dp_raw = snap_dp.get();  // for the WedgeRelaySensor
    out.control = std::move(cp_concrete);
    out.data    = std::move(snap_dp);

    // 6) Evidence(复用)
    out.console = std::make_unique<evidence::UnixSerialConsoleSource>();
    auto step_concrete = std::make_unique<evidence::IvshmemStepEventSource>(*shm);
    evidence::IvshmemStepEventSource* step_raw = step_concrete.get();
    out.steps   = std::move(step_concrete);
    out.console_ring = std::make_unique<evidence::ConsoleRingBuffer>(/*max_lines=*/200);
    auto* ring_raw = out.console_ring.get();

    // 7) Health —— ConsoleSensor(serial crash 模式 = syzkaller ContainsCrash) +
    //    VmAliveSensor(QEMU 进程存活)。**不挂 HeartbeatSensor**:它要 worker 心跳计数
    //    递增,会在 ~savevm 暂停期误判 worker dead,且 syzkaller snapshot 本就无心跳。
    //    ConsoleSensor 检测到内核 panic → Fault(kKernelCrash) → HandleFault →
    //    SnapshotRecovery 返回 kReloadSnapshot(不重启)。
    auto health_cfg = prof->health_monitor;
    health_cfg.expected_worker_count = shm->n_workers();
    auto hm = std::make_unique<health::HealthMonitor>(
        health::HealthMonitorView{/* 空 view:Boot 时 Bind */}, health_cfg);
    {
        health::ConsoleSensorConfig cc_cfg;
        cc_cfg.pre_context_lines   = prof->health_monitor.serial_watcher.pre_context_lines;
        cc_cfg.post_context_lines  = prof->health_monitor.serial_watcher.post_context_lines;
        cc_cfg.capture_step_events = prof->health_monitor.serial_watcher.capture_step_events;
        hm->AddSensor(std::make_unique<health::ConsoleSensor>(
            out.console.get(), step_raw, cc_cfg, ring_raw));
    }
    {
        health::VmAliveSensorConfig vc;
        vc.check_interval = prof->health_monitor.vm_liveness.check_interval;
        auto* sub_raw = out.substrate.get();
        hm->AddSensor(std::make_unique<health::VmAliveSensor>(
            [sub_raw] { return sub_raw && sub_raw->IsVMAlive(0); }, vc));
    }
    {
        // [Brick 4a step 3b — recovery-on-wedge] A silent hang produces NO console
        // crash (ConsoleSensor blind) and the QEMU process stays alive (VmAlive
        // blind). SnapshotDataPlane::Poll latches a wedge after the in-flight
        // timeout; this relay sensor consumes it and publishes a crash event →
        // SnapshotRecovery returns kReloadSnapshot → ResetAll → the next Submit's
        // loadvm S0 unsticks the wedged VM. Reuses the XiUOS wedge-relay path.
        health::WedgeRelaySensorConfig wc;
        wc.check_interval = std::chrono::milliseconds(500);
        wc.worker_id      = 0;
        hm->AddSensor(std::make_unique<health::WedgeRelaySensor>(
            [snap_dp_raw] { return snap_dp_raw->ConsumeWedgePending(); }, wc));
    }
    health::IHealthMonitor* hm_raw = hm.get();
    out.health = std::move(hm);
    (void)hm_raw;  // snapshot recovery 不需要 health* (无 RestartHealthMonitor 路径)

    // 8) ChannelConfig
    out.channel_cfg                  = cfg;
    out.channel_cfg.backend_id       = std::string(channel_backend_id::kQemuIvshmemSnapshotLinux);
    out.channel_cfg.max_payload_size = static_cast<std::size_t>(shm->MaxInput());
    if (out.channel_cfg.deploy_bundle.artifacts.empty() &&
        out.channel_cfg.deploy_bundle.worker_start_cmd.empty()) {
        out.channel_cfg.deploy_bundle.artifacts.push_back(runtime::DeployArtifact{
            prof->worker.worker_binary_host_path, prof->worker.worker_remote_path, 0755});
        out.channel_cfg.deploy_bundle.deploy_timeout = prof->worker.deploy_timeout;
    }

    // 9) Recovery —— SnapshotRecovery:内核崩溃返回 kReloadSnapshot(不重启 VM、不毁
    //    S0),释放 in-flight + ResetAll data plane;内核由下一次 loadvm S0 还原。
    out.recovery = std::make_unique<recovery::SnapshotRecovery>(out.data.get());

    return Result<ChannelComponents>::Ok(std::move(out));
}

Result<std::unique_ptr<IChannel>> SnapshotAssembler::AssembleAndBuild(
    const ChannelBuildContext& ctx)
{
    auto comps_r = SnapshotAssembler{}.Assemble(ctx);
    if (!comps_r.ok())
        return Error{comps_r.error().kind, comps_r.error().message};
    auto built_r = ChannelBuilder::Build(std::move(comps_r.value()));
    if (!built_r.ok())
        return Error{built_r.error().kind, built_r.error().message};
    return Result<std::unique_ptr<IChannel>>::Ok(std::move(built_r.value()));
}

} // namespace refuzz::channel

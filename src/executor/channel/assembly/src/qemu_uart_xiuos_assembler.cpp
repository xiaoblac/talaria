// QemuUartXiuosAssembler 实现 — "qemu_uart_xiuos" 后端
//
// 形态参考 MockAssembler（同样不需要 ShmInfra 路径），但组件全是真实实现：
// 真的会启动 QEMU、连 TCP serial、跑 XiUOS in-kernel worker。

#include "refuzz/channel/factory/qemu_uart_xiuos_assembler.hpp"

#include "refuzz/channel/channel_impl.hpp"  // Channel complete type for unique_ptr dtor
#include "refuzz/channel/control/xiuos_uart_control_plane.hpp"
#include "refuzz/channel/data/xiuos_uart_data_plane.hpp"
#include "refuzz/channel/factory/channel_builder.hpp"
#include "refuzz/channel/factory/mock_components.hpp"  // NullConsoleSource
#include "refuzz/channel/factory/xiuos_uart_profile.hpp"
// [Stage 3 去山头] 标准 health/recovery 件替换 Noop。XiUOS 的单 UART socket
// 不装 HeartbeatSensor，避免 PING/PONG 与 PROGRAM/RESULT 在同一 backbone 上互抢。
// Wedge 检测在 DataPlane::Poll 的 per-program timeout 内完成，WedgeRelaySensor
// 只把 latched flag 转成 health crash event；Recovery 再经 ISubstrate::RebootVM
// 重启 QEMU。VmAliveSensor 兜底 QEMU 进程死亡。
#include "refuzz/channel/health/health_monitor.hpp"
#include "refuzz/channel/health/vm_alive_sensor.hpp"
#include "refuzz/channel/health/wedge_relay_sensor.hpp"
#include "refuzz/channel/infra/xiuos_uart_backbone.hpp"
#include "refuzz/channel/recovery/recovery.hpp"
#include "refuzz/channel/runtime/xiuos_uart_substrate.hpp"

#include <string>

namespace refuzz::channel {

std::string_view QemuUartXiuosAssembler::Id() const {
    return "qemu_uart_xiuos";
}

Result<ChannelComponents>
QemuUartXiuosAssembler::Assemble(const ChannelBuildContext& ctx) {
    const auto* profile =
        dynamic_cast<const factory::XiuosUartProfile*>(ctx.backend_profile);
    if (profile == nullptr) {
        return Error{ErrorKind::kConfig,
                     "QemuUartXiuosAssembler: backend_profile is not a XiuosUartProfile"};
    }
    if (profile->elf_path.empty()) {
        return Error{ErrorKind::kConfig,
                     "QemuUartXiuosAssembler: XiuosUartProfile.elf_path is empty"};
    }
    if (profile->serial_port == 0) {
        return Error{ErrorKind::kConfig,
                     "QemuUartXiuosAssembler: XiuosUartProfile.serial_port is zero"};
    }

    // ───── Backbone (shared by CP + DP) ─────
    infra::XiuosUartBackbone::Config bb_cfg;
    bb_cfg.host = profile->serial_host;
    bb_cfg.port = profile->serial_port;
    bb_cfg.connect_timeout = profile->connect_timeout;
    bb_cfg.frame_timeout   = profile->frame_timeout;
    bb_cfg.max_queued_frames = profile->max_queued_frames;
    auto backbone_result = infra::XiuosUartBackbone::Create(bb_cfg);
    if (!backbone_result.ok()) {
        return Error{backbone_result.error().kind, backbone_result.error().message};
    }
    auto backbone = backbone_result.value();

    // ───── Substrate ─────
    runtime::XiuosUartSubstrate::Config sub_cfg;
    sub_cfg.qemu_bin       = profile->qemu_bin;
    sub_cfg.elf_path       = profile->elf_path;
    sub_cfg.serial_host    = profile->serial_host;
    sub_cfg.serial_port    = profile->serial_port;
    sub_cfg.shutdown_grace = profile->shutdown_grace;
    auto substrate = std::make_unique<runtime::XiuosUartSubstrate>(sub_cfg);

    // ───── ControlPlane ─────
    // Channel::Boot passes 0 ms to WaitAllWorkersReady; the CP impl uses its
    // configured ready_timeout as the real bound. Inject the neutral
    // ChannelConfig::wait_ready_timeout here so orchestrator-side tuning
    // flows through.
    control::XiuosUartControlPlane::Config cp_cfg;
    cp_cfg.backbone = backbone;
    cp_cfg.heartbeat_timeout = profile->heartbeat_timeout;
    cp_cfg.ready_timeout     = ctx.channel_cfg.wait_ready_timeout;
    auto control = std::make_unique<control::XiuosUartControlPlane>(cp_cfg);

    // ───── DataPlane ─────
    data::XiuosUartDataPlane::Config dp_cfg;
    dp_cfg.backbone = backbone;
    dp_cfg.poll_slice = profile->poll_slice;
    // [Stage 3 wedge timeout] per-program wall-clock budget enforced in Poll
    // (frees the single slot when a program never returns its RESULT). This is
    // the de-siloed XiuosFuzzSession::Step wedge_initial_drain_ms deadline.
    dp_cfg.program_timeout = profile->program_timeout;
    auto data_plane = std::make_unique<data::XiuosUartDataPlane>(dp_cfg);

    // ───── Components ─────
    // Capture raw pointers before moving the unique_ptrs into `out`; the
    // HealthMonitor sensors + Recovery borrow them (Channel guarantees their
    // lifetime outlives the sensors/recovery).
    runtime::ISubstrate*           substrate_raw = substrate.get();
    control::IControlPlane*        cp_raw        = control.get();
    data::IDataPlane*              dp_raw        = data_plane.get();
    // Concrete handle for the wedge relay closure (ConsumeWedgePending is a
    // XiUOS-specific test-and-clear, not on IDataPlane).
    data::XiuosUartDataPlane*      dp_xiuos      = data_plane.get();

    ChannelComponents out;
    out.shm          = nullptr;  // no ivshmem for XiUOS
    out.substrate    = std::move(substrate);
    out.control      = std::move(control);
    out.data         = std::move(data_plane);
    out.console      = std::make_unique<factory::NullConsoleSource>();
    out.console_ring = nullptr;  // future XiUOS console source can fill this
    out.steps        = nullptr;  // no step-event ring for XiUOS

    out.channel_cfg                  = ctx.channel_cfg;
    out.channel_cfg.backend_id       = "qemu_uart_xiuos";
    if (out.channel_cfg.n_workers == 0 || out.channel_cfg.n_workers > 1) {
        out.channel_cfg.n_workers = 1;  // XiUOS is single-worker
    }
    // Wire-level payload upper bound. Channel::Submit reads this instead of
    // dereferencing shm_ (XiUOS has shm == nullptr). XIUOS_MAX_PAYLOAD = 512
    // matches the worker's static frame buffer (kernel/refuzz/refuzz_worker.c)
    // and 030_worker_abi.md §"Phase 1 worker enforcement".
    out.channel_cfg.max_payload_size = static_cast<std::size_t>(XIUOS_MAX_PAYLOAD);

    // ───── HealthMonitor (heartbeat + vm-liveness) ─────
    // view 留空:Channel::Boot 会 BindChannelSignals 填真实 loop_cv/epoch。
    health::HealthMonitorConfig health_cfg;
    health_cfg.expected_worker_count = 1;  // XiUOS single worker
    auto hm = std::make_unique<health::HealthMonitor>(
        health::HealthMonitorView{/* 空 view:Boot 时再 Bind */}, health_cfg);

    // [Stage 3 wedge 检测/恢复] wedge(worker 不回 RESULT)的**检测**在 data plane 的
    // per-program timeout(XiuosUartDataPlane::Config.program_timeout,Poll 超预算 →
    // emit kTimeout + 清 inflight 释放 slot + latch wedge flag),忠实复刻
    // XiuosFuzzSession::Step 把 deadline 放在 submit/drain 路径本身。**不**用
    // HeartbeatSensor(单 socket 无 mutex,Ping/WaitFrame 会与 data 帧 race 吞 RESULT)。
    // 但 Channel 的 recovery(reboot)只由 health crash event 触发,abnormal outcome
    // 不触发 → 所以加 WedgeRelaySensor 作 Poll→health 桥:轮询 ConsumeWedgePending()
    // (不碰 socket),latch 命中 → Publish kWorkerDead → recovery 重启 QEMU。
    {
        health::WedgeRelaySensorConfig wc;
        wc.worker_id      = 0;
        wc.check_interval = std::chrono::milliseconds(500);
        hm->AddSensor(std::make_unique<health::WedgeRelaySensor>(
            [dp_xiuos] { return dp_xiuos && dp_xiuos->ConsumeWedgePending(); },
            wc));
    }
    // VmAliveSensor:兜底检测 QEMU 进程死亡(IsVMAlive 走 waitpid,不碰 serial socket)。
    {
        health::VmAliveSensorConfig vc;
        hm->AddSensor(std::make_unique<health::VmAliveSensor>(
            [substrate_raw] { return substrate_raw && substrate_raw->IsVMAlive(0); },
            vc));
    }
    health::HealthMonitor* hm_raw = hm.get();
    out.health = std::move(hm);

    // ───── Recovery (substrate RebootVM) ─────
    // XiUOS DeployArtifacts 是 no-op(worker 编进 ELF),deploy_bundle 留空即可:
    // Recovery 的 Reboot 路径 RebootVM(stop+restart QEMU)→ DeployArtifacts(no-op)。
    //
    // [Stage 3 wedge recovery policy] XiUOS 是单 worker 且 StopWorker/StartWorker /
    // StartAllWorkers 全是 no-op —— 默认 EscalationPolicy 会先 kRestartSingleWorker
    // (no-op,假成功,worker 仍 wedged,每 15s 再 wedge 死循环)。把
    // max_single_worker_restart_attempts=0 让 worker-dead 跳过单 worker 重启,落到
    // unusable_ratio 路径(1/1=100% ≥ 50%)→ kRebootVm(真重启 QEMU,唯一能解 wedge)。
    // max_vm_reboot_attempts 抬高:fuzz 中每个 wedging program 都要 reboot,不应几次后
    // 升级到 kFailChannel 把 channel 打死(healthy 完成会 decay reboot_count,但保险设高)。
    recovery::RecoveryConfig rec_cfg;
    rec_cfg.policy.escalation.max_single_worker_restart_attempts = 0;
    rec_cfg.policy.escalation.max_vm_reboot_attempts             = 1000000;
    auto rec_r = recovery::Recovery::Create(
        std::move(rec_cfg),
        substrate_raw,
        out.channel_cfg.deploy_bundle,
        cp_raw,
        dp_raw,
        hm_raw,
        out.channel_cfg.wait_ready_timeout);
    if (!rec_r.ok()) {
        return Error{rec_r.error().kind,
                     "QemuUartXiuosAssembler: Recovery.Create failed: " +
                         rec_r.error().message};
    }
    out.recovery = std::move(rec_r.value());

    return Result<ChannelComponents>::Ok(std::move(out));
}

Result<std::unique_ptr<IChannel>>
QemuUartXiuosAssembler::AssembleAndBuild(const ChannelBuildContext& ctx) {
    auto comps_r = QemuUartXiuosAssembler{}.Assemble(ctx);
    if (!comps_r.ok()) {
        return Error{comps_r.error().kind, comps_r.error().message};
    }
    auto built_r = ChannelBuilder::Build(std::move(comps_r.value()));
    if (!built_r.ok()) {
        return Error{built_r.error().kind, built_r.error().message};
    }
    return Result<std::unique_ptr<IChannel>>::Ok(std::move(built_r.value()));
}

}  // namespace refuzz::channel

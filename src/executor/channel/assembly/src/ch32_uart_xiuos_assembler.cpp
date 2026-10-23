// Ch32UartXiuosAssembler 实现 — "ch32_uart_xiuos" 后端(物理 CH32V208RBT6 板)
//
// 镜像 QemuUartXiuosAssembler:同样的 CP/DP/console/health/recovery 组装,只把
// substrate 换成 Ch32UartSubstrate(wlink flash/reset + 真串口),backbone transport
// 换成 serial。其余一切复用 —— 这就是 docs/plans/xiuos-ch32-bringup.md "板适配住
// ISubstrate seam,复用全栈" 的落地。

#include "refuzz/channel/factory/ch32_uart_xiuos_assembler.hpp"

#include "refuzz/channel/channel_impl.hpp"  // Channel complete type for unique_ptr dtor
#include "refuzz/channel/control/xiuos_uart_control_plane.hpp"
#include "refuzz/channel/data/xiuos_uart_data_plane.hpp"
#include "refuzz/channel/factory/ch32_uart_profile.hpp"
#include "refuzz/channel/factory/channel_builder.hpp"
#include "refuzz/channel/factory/mock_components.hpp"  // NullConsoleSource
#include "refuzz/channel/health/health_monitor.hpp"
#include "refuzz/channel/health/vm_alive_sensor.hpp"
#include "refuzz/channel/health/wedge_relay_sensor.hpp"
#include "refuzz/channel/infra/xiuos_uart_backbone.hpp"
#include "refuzz/channel/recovery/recovery.hpp"
#include "refuzz/channel/runtime/ch32_uart_substrate.hpp"

#include <string>

namespace refuzz::channel {

std::string_view Ch32UartXiuosAssembler::Id() const {
    return "ch32_uart_xiuos";
}

Result<ChannelComponents>
Ch32UartXiuosAssembler::Assemble(const ChannelBuildContext& ctx) {
    const auto* profile =
        dynamic_cast<const factory::Ch32UartProfile*>(ctx.backend_profile);
    if (profile == nullptr) {
        return Error{ErrorKind::kConfig,
                     "Ch32UartXiuosAssembler: backend_profile is not a Ch32UartProfile"};
    }
    if (profile->serial_device.empty()) {
        return Error{ErrorKind::kConfig,
                     "Ch32UartXiuosAssembler: Ch32UartProfile.serial_device is empty"};
    }

    // ───── Backbone (shared by CP + DP) — serial transport ─────
    infra::XiuosUartBackbone::Config bb_cfg;
    bb_cfg.transport     = infra::XiuosUartBackbone::Config::Transport::kSerial;
    bb_cfg.serial_device = profile->serial_device;
    bb_cfg.baud          = profile->baud;
    bb_cfg.connect_timeout = profile->connect_timeout;
    bb_cfg.frame_timeout   = profile->frame_timeout;
    bb_cfg.max_queued_frames = profile->max_queued_frames;
    auto backbone_result = infra::XiuosUartBackbone::Create(bb_cfg);
    if (!backbone_result.ok()) {
        return Error{backbone_result.error().kind, backbone_result.error().message};
    }
    auto backbone = backbone_result.value();

    // ───── Substrate (physical board: wlink flash/reset + real serial) ─────
    runtime::Ch32UartSubstrate::Config sub_cfg;
    sub_cfg.serial_device   = profile->serial_device;
    sub_cfg.baud            = profile->baud;
    sub_cfg.image_path      = profile->image_path;
    sub_cfg.flash_command   = profile->flash_command;
    sub_cfg.reset_command   = profile->reset_command;
    sub_cfg.command_timeout = profile->command_timeout;
    sub_cfg.shutdown_grace  = profile->shutdown_grace;
    auto substrate = std::make_unique<runtime::Ch32UartSubstrate>(sub_cfg);

    // ───── ControlPlane (reuse XiUOS CP) ─────
    control::XiuosUartControlPlane::Config cp_cfg;
    cp_cfg.backbone = backbone;
    cp_cfg.heartbeat_timeout = profile->heartbeat_timeout;
    cp_cfg.ready_timeout     = ctx.channel_cfg.wait_ready_timeout;
    auto control = std::make_unique<control::XiuosUartControlPlane>(cp_cfg);

    // ───── DataPlane (reuse XiUOS DP) ─────
    data::XiuosUartDataPlane::Config dp_cfg;
    dp_cfg.backbone = backbone;
    dp_cfg.poll_slice = profile->poll_slice;
    dp_cfg.program_timeout = profile->program_timeout;
    auto data_plane = std::make_unique<data::XiuosUartDataPlane>(dp_cfg);

    // ───── Components ─────
    runtime::ISubstrate*           substrate_raw = substrate.get();
    control::IControlPlane*        cp_raw        = control.get();
    data::IDataPlane*              dp_raw        = data_plane.get();
    data::XiuosUartDataPlane*      dp_xiuos      = data_plane.get();

    ChannelComponents out;
    out.shm          = nullptr;  // no ivshmem for XiUOS
    out.substrate    = std::move(substrate);
    out.control      = std::move(control);
    out.data         = std::move(data_plane);
    out.console      = std::make_unique<factory::NullConsoleSource>();
    out.console_ring = nullptr;
    out.steps        = nullptr;

    out.channel_cfg                  = ctx.channel_cfg;
    out.channel_cfg.backend_id       = "ch32_uart_xiuos";
    if (out.channel_cfg.n_workers == 0 || out.channel_cfg.n_workers > 1) {
        out.channel_cfg.n_workers = 1;  // XiUOS is single-worker
    }
    out.channel_cfg.max_payload_size = static_cast<std::size_t>(XIUOS_MAX_PAYLOAD);

    // ───── HealthMonitor (wedge relay + board-alive) ─────
    // 与 QEMU 路径同件:不挂 HeartbeatSensor(单 UART 上 Ping/WaitFrame 会和 PROGRAM/
    // RESULT race 吞 RESULT)。wedge 检测在 DP per-program timeout;WedgeRelaySensor 把
    // latched flag 转 health crash event → Recovery 经 ISubstrate::RebootVM(=板 reset)。
    health::HealthMonitorConfig health_cfg;
    health_cfg.expected_worker_count = 1;
    auto hm = std::make_unique<health::HealthMonitor>(
        health::HealthMonitorView{/* 空 view:Boot 时再 Bind */}, health_cfg);

    {
        health::WedgeRelaySensorConfig wc;
        wc.worker_id      = 0;
        wc.check_interval = std::chrono::milliseconds(500);
        hm->AddSensor(std::make_unique<health::WedgeRelaySensor>(
            [dp_xiuos] { return dp_xiuos && dp_xiuos->ConsumeWedgePending(); },
            wc));
    }
    // VmAliveSensor:兜底板死亡(Ch32UartSubstrate::IsVMAlive 返回 started_,不碰 serial)。
    {
        health::VmAliveSensorConfig vc;
        hm->AddSensor(std::make_unique<health::VmAliveSensor>(
            [substrate_raw] { return substrate_raw && substrate_raw->IsVMAlive(0); },
            vc));
    }
    health::HealthMonitor* hm_raw = hm.get();
    out.health = std::move(hm);

    // ───── Recovery (substrate RebootVM = board reset) ─────
    // 同 QEMU 路径策略:worker-dead 跳过单 worker 重启(全 no-op)→ unusable_ratio →
    // kRebootVm(板 reset,唯一能解 wedge)。max_vm_reboot 抬高:每个 wedging program
    // 都要 reset,不应几次后升级 kFailChannel。
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
                     "Ch32UartXiuosAssembler: Recovery.Create failed: " +
                         rec_r.error().message};
    }
    out.recovery = std::move(rec_r.value());

    return Result<ChannelComponents>::Ok(std::move(out));
}

Result<std::unique_ptr<IChannel>>
Ch32UartXiuosAssembler::AssembleAndBuild(const ChannelBuildContext& ctx) {
    auto comps_r = Ch32UartXiuosAssembler{}.Assemble(ctx);
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

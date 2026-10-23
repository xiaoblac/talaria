// SifiveUartXiuosAssembler 实现 — "qemu_uart_sifive_u" 后端(app-surface 面)
//
// 镜像 QemuUartXiuosAssembler:同样的 backbone/CP/DP/console/health/recovery 组装,
// 只把 substrate 配成 rv64 sifive_u + 二段 ELF(kernel.elf + app.bin),底座仍是共用的
// XiuosUartSubstrate(fork qemu-system-riscv64 + TCP serial)。这就是宪法
// xiuos-app-surface-fuzz.md §3.8 打通的 ecall 边界接进 fuzz 回路的落地。

#include "refuzz/channel/factory/sifive_uart_xiuos_assembler.hpp"

#include "refuzz/channel/channel_impl.hpp"  // Channel complete type for unique_ptr dtor
#include "refuzz/channel/control/xiuos_uart_control_plane.hpp"
#include "refuzz/channel/data/xiuos_uart_data_plane.hpp"
#include "refuzz/channel/factory/channel_builder.hpp"
#include "refuzz/channel/factory/mock_components.hpp"  // NullConsoleSource
#include "refuzz/channel/factory/sifive_uart_xiuos_profile.hpp"
#include "refuzz/channel/health/health_monitor.hpp"
#include "refuzz/channel/health/vm_alive_sensor.hpp"
#include "refuzz/channel/health/wedge_relay_sensor.hpp"
#include "refuzz/channel/infra/xiuos_uart_backbone.hpp"
#include "refuzz/channel/recovery/recovery.hpp"
#include "refuzz/channel/runtime/xiuos_uart_substrate.hpp"

#include <string>

namespace refuzz::channel {

std::string_view SifiveUartXiuosAssembler::Id() const {
    return "qemu_uart_sifive_u";
}

Result<ChannelComponents>
SifiveUartXiuosAssembler::Assemble(const ChannelBuildContext& ctx) {
    const auto* profile =
        dynamic_cast<const factory::SifiveUartXiuosProfile*>(ctx.backend_profile);
    if (profile == nullptr) {
        return Error{ErrorKind::kConfig,
                     "SifiveUartXiuosAssembler: backend_profile is not a SifiveUartXiuosProfile"};
    }
    if (profile->elf_path.empty()) {
        return Error{ErrorKind::kConfig,
                     "SifiveUartXiuosAssembler: SifiveUartXiuosProfile.elf_path is empty (kernel ELF)"};
    }
    // app_bin_path optional: absent → flat worker kernel (S1 wire/coverage
    // plumbing checkpoint); present → separate-compile + U-mode app loaded via
    // `-device loader` (S2 app-surface). The substrate adds the loader only when
    // it is non-empty.
    if (profile->serial_port == 0) {
        return Error{ErrorKind::kConfig,
                     "SifiveUartXiuosAssembler: SifiveUartXiuosProfile.serial_port is zero"};
    }

    // ───── Backbone (shared by CP + DP) — TCP serial (QEMU) ─────
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

    // ───── Substrate (shared XiuosUartSubstrate; rv64 sifive_u + 二段 ELF) ─────
    runtime::XiuosUartSubstrate::Config sub_cfg;
    sub_cfg.qemu_bin       = profile->qemu_bin;       // qemu-system-riscv64
    sub_cfg.elf_path       = profile->elf_path;       // kernel.elf
    sub_cfg.machine        = profile->machine;        // sifive_u
    sub_cfg.mem            = profile->mem;             // -m 256M
    sub_cfg.app_bin_path   = profile->app_bin_path;   // app.bin → -device loader
    sub_cfg.app_load_addr  = profile->app_load_addr;  // USERSPACE 0x80101000
    sub_cfg.serial_host    = profile->serial_host;
    sub_cfg.serial_port    = profile->serial_port;    // wire = uart1 (M4)
    sub_cfg.console_endpoint = profile->console_endpoint;  // uart0 console sink (M4)
    sub_cfg.shutdown_grace = profile->shutdown_grace;
    auto substrate = std::make_unique<runtime::XiuosUartSubstrate>(sub_cfg);

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
    out.channel_cfg.backend_id       = "qemu_uart_sifive_u";
    if (out.channel_cfg.n_workers == 0 || out.channel_cfg.n_workers > 1) {
        out.channel_cfg.n_workers = 1;  // XiUOS is single-worker
    }
    out.channel_cfg.max_payload_size = static_cast<std::size_t>(XIUOS_MAX_PAYLOAD);

    // ───── HealthMonitor (wedge relay + vm-alive) — 同 qemu_uart_xiuos ─────
    // 不挂 HeartbeatSensor(单 socket 上 Ping/WaitFrame 会和 PROGRAM/RESULT race 吞
    // RESULT)。wedge 检测在 DP per-program timeout;WedgeRelaySensor 把 latched flag
    // 转 health crash event → Recovery 经 ISubstrate::RebootVM 重启 QEMU。
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
    {
        health::VmAliveSensorConfig vc;
        hm->AddSensor(std::make_unique<health::VmAliveSensor>(
            [substrate_raw] { return substrate_raw && substrate_raw->IsVMAlive(0); },
            vc));
    }
    health::HealthMonitor* hm_raw = hm.get();
    out.health = std::move(hm);

    // ───── Recovery (substrate RebootVM = restart QEMU) — 同 qemu_uart_xiuos ─────
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
                     "SifiveUartXiuosAssembler: Recovery.Create failed: " +
                         rec_r.error().message};
    }
    out.recovery = std::move(rec_r.value());

    return Result<ChannelComponents>::Ok(std::move(out));
}

Result<std::unique_ptr<IChannel>>
SifiveUartXiuosAssembler::AssembleAndBuild(const ChannelBuildContext& ctx) {
    auto comps_r = SifiveUartXiuosAssembler{}.Assemble(ctx);
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

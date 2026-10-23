#pragma once

// RecoveryExe — 恢复执行层（channel/recovery 内部实现）
//
// [v3 Phase 6] 三轴派发：
//   输入收敛为 recovery::ExecPlan（SessionAction / SubstrateAction / MonitorAction）。
//   执行层只消费 plan，不做二次决策；按"monitor → substrate → session"顺序执行。
//
// 依赖切换（v4.0 Phase K 关键变化）：
//   v3 旧形态：runtime::Runtime* + IControlPlane* + IDataPlane* + IHealthMonitor*
//   v4.0 新形态：runtime::ISubstrate* + DeployBundle + IControlPlane* + IDataPlane* + IHealthMonitor*
//   Recovery 层不再感知具体 Runtime 类型；所有底座调用走 ISubstrate。
//   Reboot 后重新部署 worker 走 ISubstrate::DeployArtifacts(bundle)，
//   不再走 Runtime::DeployWorker（DeployWorker 是 Runtime 的过渡 API）。
//
// 注意：本文件为 channel/recovery 内部实现头，不对外暴露。
// 外部使用方请只包含 recovery.hpp（或 recovery_types.hpp 获取公共类型）。

#include "refuzz/channel/recovery/exec_plan.hpp"      // SessionAction / SubstrateAction / MonitorAction / ExecPlan
#include "refuzz/channel/recovery/recovery_types.hpp" // RecoveryResult / RecoveryConfig
#include "refuzz/channel/result.hpp"
#include "refuzz/channel/runtime/deploy_bundle.hpp"   // DeployBundle

#include <chrono>

namespace refuzz::channel::runtime  { class ISubstrate; }
namespace refuzz::channel::control  { class IControlPlane; }
namespace refuzz::channel::data     { class IDataPlane; }
namespace refuzz::channel::health   { class IHealthMonitor; }
namespace refuzz::channel::evidence { class IConsoleSource; }

namespace refuzz::channel::recovery {

class RecoveryExe {
public:
    // 构造（v4.0 Phase K 目标形态）。
    //   substrate      — VM 生命周期 / worker start-stop / deploy（仅 ISubstrate 接口）
    //   deploy_bundle  — Reboot 后 re-deploy worker binary 用；Recovery::Create 透传
    //   control_plane  — 会话 reset / worker reset / WaitReady
    //   data_plane     — inflight 采集 / Pause-Resume / slot reset
    //   health_monitor — MonitorAction::kRestartMonitor 及 Reboot 路径重启 console drain 需要；无则 nullptr
    //   console_source — Reboot 路径在 worker 启动前重开到新 qemu serial 用（见 ExecuteRebootInstance）；
    //                    无 console 的底座（如 UART）传 nullptr
    RecoveryExe(runtime::ISubstrate*      substrate,
                runtime::DeployBundle     deploy_bundle,
                control::IControlPlane*   control_plane,
                data::IDataPlane*         data_plane,
                health::IHealthMonitor*   health_monitor = nullptr,
                std::chrono::milliseconds worker_startup_timeout =
                    std::chrono::milliseconds{60'000},
                evidence::IConsoleSource* console_source = nullptr);
    ~RecoveryExe() = default;

    RecoveryExe(const RecoveryExe&)            = delete;
    RecoveryExe& operator=(const RecoveryExe&) = delete;

    // 执行三轴计划（Phase 6 主入口）
    //
    // 前置条件（由 Recovery 顶层保证，来自 QemuChannel 编排）：
    //   - 若 plan 含 session=All / substrate=Reboot：DataPlane.Pause() 已调用、inflight 已 drain
    //   - HealthMonitor 已停止 / Suspended（视 plan 类型）
    //
    // 执行顺序（§60_recovery.md §4.1）：
    //   1. monitor=Restart → HealthMonitor::Reboot
    //   2. substrate=Reboot → StopAllWorkers + RebootVM（合规组合要求同含 session=All）
    //   3. session 分派：Single / All
    //
    // 返回 inflight_executor_ids 有效性矩阵：
    //   - session=All / substrate=Reboot           → 采集全部 inflight
    //   - session=Single                            → 返回全量 inflight 快照（非目标 worker 子集）
    //   - monitor=Restart only                      → 空
    //   - {} （no-op）                              → 空
    Result<RecoveryResult> Execute(const ExecPlan& plan);

private:
    // session=All 序列：StopAllWorkers → DP.ResetAll → CP.ResetSession → BeginSession
    //   → DeployArtifacts → (StartWorker → WaitWorkerReady) × N
    Result<void>           ExecuteRestartAllWorkers();

    // substrate=Reboot 序列：DP.ResetAll → CP.ResetSession → StartServer → RebootVM
    //   → [重开 console 到新 serial] → DP.Prepare → [HealthMonitor.Reboot 重启 drain]
    //   → BeginSession → DeployArtifacts → (StartWorker → WaitWorkerReady) × N
    //
    // [console-drain-before-workers] RebootVM 是硬重启（kill qemu → 新 qemu + 新 serial.sock），
    //   worker 0 冷启动会灌大量 guest console 输出；ConsoleSensor 是该 socket 唯一 drain 者，若在
    //   worker 注册序列跑完之后才重启，drain 缺席窗口内 guest 8250 写路径死等 THRE → 耗尽 vCPU →
    //   整机失联 → WaitAllWorkersReady 卡 GUEST_REG_CLAIMED 超时。故把「重开 console + Reboot 监控」
    //   提前到 StartWorkersAndWaitReady 之前，与 Channel::Boot 同构（console Open→Prepare→HM.Start→
    //   worker 注册）。console_source_/health_monitor_ 为空则各自跳过。
    Result<void>           ExecuteRebootInstance();

    // session=Single 序列：SnapshotInflight → StopWorker → DP.ResetWorker → CP.ResetWorkerSession → StartWorker → WaitWorkerReady
    Result<RecoveryResult> ExecuteSingleWorkerRestart(uint32_t worker_id);

    // monitor=Restart 序列：HealthMonitor::Reboot
    Result<void>           ExecuteRestartHealthMonitor();

    runtime::ISubstrate*     substrate_;
    runtime::DeployBundle    deploy_bundle_;   // Reboot 后 re-deploy 专用
    control::IControlPlane*  cp_;
    data::IDataPlane*        dp_;
    health::IHealthMonitor*  health_monitor_;  // nullable；monitor=Restart 与 Reboot 路径使用
    std::chrono::milliseconds worker_startup_timeout_;
    evidence::IConsoleSource* console_source_;  // nullable；Reboot 路径重开新 qemu serial（非拥有，Channel 拥有）
};

} // namespace refuzz::channel::recovery

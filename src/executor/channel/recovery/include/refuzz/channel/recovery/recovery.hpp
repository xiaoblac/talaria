#pragma once

// Recovery — channel/recovery 子系统唯一 public 入口
//
// 内部持有并编排（§13.1 / §13.3.1）：
//   - RecoveryExe（执行层）：执行恢复动作序列
//   - IFaultPolicy / EscalationPolicy（策略层）：根据故障原因和历史统计决定动作
//   - FaultTracker（机制层）：维护窗口衰减、计数、recovery_in_progress、event_id 配对
//
// Recovery 不是薄转发层，而是内部编排层：
//   - ObserveFault：tracker 机制观测 → policy 决策 → tracker 事务绑定
//   - ExecuteRecovery：阶段门禁 → ExecPlan 构建 → RecoveryExe 执行
//   - Complete*：严格 event/action 配对 + 幂等完成回写
//
// 调用顺序（每次恢复）：
//   1. ObserveFault(...)                         → ObservationResult（含 action/abort_scope）
//      ↳ QemuChannel 做恢复前编排（pause/drain/stop-watcher 等）
//   2. ExecuteRecovery(action, ...)              → Result<RecoveryResult>
//      ↳ QemuChannel 做恢复后编排（resume/restart-watcher/generation-bump 等）
//   3. CompleteFullChannelRecovery(...)
//      或 CompleteSingleWorkerRecovery(...)
//
// 公共类型（RecoveryResult / RecoveryObservationResult / RecoverySnapshot / RecoveryConfig）
// 已收口到 recovery_types.hpp，外部只需包含该文件即可访问全部公共类型。
//
// 设计来源：channel/recovery/design.md §13

#include "refuzz/channel/result.hpp"
#include "refuzz/channel/recovery/recovery_contract.hpp" // IRecovery
#include "refuzz/channel/recovery/recovery_types.hpp"   // RecoveryResult / RecoveryObservationResult / RecoverySnapshot / ChannelRecoverySnapshot
#include "refuzz/channel/recovery/fault_policy.hpp"     // RecoveryConfig / IFaultPolicy / FaultContext / EscalationPolicy
#include "refuzz/channel/runtime/deploy_bundle.hpp"      // DeployBundle（Recovery 透传给 RecoveryExe）

#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>

namespace refuzz::channel::runtime  { class ISubstrate; }
namespace refuzz::channel::control  { class IControlPlane; }
namespace refuzz::channel::data     { class IDataPlane; }
namespace refuzz::channel::health   { class IHealthMonitor; }
namespace refuzz::channel::evidence { class IConsoleSource; }

namespace refuzz::channel::recovery {

// 内部协作者：完整定义在内部头文件（fault_tracker.hpp / recovery_exe.hpp）。
// QemuChannel 无需包含这些内部头文件。
class FaultTracker;
class RecoveryExe;
struct ExecPlan;  // 三轴 ExecPlan 定义在 exec_plan.hpp（内部实现读取）

// ============================================================
// Recovery — 顶层入口组件
// ============================================================

class Recovery : public IRecovery {
public:
    using Config            = RecoveryConfig;
    using ObservationResult = RecoveryObservationResult;
    using Snapshot          = RecoverySnapshot;

    // ── 工厂方法（唯一公开构造入口）────────────────────────────────────────────
    //
    // [v4.0 Phase K] 参数形态变化：
    //   v3.5：(config, runtime::Runtime*, IControlPlane*, IDataPlane*, IHealthMonitor*)
    //   v4.0：(config, runtime::ISubstrate*, DeployBundle, IControlPlane*, IDataPlane*, IHealthMonitor*)
    //
    // 关键变化：
    //   - Recovery 不再感知具体的 Runtime 类型，只依赖 ISubstrate 接口
    //   - Reboot 后的 re-deploy 走 ISubstrate::DeployArtifacts(bundle)，不再走
    //     runtime::Runtime::DeployWorker（DeployWorker 属于 Runtime 私有过渡 API）
    //   - Assembler 把 ChannelConfig.deploy_bundle 透传给 Recovery，RecoveryExe
    //     在 ExecuteRebootInstance 里直接使用
    //
    // config 非法 → Result::Error(kConfig)；成功 → Result::Ok(unique_ptr<Recovery>)。
    //   console_source — 透传给 RecoveryExe，Reboot 路径在 worker 启动前重开新 qemu serial 用；
    //                    无 console 的底座传 nullptr（Assembler 传 out.console.get()）。
    static Result<std::unique_ptr<Recovery>> Create(
        Config                       config,
        runtime::ISubstrate*         substrate,
        runtime::DeployBundle        deploy_bundle,
        control::IControlPlane*      control_plane,
        data::IDataPlane*            data_plane,
        health::IHealthMonitor*      health_monitor = nullptr,
        std::chrono::milliseconds    worker_startup_timeout =
            std::chrono::milliseconds{60'000},
        evidence::IConsoleSource*    console_source = nullptr);

    // 析构在 recovery.cpp 中定义，确保 FaultTracker / RecoveryExe 完整类型可见
    ~Recovery() override;

    Recovery(const Recovery&)            = delete;
    Recovery& operator=(const Recovery&) = delete;

    // ── IRecovery overrides ────────────────────────────────────────────────
    ObservationResult ObserveFault(uint64_t               fault_event_id,
                                   cc::ChannelFaultReason reason,
                                   cc::ChannelFaultSource source,
                                   const FaultContext&    context) override;

    Result<RecoveryResult> ExecuteRecovery(cc::ChannelFaultReason reason,
                                           cc::RecoveryAction     action,
                                           uint32_t               target_worker_id = UINT32_MAX) override;

    bool CompleteFullChannelRecovery(uint64_t           trigger_fault_event_id,
                                     cc::RecoveryAction action,
                                     bool               success) override;
    void CompleteSingleWorkerRecovery(uint32_t worker_id, bool success) override;

    void NoteHealthy() override;

    Snapshot GetSnapshot() const override;
    void Reset() override;

    // [v2 metric bus — 当前版本]
    // 转发给内部 FaultTracker，以便 UpdateCountForAction 里 Counter Inc() 调用。
    // 由 Channel::AttachObservabilityPublishers 调用；nullptr = 不发布 metric。
    void SetMetrics(refuzz::core::metrics::ChannelMetrics* metrics) noexcept override;  // [v2 metric bus]

private:
    // 私有构造：仅由 Create() 调用，外部不可直接构造
    Recovery(Config                     config,
             runtime::ISubstrate*       substrate,
             runtime::DeployBundle      deploy_bundle,
             control::IControlPlane*    control_plane,
             data::IDataPlane*          data_plane,
             health::IHealthMonitor*    health_monitor,
             std::chrono::milliseconds  worker_startup_timeout,
             evidence::IConsoleSource*  console_source);

    // ── 内部编排辅助 ───────────────────────────────────────────────────────
    // [v3 Phase 6] RecoveryAction (v2 枚举) → 三轴 ExecPlan 的 1:1 映射（§60 §7）。
    //   kRestartSingleWorker  → { session=Single, target=X }
    //   kRestartAllWorkers    → { session=All }
    //   kRebootVm             → { session=All, substrate=Reboot }
    //   kRestartHealthMonitor → { monitor=Restart }
    //   kNone / kFailChannel  → 上层已拦截，BuildExecPlan 仅保留 action 语义以防御式返回
    ExecPlan BuildExecPlan(cc::RecoveryAction action, uint32_t target_worker_id) const;

    // ── 内部协作者 ─────────────────────────────────────────────────────────
    std::unique_ptr<IFaultPolicy> policy_;    // 策略层（从 FaultTracker 上移）
    std::unique_ptr<FaultTracker> tracker_;   // 机制层
    std::unique_ptr<RecoveryExe>  exe_;       // 执行层
};

} // namespace refuzz::channel::recovery

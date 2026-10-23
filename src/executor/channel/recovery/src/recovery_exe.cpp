// RecoveryExe — 恢复执行层实现
//
// [v3 Phase 6] 三轴派发：
//   输入为 recovery::ExecPlan（SessionAction / SubstrateAction / MonitorAction）。
//   执行顺序（§60_recovery.md §4.1）：monitor → substrate → session。
//
// [v4.0 Phase K] 依赖收口为 ISubstrate：
//   底座操作 (Start/Stop/Reboot/DeployArtifacts) 经 ISubstrate 接口，不再感知
//   具体 runtime::Runtime。Reboot 后 re-deploy 使用 DeployBundle + DeployArtifacts，
//   不再调用已废弃的 Runtime::DeployWorker。

#include "refuzz/channel/recovery/recovery_exe.hpp"

#include "refuzz/channel/control/control_plane.hpp"
#include "refuzz/channel/data/data_plane.hpp"
#include "refuzz/channel/evidence/console_source.hpp"   // IConsoleSource / ConsoleEndpoint（Reboot 重开 console）
#include "refuzz/channel/health/health_monitor_contract.hpp"
#include "refuzz/channel/internal/worker_start_sequence.hpp"
#include "refuzz/channel/substrate/substrate_contract.hpp"

#include <cassert>
#include <chrono>
#include <string>
#include <utility>

namespace refuzz::channel::recovery {

RecoveryExe::RecoveryExe(runtime::ISubstrate*      substrate,
                         runtime::DeployBundle     deploy_bundle,
                         control::IControlPlane*   control_plane,
                         data::IDataPlane*         data_plane,
                         health::IHealthMonitor*   health_monitor,
                         std::chrono::milliseconds worker_startup_timeout,
                         evidence::IConsoleSource* console_source)
    : substrate_(substrate)
    , deploy_bundle_(std::move(deploy_bundle))
    , cp_(control_plane)
    , dp_(data_plane)
    , health_monitor_(health_monitor)
    , worker_startup_timeout_(worker_startup_timeout)
    , console_source_(console_source)
{}

namespace {

// [crash-terminal] One snapshot → all ids + the NOT-running (TASK_READY) subset.
// The Channel emits the idle subset as kCancelled (innocent, re-run) and the rest
// as kWorkerCrashed (crash-suspect, terminal). One snapshot keeps the two lists
// consistent (a second SnapshotInflight could race a worker pickup).
struct InflightSplit {
    std::vector<uint64_t> all;
    std::vector<uint64_t> idle;  // was_running == false
};
InflightSplit CollectInflightSplit(const data::IDataPlane* dp)
{
    InflightSplit s;
    if (!dp) return s;
    auto entries = dp->SnapshotInflight();
    s.all.reserve(entries.size());
    for (const auto& e : entries) {
        s.all.push_back(e.executor_id);
        if (!e.was_running) {
            s.idle.push_back(e.executor_id);
        }
    }
    return s;
}

// [single-worker inflight leak] One snapshot → the whole-channel lists plus the
// subset owned by `worker_id`. Single-worker restart needs both: the whole list to
// stay contract-compatible (§13.10 row 8 forbids emitting abnormal completions for
// it), and the target subset because that worker's own in-flight task is about to
// be destroyed by StopWorker and would otherwise never reach a terminal event.
// Both come from ONE SnapshotInflight for the same reason CollectInflightSplit
// does: a second snapshot could race a worker pickup and make the lists disagree.
struct InflightSplitWithTarget {
    InflightSplit all;
    InflightSplit target;
};
InflightSplitWithTarget CollectInflightSplitWithTarget(const data::IDataPlane* dp,
                                                      uint32_t worker_id)
{
    InflightSplitWithTarget s;
    if (!dp) return s;
    auto entries = dp->SnapshotInflight();
    s.all.all.reserve(entries.size());
    for (const auto& e : entries) {
        s.all.all.push_back(e.executor_id);
        if (!e.was_running) {
            s.all.idle.push_back(e.executor_id);
        }
        if (e.worker_id == worker_id) {
            s.target.all.push_back(e.executor_id);
            if (!e.was_running) {
                s.target.idle.push_back(e.executor_id);
            }
        }
    }
    return s;
}

Error PreserveKind(const Error& error, const std::string& prefix)
{
    return Error{error.kind, prefix + ": " + error.message};
}

} // namespace

// ── Execute — 主入口 ─────────────────────────────────────────────────────────
// 顺序：monitor → substrate → session；任一步失败整体返回。

Result<RecoveryResult> RecoveryExe::Execute(const ExecPlan& plan)
{
    // 1. MonitorAction 先走（与 session/substrate 互不干涉）
    if (plan.monitor == MonitorAction::kRestartMonitor) {
        auto r = ExecuteRestartHealthMonitor();
        if (!r.ok()) {
            return PreserveKind(r.error(), "Execute(monitor=Restart) failed");
        }
    }

    // 2. SubstrateAction：Reboot 必然附带 session=All（合规组合约束）
    if (plan.substrate == SubstrateAction::kRebootInstance) {
        assert(plan.session == SessionAction::kRestartAllWorkers);
        auto inflight = CollectInflightSplit(dp_);
        auto r = ExecuteRebootInstance();
        if (!r.ok()) {
            return PreserveKind(r.error(), "Execute(substrate=Reboot) failed");
        }
        return Result<RecoveryResult>::Ok(RecoveryResult{
            .action                     = cc::RecoveryAction::kRebootVm,
            .inflight_executor_ids      = std::move(inflight.all),
            .inflight_idle_executor_ids = std::move(inflight.idle),
            // 非 kRestartSingleWorker：目标 worker 概念不适用（本 action 的在飞任务
            // 已由上面两个列表覆盖），见 recovery_types.hpp 的有效性矩阵。
            .target_worker_inflight_executor_ids      = {},
            .target_worker_inflight_idle_executor_ids = {},
        });
    }

    // 3. SessionAction
    switch (plan.session) {
    case SessionAction::kNone:
        // monitor-only 或 no-op 路径
        return Result<RecoveryResult>::Ok(RecoveryResult{
            .action                = (plan.monitor == MonitorAction::kRestartMonitor)
                                         ? cc::RecoveryAction::kRestartHealthMonitor
                                         : cc::RecoveryAction::kNone,
            .inflight_executor_ids      = {},
            .inflight_idle_executor_ids = {},
            // 非 kRestartSingleWorker：目标 worker 概念不适用（本 action 的在飞任务
            // 已由上面两个列表覆盖），见 recovery_types.hpp 的有效性矩阵。
            .target_worker_inflight_executor_ids      = {},
            .target_worker_inflight_idle_executor_ids = {},
        });
    case SessionAction::kRestartSingleWorker:
        return ExecuteSingleWorkerRestart(plan.target_worker_id);
    case SessionAction::kRestartAllWorkers: {
        auto inflight = CollectInflightSplit(dp_);
        auto r = ExecuteRestartAllWorkers();
        if (!r.ok()) {
            return PreserveKind(r.error(), "Execute(session=All) failed");
        }
        return Result<RecoveryResult>::Ok(RecoveryResult{
            .action                     = cc::RecoveryAction::kRestartAllWorkers,
            .inflight_executor_ids      = std::move(inflight.all),
            .inflight_idle_executor_ids = std::move(inflight.idle),
            // 非 kRestartSingleWorker：目标 worker 概念不适用（本 action 的在飞任务
            // 已由上面两个列表覆盖），见 recovery_types.hpp 的有效性矩阵。
            .target_worker_inflight_executor_ids      = {},
            .target_worker_inflight_idle_executor_ids = {},
        });
    }
    }

    return Error{ErrorKind::kRecovery, "Execute: unrecognized SessionAction"};
}

// ── ExecuteRestartAllWorkers ─────────────────────────────────────────────────
// 当前序列遵守 session 合同：
//   StopAllWorkers → DP.ResetAll → CP.ResetSession → CP.BeginSession
//     → DeployArtifacts → (StartWorker → WaitWorkerReady) × N
Result<void> RecoveryExe::ExecuteRestartAllWorkers()
{
    if (substrate_ == nullptr || cp_ == nullptr || dp_ == nullptr) {
        return Error{ErrorKind::kRecovery,
                     "ExecuteRestartAllWorkers: substrate/cp/dp must be non-null"};
    }

    auto r1 = substrate_->StopAllWorkers(0);
    if (!r1.ok()) {
        return PreserveKind(r1.error(), "StopAllWorkers failed");
    }

    dp_->ResetAll();

    auto r2 = cp_->ResetSession();
    if (!r2.ok()) {
        return PreserveKind(r2.error(), "CP.ResetSession failed");
    }

    auto r3 = cp_->BeginSession();
    if (!r3.ok()) {
        return PreserveKind(r3.error(), "CP.BeginSession failed");
    }

    auto r4 = substrate_->DeployArtifacts(0, deploy_bundle_);
    if (!r4.ok()) {
        return PreserveKind(r4.error(), "DeployArtifacts failed");
    }

    auto r5 = internal::StartWorkersAndWaitReady(
        *substrate_, *cp_, 0, cp_->MaxWorkerSlots(),
        worker_startup_timeout_);
    if (!r5.ok()) {
        return PreserveKind(r5.error(), "worker startup sequence failed");
    }

    return Result<void>::Ok();
}

// ── ExecuteRebootInstance ────────────────────────────────────────────────────
// 序列：DP.ResetAll → CP.ResetSession → DP.StartServer → RebootVM → DP.Prepare
//     → CP.BeginSession → DeployArtifacts → (StartWorker → WaitWorkerReady) × N
// ResetAll/ResetSession 在 Reboot 前执行：Reboot 失败时 slot 已清零，重试不会重复消费旧 executor_id。
//
// [v4.0 Phase K] DeployArtifacts 替代 DeployWorker：走 ISubstrate 接口而非
//   Runtime 过渡 API；DeployBundle 由 Assembler 从 ChannelConfig 透传进来。

Result<void> RecoveryExe::ExecuteRebootInstance()
{
    if (substrate_ == nullptr || cp_ == nullptr || dp_ == nullptr) {
        return Error{ErrorKind::kRecovery,
                     "ExecuteRebootInstance: substrate/cp/dp must be non-null"};
    }

    dp_->ResetAll();

    auto r1 = cp_->ResetSession();
    if (!r1.ok()) {
        return PreserveKind(r1.error(), "CP.ResetSession failed");
    }

    auto r2 = dp_->StartServer();
    if (!r2.ok()) {
        return PreserveKind(r2.error(), "DP.StartServer failed");
    }

    auto r3 = substrate_->RebootVM(0);
    if (!r3.ok()) {
        return PreserveKind(r3.error(), "RebootVM failed");
    }

    auto clear_proc_state = cp_->ClearProcIsolationState();
    if (!clear_proc_state.ok()) {
        return PreserveKind(clear_proc_state.error(),
                            "CP.ClearProcIsolationState failed");
    }

    // [console-drain-before-workers] RebootVM 硬重启后旧 console_source_ 的 fd 指向已死的 qemu；
    //   重开到新 qemu 的 serial（路径不变、连接是新的）。与 Channel::Boot 里「StartVM 后 Open
    //   console」同构，放在 worker 注册序列之前，让下面的 HealthMonitor.Reboot 起来的 ConsoleSensor
    //   能持续 drain worker 0 冷启动的 console 洪峰。Open 失败不致命：ConsoleSensor 按 idle 自洽退出，
    //   不阻塞握手。console 为空的底座（UART 等）跳过。
    if (console_source_ != nullptr) {
        console_source_->Close();
        evidence::ConsoleEndpoint ep = substrate_->DefaultConsoleEndpoint(0);
        (void)console_source_->Open(ep);
    }

    auto r4 = dp_->Prepare();
    if (!r4.ok()) {
        return PreserveKind(r4.error(), "DP.Prepare failed");
    }

    // [console-drain-before-workers] 提前一步启动 monitor：Reboot()=Stop()+Start() 重建全部 sensor
    //   （清 ghost parked_count_、worker_alive_bits_ 重置全活、新基线），新 ConsoleSensor 线程接管上面
    //   刚重开的新 serial 并持续 drain。与 Channel::Boot 里「Prepare 后 HealthMonitor.Start」同构：必须
    //   在 StartWorkersAndWaitReady 之前，drain 才能覆盖 worker 0 的 console 洪峰，避免 guest 8250 写路径
    //   死等 THRE → vCPU 耗尽 → GUEST_REG_CLAIMED 握手超时。HeartbeatSensor 靠 grace_rounds_after_rearm
    //   吸收冷启动抖动（同 boot）。health_monitor_ 为空则跳过（无 health 的底座）。
    if (health_monitor_ != nullptr) {
        auto rhm = health_monitor_->Reboot();
        if (!rhm.ok()) {
            return PreserveKind(rhm.error(), "HealthMonitor.Reboot (pre-worker-startup) failed");
        }
    }

    auto r5 = cp_->BeginSession();
    if (!r5.ok()) {
        return PreserveKind(r5.error(), "CP.BeginSession failed");
    }

    auto r6 = substrate_->DeployArtifacts(0, deploy_bundle_);
    if (!r6.ok()) {
        return PreserveKind(r6.error(), "DeployArtifacts failed");
    }

    auto r7 = internal::StartWorkersAndWaitReady(
        *substrate_, *cp_, 0, cp_->MaxWorkerSlots(),
        worker_startup_timeout_);
    if (!r7.ok()) {
        return PreserveKind(r7.error(), "worker startup sequence failed");
    }

    return Result<void>::Ok();
}

// ── ExecuteSingleWorkerRestart ────────────────────────────────────────────────
// 序列：SnapshotInflight → StopWorker → DP.ResetWorker → CP.ResetWorkerSession → StartWorker → WaitWorkerReady
//
// 注意（§13.10 row 8）：inflight_executor_ids 是全量快照，QemuChannel 不得据它发批量
// 异常完成。但 target_worker_inflight_* 是被重启 worker 自己的那一份，Channel **必须**
// 据它发异常完成 —— 否则 StopWorker 之后那条任务既无 completion 也无 abnormal，任何
// 按终结事件计数的宿主侧观察者都会每次重启泄漏一条（见 recovery_types.hpp 的说明）。

Result<RecoveryResult> RecoveryExe::ExecuteSingleWorkerRestart(uint32_t worker_id)
{
    if (substrate_ == nullptr || cp_ == nullptr || dp_ == nullptr) {
        return Error{ErrorKind::kRecovery,
                     "ExecuteSingleWorkerRestart: substrate/cp/dp must be non-null"};
    }

    // Snapshot BEFORE StopWorker: afterwards the worker's slot is gone and its
    // in-flight task is unrecoverable.
    auto inflight = CollectInflightSplitWithTarget(dp_, worker_id);

    auto r1 = substrate_->StopWorker(0, worker_id);
    if (!r1.ok()) {
        return PreserveKind(r1.error(), "StopWorker failed");
    }

    dp_->ResetWorker(worker_id);

    auto r2 = cp_->ResetWorkerSession(worker_id);
    if (!r2.ok()) {
        return PreserveKind(r2.error(), "CP.ResetWorkerSession failed");
    }

    auto r3 = substrate_->StartWorker(0, worker_id);
    if (!r3.ok()) {
        return PreserveKind(r3.error(), "StartWorker failed");
    }

    auto r4 = cp_->WaitWorkerReady(worker_id, std::chrono::milliseconds{0});
    if (!r4.ok()) {
        return PreserveKind(r4.error(), "CP.WaitWorkerReady failed");
    }

    return Result<RecoveryResult>::Ok(RecoveryResult{
        .action                     = cc::RecoveryAction::kRestartSingleWorker,
        .inflight_executor_ids      = std::move(inflight.all.all),
        .inflight_idle_executor_ids = {},
        .target_worker_inflight_executor_ids      = std::move(inflight.target.all),
        .target_worker_inflight_idle_executor_ids = std::move(inflight.target.idle),
    });
}

// ── ExecuteRestartHealthMonitor ───────────────────────────────────────────────
// 序列：health_monitor_->Reboot()

Result<void> RecoveryExe::ExecuteRestartHealthMonitor()
{
    if (health_monitor_ == nullptr) {
        return Error{ErrorKind::kRecovery,
                     "ExecuteRestartHealthMonitor: health_monitor_ is null (programming error)"};
    }

    auto r = health_monitor_->Reboot();
    if (!r.ok()) {
        return PreserveKind(r.error(), "HealthMonitor::Reboot failed");
    }

    return Result<void>::Ok();
}

} // namespace refuzz::channel::recovery

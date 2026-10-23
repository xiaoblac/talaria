// recovery.cpp — Recovery 顶层组件实现（编排层，非转发层）
//
// Recovery 在内部完成"观测 → 决策 → 执行 → 完成回写"的阶段组合：
//   - ObserveFault：tracker.ObserveFault → policy.Decide → tracker.TryBeginRecovery
//   - ExecuteRecovery：阶段门禁 → ExecPlan → exe_.Execute
//   - CompleteFullChannelRecovery：严格 event/action 配对 + 幂等
//   - kFailChannel 不进入执行层，返回终态结果
//
// [v3 Phase 6] 依赖切换：
//   不再持 transport::Transport*；改持 control::IControlPlane* + data::IDataPlane*，
//   直接透传给 RecoveryExe。BuildExecPlan 把 v2 cc::RecoveryAction 映射为三轴 ExecPlan。

#include "refuzz/channel/recovery/recovery.hpp"
#include "refuzz/channel/recovery/recovery_exe.hpp"
#include "refuzz/channel/recovery/fault_tracker.hpp"
#include "refuzz/channel/substrate/substrate_contract.hpp"

#include "refuzz/core/metrics/channel_metrics.hpp"  // [v2 metric bus]

#include <utility>

namespace refuzz::channel::recovery {

namespace {

std::unique_ptr<IFaultPolicy> BuildPolicy(const Recovery::Config& config)
{
    if (config.policy.factory) {
        auto policy = config.policy.factory(config.policy.escalation);
        if (policy) {
            return policy;
        }
    }
    return std::make_unique<EscalationPolicy>(config.policy.escalation);
}

// Config 校验改为 Result 语义，与整体错误处理风格一致，不再抛异常。
static Result<void> Validate(const Recovery::Config& config)
{
    if (config.mechanism.fault_window_ms == 0) {
        return Error{ErrorKind::kConfig,
            "RecoveryConfig invalid: mechanism.fault_window_ms must be > 0"};
    }
    if (config.mechanism.healthy_streak_to_reset == 0) {
        return Error{ErrorKind::kConfig,
            "RecoveryConfig invalid: mechanism.healthy_streak_to_reset must be > 0"};
    }
    if (config.policy.escalation.unusable_ratio_reboot_threshold_pct > 100) {
        return Error{ErrorKind::kConfig,
            "RecoveryConfig invalid: policy.escalation.unusable_ratio_reboot_threshold_pct must be <= 100"};
    }
    return Result<void>::Ok();
}

} // namespace

// ── 工厂方法 Create ──────────────────────────────────────────────────────────

Result<std::unique_ptr<Recovery>> Recovery::Create(
    Config                       config,
    runtime::ISubstrate*         substrate,
    runtime::DeployBundle        deploy_bundle,
    control::IControlPlane*      control_plane,
    data::IDataPlane*            data_plane,
    health::IHealthMonitor*      health_monitor,
    std::chrono::milliseconds    worker_startup_timeout,
    evidence::IConsoleSource*    console_source)
{
    auto v = Validate(config);
    if (!v.ok()) return v.error();

    return Result<std::unique_ptr<Recovery>>::Ok(
        std::unique_ptr<Recovery>(
            new Recovery(std::move(config),
                         substrate,
                         std::move(deploy_bundle),
                         control_plane,
                         data_plane,
                         health_monitor,
                         worker_startup_timeout,
                         console_source)));
}

// ── 私有构造 / 析构 ──────────────────────────────────────────────────────────

Recovery::Recovery(Config                     config,
                   runtime::ISubstrate*       substrate,
                   runtime::DeployBundle      deploy_bundle,
                   control::IControlPlane*    control_plane,
                   data::IDataPlane*          data_plane,
                   health::IHealthMonitor*    health_monitor,
                   std::chrono::milliseconds  worker_startup_timeout,
                   evidence::IConsoleSource*  console_source)
{
    policy_  = BuildPolicy(config);

    tracker_ = std::make_unique<FaultTracker>(
        FaultTrackerConfig{
            config.mechanism.fault_window_ms,
            config.mechanism.healthy_streak_to_reset,
            config.mechanism.recovery_window_base_ms,
            config.mechanism.recovery_window_cap_ms,
            config.mechanism.cascade_window_ms});

    exe_ = std::make_unique<RecoveryExe>(
        substrate,
        std::move(deploy_bundle),
        control_plane,
        data_plane,
        health_monitor,
        worker_startup_timeout,
        console_source);
}

Recovery::~Recovery() = default;

// ── Phase 1：ObserveFault — 观测 → 决策 → 事务绑定 ──────────────────────────

Recovery::ObservationResult Recovery::ObserveFault(uint64_t            fault_event_id,
                                                   cc::ChannelFaultReason  reason,
                                                   cc::ChannelFaultSource  source,
                                                   const FaultContext& context)
{
    (void)source;

    ObservationResult result;

    auto obs = tracker_->ObserveFault(fault_event_id, context);
    if (!obs.can_proceed) {
        return result;
    }

    auto decision = policy_->Decide(reason, obs.history, context);

    result.accepted         = true;
    result.abort_scope      = decision.abort_scope;
    result.recovery_action  = decision.action;
    result.target_worker_id = decision.target_worker_id;

    if (decision.action == cc::RecoveryAction::kNone) {
        return result;
    }

    if (FaultTracker::IsFullChannelAction(decision.action)) {
        bool bound = tracker_->TryBeginRecovery(fault_event_id, reason, decision.action);
        if (!bound) {
            result.accepted = false;
            return result;
        }
    }

    return result;
}

// ── Phase 2：ExecuteRecovery — 阶段门禁 → ExecPlan → 执行 ──────────────────

Result<RecoveryResult> Recovery::ExecuteRecovery(cc::ChannelFaultReason reason,
                                                 cc::RecoveryAction     action,
                                                 uint32_t           target_worker_id)
{
    (void)reason;

    if (action == cc::RecoveryAction::kFailChannel) {
        return Result<RecoveryResult>::Ok(RecoveryResult{
            .action                     = cc::RecoveryAction::kFailChannel,
            .inflight_executor_ids      = {},
            .inflight_idle_executor_ids = {},
            // 非 kRestartSingleWorker：目标 worker 概念不适用（本 action 的在飞任务
            // 已由上面两个列表覆盖），见 recovery_types.hpp 的有效性矩阵。
            .target_worker_inflight_executor_ids      = {},
            .target_worker_inflight_idle_executor_ids = {},
        });
    }

    auto plan = BuildExecPlan(action, target_worker_id);
    auto res  = exe_->Execute(plan);
    if (!res.ok()) {
        return res.error();
    }

    // 保证 RecoveryResult.action 与入参 action 一致（ExecuteSingleWorkerRestart 等已填充，这里做兜底）
    auto value = std::move(res.value());
    value.action = action;
    return Result<RecoveryResult>::Ok(std::move(value));
}

// ── Phase 3a：CompleteFullChannelRecovery — 严格配对 + 幂等 ─────────────────

bool Recovery::CompleteFullChannelRecovery(uint64_t       trigger_fault_event_id,
                                           cc::RecoveryAction action,
                                           bool           success)
{
    bool paired = tracker_->CompleteRecovery(trigger_fault_event_id, action, success);
    if (paired) {
        policy_->OnRecoveryComplete(
            cc::ChannelFaultReason::kWorkerHeartbeatLost,
            action, success);
    }
    return paired;
}

// ── Phase 3b：CompleteSingleWorkerRecovery ──────────────────────────────────

void Recovery::CompleteSingleWorkerRecovery(uint32_t worker_id, bool success)
{
    tracker_->NoteSingleWorkerRecoveryComplete(worker_id, success);
}

// ── 健康信号 ────────────────────────────────────────────────────────────────

void Recovery::NoteHealthy()
{
    tracker_->NoteHealthy();
}

// ── 只读观测 ────────────────────────────────────────────────────────────────

Recovery::Snapshot Recovery::GetSnapshot() const
{
    RecoverySnapshot snap = tracker_->GetSnapshot();
    snap.policy = policy_->GetSnapshot();
    return snap;
}

void Recovery::Reset()
{
    tracker_->Reset();
    policy_->Reset();
}

// ── SetMetrics ────────────────────────────────────────────────────────────────

// [v2 metric bus — 当前版本]
// 转发给内部 FaultTracker。Channel::AttachObservabilityPublishers 在 Attach 时调用。
void Recovery::SetMetrics(refuzz::core::metrics::ChannelMetrics* metrics) noexcept
{
    if (tracker_) tracker_->SetMetrics(metrics);
}

// ── 内部编排辅助 ────────────────────────────────────────────────────────────
//
// [v3 Phase 6] cc::RecoveryAction (v2 枚举) → 三轴 ExecPlan 的 1:1 映射（§60_recovery.md §7）。
// 旧 cc::RecoveryAction 继续留给 telemetry/observability schema；executor-level 逻辑走 ExecPlan。

ExecPlan Recovery::BuildExecPlan(cc::RecoveryAction action, uint32_t target_worker_id) const
{
    ExecPlan plan;
    switch (action) {
    case cc::RecoveryAction::kNone:
    case cc::RecoveryAction::kFailChannel:
    case cc::RecoveryAction::kReloadSnapshot:
        // kReloadSnapshot 只由 SnapshotRecovery 自处理，不经此标准 Recovery 的
        // BuildExecPlan；到这里视为编程错误，防御式返回空 plan。
        break;
    case cc::RecoveryAction::kRestartSingleWorker:
        plan.session          = SessionAction::kRestartSingleWorker;
        plan.target_worker_id = target_worker_id;
        break;
    case cc::RecoveryAction::kRestartAllWorkers:
        plan.session = SessionAction::kRestartAllWorkers;
        break;
    case cc::RecoveryAction::kRebootVm:
        plan.session   = SessionAction::kRestartAllWorkers;
        plan.substrate = SubstrateAction::kRebootInstance;
        break;
    case cc::RecoveryAction::kRestartHealthMonitor:
        plan.monitor = MonitorAction::kRestartMonitor;
        break;
    }
    return plan;
}

} // namespace refuzz::channel::recovery

// EscalationPolicy 实现
// 设计来源：docs/channel-redesign/components/channel.md §4

#include "refuzz/channel/recovery/fault_policy.hpp"

namespace refuzz::channel::recovery {

namespace {

bool IsValidSourceWorker(const FaultContext& context)
{
    return context.total_workers > 0 &&
           context.source_worker_id < context.total_workers;
}

uint32_t ComputeUnusableRatioPct(const FaultContext& context)
{
    if (context.total_workers == 0) {
        return 100;
    }
    const uint32_t capped_unusable =
        (context.unusable_workers > context.total_workers)
            ? context.total_workers
            : context.unusable_workers;
    return static_cast<uint32_t>(
        (static_cast<uint64_t>(capped_unusable) * 100ULL) /
        static_cast<uint64_t>(context.total_workers));
}

cc::ChannelAbortScope AbortScopeForAction(cc::RecoveryAction action)
{
    switch (action) {
    case cc::RecoveryAction::kRestartSingleWorker:
        return cc::ChannelAbortScope::kSlot;
    case cc::RecoveryAction::kRestartAllWorkers:
    case cc::RecoveryAction::kRebootVm:
    case cc::RecoveryAction::kFailChannel:
        return cc::ChannelAbortScope::kChannel;
    case cc::RecoveryAction::kRestartHealthMonitor:
        return cc::ChannelAbortScope::kNone;
    case cc::RecoveryAction::kNone:
    default:
        return cc::ChannelAbortScope::kNone;
    }
}

// RebootOrDamp — reboot 准入 + 级联阻尼。
//   佐证型死亡（qemu 退 / daemon 显式死亡）：预算内立即 reboot,绕过 recovery-window *延迟*——
//     确凿故障不该被自我放大的 liveness 误判保护窗拖延。但 cascade/reboot 硬上限**仍适用**:
//     反复确凿死亡 = reboot 治不好它,继续只是空转 → 预算耗尽放弃通道(kFailChannel),
//     不是无限 reboot(旧实现 corroborated 无条件 reboot → 4516 次风暴的末端放大器)。
//   推断型（聚合冻结 / 队列退化阈值 / ssh-dead）：受治理——这正是自我放大的 liveness 误判
//     该被压的地方。保护窗内不 reboot；cascade 预算耗尽则退避（kNone，隔离/退避）。
//   本函数只服务 VM 基础设施故障路径；真 kernel crash（kKernelCrash）走
//   RebootOnKernelCrash —— 那是"发现"不是故障，不适用 cascade 预算。
cc::RecoveryAction RebootOrDamp(const EscalationPolicy::Config& cfg,
                                const FaultHistory&             history,
                                bool                            corroborated)
{
    if (corroborated) {
        // 硬上限对确凿型也生效。两计数器互补:cascade budget 抓"reboot 成功但 VM 反复
        //   再死"(成功才 ++ reboots_in_cascade_window);vm_reboot_count 抓"reboot 本身
        //   一直失败"(begin 即 ++,失败不清零)。任一耗尽 → kFailChannel。
        if (history.reboots_in_cascade_window >= cfg.cascade_reboot_budget ||
            history.vm_reboot_count           >= cfg.max_vm_reboot_attempts) {
            return cc::RecoveryAction::kFailChannel;
        }
        return cc::RecoveryAction::kRebootVm;
    }
    if (history.in_recovery_window) {
        return cc::RecoveryAction::kNone;
    }
    if (history.reboots_in_cascade_window >= cfg.cascade_reboot_budget) {
        return cc::RecoveryAction::kNone;
    }
    if (history.vm_reboot_count < cfg.max_vm_reboot_attempts) {
        return cc::RecoveryAction::kRebootVm;
    }
    return cc::RecoveryAction::kFailChannel;
}

// RebootOnKernelCrash — 真 kernel bug 的 reboot 准入。
//   kKernelCrash 是 console 命中的确凿内核崩溃（panic/BUG/KASAN，且已过
//   is_real_kernel_crash 良性告警过滤），是**发现**而不是基础设施故障：每次崩溃都值得
//   reboot 继续跑，与 syzkaller 对齐，不受 cascade budget / 保护窗约束（高频真 bug 或
//   不同 bug 反复崩溃都不熔断通道，也不消耗基础设施的级联预算）。
//   唯一保留的封顶是 vm_reboot_count —— 其语义是"reboot 连续失败次数"（成功即清零）：
//   reboot 机制本身起不来 = 基础设施问题，继续尝试只是空转 → kFailChannel。
cc::RecoveryAction RebootOnKernelCrash(const EscalationPolicy::Config& cfg,
                                       const FaultHistory&             history)
{
    if (history.vm_reboot_count >= cfg.max_vm_reboot_attempts) {
        return cc::RecoveryAction::kFailChannel;
    }
    return cc::RecoveryAction::kRebootVm;
}

} // namespace

PolicyDecision EscalationPolicy::Decide(cc::ChannelFaultReason reason,
                                        const FaultHistory& history,
                                        const FaultContext& context)
{
    PolicyDecision decision;

    switch (reason) {
    case cc::ChannelFaultReason::kExecutionDomainHung:
        // The daemon explicitly reported that execution-domain ownership was
        // not reclaimed. Starting another worker with the same worker ID could
        // overlap that domain, so recover at VM scope.
        decision.action = RebootOrDamp(config_, history, /*corroborated=*/true);
        break;

    case cc::ChannelFaultReason::kNoOutput:
        // VM 级 no-output（forward-progress frozen，推断型，inferred=true）：
        //   FaultKind::kNoOutput 保持"可汇报 finding"语义（crash pipeline
        //   落 no_output bucket、exec_code=kCrashed），但 reboot 准入与推断型
        //   kVmDead 一致 —— 受 recovery-window / cascade / backoff 治理。
        //   不再用 RebootOnKernelCrash：那会绕过 cascade 预算，冻结反复出现时
        //   会变成无封顶 reboot 循环（旧 retained-deadline 是低频事件可以豁免，
        //   现在它是连续 liveness 信号，必须受阻尼）。佐证型 kNoOutput（未来
        //   可能出现的确认死因）仍走 corroborated 分支立即 reboot。
        decision.action = RebootOrDamp(config_, history, context.corroborated);
        break;

    case cc::ChannelFaultReason::kWorkerHarnessFatal:
        // The daemon reported an unrecoverable execution-domain failure and
        // exited. This is confirmed worker death, not an inferred heartbeat
        // miss, so the post-reboot recovery window must not absorb it.
        if (IsValidSourceWorker(context) &&
            history.source_worker_failed_recovery_count <
                config_.max_single_worker_restart_attempts) {
            decision.action = cc::RecoveryAction::kRestartSingleWorker;
            decision.target_worker_id = context.source_worker_id;
        } else {
            // A confirmed worker failure that outlives the per-worker restart
            // budget escalates regardless of the current unusable-worker ratio.
            decision.action = RebootOrDamp(config_, history, /*corroborated=*/true);
        }
        break;

    case cc::ChannelFaultReason::kWorkerHeartbeatLost:
    case cc::ChannelFaultReason::kInflightStale: {
        // [级联断路·保护窗] reboot 刚完成、workers 还在重新注册：心跳 miss 是预期的
        //   （冷 boot + re-registration 延迟），一律 kNone 吸收，连单 worker 重启都不做
        //   （重启一个正在注册的 worker 只会拖更久）。这是 policy 侧的断路；sensor 侧的
        //   verdict 抑制是另一层冗余保护。
        if (history.in_recovery_window) {
            decision.action = cc::RecoveryAction::kNone;
            break;
        }
        // 心跳路径（检测器 B 已做相对进度门控：到这里的都是"本 worker 冻结 while
        //   聚合在前进"的真卡，不是全局饿死）。恢复范围跟着故障走、不动健康 worker：
        //   ① 有合法 source 且重试预算未用尽 → 只重启那一个 worker；
        //   ② 否则掉的 worker 占比 ≥ 阈值 → RebootOrDamp（一次 reboot 收回全队，
        //      推断型，受阻尼）；
        //   ③ 否则 kNone → 隔离该 worker、跑降级（N-1）。
        // 不再有 kRestartAllWorkers——单 worker 卡只动那一个；reboot 只在掉太多 /
        // VM 级死亡时发生。
        if (IsValidSourceWorker(context) &&
            history.source_worker_failed_recovery_count <
                config_.max_single_worker_restart_attempts) {
            decision.action = cc::RecoveryAction::kRestartSingleWorker;
            decision.target_worker_id = context.source_worker_id;
            break;
        }

        const uint32_t unusable_ratio_pct = ComputeUnusableRatioPct(context);
        if (unusable_ratio_pct >= config_.unusable_ratio_reboot_threshold_pct) {
            // 心跳引发的 reboot 是"掉太多 → 收回全队"的推断型，受 cascade 阻尼。
            decision.action = RebootOrDamp(config_, history, /*corroborated=*/false);
        } else {
            decision.action = cc::RecoveryAction::kNone;
        }
        break;
    }

    case cc::ChannelFaultReason::kVmDead:
        // VM 路径：佐证型(qemu 退) 预算内立即 reboot 不受阻尼；
        //   推断型(聚合前进时钟冻结超 vm_dead_timeout) 受 recovery-window + cascade
        //   budget 治理。corroborated 由 Channel 从 CrashEvent.inferred 推出填入。
        decision.action = RebootOrDamp(config_, history, context.corroborated);
        break;

    case cc::ChannelFaultReason::kKernelCrash:
        // 真内核 bug（console panic/BUG/KASAN，已过良性过滤）：发现而非故障 → 立即
        //   reboot，不受 cascade budget / 保护窗约束（corroborated 恒为 true，console
        //   路径无推断；若未来出现推断型 kKernelCrash，回退到受治理的 RebootOrDamp）。
        decision.action = context.corroborated
            ? RebootOnKernelCrash(config_, history)
            : RebootOrDamp(config_, history, /*corroborated=*/false);
        break;

    case cc::ChannelFaultReason::kHealthInternal:
        // health 监控线程内部不可恢复错误 → 重启 health 子系统（cross_component_design.md §5.1）
        // 不升级到 VM/runtime 恢复；若 Reboot() 失败，recovery 直接报错（按工具级故障处理）。
        decision.action = cc::RecoveryAction::kRestartHealthMonitor;
        break;

    case cc::ChannelFaultReason::kGenerationReset:
    case cc::ChannelFaultReason::kSubmitFailed:
        decision.action = cc::RecoveryAction::kNone;
        break;
    }

    decision.abort_scope = AbortScopeForAction(decision.action);
    return decision;
}

// ============================================================
// EscalationPolicy::OnRecoveryComplete
// ============================================================

void EscalationPolicy::OnRecoveryComplete(cc::ChannelFaultReason /*reason*/,
                                           cc::RecoveryAction /*action*/,
                                           bool /*success*/)
{
    // EscalationPolicy 是无状态策略：决策完全基于 FaultHistory（由 tracker 维护）
    // 不需要在此更新内部状态
}

// ============================================================
// EscalationPolicy::Reset
// ============================================================

void EscalationPolicy::Reset()
{
    // 无状态，无需清理
}

// ============================================================
// EscalationPolicy::GetSnapshot
// ============================================================
//
// 返回策略名称 "escalation" 及 Config 字段的直接投影。
// 无状态策略无需加锁；Config 在构造后不变（动态调整通过替换 policy 实例实现）。

cc::PolicySnapshot EscalationPolicy::GetSnapshot() const
{
    cc::PolicySnapshot snap;
    snap.policy_name                          = "escalation";
    snap.max_runtime_restart_attempts         = config_.max_runtime_restart_attempts;
    snap.max_vm_reboot_attempts               = config_.max_vm_reboot_attempts;
    snap.max_single_worker_restart_attempts   = config_.max_single_worker_restart_attempts;
    snap.unusable_ratio_reboot_threshold_pct  = config_.unusable_ratio_reboot_threshold_pct;
    return snap;
}

} // namespace refuzz::channel::recovery

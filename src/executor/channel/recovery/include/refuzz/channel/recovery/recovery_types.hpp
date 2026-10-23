#pragma once

// recovery_types.hpp — channel/recovery 公共词汇 + 快照 / 结果类型收口
//
// 统一承接对外可见的枚举、快照、结果类型，切断外部对 recovery 内部类型名的直接依赖。
//
// 包含关系（单向，无环）：
//   recovery_types.hpp   (本文件：枚举 + PolicySnapshot + ChannelRecoverySnapshot
//                                  + RecoveryResult / RecoveryObservationResult / RecoverySnapshot)
//        ↓
//   fault_policy.hpp     (IFaultPolicy / EscalationPolicy / RecoveryConfig)
//        ↓
//   recovery.hpp         (Recovery 顶层入口)
//
// 注意：RecoveryConfig（含 IFaultPolicy / EscalationPolicy::Config）定义在 fault_policy.hpp，
// 而非本文件，以避免 recovery_types.hpp → fault_policy.hpp 的循环依赖。

#include "refuzz/core/channel_contract.hpp"

#include <cstdint>
#include <vector>

// ============================================================
// recovery 子系统内部快照 / 结果类型
// ============================================================
// 定义在 refuzz::channel::recovery，供 Recovery / FaultTracker / RecoveryExe 内部使用。
//
// [v3 Phase 10] 使用文件级 `namespace cc = refuzz::core::channel_contract;` 别名
// 引用对外合同枚举，替代原先依赖 channel_types.hpp / channel_recovery_snapshot.hpp
// 提供的 `using = ...` alias 层（Phase 10 已清理）。

namespace refuzz::channel::recovery {

namespace cc = refuzz::core::channel_contract;

// ── RecoveryResult — ExecuteRecovery() 返回值 ────────────────────────────────
//
// 字段有效性矩阵（按 action）：
//   kRestartAllWorkers / kRebootVm      : inflight_executor_ids 含全部 inflight
//   kRestartSingleWorker                : inflight_executor_ids 返回全量快照（非目标
//                                         worker 子集，不得据此发批量异常完成）；
//                                         target_worker_inflight_* 是被重启 worker
//                                         自己的那一份，**必须**据此发异常完成
//   kRestartHealthMonitor               : inflight_executor_ids 为空
//   kFailChannel                        : inflight_executor_ids 为空

struct RecoveryResult {
    cc::RecoveryAction action = cc::RecoveryAction::kNone;
    std::vector<uint64_t> inflight_executor_ids;
    // [crash-terminal] Subset of inflight_executor_ids that were NOT running
    // (TASK_READY — submitted but the worker never picked them up). The Channel
    // emits these as kCancelled (innocent → re-run) instead of kWorkerCrashed
    // (crash-suspect → terminal). Empty = all in-flight treated as running
    // (legacy behavior), so paths that don't populate it are unchanged.
    std::vector<uint64_t> inflight_idle_executor_ids;

    // [single-worker inflight leak] The subset of the SAME snapshot that belonged to
    // the worker being restarted, split running/idle exactly like the two lists above.
    //
    // Why a separate pair instead of reusing inflight_executor_ids: for
    // kRestartSingleWorker that list is the WHOLE-channel snapshot, so emitting
    // abnormal completions for it would falsely terminate other, healthy workers'
    // in-flight tasks (§13.10 row 8). But emitting for *nobody* silently drops the
    // restarted worker's own task: no completion, no abnormal, so every host-side
    // observer that counts terminal events leaks one per restart. Observed
    // 2026-07-25 on a 7-worker replay -- 3 single-worker restarts leaked 16
    // requests, FixedInputProducerJob's in_flight never reached 0, and the run
    // only ended when the unrelated run-limit backstop expired.
    //
    // Populated only by kRestartSingleWorker; empty for every other action (whose
    // in-flight accounting is already handled by the two lists above).
    std::vector<uint64_t> target_worker_inflight_executor_ids;
    std::vector<uint64_t> target_worker_inflight_idle_executor_ids;
};

// ── RecoveryObservationResult — ObserveFault() 返回值 ────────────────────────

struct RecoveryObservationResult {
    bool                  accepted         = false;
    cc::ChannelAbortScope abort_scope      = cc::ChannelAbortScope::kNone;
    cc::RecoveryAction    recovery_action  = cc::RecoveryAction::kNone;
    uint32_t              target_worker_id = UINT32_MAX;
};

// ── RecoverySnapshot — GetSnapshot() 返回值（机制层只读投影）─────────────────

struct RecoverySnapshot {
    uint32_t           runtime_restart_count  = 0;
    uint32_t           vm_reboot_count        = 0;
    uint32_t           consecutive_healthy    = 0;
    uint64_t           last_fault_ts_us       = 0;
    bool               offline                = false;
    bool               recovery_in_progress   = false;
    uint64_t           active_fault_event_id  = 0;
    cc::RecoveryAction active_recovery_action = cc::RecoveryAction::kNone;

    // [级联断路] reboot 后的保护窗截止时刻（steady us）。Channel 在 reboot 成功后读它
    //   设置 HeartbeatSensor 的 verdict 抑制窗 + VmAliveSensor 经 ProgressClock::Reset
    //   重置基线。0 = 不在保护窗内。
    uint64_t           recovery_window_until_us   = 0;
    uint32_t           reboots_in_cascade_window  = 0;
    uint32_t           recovery_backoff_level     = 0;

    // 策略快照（IFaultPolicy::GetSnapshot() 填充）
    // 动态调整策略参数或替换策略实现后，下次 GetSnapshot() 立即反映新配置。
    cc::PolicySnapshot policy;
};

} // namespace refuzz::channel::recovery

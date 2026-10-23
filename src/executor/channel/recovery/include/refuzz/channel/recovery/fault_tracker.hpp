#pragma once

// FaultTracker — 机制层（channel/recovery 内部实现）
// [v2 metric bus] ChannelMetrics* 由 FaultTracker::SetMetrics() 注入，
//   供 UpdateCountForAction 里的 recovery_runtime_restart / recovery_vm_reboot Counter Inc。
//
// 职责（§13.3.4 / §13.6 拆分后）：
//   - 窗口衰减、计数、时间戳
//   - recovery_in_progress 门禁与 event/action 配对
//   - 健康连续计数（healthy_streak_to_reset 后清零升级历史）
//   - 产出 FaultHistory 快照供 policy 决策
//
// 不负责：
//   - 策略决策（policy 由 Recovery 持有并在 ObserveFault 阶段调用）
//   - 对外语义稳定性（由 Recovery 统一封装）
//
// 注意：本文件为 channel/recovery 内部实现头，不对外暴露。

#include "refuzz/channel/recovery/recovery_types.hpp"  // RecoverySnapshot
#include "refuzz/channel/recovery/fault_policy.hpp"    // FaultHistory, FaultContext

#include <cstdint>
#include <mutex>
#include <unordered_map>

// Forward-declare metric types to avoid pulling in metric headers from this internal header.
namespace refuzz::core::metrics {
struct ChannelMetrics;
} // namespace refuzz::core::metrics

namespace refuzz::channel::recovery {

/// FaultTracker 内部配置（由 RecoveryConfig 提取后传入，不对外暴露）
struct FaultTrackerConfig {
    // [2026-05-13] 60000 → 600000：fault_window_ms 必须 > 单次 reboot 的最大耗时
    // (runtime_config.hpp::boot_timeout = 180000ms)，否则每次 reboot 失败之间
    // 的间隔都超过 window，MaybeDecayWindow 会清零 vm_reboot_count，永远
    // 升不到 max_vm_reboot_attempts → 无法 escalate 到 FailChannel，死循环。
    uint32_t fault_window_ms         = 600000;
    uint32_t healthy_streak_to_reset = 8;

    // [级联断路] reboot 后的保护窗（指数退避基值）。覆盖 KASAN 冷 boot(60-90s) +
    //   worker 重新注册。窗内 in_recovery_window=true → 心跳路径一律 kNone。
    uint32_t recovery_window_base_ms = 90000;
    uint32_t recovery_window_cap_ms  = 600000;
    // [级联断路] cascade 窗：reboots_in_cascade_window 在此时间内累计、超过后衰减。
    //   独立于 fault_window_ms（120s ≪ 600s），专门封顶"reboot 风暴"。
    uint32_t cascade_window_ms       = 120000;
};

/// ObserveFault() 返回值：机制层观测结果（不含策略决策）
struct FaultObservation {
    bool can_proceed = false;  // false 表示 offline 或 event_id==0，不应继续
    FaultHistory history;      // can_proceed==true 时有效，供 policy 决策使用
};

class FaultTracker {
public:
    // 不再持有 policy — policy 由 Recovery 持有并在 ObserveFault 阶段显式调用
    explicit FaultTracker(FaultTrackerConfig config);

    // ── Phase 1：机制观测 ─────────────────────────────────────────────────
    // 窗口衰减 + 时间戳更新 + consecutive_healthy 清零 + 产出 FaultHistory。
    // 不做策略决策，不设置 recovery_in_progress。
    FaultObservation ObserveFault(uint64_t fault_event_id, const FaultContext& context);

    // ── Phase 2：开始恢复事务（由 Recovery 在 policy 决策后调用）──────────
    // 仅处理全通道动作（IsFullChannelAction==true）。
    // 设置 recovery_in_progress + active event/action 配对 + 计数更新。
    // 返回 false 表示被 recovery_in_progress 门禁阻止。
    bool TryBeginRecovery(uint64_t fault_event_id,
                          cc::ChannelFaultReason reason,
                          cc::RecoveryAction action);

    // ── 完成回写 ──────────────────────────────────────────────────────────
    // 严格 event/action 配对；不匹配 → 无操作返回 false。
    // 同事务重复完成 → 幂等 no-op 返回 true。
    bool CompleteRecovery(uint64_t trigger_fault_event_id,
                          cc::RecoveryAction action,
                          bool success);

    void NoteSingleWorkerRecoveryComplete(uint32_t worker_id, bool success);

    // ── 健康信号 / 只读观测 / 重置 ───────────────────────────────────────
    void NoteHealthy();
    RecoverySnapshot GetSnapshot() const;
    void Reset();

    // [v2 metric bus — 当前版本]
    // 注入 ChannelMetrics* 以便 UpdateCountForAction 里 Counter Inc() 调用。
    // Recovery::SetMetrics 转发到此处。nullptr = 不发布 metric。
    void SetMetrics(refuzz::core::metrics::ChannelMetrics* metrics) noexcept;  // [v2 metric bus]

    // ── 工具方法（Recovery 也需要）────────────────────────────────────────
    static bool IsFullChannelAction(cc::RecoveryAction action);

private:
    struct State {
        uint32_t runtime_restart_count = 0;
        uint32_t vm_reboot_count       = 0;
        uint32_t consecutive_healthy   = 0;
        uint64_t last_fault_ts_us      = 0;
        bool offline              = false;
        bool recovery_in_progress = false;
        uint64_t active_fault_event_id            = 0;
        cc::RecoveryAction active_recovery_action = cc::RecoveryAction::kNone;
        cc::ChannelFaultReason active_fault_reason = cc::ChannelFaultReason::kWorkerHeartbeatLost;
        std::unordered_map<uint32_t, uint32_t> failed_single_worker_recovery_count_by_worker;

        // [级联断路] reboot 成功后置为 now + RecoveryWindowMs(backoff)；BuildHistory
        //   据此填 in_recovery_window。
        uint64_t recovery_window_until_us = 0;
        // [级联断路] cascade 窗起点 + 窗内 reboot 计数（**不随单次成功 reboot 清零**，
        //   只按 cascade_window_ms 时间衰减 / 健康连续衰减）。只统计基础设施故障的
        //   reboot；真 kernel crash（kKernelCrash）的 reboot 不累计（CompleteRecovery
        //   按 active_fault_reason 区分）。
        uint64_t cascade_window_start_us  = 0;
        uint32_t reboots_in_cascade_window = 0;
        // [级联断路] 指数退避级数：每次 reboot 成功 ++（封顶到 cap 对应级），健康连续
        //   达标后清零。
        uint32_t recovery_backoff_level    = 0;
    };

    static uint64_t NowUs();
    void MaybeDecayWindow(State& state, uint64_t now_us);
    void UpdateCountForAction(State& state, cc::RecoveryAction action);
    FaultHistory BuildHistory(const State& state, uint32_t source_worker_id) const;

    FaultTrackerConfig config_;
    mutable std::mutex mu_;
    State              state_;

    // [v2 metric bus — 当前版本]
    // 注入：Recovery::SetMetrics → FaultTracker::SetMetrics。
    // 在 UpdateCountForAction（已加锁路径）内读取：无 race（SetMetrics 在 Start 之前调用）。
    refuzz::core::metrics::ChannelMetrics* metrics_ = nullptr;  // [v2 metric bus]
};

} // namespace refuzz::channel::recovery

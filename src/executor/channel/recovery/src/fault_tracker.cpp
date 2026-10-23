// FaultTracker — 机制层实现（策略决策已上移至 Recovery）
//
// 设计来源：channel/recovery/design.md §13.3.4 / §13.6
//
// 改造要点：
//   - 移除 policy_ 持有：策略由 Recovery 持有并显式调用
//   - Observe() 拆分为 ObserveFault()（机制观测）+ TryBeginRecovery()（事务绑定）
//   - CompleteRecovery() 返回 bool，供 Recovery 判断配对成功与否
//   - Reset() 不再调用 policy_->Reset()

#include "refuzz/channel/recovery/fault_tracker.hpp"

#include "refuzz/core/metrics/channel_metrics.hpp"  // [v2 metric bus]

#include <chrono>

namespace refuzz::channel::recovery {

// ── 构造 ──────────────────────────────────────────────────────────────────────

FaultTracker::FaultTracker(FaultTrackerConfig config)
    : config_(config)
{}

// ── 工具方法 ──────────────────────────────────────────────────────────────────

uint64_t FaultTracker::NowUs()
{
    const auto now = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(now).count());
}

bool FaultTracker::IsFullChannelAction(cc::RecoveryAction action)
{
    return action == cc::RecoveryAction::kRestartAllWorkers  ||
           action == cc::RecoveryAction::kRebootVm        ||
           action == cc::RecoveryAction::kFailChannel     ||
           action == cc::RecoveryAction::kRestartHealthMonitor;
}

void FaultTracker::MaybeDecayWindow(State& state, uint64_t now_us)
{
    if (state.last_fault_ts_us == 0) return;
    const uint64_t window_us = static_cast<uint64_t>(config_.fault_window_ms) * 1000ULL;
    if (now_us > state.last_fault_ts_us &&
        (now_us - state.last_fault_ts_us) > window_us) {
        state.runtime_restart_count = 0;
        state.vm_reboot_count       = 0;
        state.failed_single_worker_recovery_count_by_worker.clear();
    }
    // [级联断路] cascade 窗独立衰减（比 fault_window_ms 短得多）：风暴在 cascade_window_ms
    //   内没有新 reboot → 计数 + 退避归零。这是封顶"reboot 风暴"的时间侧出口（另一侧
    //   是 NoteHealthy 的健康连续）。
    const uint64_t cascade_us = static_cast<uint64_t>(config_.cascade_window_ms) * 1000ULL;
    if (state.cascade_window_start_us != 0 &&
        now_us > state.cascade_window_start_us &&
        (now_us - state.cascade_window_start_us) > cascade_us) {
        state.reboots_in_cascade_window = 0;
        state.cascade_window_start_us   = now_us;
        state.recovery_backoff_level    = 0;
    }
}

void FaultTracker::UpdateCountForAction(State& state, cc::RecoveryAction action)
{
    switch (action) {
    case cc::RecoveryAction::kRestartSingleWorker:
    case cc::RecoveryAction::kReloadSnapshot:
        // kReloadSnapshot 不重启 VM/worker，不计入 restart/reboot 计数（窗口衰减无关）。
        break;
    case cc::RecoveryAction::kRestartAllWorkers:
        ++state.runtime_restart_count;
        // [v2 metric bus — 当前版本]
        // 源头单调 Counter：每次 ++ 后立即 Inc。
        // Counter = "本 run 内累计发生次数"（D1 option a）；窗口衰减（MaybeDecayWindow）
        // 只重置 snapshot 字段，不影响 Counter——两者语义独立。
        // Inc 在锁内执行（TryBeginRecovery 已加锁）；metrics_ 在 Start 之前注入，无 race。
        if (metrics_ != nullptr && metrics_->recovery_runtime_restart != nullptr) {
            metrics_->recovery_runtime_restart->Inc();
        }
        break;
    case cc::RecoveryAction::kRebootVm:
        ++state.vm_reboot_count;
        // [v2 metric bus — 当前版本]
        if (metrics_ != nullptr && metrics_->recovery_vm_reboot != nullptr) {
            metrics_->recovery_vm_reboot->Inc();
        }
        break;
    case cc::RecoveryAction::kFailChannel:
        state.offline = true;
        break;
    case cc::RecoveryAction::kRestartHealthMonitor:
        // health monitor 重启不计入 vm/runtime 升级窗口（按工具级故障处理）
        break;
    case cc::RecoveryAction::kNone:
        break;
    }
}

// ── SetMetrics ────────────────────────────────────────────────────────────────

// [v2 metric bus — 当前版本]
// 由 Recovery::SetMetrics 在 Channel::AttachObservabilityPublishers 路径上调用。
// 在 Start 之前注入，UpdateCountForAction（加锁）读取时 metrics_ 已稳定，无 race。
void FaultTracker::SetMetrics(refuzz::core::metrics::ChannelMetrics* metrics) noexcept
{
    metrics_ = metrics;
}

FaultHistory FaultTracker::BuildHistory(const State& state, uint32_t source_worker_id) const
{
    uint32_t source_failed_count = 0;
    const auto it = state.failed_single_worker_recovery_count_by_worker.find(source_worker_id);
    if (it != state.failed_single_worker_recovery_count_by_worker.end()) {
        source_failed_count = it->second;
    }

    const uint64_t now_us = NowUs();
    return FaultHistory{
        .runtime_restart_count               = state.runtime_restart_count,
        .vm_reboot_count                     = state.vm_reboot_count,
        .consecutive_healthy                 = state.consecutive_healthy,
        .last_fault_ts_us                    = state.last_fault_ts_us,
        .source_worker_failed_recovery_count = source_failed_count,
        // [级联断路] 保护窗内 = now 还没到 recovery_window_until_us。
        .in_recovery_window        = (state.recovery_window_until_us != 0 &&
                                      now_us < state.recovery_window_until_us),
        .reboots_in_cascade_window = state.reboots_in_cascade_window,
    };
}

// ── Phase 1：ObserveFault — 机制观测（不含策略决策）─────────────────────────
// 窗口衰减 + 时间戳更新 + consecutive_healthy 清零 + 产出 FaultHistory。
// 不设置 recovery_in_progress，不调用 policy。

FaultObservation FaultTracker::ObserveFault(uint64_t            fault_event_id,
                                             const FaultContext& context)
{
    std::lock_guard<std::mutex> lock(mu_);
    FaultObservation obs;

    if (fault_event_id == 0 || state_.offline) {
        return obs;  // can_proceed = false
    }

    const uint64_t now_us = NowUs();
    MaybeDecayWindow(state_, now_us);

    state_.last_fault_ts_us    = now_us;
    state_.consecutive_healthy = 0;

    obs.can_proceed = true;
    obs.history     = BuildHistory(state_, context.source_worker_id);
    return obs;
}

// ── Phase 2：TryBeginRecovery — 事务绑定（由 Recovery 在 policy 决策后调用）──
// 仅处理全通道动作。设置 recovery_in_progress + active event/action + 计数更新。
// 返回 false 表示被 recovery_in_progress 门禁阻止。

bool FaultTracker::TryBeginRecovery(uint64_t           fault_event_id,
                                     cc::ChannelFaultReason reason,
                                     cc::RecoveryAction     action)
{
    if (!IsFullChannelAction(action)) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mu_);

    if (state_.recovery_in_progress) {
        return false;
    }

    state_.recovery_in_progress   = true;
    state_.active_fault_event_id  = fault_event_id;
    state_.active_recovery_action = action;
    state_.active_fault_reason    = reason;
    UpdateCountForAction(state_, action);
    return true;
}

// ── CompleteRecovery — 全通道恢复完成 ────────────────────────────────────────
// 严格 event/action 配对；不匹配 → 无操作返回 false。
// 同事务重复完成 → 幂等 no-op 返回 true（recovery_in_progress 已 false）。

bool FaultTracker::CompleteRecovery(uint64_t       trigger_fault_event_id,
                                     cc::RecoveryAction action,
                                     bool           success)
{
    std::lock_guard<std::mutex> lock(mu_);

    // 幂等：同一事务已完成（recovery_in_progress=false 且 event_id 未变）
    if (!state_.recovery_in_progress) {
        return false;
    }

    // 严格配对校验
    if (state_.active_fault_event_id  != trigger_fault_event_id ||
        state_.active_recovery_action != action) {
        return false;
    }

    // 先保存本次恢复的 fault reason —— 下面的成功回收需要区分"真 kernel crash 的 reboot"
    //   与"基础设施故障的 reboot"（前者不消耗 cascade 预算）。
    const cc::ChannelFaultReason completed_reason = state_.active_fault_reason;

    state_.recovery_in_progress   = false;
    state_.active_fault_event_id  = 0;
    state_.active_recovery_action = cc::RecoveryAction::kNone;
    state_.active_fault_reason    = cc::ChannelFaultReason::kWorkerHeartbeatLost;

    if (!success) return true;

    // 成功后的计数回收
    if (action == cc::RecoveryAction::kRestartAllWorkers) {
        state_.failed_single_worker_recovery_count_by_worker.clear();
    }
    if (action == cc::RecoveryAction::kRebootVm) {
        state_.runtime_restart_count = 0;
        state_.vm_reboot_count       = 0;
        state_.failed_single_worker_recovery_count_by_worker.clear();

        // [级联断路] reboot 成功 → 开保护窗 + 记 cascade + 退避。
        //   reboots_in_cascade_window **不在这里清零**（清零会让 cascade_reboot_budget
        //   永远拦不住风暴，正是要避免的）——只按时间(MaybeDecayWindow) / 健康连续
        //   (NoteHealthy) 衰减。保护窗 = now + base·2^level（封顶 cap），覆盖 KASAN
        //   boot + 重新注册；窗内 in_recovery_window=true → 心跳路径一律 kNone。
        //   [真 kernel crash 豁免] kKernelCrash 的 reboot 是"发现"不是基础设施故障：
        //   不消耗 cascade budget、不增长退避（否则 bch2 这类高频真 bug 会把预算打满，
        //   后续基础设施故障被错误熔断）；保护窗仍照常打开（吸收重新注册噪声）。
        //   kNoOutput 不再豁免：它现在是推断型 forward-progress frozen（连续
        //   liveness 信号），反复冻结必须累计 cascade/backoff 才能被治理，否则
        //   会绕过 RebootOrDamp 的预算变成无封顶 reboot 循环。
        const uint64_t now_us = NowUs();
        uint64_t window_ms = static_cast<uint64_t>(config_.recovery_window_base_ms);
        if (completed_reason != cc::ChannelFaultReason::kKernelCrash) {
            if (state_.cascade_window_start_us == 0) {
                state_.cascade_window_start_us = now_us;
            }
            ++state_.reboots_in_cascade_window;

            for (uint32_t i = 0;
                 i < state_.recovery_backoff_level &&
                 window_ms < static_cast<uint64_t>(config_.recovery_window_cap_ms);
                 ++i) {
                window_ms *= 2;
            }
            if (window_ms > static_cast<uint64_t>(config_.recovery_window_cap_ms)) {
                window_ms = config_.recovery_window_cap_ms;
            }
            ++state_.recovery_backoff_level;
        }
        state_.recovery_window_until_us = now_us + window_ms * 1000ULL;
    }
    if (action == cc::RecoveryAction::kFailChannel) {
        state_.offline = true;
    }
    state_.consecutive_healthy = 0;
    return true;
}

// ── NoteSingleWorkerRecoveryComplete — 单 worker 恢复完成 ─────────────────────

void FaultTracker::NoteSingleWorkerRecoveryComplete(uint32_t worker_id, bool success)
{
    std::lock_guard<std::mutex> lock(mu_);
    if (state_.offline) return;

    const uint64_t now_us = NowUs();
    MaybeDecayWindow(state_, now_us);

    if (worker_id == UINT32_MAX) return;

    if (success) {
        state_.failed_single_worker_recovery_count_by_worker.erase(worker_id);
        return;
    }
    ++state_.failed_single_worker_recovery_count_by_worker[worker_id];
}

// ── NoteHealthy — 健康信号 ────────────────────────────────────────────────────

void FaultTracker::NoteHealthy()
{
    std::lock_guard<std::mutex> lock(mu_);
    if (state_.offline || state_.recovery_in_progress) return;

    ++state_.consecutive_healthy;
    if (state_.consecutive_healthy >= config_.healthy_streak_to_reset) {
        state_.runtime_restart_count = 0;
        state_.vm_reboot_count       = 0;
        state_.failed_single_worker_recovery_count_by_worker.clear();
        state_.consecutive_healthy   = 0;
        // [级联断路] 仅在保护窗已过之后的健康连续才清 cascade + 退避——窗内的健康多半
        //   是重新注册噪声，不算真平息。窗外健康达标 = 风暴真结束 → 归零。
        const uint64_t now_us = NowUs();
        if (state_.recovery_window_until_us == 0 ||
            now_us >= state_.recovery_window_until_us) {
            state_.reboots_in_cascade_window = 0;
            state_.recovery_backoff_level    = 0;
        }
    }
}

// ── GetSnapshot / Reset ───────────────────────────────────────────────────────

RecoverySnapshot FaultTracker::GetSnapshot() const
{
    std::lock_guard<std::mutex> lock(mu_);
    return RecoverySnapshot{
        .runtime_restart_count  = state_.runtime_restart_count,
        .vm_reboot_count        = state_.vm_reboot_count,
        .consecutive_healthy    = state_.consecutive_healthy,
        .last_fault_ts_us       = state_.last_fault_ts_us,
        .offline                = state_.offline,
        .recovery_in_progress   = state_.recovery_in_progress,
        .active_fault_event_id  = state_.active_fault_event_id,
        .active_recovery_action = state_.active_recovery_action,
        .recovery_window_until_us  = state_.recovery_window_until_us,
        .reboots_in_cascade_window = state_.reboots_in_cascade_window,
        .recovery_backoff_level    = state_.recovery_backoff_level,
        .policy                 = {},  // 由 Recovery::GetSnapshot() 合并策略快照
    };
}

void FaultTracker::Reset()
{
    std::lock_guard<std::mutex> lock(mu_);
    state_ = State{};
}

} // namespace refuzz::channel::recovery

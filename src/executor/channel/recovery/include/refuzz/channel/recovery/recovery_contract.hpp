#pragma once

// IRecovery — recovery 子系统的抽象接口（v3.5 Phase G）
//
// 方法集从 channel.cpp 的实际调用点提取（recovery_->xxx），保证 Channel
// 只通过此接口访问 Recovery，不感知具体实现。
//
// 设计来源：docs/channel-redesign/v3.5/160_phase_G_health_recovery.md §G.4

#include "refuzz/channel/recovery/recovery_types.hpp"
#include "refuzz/channel/recovery/fault_policy.hpp"
#include "refuzz/channel/result.hpp"

#include <cstdint>

// Forward-declare metric types to avoid pulling in metric headers from this interface.
namespace refuzz::core::metrics {
struct ChannelMetrics;
} // namespace refuzz::core::metrics

namespace refuzz::channel::recovery {

class IRecovery {
public:
    virtual ~IRecovery() = default;

    // ── Phase 1：观测故障，获取策略决策 ───────────────────────
    virtual RecoveryObservationResult ObserveFault(
        uint64_t               fault_event_id,
        cc::ChannelFaultReason reason,
        cc::ChannelFaultSource source,
        const FaultContext&    context) = 0;

    // ── Phase 2：执行恢复动作 ──────────────────────────────────
    virtual Result<RecoveryResult> ExecuteRecovery(
        cc::ChannelFaultReason reason,
        cc::RecoveryAction     action,
        uint32_t               target_worker_id = UINT32_MAX) = 0;

    // ── Phase 3：完成回写 ──────────────────────────────────────
    virtual bool CompleteFullChannelRecovery(
        uint64_t           trigger_fault_event_id,
        cc::RecoveryAction action,
        bool               success) = 0;
    virtual void CompleteSingleWorkerRecovery(uint32_t worker_id, bool success) = 0;

    // ── 健康信号 ───────────────────────────────────────────────
    virtual void NoteHealthy() = 0;

    // ── 只读观测 ───────────────────────────────────────────────
    virtual RecoverySnapshot GetSnapshot() const = 0;
    virtual void Reset() = 0;

    // [v2 metric bus — 当前版本]
    // 注入 ChannelMetrics* 以便 recovery_runtime_restart / recovery_vm_reboot
    // Counter Inc() 调用（由 FaultTracker 内部执行）。
    // 由 Channel::AttachObservabilityPublishers 调用；nullptr = 不发布 metric。
    // 默认 no-op；Recovery 具体实现 override 此方法。
    virtual void SetMetrics(refuzz::core::metrics::ChannelMetrics* /*metrics*/) noexcept {}
};

} // namespace refuzz::channel::recovery

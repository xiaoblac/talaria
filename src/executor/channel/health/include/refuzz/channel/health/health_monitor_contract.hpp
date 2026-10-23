#pragma once

// IHealthMonitor — health 子系统的抽象接口（v3.5 Phase G）
//
// 方法集从 channel.cpp + recovery_exe.cpp 的实际调用点提取，保证
// Channel 和 Recovery 仅通过此接口访问 HealthMonitor，不感知具体实现。
//
// 不在接口中：
//   - Publish()       — HealthPublisher 接口，Sensor 侧使用
//   - PublishCrashEvent() — 同上
//   - ParkUntilResumed / NotifyThreadExiting — Sensor 内部协议
//
// 设计来源：docs/channel-redesign/v3.5/160_phase_G_health_recovery.md §G.1
//           docs/channel-redesign/v4.0/900_cleanup_backlog.md Phase J

#include "refuzz/channel/health/health_types.hpp"
#include "refuzz/channel/result.hpp"
#include "refuzz/core/channel_contract.hpp"

#include <cstdint>
#include <memory>
#include <vector>

// Forward-declare metric types to avoid pulling in metric headers from this interface.
namespace refuzz::core::metrics {
struct ChannelMetrics;
} // namespace refuzz::core::metrics

namespace refuzz::channel::health {
class IHealthSensor;
} // namespace refuzz::channel::health

namespace refuzz::channel::health {

class IHealthMonitor {
public:
    virtual ~IHealthMonitor() = default;

    // ── Lifecycle ──────────────────────────────────────────────
    virtual Result<void> Start() = 0;
    virtual void         Stop() noexcept = 0;

    // ── Sensor 装配（仅在 Start() 之前调用）────────────────────
    // 装配期契约：Assembler 在 Start() 之前调用；Start() 之后行为 UB。
    // NoopHealthMonitor 直接 drop 传入的 sensor（语义自然）。
    virtual void AddSensor(std::unique_ptr<IHealthSensor> sensor) = 0;

    // ── Channel signal injection（Boot 时在 Start 之前调用）────
    virtual void BindChannelSignals(HealthMonitorView view) noexcept = 0;

    // ── Worker liveness（loop 线程热路径）──────────────────────
    virtual void SetWorkerAlive(uint32_t worker_id, bool alive) noexcept = 0;

    // ── Rearm 单 worker 心跳观察（kRestartSingleWorker recovery 成功后调用）──
    // 语义:单 worker 粒度恢复 heartbeat 观察。HeartbeatSensor 在上报 worker_dead
    //      时会把该 worker observed=false 防止重复上报;过去只有 Reboot() 全量
    //      重建会恢复它,单 worker 恢复路径缺这一环,导致"阈值才 boot"的多 worker
    //      容错策略在 heartbeat 侧实际只生效一次——第二次卡死时 heartbeat 不再
    //      检测,channel 挂死。RearmSingleWorker 补齐这条路径。
    // 转发:支持此语义的 Sensor(目前仅 HeartbeatSensor);其他 Sensor 默认 no-op。
    // 并发:与 sensor 线程并发安全,sensor 内部自行加锁。
    virtual void RearmSingleWorker(uint32_t worker_id) = 0;

    // ── Crash event drain（loop 线程调用）──────────────────────
    virtual bool                    HasPendingCrashEvents() const noexcept = 0;
    virtual std::vector<CrashEvent> DrainCrashEvents() = 0;

    // ── Quiesce（recovery 前后暂停/恢复采集）──────────────────
    virtual void SuspendMonitoring() = 0;
    virtual void ResumeMonitoring() = 0;

    // ── kRestartHealthMonitor recovery 动作────────────────────
    // 全量重启 health 子系统（Stop 所有 Sensor + Start 所有 Sensor）。
    // 由 RecoveryExe::ExecuteRestartHealthMonitor 调用。
    virtual Result<void> Reboot() = 0;

    // ── Observability ──────────────────────────────────────────
    virtual refuzz::core::channel_contract::HealthMonitorSnapshot
        GetSnapshot() const = 0;

    // [v2 metric bus — 当前版本]
    // 注入 ChannelMetrics* 以便 health_crash[N]->Inc() 调用。
    // 在 Channel::AttachObservabilityPublishers 里调用;nullptr = 不发布 metric。
    // 默认 no-op;HealthMonitor 具体实现 override 此方法。
    virtual void SetMetrics(refuzz::core::metrics::ChannelMetrics* /*metrics*/) noexcept {}
};

} // namespace refuzz::channel::health

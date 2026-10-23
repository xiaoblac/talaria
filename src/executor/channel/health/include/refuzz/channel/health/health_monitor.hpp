#pragma once

// HealthMonitor — health 子系统唯一入口和生命周期管理者（§18.3.1）。
//
// 职责：
//   - 持有并管理一组 IHealthSensor（AddSensor 装配期注入）
//   - 统一线程生命周期：Start / Stop / SuspendMonitoring / ResumeMonitoring
//   - 统一异常写入入口：PublishCrashEvent / Publish（Sensor 线程调用）
//   - 统一消费入口：DrainCrashEvents（Channel loop 线程调用）
//   - per-worker 存活状态（bitmask，lock-free 热路径）
//   - 监听范围控制：SyncObservedWorkers（上层 worker 生命周期同步）
//
// 并发契约（§18.4.2）：
//   - monitor_mutex_ 唯一保护 pending_events_ 队列（单 mutex）
//   - PublishCrashEvent：lock → enqueue → update worker_alive_bits_ → unlock → notify_one(loop_cv)
//   - DrainCrashEvents：lock → swap → unlock → return（无 wait）
//   - has_pending_：atomic bool，lock-free 供 Channel loop cv 谓词使用
//
// SuspendMonitoring / ResumeMonitoring quiesce 机制（§18.6 / §18.7）：
//   - suspended_ atomic flag：Sensor 主循环检查，true 时调用 ParkUntilResumed()
//   - parked_count_ atomic：当前已 park 的线程数
//   - quiesce_mutex_ / quiesce_cv_：SuspendMonitoring wait / ParkUntilResumed wait
//   - SuspendMonitoring：set suspended_=true → Poke 各 Sensor → wait parked_count==n_threads_
//   - ResumeMonitoring：set suspended_=false → broadcast quiesce_cv_
//   - ParkUntilResumed（Sensor 调用）：parked_count_++ → notify → wait !suspended_ → parked_count_--
//
// 设计来源：health/design.md §18.3.1 / §18.4 / §18.6 / §18.7 / §18.8

#include "refuzz/channel/health/health_monitor_contract.hpp"
#include "refuzz/channel/health/health_types.hpp"
#include "refuzz/channel/health/sensor.hpp"
#include "refuzz/channel/result.hpp"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

// Forward-declare metric types (matches health_monitor_contract.hpp forward decl).
namespace refuzz::core::metrics {
struct ChannelMetrics;
} // namespace refuzz::core::metrics

namespace refuzz::channel::health {

namespace cc = refuzz::core::channel_contract;


// ============================================================
// HealthMonitorConfig — 聚合各 Sensor 数据参数
// ============================================================
//
// Assembler 从 Profile 读出后填入；HealthMonitor 本身不消费这些字段，
// 仅作为 Assembler 装配 Sensor 的数据来源。expected_worker_count 由
// HealthMonitor 直接使用（GetSnapshot 构造 worker_liveness.size()）。

struct HealthMonitorConfig {
    HealthHeartbeatConfig      heartbeat;
    HealthSerialWatcherConfig  serial_watcher;
    HealthVmLivenessConfig     vm_liveness;

    // worker 数量提示：GetSnapshot() 用此值填 worker_liveness.size()。
    // Assembler 在装配时从 infra config 取值后填入。
    uint32_t expected_worker_count = 0;
};

// ============================================================
// HealthMonitor
// ============================================================

class HealthMonitor : public HealthPublisher, public IHealthMonitor {
public:
    // 构造：HealthMonitor 不接收 infra/runtime 等具体实现依赖；
    // 它只是 "Sensor 注册表 + 事件总线 + quiesce"；所有采集逻辑由 Sensor 承担。
    //
    // 调用序：
    //   1) HealthMonitor hm(view, cfg);
    //   2) hm.AddSensor(std::make_unique<HeartbeatSensor>(cp, ...));
    //      hm.AddSensor(std::make_unique<ConsoleSensor>(src, steps, ...));
    //      hm.AddSensor(std::make_unique<VmAliveSensor>([rt]{...}, ...));
    //   3) hm.Start();          // 无参；遍历 sensors_ 逐个 Start(*this)
    HealthMonitor(HealthMonitorView    view,
                  HealthMonitorConfig  config);

    ~HealthMonitor() override;

    HealthMonitor(const HealthMonitor&)            = delete;
    HealthMonitor& operator=(const HealthMonitor&) = delete;

    // ── Sensor 装配（在 Start() 之前串行调用） ───────────────

    // AddSensor：把自定义 Sensor 塞入注册表。必须在 Start() 之前调用。
    // 线程安全：Channel 装配线程单线程调用，不并发；内部无锁。
    // [v4.0 Phase J] 上提至 IHealthMonitor 接口 override。
    void AddSensor(std::unique_ptr<IHealthSensor> sensor) override;

    // BindChannelSignals — 注入 Channel 级别 cv/epoch；必须在 Start() 之前调用。
    //   Assembler 构造 HealthMonitor 时传入空 view（Channel 还未构造，无法引用其 loop_cv/vm_epoch），
    //   Channel::Boot 调用 BindChannelSignals 把真实 view 绑定上去。
    //   Start 之后再调用为 UB（并发访问 view_）。
    void BindChannelSignals(HealthMonitorView view) noexcept override;

    // 当前已注册 Sensor 数量（Start() 之后固定）
    size_t sensor_count() const { return sensors_.size(); }

    // ── 生命周期 ──────────────────────────────────────────────

    // 启动已注册的 Sensor。
    // 要求：AddSensor 已至少调用一次；sensors_ 非空。
    // 任一 Sensor Start 失败 → 已启动的 Sensor 全部 Stop 后返回错误。
    Result<void> Start() override;

    // 停止全部子线程（可重复调用）
    void Stop() noexcept override;

    // 挂起监控：set suspended_=true，Poke 各 Sensor，阻塞到所有子线程 parked 后返回
    // 调用方（Channel）：进入 recovery 时调用，此后 PublishCrashEvent 会被 Sensor
    // 在 park 期间屏蔽（Sensor 不运行即不产出事件）
    // 前置：Start() 已成功调用，且当前未处于 suspended 状态
    void SuspendMonitoring() override;

    // 恢复监控：set suspended_=false，broadcast quiesce_cv_，阻塞到所有子线程离开 park 后返回
    // 子线程离开 park 后自行重建基线（armed=false），HealthMonitor 不等待基线重建完成
    // 前置：SuspendMonitoring() 已成功调用
    void ResumeMonitoring() override;

    // 最小化恢复接口（cross_component_design.md §3.1）
    // 供 Recovery 在 kRestartHealthMonitor 路径下调用。
    // 语义：全量重启 health 子系统（Stop 所有 Sensor + Start 所有 Sensor）。
    // 约束：
    //   - health 正常生命周期（Start/Stop）仍由 Channel 负责，Reboot 不转移 ownership。
    //   - Reboot() 成功返回后 health 处于正常运行状态（suspended_=false，所有 Sensor 活跃）。
    //   - Reboot() 失败时 health 处于停止状态；调用方（Recovery）应上报错误。
    // 前置：Start() 已被成功调用。
    Result<void> Reboot() override;

    // ── 监听范围控制 ──────────────────────────────────────────

    // 批量同步 worker 的 observed 状态，转发给所有 Sensor（§18.7）
    // 必须在 SuspendMonitoring() 已生效期间调用（Sensor 线程 parked，无并发写）
    void SyncObservedWorkers(const std::vector<bool>& observed);

    // 单 worker 粒度恢复 heartbeat 观察(kRestartSingleWorker recovery 成功后)。
    // 与 SyncObservedWorkers 不同,不要求 SuspendMonitoring;sensor 侧自行加锁。
    void RearmSingleWorker(uint32_t worker_id) override;

    // ── 事件生产（Sensor 线程调用）────────────────────────────

    // 构造 CrashEvent 并追加到 pending_events_，notify Channel loop_cv
    // origin        ：事件来源（由各 Sensor 传入）
    // fragment      ：crash 现场（move in）
    // checker_name  ：§18.9.2 字段，health_internal 必填，其他来源传 {}
    // errno_value   ：§18.9.2 字段，health_internal 必填，其他来源传 0
    void PublishCrashEvent(CrashEventOrigin origin,
                           CrashFragment&&  fragment,
                           std::string      checker_name = {},
                           int              errno_value  = 0);

    // ── HealthPublisher 接口实现 ─────────────────────────────

    // Publish：Sensor 直接提交已构造好的 CrashEvent（event_id / vm_epoch /
    // detected_ts_us 由 HealthMonitor 补齐，fragment 按原样转发）。
    void Publish(CrashEvent event) override;

    // IsSuspended：Sensor 主循环 tick 前查询
    bool IsSuspended() const override;

    // ParkUntilResumed / NotifyThreadExiting：quiesce 协议对应接口
    void ParkUntilResumed() override;
    void NotifyThreadExiting() override;

    // SetWorkerAlive：HealthPublisher + IHealthMonitor 双接口 override
    void SetWorkerAlive(uint32_t worker_id, bool alive) noexcept override;

    // ── 事件消费（Channel loop 线程调用）─────────────────────

    // 批量取走全部待处理事件（FIFO），清空内部队列
    // 返回后 has_pending_ 置 false（若队列清空）
    std::vector<CrashEvent> DrainCrashEvents() override;

    // lock-free 检查是否有待处理事件（Channel loop cv 谓词用）
    bool HasPendingCrashEvents() const noexcept override;

    // ── per-worker 存活查询（lock-free，热路径）───────────────

    // 返回 worker_id 对应 bit 的存活状态
    // worker_id >= 64 时返回 false（防越界）
    bool WorkerAlive(uint32_t worker_id) const;

    // ── 快照（供 Channel::CollectHealthPart 调用）─────────────

    // 构造当前 health 状态快照：
    //   - worker_liveness：遍历 config_.expected_worker_count 个 worker 的 alive bit
    //   - sampled_ts_us：调用时刻
    // crash 计数不在此：事件在 Publish/PublishCrashEvent 里已按 kind 分类并 Inc 源头
    //   Counter（channel.health.crash{kind=...}），不再于 snapshot 里维护第二套账本。
    // 线程安全：worker_alive_bits_ 是 atomic，无需加锁
    refuzz::core::channel_contract::HealthMonitorSnapshot GetSnapshot() const override;

    // [v2 metric bus — 当前版本]
    // 注入 ChannelMetrics* 以便 health_crash[N]->Inc() 调用。
    // nullptr = 不发布 metric（降级为旧行为）。
    void SetMetrics(refuzz::core::metrics::ChannelMetrics* metrics) noexcept override;

private:
    uint64_t NextEventId();
    static uint64_t NowUs();

    // ── 注入依赖 ──
    HealthMonitorView   view_;
    HealthMonitorConfig config_;

    // Sensor 注册表。AddSensor 追加，Start() 遍历启动。
    std::vector<std::unique_ptr<IHealthSensor>> sensors_;

    // ── 事件队列（monitor_mutex_ 唯一保护，§18.4.2 "单 mutex"）──
    mutable std::mutex      monitor_mutex_;
    std::vector<CrashEvent> pending_events_;
    // lock-free 快速检查标志；DrainCrashEvents 清空队列后置 false
    std::atomic<bool>       has_pending_{false};
    std::atomic<uint64_t>   next_event_id_{1};

    // ── per-worker 存活 bitmask（lock-free，bit i = worker i alive）──
    // PublishCrashEvent(kWorkerDead) 清 bit source_worker_id
    // PublishCrashEvent(kVmDead)     清全部 bit
    // SetWorkerAlive(id, true)       置 bit id（Channel recovery 后调用）
    std::atomic<uint64_t> worker_alive_bits_{0};

    // ── Suspend/Resume quiesce 机制（§18.6）──
    // suspended_：Sensor 主循环检查此 flag；true 时调用 ParkUntilResumed()
    std::atomic<bool> suspended_{false};
    // parked_count_：当前已进入 park 的 Sensor 线程数
    std::atomic<int>  parked_count_{0};
    // quiesce_mutex_ / quiesce_cv_：SuspendMonitoring wait 与 ParkUntilResumed wait 共用
    std::mutex              quiesce_mutex_;
    std::condition_variable quiesce_cv_;
    // n_threads_：Start 成功后固定为 sensors_.size()
    int n_threads_ = 0;

    bool started_ = false;

    // [v2 metric bus — 当前版本]
    // 由 SetMetrics() 注入（Channel::AttachObservabilityPublishers → recovery_->SetMetrics
    // 与 health_monitor_->SetMetrics 分别调用）。允许为 nullptr（旧行为）。
    refuzz::core::metrics::ChannelMetrics* metrics_ = nullptr;  // [v2 metric bus]
};

} // namespace refuzz::channel::health

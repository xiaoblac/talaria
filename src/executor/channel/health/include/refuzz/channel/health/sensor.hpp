#pragma once

// [v3 Phase 1.B] IHealthSensor + HealthPublisher — health 插件式 Sensor 接口
//
// 设计来源：docs/channel-redesign/v3/50_health.md §2.2 / §2.3
// 职责分层：
//   - HealthPublisher：Sensor "上报 / 查 quiesce / 维护 alive bitmap" 的统一出口面
//   - IHealthSensor：Sensor 自身的 lifecycle（Name/Start/Stop/Poke/SyncObservedWorkers）
//
// HealthMonitor 自己实现 HealthPublisher（聚合 Sensor 事件 + quiesce 协议）；
// Sensor 只看到 HealthPublisher&，看不见 HealthMonitor*。

#include "refuzz/channel/health/health_types.hpp"
#include "refuzz/channel/result.hpp"

#include <cstdint>
#include <string_view>
#include <vector>

namespace refuzz::channel::health {

// HealthPublisher — Sensor 看见的上报面
class HealthPublisher {
public:
    virtual ~HealthPublisher() = default;

    // 事件上报；内部入队并 notify Channel loop
    virtual void Publish(CrashEvent event) = 0;

    // ───── Quiesce 支持 ─────
    //
    // Sensor 每次主循环 tick 检查 IsSuspended()；为 true 时调 ParkUntilResumed()。
    // NotifyThreadExiting() 用于线程即将不再 park（退出 / 永久 park）的通知。
    virtual bool IsSuspended() const = 0;
    virtual void ParkUntilResumed() = 0;
    virtual void NotifyThreadExiting() = 0;

    // ───── per-worker alive 位图 ─────
    //
    // 语义：Sensor 判断某 worker 存亡时直接标记；HealthMonitor 根据事件类型也可能更新
    virtual void SetWorkerAlive(uint32_t worker_id, bool alive) = 0;
};

// IHealthSensor — Sensor 自身接口
class IHealthSensor {
public:
    virtual ~IHealthSensor() = default;

    virtual std::string_view Name() const = 0;

    // Start：HealthMonitor 在统一 Start 时调用；实现应启动自己的后台线程
    virtual Result<void> Start(HealthPublisher& publisher) = 0;
    virtual void         Stop() = 0;

    // Poke：SuspendMonitoring 时唤醒自己阻塞点，让线程尽快进入 park
    virtual void Poke() = 0;

    // SyncObservedWorkers：可选；HeartbeatSensor 用来同步 quarantine 集
    //                     默认 no-op 实现（其他 Sensor 不关心 per-worker 观察集）
    virtual void SyncObservedWorkers(const std::vector<bool>& /*observed*/) {}

    // RearmSingleWorker：可选；kRestartSingleWorker recovery 成功后调用。
    //   历史语义:HeartbeatSensor 在上报 worker_dead 时把该 worker observed=false
    //   防止重复上报,过去只有 Reboot() 全量重建 sensor 会恢复它。单 worker
    //   recovery 路径不会 Reboot,结果同一 worker(或该 channel 的其他 worker)
    //   第二次卡死时 heartbeat 不再检测,"阈值才 boot channel"的策略前提被打破。
    //   这里给单 worker 粒度的重置入口,默认 no-op(其他 Sensor 无 per-worker 观察态)。
    virtual void RearmSingleWorker(uint32_t /*worker_id*/) {}

    // GetWorkerProgress：可选；HealthMonitor::GetSnapshot() 拉取 per-worker 的**连续量**，
    //   给面板一行一 worker 的展示用。默认 no-op（返回 false = 本 Sensor 无此语义）。
    //
    //   为什么是拉不是推：这些量的主人是 Sensor（关在它的 state_mutex_ 里），而 GetSnapshot
    //   走的是低频观测节奏、不是热路径 —— 拉一次即可，无需为此引入一条跨线程推送。
    //
    //   为什么需要：is_alive 是判死之后的终态，判死要等满 miss_threshold（300s）。只有它，
    //   面板上就是"299s 一直 alive，然后啪一下 dead" —— stall 没有过程可看。
    struct WorkerProgress {
        uint32_t silent_s = 0;         // 进度令牌静止了多久
        uint32_t silent_budget_s = 0;  // 判死阈值 = miss_threshold × poll_interval
        uint32_t proc_epoch = 0;       // daemon 轮换 domain 的代次
        bool     recovering = false;   // proc_epoch 在本次静默期内涨过 = daemon 正在自救
        refuzz::core::channel_contract::WorkerSlotState slot{};
    };
    virtual bool GetWorkerProgress(uint32_t /*worker_id*/, WorkerProgress* /*out*/) const {
        return false;
    }
};

} // namespace refuzz::channel::health

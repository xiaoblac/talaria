#pragma once

// HeartbeatSensor — worker 心跳采样 Sensor
//
// 设计来源：docs/channel-redesign/v3/50_health.md §4.1
//
// 职责：
//   - 单后台线程以 round-robin 方式轮询全部 worker 的心跳；
//   - 连续 miss_threshold 次未增长 → Publish(CrashEvent::WorkerDead)
//   - 依赖 IControlPlane::SampleHeartbeat，与具体 ivshmem/shm 协议解耦
//
// 解耦要点：
//   - 读 heartbeat 的细节由 IControlPlane 实现（ivshmem 直读 ctrl.heartbeat_counter
//     / vsock 走 RPC 均可）；Sensor 对此无感
//   - 对 HealthMonitor 的依赖仅限上报面 HealthPublisher&
//   - step_event_snapshot 字段由可选注入的 IStepEventSource 提供；未提供则不填
//
// 线程安全：
//   - Start / Stop / Poke / SyncObservedWorkers 由 HealthMonitor 串行调用
//   - 后台线程独占 per-worker 状态（cursor_mutex_ 保护 SyncObservedWorkers 路径）

#include "refuzz/channel/control/control_plane.hpp"
#include "refuzz/channel/evidence/console_ring_buffer.hpp"
#include "refuzz/channel/evidence/progress_clock.hpp"
#include "refuzz/channel/evidence/step_event_source.hpp"
#include "refuzz/channel/health/sensor.hpp"
#include "refuzz/channel/result.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <string_view>
#include <thread>
#include <vector>

namespace refuzz::channel::health {

struct HeartbeatSensorConfig {
    // 单轮 poll 等待间隔。
    // [调优记录] 250ms:在 Phase H 后观察到 1s 默认值下单 worker dead 的最坏检测延迟 = 3s,
    //   叠加多 worker recovery 路径会让 exec_s 毛速率被 backoff 压到 12 task/s。
    //   250ms + miss_threshold=3 → 最坏延迟 ~750ms,recovery 能更快启动,smoke 场景
    //   backoff 占比预计从 ~94% 降到 ~50% 以内(具体看 mutation 产出的系统调用稳定性)。
    std::chrono::milliseconds poll_interval{250};
    // 连续多少次未变化判定为 dead
    uint32_t miss_threshold = 3;
    // 每轮 round-robin 推进的 worker 数。
    //   0 = 刷全部(推荐:heartbeat 采样本身很轻量,单个 ctrl region 读一次 uint64_t,
    //       n_workers ≤ 16 时也远低于 poll_interval,没必要 round-robin 分摊)。
    //   >0 = 每轮只推进 N 个,cursor 递进(历史兼容:防止大集群 poll 一次压力过大)。
    uint32_t workers_per_round = 0;
    // worker 总数（Sensor 不依赖 ShmInfra；必须显式提供）
    uint32_t worker_count = 0;
    // 是否在上报时带 step-event ring 快照（step_source 非空时生效）
    bool capture_step_events = false;

    // [Rearm grace] 单 worker 刚 restart 完成后的宽容轮数。
    //   背景:RearmSingleWorker 把 armed=false + last_counter=0 后,首轮 poll 只是建立
    //   基线(不算 miss),从第 2 轮开始 miss_threshold(3)轮连续未变 → 判死,总计最短
    //   ~1s 即可 Publish worker_dead。
    //   但冷启动时 worker 心跳线程在 VM 里可能因 vCPU 争抢、ssh/exec 开销被短暂饿。
    //   grace_rounds_after_rearm 表示"Rearm 之后的前 N 轮 poll 只更新基线、不累计
    //   consecutive_miss,也不递增 miss_threshold 判定"。
    //   默认 6 轮 × 250ms = 1.5s,配合 worker 200ms throttle 能吸收 vCPU 级别抖动。
    //   配置思路:n_workers 多 / vCPU 少时适当增大(冷启动路径拥塞更久)。
    uint32_t grace_rounds_after_rearm = 6;

    // §3.11-B — worker_dead 触发时从 ring buffer 拉的最大行数；填到
    // CrashFragment.serial_lines / console_output 作为 evidence。
    // 0 = 不抓（保持原行为）。默认 80（覆盖 rcu stall / softlockup /
    // hung_task 等典型内核 hang 警告的多行 backtrace）。
    uint32_t console_snapshot_lines = 80;
};

class HeartbeatSensor final : public IHealthSensor {
public:
    // 构造：注入 IControlPlane（心跳采样源）与可选 IStepEventSource / 可选
    // ConsoleRingBuffer（§3.11-B Bug #2 — worker_dead 触发时旁路拉 console
    // 上下文，捕获 hung_task / rcu_stall / softlockup 等内核证据）。
    // 所有指针均由上层装配保证生命周期先于 Sensor。ring_buffer 为 null 时
    // 退化到原行为（fragment.serial_lines / console_output 留空）。
    // progress_clock（检测器 B）：本 worker 心跳推进时 Note()（写）；判 worker 卡前
    //   读 LastUs() 看"本 worker 冻结期间聚合是否在前进"（相对进度门控）。null 时退化
    //   到纯绝对墙钟判定（无聚合时钟的后端）。
    HeartbeatSensor(control::IControlPlane*          cp,
                    evidence::IStepEventSource*      step_source,
                    HeartbeatSensorConfig            config,
                    evidence::ConsoleRingBuffer*     ring_buffer    = nullptr,
                    evidence::ProgressClock*         progress_clock = nullptr) noexcept;

    ~HeartbeatSensor() override;

    HeartbeatSensor(const HeartbeatSensor&)            = delete;
    HeartbeatSensor& operator=(const HeartbeatSensor&) = delete;

    std::string_view Name() const override { return "heartbeat"; }

    Result<void> Start(HealthPublisher& publisher) override;
    void         Stop() override;
    void         Poke() override;

    void SyncObservedWorkers(const std::vector<bool>& observed) override;

    // kRestartSingleWorker recovery 成功后调用:把该 worker 重新加入观察集,
    // 清掉 armed / consecutive_miss / last_counter,避免 sensor 以旧基线误判
    // 新起来的 worker(counter 从 0 开始)。
    // 并发:与 ThreadMain 并发,内部用 state_mutex_ 保护 worker_states_。
    void RearmSingleWorker(uint32_t worker_id) override;

    // 面板拉取 per-worker 连续量（见 IHealthSensor::GetWorkerProgress）。
    // 与 ThreadMain 并发，走 state_mutex_。
    bool GetWorkerProgress(uint32_t worker_id, WorkerProgress* out) const override;

private:
    void ThreadMain();

    // ── per-worker 状态（state_mutex_ 保护）──
    struct WorkerState {
        bool     observed          = true;
        bool     armed             = false;
        uint64_t last_counter      = 0;
        uint32_t consecutive_miss  = 0;
        // Rearm 之后剩余的宽容轮数。>0 时:本轮即使 counter 未变也只更新基线,不累
        // consecutive_miss。每轮 poll 扣 1。Rearm 时由 RearmSingleWorker 置为
        // config_.grace_rounds_after_rearm;SyncObservedWorkers 中将 worker 重新
        // 加入观察集时同样重置。稳态(grace=0)行为与历史版本一致。
        uint32_t grace_rounds_left = 0;
        // [检测器 B 相对进度] 本 worker 进入连续 miss 时（consecutive_miss 0→1）快照
        //   一次聚合前进时钟 LastProgressUs()。到 miss_threshold 时再读一次：若聚合
        //   推进了（别的 worker / completion 在前进），而本 worker 整窗冻结 → 真卡 →
        //   上报；若聚合也没动 = 全局停顿，不是本 worker 的锅 → 不上报，交给检测器 A。
        uint64_t miss_start_progress_us = 0;

        // ── 面板用（GetWorkerProgress 拉取）──
        // 判死要等满 miss_threshold（300s），光靠 alive/dead 面板上就是"299s 一直 alive
        // 然后啪一下 dead"。下面几个让 stall 变成看得见的过程。
        //   last_slot / last_proc_epoch：最近一次采样的分量原样留存。
        //   proc_epoch_at_miss_start：进入连续 miss 时的 epoch 快照。与当前值一比就知道
        //     **daemon 在这段静默里有没有去轮换 domain** —— 涨了 = 它活着、正在自救、卡的
        //     是被测程序（合法，最长 65s）；没涨 = 连自救都没做 = 卡的是 daemon 自己。
        //     没有这个对比，"静默 60s"无法解读。
        refuzz::core::channel_contract::WorkerSlotState last_slot{};
        uint32_t last_proc_epoch = 0;
        uint32_t proc_epoch_at_miss_start = 0;
    };

    control::IControlPlane*      cp_;
    evidence::IStepEventSource*  step_source_ = nullptr;  // 可为 null
    HeartbeatSensorConfig        config_;
    HealthPublisher*             publisher_ = nullptr;    // Start 后有效
    // [§3.11-B 移除] 心跳不再自采 console(ConsoleSensor 是串口唯一权威 reader)。
    // 成员暂保留以不动构造签名 / assembler 调用方;彻底删待 #2 动构造函数时一并清理。
    [[maybe_unused]] evidence::ConsoleRingBuffer* ring_buffer_ = nullptr;
    // 检测器 B — 共享聚合前进时钟（Channel 拥有）；本 sensor 既写（心跳推进）又读
    //   （相对进度门控）。VmAliveSensor 也读它（检测器 A）。
    evidence::ProgressClock*     progress_clock_ = nullptr;

    std::thread             thread_;
    std::atomic<bool>       stop_flag_{false};
    std::condition_variable cv_;
    std::mutex              cv_mutex_;
    bool                    thread_running_ = false;

    // mutable：GetWorkerProgress() 是 const 观测口，但仍需锁住 worker_states_
    mutable std::mutex       state_mutex_;
    std::vector<WorkerState> worker_states_;
    uint32_t                 cursor_worker_id_ = 0;
};

} // namespace refuzz::channel::health

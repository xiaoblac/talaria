#pragma once

#include "refuzz/core/metrics/metric_registry.hpp"
#include "refuzz/core/channel_contract.hpp"

#include <array>
#include <cstdint>
#include <unordered_map>

namespace refuzz::core::metrics {

// ChannelMetrics — 每个 Channel 实例一份,构造期 Bind 后指针稳定。
// 发布方只持有 ChannelMetrics*, 允许为 nullptr。
//
// Step 5a: scaffold + 所有 Gauge + §4.5 事件计数。
// Step 5b: §4.3/§4.4 源头 Counter Inc (等 D1 决策)。
struct ChannelMetrics {
    // ---- §4.1 top-level ----
    Gauge* generation                = nullptr;
    // lifecycle_state 用 one-hot: 7 个状态各一个 Gauge, 当前态置 1 其它置 0。
    // 索引顺序与 cc::ChannelLifecycleState 枚举对齐:
    //   stopped=0, booting=1, running=2, degraded=3, recovering=4, failed=5, closed=6
    std::array<Gauge*, 7> lifecycle_state{};
    Gauge* boot_ts_us                = nullptr;

    // ---- §4.2 runtime ----
    Gauge* runtime_total_slots          = nullptr;
    Gauge* runtime_free_slots           = nullptr;
    Gauge* runtime_inflight             = nullptr;
    Gauge* runtime_registered_workers   = nullptr;
    Gauge* runtime_quarantined_workers  = nullptr;

    // ---- §4.3 recovery ----
    Counter* recovery_runtime_restart   = nullptr;  // 5b, 源头 Inc
    Counter* recovery_vm_reboot         = nullptr;  // 5b, 源头 Inc
    Gauge*   recovery_consecutive_healthy = nullptr;
    Gauge*   recovery_last_fault_ts_us    = nullptr;
    Gauge*   recovery_offline             = nullptr;
    Gauge*   recovery_in_progress         = nullptr;
    // active_action one-hot: 6 个 action,索引与 cc::RecoveryAction 对齐:
    //   none=0, restart_single_worker=1, restart_all_workers=2, reboot_vm=3,
    //   fail_channel=4, restart_health_monitor=5
    std::array<Gauge*, 6> recovery_active_action{};

    // ---- §4.4 health ----
    // crash{kind=kernel|vm|worker|internal|no_output} — 5 个 Counter,5b 源头 Inc
    // 索引: 0=kernel, 1=vm, 2=worker, 3=internal, 4=no_output
    //       (对齐 cc::CrashKind 枚举顺序)
    std::array<Counter*, 5> health_crash{};
    Gauge*   health_sampled_ts_us       = nullptr;
    // per-worker 面板量 — 懒加载,避免在 snapshot 热路径上反复命中 GaugeOf 的全局锁。
    //   [0]/[1] worker_liveness{worker_id=N,state=alive|dead} — one-hot,判死后的终态
    //   [2]     worker_silent_s{worker_id=N}                  — 进度令牌静止了多久
    //   [3]     worker_silent_budget_s{worker_id=N}           — 判死阈值
    //   [4]     worker_proc_epoch{worker_id=N}                — daemon 轮换 domain 的代次
    //   [5]     worker_recovering{worker_id=N}                — 1 = 正在自救
    //   [6]     worker_slot{worker_id=N}                      — cc::WorkerSlotState
    // [2..6] 是 stall 的**过程**:只有 [0]/[1] 的话,面板上就是"299s 一直 alive,然后
    //   啪一下 dead"。尤其 [4]:静默且 proc_epoch 在涨 = daemon 活着、卡的是被测程序;
    //   静默且它冻着 = 卡的是 daemon 自己 —— 两者处置完全不同。
    static constexpr size_t kWorkerGaugeCount = 7;
    std::unordered_map<uint32_t, std::array<Gauge*, kWorkerGaugeCount>> worker_liveness_cache;

    // ---- §4.5 event aggregation ----
    // channel.event{kind=...} — 5 个 kind,在 QueueObserveEvent 里 Inc
    // 索引顺序与 cc::ChannelObserveEventKind 枚举对齐:
    //   lifecycle_changed=0, fault_detected=1, recovery_started=2,
    //   recovery_completed=3, generation_reset=4
    std::array<Counter*, 5> event_kind{};

    // ---- §4.6 input_queue (替代 Phase G input_queue_full_enter/exit 事件) ----
    // depth      = input_queue_.size() + deferred_submissions_.size() (deferred 影子值);
    //              即 Channel 总 backlog (尚未发到 worker 的 SubmitSlot 数)。
    // capacity   = channel_cfg_.input_queue_capacity 的快照;Attach 时一次 Set。
    // full_episodes  = 进入饱和的次数 (cur ≥ cap 边沿)。
    // busy_rejects   = 累计 busy 拒绝总数 (饱和期间每次 Submit 被退回 +1)。
    // full_us        = 累计饱和持续时长 (µs);消费者除以窗口长度得 full_pct。
    Gauge*   input_queue_depth          = nullptr;
    Gauge*   input_queue_capacity       = nullptr;
    Counter* input_queue_full_episodes  = nullptr;
    Counter* input_queue_busy_rejects   = nullptr;
    Counter* input_queue_full_us        = nullptr;

    // 一次性绑定 (channel_id 作为所有 series 的固定 label)。
    // 重复调用幂等 (MetricRegistry 内部返回相同引用)。
    void Bind(MetricRegistry& r, uint32_t channel_id);

    // 从 snapshot + 3 个子结构推送所有 Gauge 值 (在 PublishObserveSnapshot 里调用)。
    // 子结构改由调用方本地构造后分别传入。registry 引用仅用于懒加载 worker_liveness;
    // 其余 Gauge 用缓存指针直接赋值。
    void PublishFromSnapshot(const channel_contract::ChannelSnapshot& snap,
                             const channel_contract::ChannelRuntimeSnapshot& runtime,
                             const channel_contract::HealthMonitorSnapshot& health,
                             const channel_contract::ChannelRecoverySnapshot& recovery,
                             MetricRegistry& r);
};

} // namespace refuzz::core::metrics

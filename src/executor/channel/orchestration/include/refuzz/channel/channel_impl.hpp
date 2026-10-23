#pragma once

// channel_impl.hpp — class Channel（IChannel 的 QEMU/ivshmem 具体实现）
//
// 职责：
//   拥有全部 host 侧组件（Infra/Runtime/CP/DP/Health/Recovery）和共享状态，
//   编排生命周期，驱动事件循环，对外暴露 IChannel 接口。
//
// 线程模型：
//   - loop_thread_ 是唯一调用 cp_ / dp_ 方法的线程
//   - Submit/DrainEvents 通过 io_mutex_ 保护的队列与 loop_thread_ 交互
//   - Health 后台线程通过共享状态 + loop_cv_ 单向通知
//
// QEMU/ivshmem 特有方法（不在 IChannel 接口中）：
//   - free_slots() / inflight() / generation()：基于 ivshmem slot 模型的状态
//   - Snapshot()：包含 Health/Worker/Recovery 的完整冷快照
//
// 两段式配置：
//   - 中性字段由 ChannelConfig 承载
//   - 后端专属字段由 factory::IChannelBackendProfile 承载
//   - Assembler 组装后产出 ChannelComponents，ChannelBuilder 构造 Channel

#include "refuzz/channel/channel.hpp"
#include "refuzz/channel/internal/dispatch_record.hpp"
#include "refuzz/channel/internal/recent_program_ring.hpp"
#include "refuzz/channel/result.hpp"
#include "refuzz/core/broadcast_bus.hpp"
#include "refuzz/core/channel_contract.hpp"
#include "refuzz/core/metrics/channel_metrics.hpp"

// Channel 只持 ShmInfra / Substrate / Health / Recovery 四个具体类型的 unique_ptr。
#include "refuzz/channel/infra/shm_infra.hpp"
#include "refuzz/channel/runtime/runtime.hpp"
#include "refuzz/channel/substrate/substrate_contract.hpp"
// Channel 只依赖控制/数据/证据面的**抽象**；不再 include ivshmem 具体头。
// QemuIvshmemLinuxAssembler / MockAssembler 内部才 include 具体实现头。
#include "refuzz/channel/control/control_plane.hpp"
#include "refuzz/channel/data/data_plane.hpp"
#include "refuzz/channel/evidence/console_ring_buffer.hpp"
#include "refuzz/channel/evidence/console_source.hpp"
#include "refuzz/channel/evidence/progress_clock.hpp"
#include "refuzz/channel/evidence/step_event_source.hpp"
#include "refuzz/channel/factory/channel_assembler.hpp"  // ChannelConfig
#include "refuzz/channel/health/health_monitor_contract.hpp"
#include "refuzz/channel/recovery/recovery_contract.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <set>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace refuzz::channel {

// [v3 Phase 10] 文件级别名；头内引用对外合同类型均通过 cc::
// （由 channel.hpp 同样引入，但显式再写一次以便 include order 不同的消费方安全）
namespace cc = refuzz::core::channel_contract;

// ============================================================
// Channel — IChannel 的 QEMU/ivshmem 具体实现
// ============================================================

class Channel : public IChannel {
public:
    // [v3.5 Phase D] 公共构造器已关闭。
    //   Channel 只能由 `ChannelBuilder::Build(ChannelComponents)` 构造。
    //   理由：强制所有"装配 → 构造"路径走 Assembler → Builder，
    //         外部直接 `new Channel(cfg)` 编译期即失败。
    ~Channel() override;

    Channel(const Channel&) = delete;
    Channel& operator=(const Channel&) = delete;

    // ── IChannel 接口实现 ──
    refuzz::channel::Result<void> Boot() override;
    void Close() override;

    cc::ChannelSubmitResult Submit(const cc::ChannelDispatchRequest& request,
                               std::chrono::microseconds wait_for_slot) override;
    cc::ChannelSubmitResult Submit(cc::ChannelDispatchRequest&& request,
                               std::chrono::microseconds wait_for_slot) override;
    bool DrainEvents(EventList& events,
                     std::chrono::microseconds timeout) override;

    // [machine-check C4.6 ③] Forward to the shared-memory infra (worker-0
    // publishes env facts into the ShmHeader; ReadEnvFeatures returns false
    // until then). shm_ is declared later in this class — legal inside an
    // inline member body.
    bool ReadGuestEnvFeatures(::EnvFeatures* out) const override {
        return shm_ ? shm_->ReadEnvFeatures(out) : false;
    }
    void PublishInitialCorpusTriaged() override;

    // ── 观测平面 ──
    void AttachObservabilityPublishers(
        refuzz::core::BroadcastBus<cc::ChannelSnapshot>* snapshot_bus,
        refuzz::core::BroadcastBus<cc::ChannelObserveEvent>* event_bus,
        core::metrics::ChannelMetrics* metrics = nullptr,
        core::metrics::MetricRegistry* registry = nullptr) override;
    cc::ChannelSnapshot ObserveSnapshot() const override;
    bool DrainObserveEvents(cc::ChannelObserveEventList& events,
                            std::chrono::microseconds timeout) override;

    // 供 Orchestrator / ServiceRegistry 编排（Boot 之后非空）
    health::IHealthMonitor* GetHealthMonitor() noexcept { return health_monitor_.get(); }

private:
    // [v3.5 Phase D] 唯一构造器：接受已装配的 ChannelComponents。
    //   private + friend ChannelBuilder：强制外部走 ChannelBuilder::Build。
    explicit Channel(ChannelComponents components);
    friend class ChannelBuilder;


    // Submit 非阻塞：Submit() 入队后立即返回 kAccepted，loop_thread_ 异步处理 TrySend。
    // TrySend 失败（deadline 到期或 channel 不可用）→ 通过 DrainEvents 发出 AbnormalCompletion(kCancelled)。
    struct SubmitSlot {
        cc::ChannelDispatchRequest                  request;
        std::chrono::steady_clock::time_point   deadline;
    };

    using DispatchRecordMap = std::unordered_map<uint64_t, DispatchRecord>;

    // ── 编排循环 ──
    void LoopMain();
    void DrainInputAndSend();
    void DrainTransport(std::chrono::microseconds timeout = std::chrono::microseconds{0});
    bool HasPendingFaultEvents() const;
    void HandleFault();
    void MaybeNoteHealthy();

    // ── input_queue metric helpers (调用方需持 io_mutex_) ──
    // depth = input_queue_.size() + deferred_count_.load() (deferred 影子值);
    // ComputeInputQueueDepthLocked 只读,PublishInputQueueDepthLocked 把当前 depth Set 到
    // channel.input_queue.depth gauge; ForceExitInputFullEpisodeLocked 在饱和期间被
    // 强制退出 (相位切换 / Close) 时累加 full_us 并重置三个 input_full_* 状态。
    int64_t ComputeInputQueueDepthLocked() const noexcept;
    void PublishInputQueueDepthLocked();
    void ForceExitInputFullEpisodeLocked();

    // [v2 单 worker 故障处理 — 当前版本]
    // HandleWorkerFault：处理单个 worker 级故障，进入 kDegraded 状态
    // AsyncRecoverWorker：后台线程执行单 worker 恢复，不阻塞 loop_thread_
    // CheckWorkerRecoveryComplete：loop_thread_ 轮询恢复信号并应用结果
    void HandleWorkerFault(const health::CrashFragment& fragment,
                           cc::ChannelFaultReason reason,
                           uint64_t trigger_fault_event_id,
                           uint32_t worker_id,
                           cc::FaultOrigin origin);
    void AsyncRecoverWorker(uint32_t worker_id,
                            cc::ChannelFaultReason reason,
                            uint64_t trigger_fault_event_id);
    void CheckWorkerRecoveryComplete();
    void DrainHealthyInflightBeforeReboot(uint32_t budget_ms);
    void EnqueueWorkerRecovery(uint32_t worker_id,
                               cc::ChannelFaultReason reason,
                               uint64_t trigger_fault_event_id);
    bool TryStartNextWorkerRecovery();
    void MaybeRestoreRunningFromDegraded();

    // ── 辅助方法 ──
    void QueueEvent(cc::ChannelEvent event);
    void WakeLoopPoller() noexcept;
    void AbortPendingByScope(cc::ChannelAbortScope scope,
                             uint32_t target_slot_id = UINT32_MAX);
    void EmitAbnormalCompletion(uint64_t executor_id, cc::AbnormalKind kind);
    void EmitAbnormalCompletion(const DispatchRecord& record, cc::AbnormalKind kind);
    // 恢复结果回填 in-flight 终态时使用：只对仍在本 channel pending 表中的任务发
    // abnormal，发完同步 settle（erase pending / active ids / inflight count）。
    // AbortPendingByScope 已经按 scope 提前清空并结算过的任务（例如 kKernelCrash →
    // kRebootVm 的 kChannel abort）在这里必须跳过，否则同一 executor_id 会拿到两个
    // abnormal 终态，`terminal <= generated + reexec` 不变量被 reboot 重复结算破坏。
    void EmitAbnormalCompletionAndSettleIfPending(uint64_t executor_id,
                                                  cc::AbnormalKind kind);
    void DrainWorkerMaintenanceFaults();
    void QueueWorkerMaintenanceFault(uint32_t worker_id,
                                     uint32_t error_code);
    void EmitFaultEvent(cc::ChannelFaultReason reason,
                        const health::CrashFragment& fragment,
                        cc::FaultOrigin origin = cc::FaultOrigin::kUnknown);
    static uint64_t NowUs();

    static cc::ChannelFaultReason MapCrashKindToFaultReason(health::CrashKind kind);
    static cc::ChannelState MapLifecycleToState(cc::ChannelLifecycleState lifecycle_state);
    static cc::FaultKind MapCrashKindToFaultKind(health::CrashKind kind);

    //拿到每个组件的snapshot
    cc::ChannelRuntimeSnapshot CollectRuntimePart() const;
    cc::HealthMonitorSnapshot CollectHealthPart(cc::ChannelLifecycleState lifecycle_state) const;
    cc::ChannelRecoverySnapshot CollectRecoveryPart() const;

    //向telemetry发送事件
    void QueueObserveEvent(cc::ChannelObserveEvent event);
    void PublishObserveSnapshot();
    void MaybePublishObserveSnapshot();
    void SetLifecycleState(cc::ChannelLifecycleState new_state);
    void EmitObserveFaultDetected(cc::FaultKind fault_kind, cc::ChannelFaultReason fault_reason);
    void EmitObserveRecoveryStarted(cc::RecoveryAction action, cc::ChannelFaultReason reason);
    void EmitObserveRecoveryCompleted(cc::RecoveryAction action,
                                      cc::ChannelFaultReason reason,
                                      bool success,
                                      std::string error_message = {});
    void EmitObserveGenerationReset(uint32_t old_generation, uint32_t new_generation);

    // Channel 运行参数统一走 channel_cfg_（ChannelConfig，定义在本类末尾）。
    // QEMU/ivshmem 专属配置由 QemuIvshmemLinuxAssembler 在内部 dynamic_cast
    // IChannelBackendProfile 读取，用于构造组件；Channel 类本体对 profile 零感知。

    // ── A. Health 写入的 crash 状态（Health 线程写，loop_thread_ 读）──
    // health 侧 crash 状态已移入 HealthMonitor 内部（§18.3.2）
    // vm_epoch_ 是 channel 独立维护的 VM 身份世代计数（§18.5.3）
    std::atomic<uint64_t>       vm_epoch_{0};
    std::atomic<bool>           initial_corpus_triaged_{false};
    std::mutex                  loop_mutex_;
    std::condition_variable     loop_cv_;

    // ── B. 数据平面队列（io_mutex_ 保护）──
    mutable std::mutex                         io_mutex_;
    std::condition_variable                    output_cv_;
    std::atomic<bool>                          input_pending_{false};

    // [v2 submit-slot-queue — 当前版本]
    // Submit 推入 SubmitSlot，loop_thread_ 消费并 resolve promise
    // [heap churn 减少 2026-05-22] unique_ptr 替代 shared_ptr — SubmitSlot
    // 是单 owner (Submit → input_queue → deferred → 发出后销毁), 没有真正的
    // 共享所有权. unique_ptr 省 atomic refcount inc/dec, 在 KASAN 上每个
    // alloc 也少一份 control block heap alloc.
    std::queue<std::unique_ptr<SubmitSlot>>    input_queue_;
    std::deque<cc::ChannelEvent>                   output_queue_;
    struct PendingFaultInput {
        health::CrashEvent event;
        std::optional<cc::ChannelFaultReason> reason_override;
        cc::ChannelFaultSource source = cc::ChannelFaultSource::kHealthMonitor;
        cc::FaultOrigin origin = cc::FaultOrigin::kUnknown;
    };
    // Confirmed worker failures originating from the data plane. Source,
    // reason and origin stay explicit instead of masquerading as heartbeat.
    std::deque<PendingFaultInput>                  internal_crash_events_;

    // [v2 deferred-submissions — 当前版本]
    // 尚未发送成功的 SubmitSlot，每轮 loop 重试直到 deadline 到期
    // 注：deferred_submissions_ 由 loop_thread_ 独占，无需加锁
    std::deque<std::unique_ptr<SubmitSlot>>    deferred_submissions_;
    // deferred 计数，Submit 侧读（relaxed），loop_thread_ 写
    std::atomic<uint32_t>                      deferred_count_{0};

    // [Phase G] input 队列饱和边沿事件所需的状态:
    //           进入/退出饱和时各打一次 input_queue_{full_enter,full_exit},
    //           热路径上 Submit()/loop 里不打 busy log,只在边沿改这个 bool。
    bool       input_full_{false};
    uint64_t   input_full_enter_us_{0};
    uint64_t   input_full_busy_rejects_{0};  // 进入饱和期间被拒的 Submit 计数,用于 exit 时汇总

    // ── C. 执行跟踪（loop_thread_ 独占写读）──
    DispatchRecordMap                           pending_;
    std::atomic<int>                             inflight_count_{0};  // loop_thread_ 写，外部 atomic 读
    std::atomic<uint32_t>                        generation_{0};
    uint64_t                                     next_event_id_{1};
    // loop_thread_-local scratch for IDataPlane::Poll results. Reusing the
    // outer vector avoids one hot-path allocation per DrainTransport call; the
    // output payload vectors are still moved into ChannelEvent and keep their
    // existing ownership/lifetime semantics.
    std::vector<data::DispatchOutcome>           transport_results_;

    // [v2 防重复 executor_id — 当前版本]
    // 跨 input/deferred/pending 三阶段的活动 executor_id 集，由 io_mutex_ 保护。
    // Submit 入队前检查并插入；完成/放弃/Close 时删除。防止同一 executor_id 覆盖 pending_。
    std::unordered_set<uint64_t>                 active_executor_ids_;

    // [crash-execution-history-ring] Layer-2 crash history: per-worker-slot
    // count-bounded ring of recently COMPLETED programs. loop_thread_-exclusive
    // (same discipline as pending_): Note on each completion, Collect on a
    // confirmed kernel-crash fault, Reset on VM reboot. Constructed in the ctor
    // body from channel_cfg_ (n_workers × crash_history_depth).
    RecentProgramRing                            recent_programs_;

    // ── D. 健康检查计时 + 调度状态（loop_thread_ 独占）──
    uint64_t health_check_last_us_{0};
    uint32_t next_worker_rr_{0};  // round-robin 下一个尝试的 worker

    // [v2 单 worker 隔离 — 当前版本]
    // quarantined_workers_：被隔离的 worker ID 集合，loop_thread_ 独占读写
    std::set<uint32_t> quarantined_workers_;

    // [v2 异步恢复线程 — 当前版本]
    // recovery_thread_ 执行单 worker 恢复序列（SSH 操作），不阻塞 loop_thread_
    std::thread                  recovery_thread_;
    // worker_recovery_pending_：标记后台恢复是否正在进行，原子操作防竞争
    std::atomic<bool>            worker_recovery_pending_{false};

    // RecoverySignal：恢复完成后由 recovery_thread_ 写入，loop_thread_ 读取并处理
    struct RecoverySignal {
        uint32_t worker_id = UINT32_MAX;
        bool success = false;
        cc::ChannelFaultReason reason = cc::ChannelFaultReason::kWorkerHeartbeatLost;
        uint64_t trigger_fault_event_id = 0;
        // 失败时保存 ExecuteRecovery 的具体 error message（r1/r3/r4），便于诊断
        std::string error_message;
        // [当前版本 ssh-dead-escalation] 失败时携带 ExecuteRecovery 的 ErrorKind。
        // loop_thread_ 在 CheckWorkerRecoveryComplete 看到 kTimeout/kConnection 时
        // 把 reason 改为 kVmDead 重新 ObserveFault，policy 直接跳到 kRebootVm,
        // 避免在 SSH 已死的场景上再做 2 次 5–15s 的 RestartSingleWorker。
        ErrorKind error_kind = ErrorKind::kRecovery;
        // [single-worker inflight leak] The restarted worker's OWN in-flight tasks,
        // snapshotted before StopWorker destroyed its slot. Carried across threads
        // because EmitAbnormalCompletion must run on loop_thread_ (like the bulk
        // recovery path does), while RunWorkerRecovery runs off it.
        // See recovery_types.hpp target_worker_inflight_executor_ids.
        std::vector<uint64_t> target_inflight_ids;
        std::vector<uint64_t> target_inflight_idle_ids;
    };
    struct PendingWorkerRecovery {
        uint32_t worker_id = UINT32_MAX;
        cc::ChannelFaultReason reason = cc::ChannelFaultReason::kWorkerHeartbeatLost;
        uint64_t trigger_fault_event_id = 0;
    };
    // recovery_signal_mutex_ 保护 recovery_signal_ 的跨线程访问
    std::mutex                   recovery_signal_mutex_;
    std::optional<RecoverySignal> recovery_signal_;
    std::deque<PendingWorkerRecovery> worker_recovery_queue_;
    std::set<uint32_t> worker_recovery_queued_;
    uint32_t active_worker_recovery_worker_id_{UINT32_MAX};

    // ── E. 生命周期状态 ──
    std::atomic<cc::ChannelLifecycleState> phase_{cc::ChannelLifecycleState::kStopped};
    std::atomic<bool>                   running_{false};
    std::thread                         loop_thread_;
    uint64_t                            boot_ts_us_{0};

    mutable std::mutex                  observe_mu_;
    std::condition_variable             observe_cv_;
    std::deque<cc::ChannelObserveEvent>     observe_queue_;
    std::atomic<uint64_t>               next_observe_event_id_{1};
    refuzz::core::BroadcastBus<cc::ChannelSnapshot>* observe_snapshot_bus_ = nullptr;
    refuzz::core::BroadcastBus<cc::ChannelObserveEvent>* observe_event_bus_ = nullptr;
    uint64_t                            last_snapshot_publish_us_{0};

    // [v2 metric bus — Step 5a] metric 句柄缓存,由 AttachObservabilityPublishers 注入。
    // nullptr/nullptr 降级为旧行为 (不发布 metric)。
    core::metrics::ChannelMetrics*      metrics_  = nullptr;
    core::metrics::MetricRegistry*      registry_ = nullptr;

    // ── F. 可观测数据（stats_mutex_ 保护）──
    mutable std::mutex              stats_mutex_;
    uint64_t                        total_submissions_{0};
    uint64_t                        total_completions_{0};
    uint64_t                        total_faults_{0};
    uint64_t                        total_recoveries_ok_{0};
    uint64_t                        total_recoveries_fail_{0};

    // ── 组件实例（[v3.5 Phase C] 全部面向接口声明）──
    //
    // 声明阶段只承诺"Channel 依赖抽象接口"，具体实现由 Assembler 装配并塞入。
    // Phase C 过渡期：Boot() 仍在本类内部实例化具体类型（std::make_unique<Ivshmem...>），
    // 赋值给 unique_ptr<IXxx>。Phase D/E 完成后这些实例化会完全搬到 Assembler。
    std::shared_ptr<infra::ShmInfra>                shm_;
    std::unique_ptr<runtime::ISubstrate>            substrate_;
    std::unique_ptr<control::IControlPlane>         cp_;
    std::unique_ptr<data::IDataPlane>               dp_;
    std::unique_ptr<health::IHealthMonitor>         health_monitor_;
    std::unique_ptr<recovery::IRecovery>            recovery_;

    // [v3 Phase 5] Evidence 源：Sensor 通过这两个指针取数据
    //   - console_source_：行流；ConsoleSensor 消费
    //   - step_event_source_：step-event ring；Sensor 可选使用
    std::unique_ptr<evidence::IConsoleSource>       console_source_;
    std::unique_ptr<evidence::IStepEventSource>     step_event_source_;

    // §3.11-B — 共享 console 行 buffer（ConsoleSensor 写、HeartbeatSensor
    //   读）。Sensor 持有 raw pointer；这里持有 unique_ptr 让 buffer
    //   lifetime 和 Channel 对齐 —— 必须在 health_monitor_（拥有 sensor）
    //   被销毁之后再销毁，因此 declaration 顺序放在 health_monitor_ **之前**
    //   （C++ 反序销毁：声明在前 = 析构在后 = sensor 不会看到悬空 ring）。
    //
    //   注意：health_monitor_ 在第 293 行声明 → 销毁更早。console_ring_
    //   在此处声明 → 销毁更晚。安全。
    std::unique_ptr<evidence::ConsoleRingBuffer>    console_ring_;

    // 聚合前进时钟（检测器 A/B 的中立 liveness 信号）。与 console_ring_ 同一 ownership
    //   语义：Channel 拥有 unique_ptr，声明在 health_monitor_ 之后 → 析构更晚 → sensor
    //   线程停掉后才销毁，不会悬空。写方=HeartbeatSensor(心跳推进)+本 Channel(completion
    //   收割)；读方=VmAliveSensor / HeartbeatSensor。
    std::unique_ptr<evidence::ProgressClock>        progress_clock_;

    // Channel 的权威配置：由 Assembler 完整填充，构造器直接 move。
    // 后端专属字段不在此处——Channel 本体对 backend profile 零感知。
    ChannelConfig                                   channel_cfg_;

};

} // namespace refuzz::channel

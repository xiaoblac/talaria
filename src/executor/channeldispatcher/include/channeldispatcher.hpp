// Copyright 2026 reFuzz project author -------youngkk.

#pragma once


// [v4 executor.hpp — 当前版本]
// 极简化：直接持有 IChannel*，无 TargetState 缓存，无 IDispatchTarget 适配器
// 提交策略：round-robin 轮询所有 channel，Submit(req, 0) 非阻塞尝试入队
// 两线程模型：submit 线程 + event 线程，跨线程 cv 唤醒

#include "refuzz/channel/channel.hpp"
// [6b-3 — 当前版本] ExecutorSnapshot/WatchBus 已随 6b-3 删除
#include "refuzz/core/service.hpp"
#include "refuzz/queue/event_queue.hpp"
#include "refuzz/queue/host_fuzz_task.hpp"   // §3.10 step 5 — HostFuzzTask
#include "refuzz/queue/lifecycle_queue.hpp"  // [request-window] accepted/rejected 生命周期出口
#include "refuzz/queue/task_queue.hpp"
#include "submit_strategy.hpp"
// [v2 metric bus — 当前版本]
#include "refuzz/executor/metrics/executor_metrics.hpp"

#include "refuzz/program/artifact.hpp"   // post-V1-retirement — artifact-first universal contract

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace refuzz {
namespace channeldispatcher {

// ExecutorConfig — 简化配置
// [Phase H] 执行器语义更新:
//   - 无限重试:task 永不丢,Submit 一直重试直到 Channel accept
//   - 主唤醒路径:event 线程处理 completion/abnormal 后调 NotifySubmitThread()
//   - 兜底:idle_sleep_us 作为 CV.wait_for 超时,防 NotifySubmitThread 漏发死锁
//     不再是高频轮询周期。因此默认值从 500us 提到 1'000'000us(1s)。
struct ExecutorConfig {
    uint64_t idle_sleep_us = 1'000'000;        // submit 线程被 event 唤醒的兜底超时(1s)
    uint64_t event_blocking_timeout_us = 1000; // event 线程无事件时的阻塞等待
    std::string submit_strategy = "round_robin";
    // [Phase H] 遗留字段:Channel 侧已废弃 slot deadline(无限重试),
    //   executor 传给 Submit 的 wait_for_slot 现已统一为 0。
    //   保留此配置便于将来若恢复 slot 级 deadline 时直接用。
    uint64_t submit_wait_for_slot_ms = 0;
    // [v2 Epic 7 PR-4.6] 全局 IntraTaskMode 默认值。config_parser 从
    // target.intra_task_mode 翻译过来:"threaded" → true,"serial"(default) → false。
    // true 时 BuildRequest 在 wire 翻译点统一 OR TASK_FLAG_INTRA_THREADED;
    // 单 task 通过 opts.flags |= kExecFlagIntraThreaded 仍能 per-task 设。
    // false 时 (default) 行为完全等价 Epic 7 PR-4 ship 之前 — task 全部
    // serial,worker driver 走 serial fast path,KernelThreadPool 不构造。
    bool default_intra_threaded = false;
};

class Executor : public refuzz::core::IService {
public:
    explicit Executor(ExecutorConfig config = {},
                      refuzz::core::metrics::MetricRegistry* registry = nullptr);
    ~Executor() override;

    // IService
    std::string_view Name() const override { return "executor"; }
    refuzz::core::ServiceResult Init() override;
    refuzz::core::ServiceResult Start() override;
    refuzz::core::ServiceResult Stop() override;
    bool IsRunning() const override;

    // 在 InitAll/StartAll 之前注入（IService::Start 使用）
    void SetLoopContext(refuzz::queue::InMemoryTaskQueue* task_queue,
                        refuzz::queue::InMemoryEventQueue* event_queue,
                        std::chrono::milliseconds pop_timeout,
                        std::chrono::microseconds poll_timeout);
    // [request-window] 注入 pull/window 生命周期出口(orchestrator 与 FuzzerLoop 共用同一实例)。
    // submit 线程在 Channel::Submit kAccepted / host fail-closed kRejected 时 Push 一个
    // RequestLifecycleEvent。nullptr / 未注入(直驱 ProcessOnce 的单测)→ 不发,行为等价历史。
    void SetLifecycleQueue(refuzz::queue::InMemoryLifecycleQueue* lifecycle_queue);
    // [6b-3 — 当前版本] SetSnapshotBus 已删除, executor 状态全部经 MetricRegistry 发布

    // 直接注册 IChannel 指针（不拥有生命周期）
    void AddChannel(refuzz::channel::IChannel* channel);
    void ClearChannels();

    // [Phase H] 注入 submit 策略(不传时默认 RoundRobinStrategy)。
    // 必须在 StartThreads 之前调用。策略生命周期由 Executor 拥有。
    void SetSubmitStrategy(std::unique_ptr<ISubmitStrategy> strategy);

    bool StopRequested() const;
    // [6b-3 — 当前版本] Snapshot() 已删除, 所有 executor 状态改读 MetricRegistry

    // 双线程模型：submit 线程负责 Pop + TrySubmit，event 线程负责 DrainEvents + 转发
    bool StartThreads(refuzz::queue::InMemoryTaskQueue& task_queue,
                      refuzz::queue::InMemoryEventQueue& event_queue,
                      std::chrono::milliseconds pop_timeout,
                      std::chrono::microseconds poll_timeout);
    void StopThreads();

    // 单线程兼容接口（供测试使用）：先排干事件再尝试提交
    bool ProcessOnce(refuzz::queue::InMemoryTaskQueue& task_queue,
                     refuzz::queue::InMemoryEventQueue& event_queue,
                     std::chrono::milliseconds pop_timeout,
                     std::chrono::microseconds poll_timeout);

private:
    // 已注册的 channel 条目
    struct ChannelEntry {
        refuzz::channel::IChannel* channel = nullptr;
        uint32_t channel_id = 0;  // 注册时从 ObserveSnapshot() 获取（0 则分配本地 ID）
    };

    struct ChannelCache {
        uint64_t generation = UINT64_MAX;
        std::vector<ChannelEntry> entries;
        std::vector<ChannelView> views;
    };

    // 待提交任务缓冲（Submit 线程独占）
    struct PendingSubmit {
        // [v1 — proto::Task ROLLBACK]
        // refuzz::proto::Task task;
        // [v2 — §3.10 step 5 (D7). HostFuzzTask carries ProgramArtifact +
        //  transitional payload bytes; the on-wire proto::Task is built
        //  in PendingSubmit.request below at the channel-dispatch boundary.]
        refuzz::queue::HostFuzzTask task;
        refuzz::core::channel_contract::ChannelDispatchRequest request;

        // [Phase H] 提交重试计量(无限重试语义,task 永不丢):
        //   started_at        — 第一次看到这个 PendingSubmit 的时刻(Pop 之后赋值)
        //                       仅用于汇总到 submit_accepted 的 wait_us_total 字段。
        //   retries           — 到目前被 kBusy / kUnavailable 挡回的轮数,
        //                       accept 时作为 retries= 字段一起打。
        //   backoff_logged    — 是否已经打过 submit_backoff_enter(防重);
        //                       accept 时若该标志为 true,会配对打一条 submit_backoff_exit。
        //   backoff_enter_at  — [Stage 1] 进入 backoff 的具体时刻(和 backoff_logged 同步设置);
        //                       accept 时(accept - enter_at)= 本次 backoff 实际占用墙钟时长,
        //                       累加到 submit_backoff_wait_us_total_ 供 orchestrator 算 exec_s_net。
        //                       注意:不能用 (accept - started_at),那会把第一次 kBusy 之前的
        //                       "正常处理延迟"也算进 backoff,高估限流时间。
        std::chrono::steady_clock::time_point started_at{};
        std::chrono::steady_clock::time_point backoff_enter_at{};
        uint64_t retries{0};
        bool     backoff_logged{false};
    };

    // ── channel 注册表 ──
    mutable std::mutex channels_mu_;
    std::vector<ChannelEntry> channels_;
    std::atomic<uint64_t> channels_generation_{0};
    uint32_t next_local_channel_id_ = 0x80000000u;

    // ── 配置 ──
    ExecutorConfig config_;

    // [v2 metric bus — 当前版本]
    refuzz::core::metrics::MetricRegistry* registry_ = nullptr;
    refuzz::executor::metrics::ExecutorMetrics metrics_{};

    // ── 待提交任务缓冲（Submit 线程独占） ──
    std::optional<PendingSubmit> pending_;

    // ── 在飞 artifact 表（post-V1-retirement artifact-first universal contract） ──
    // submit 线程 kAccepted 时插入；completion 线程 ForwardEvents 时按 executor_id
    // 查并 erase，把 ProgramArtifact 注入到出口 ChannelEvent 的 ctx.artifact 字段。
    // Channel 自身不知道 ProgramArtifact —— channel/worker 边界永远是 bytes-only
    // (proto::Task)，artifact 由 channeldispatcher 这一层负责跨 submit/completion
    // 配对。每个 executor_id 由上游 stage 单调分配（control/src/stages/*）；
    // 不存在重复 key。
    // 详见 docs/syzkaller-parity-review/post_v1_retirement_followups.md。
    mutable std::mutex inflight_artifacts_mu_;
    std::unordered_map<uint64_t,
                       std::shared_ptr<const ::refuzz::program::ProgramArtifact>>
        inflight_artifacts_;

    // [async-crash-reproduction Phase 1] bounded FIFO ring of recently-COMPLETED
    // programs' typed artifacts (executor_id -> artifact). On completion the
    // artifact is moved out of inflight_artifacts_, so a later fault's history
    // entries would have no typed view; this ring retains them long enough for
    // AttachArtifactToEvent to match candidate_window history entries by
    // executor_id. Guarded by inflight_artifacts_mu_. Cap >= max Layer-2 history
    // coverage (ring depth × workers). See docs/plans/async-crash-reproduction.md.
    static constexpr std::size_t kRecentArtifactsCap = 512;
    std::deque<std::pair<uint64_t,
                         std::shared_ptr<const ::refuzz::program::ProgramArtifact>>>
        recent_artifacts_;

    // ── 跨线程唤醒：event 完成通知 submit 线程 ──
    std::mutex wake_mu_;
    std::condition_variable wake_cv_;
    bool wake_signal_ = false;

    // ── 统计计数器（原子，允许跨线程读） ──
    std::atomic<uint64_t> events_forwarded_{0};
    std::atomic<uint64_t> tasks_submitted_{0};
    // [Stage 1] submit_backoff 时长累计:配合 submit_backoff_exit 时的 wait_us 递增,
    //   [6b-3] orchestrator 改从 MetricRegistry 读 executor.dispatch.backoff_wait_us。
    std::atomic<uint64_t> submit_backoff_wait_us_total_{0};
    std::atomic<uint64_t> submit_backoff_episodes_{0};
    // [v2 Epic 7 PR-11 B1] host-side encoder fail-closed:
    //   MaterializeExecWire 返 ExecError 时 task 不投 worker,改为合成 host-side
    //   AbnormalCompletion 推回 event_queue。计数让 host 操作员可观察 mutator
    //   生成 broken IR 的频率,后续 follow-up (Step B2) 修 mutator IR-invariant。
    std::atomic<uint64_t> materialize_exec_wire_failed_{0};
    // host-side synthesized abnormal completion 的 event_id 生成器。从大数起
    // 步避免和 channel-side event_id 重叠(channel event_id 通常 = inflight
    // executor_id 或递增小数);bit 63 标记 "host-synthesized"。
    std::atomic<uint64_t> host_event_id_counter_{uint64_t{1} << 62};

    // ── 目标选择策略 / 游标 ──
    // [Phase H] submit 线程:策略化选目标,默认 RoundRobinStrategy(行为等同旧 rr_cursor_)
    std::unique_ptr<ISubmitStrategy> submit_strategy_;
    ChannelCache submit_channel_cache_;
    ChannelCache event_channel_cache_;
    size_t event_rr_cursor_ = 0;     // event 线程:阻塞 drain 游标(暂未抽策略)

    // ── 线程对象与控制标志 ──
    std::thread submit_thread_;
    std::thread completion_thread_;
    std::atomic<bool> submit_running_{false};
    std::atomic<bool> completion_running_{false};
    std::atomic<bool> stop_requested_{false};
    refuzz::queue::InMemoryTaskQueue* active_task_queue_ = nullptr;
    refuzz::queue::InMemoryEventQueue* event_queue_ = nullptr;
    // [request-window] pull/window 生命周期出口(submit 线程 Push;orchestrator 注入,
    //   与 FuzzerLoop 同一实例)。nullptr = 未注入(单测直驱)→ 不发事件。
    refuzz::queue::InMemoryLifecycleQueue* lifecycle_queue_ = nullptr;

    refuzz::queue::InMemoryTaskQueue*  loop_task_queue_  = nullptr;
    refuzz::queue::InMemoryEventQueue* loop_event_queue_ = nullptr;
    std::chrono::milliseconds          loop_pop_timeout_{};
    std::chrono::microseconds          loop_poll_timeout_{};
    // [6b-3 — 当前版本] snapshot_bus_ 已删除

    // ── 内部工具 ──
    const ChannelCache& ChannelsSnapshot(ChannelCache& cache) const;
    // [6b-3 — 当前版本] 发布 executor 状态到 MetricRegistry, 无需 ExecutorSnapshot 中间体
    void PublishSnapshot();

    // ── Submit 路径 ──
    bool ProcessSubmitOnce(refuzz::queue::InMemoryTaskQueue& task_queue,
                           std::chrono::milliseconds pop_timeout);
    void SubmitLoop(refuzz::queue::InMemoryTaskQueue* task_queue,
                    std::chrono::milliseconds pop_timeout);
    void WaitForWakeOrTimeout(uint64_t max_wait_us);
    void NotifySubmitThread();

    // ── Event 路径 ──
    bool ProcessEventsOnce(std::chrono::microseconds poll_timeout);
    void EventLoop(std::chrono::microseconds poll_timeout);
    size_t ForwardEvents(refuzz::channel::EventList& events);
    // post-V1-retirement artifact-first universal contract:
    //   ForwardEvents 调用此方法在 push 到 event_queue_ 前把 inflight 表里按
    //   executor_id 缓存的 ProgramArtifact 注入到 ctx.artifact。命中时 erase。
    void AttachArtifactToEvent(refuzz::core::channel_contract::ChannelEvent& event);
};

} // namespace channeldispatcher
} // namespace refuzz

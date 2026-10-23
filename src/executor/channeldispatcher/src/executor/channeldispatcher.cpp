// Copyright 2026 reFuzz project author -------youngkk.


// 极简化：直接持有 IChannel*，无适配器，无 TargetState
// 提交：round-robin 轮询，Submit(req, 0) 非阻塞尝试入队，失败则等待唤醒
// 事件：非阻塞轮询全部 channel，无事件时阻塞等待一个 channel

#include "channeldispatcher.hpp"

#include "refuzz/program/artifact_materializer.hpp"   // §3.10 step 7 — Materialize{Canonical,ExecWire}
#include "refuzz/logging/host_logger.hpp"
#include "refuzz/core/metrics/metric_registry.hpp"
#include "refuzz/core/time.hpp"
// [v2 Epic 5 PR-5-B] proto::kExecFlagCollectComps + TASK_FLAG_COLLECT_COMPS for
// proto→wire flag translation in the request builder.
#include "refuzz/proto_domain/types.hpp"
#include "refuzz/proto_wire/ivshmem_protocol.h"

#include <algorithm>
#include <chrono>
#include <memory>
#include <string_view>
#include <thread>
#include <utility>

namespace refuzz {
namespace channeldispatcher {

namespace {

const char* SubmitStatusName(refuzz::core::channel_contract::ChannelSubmitStatus status)
{
    switch (status) {
    case refuzz::core::channel_contract::ChannelSubmitStatus::kAccepted:
        return "accepted";
    case refuzz::core::channel_contract::ChannelSubmitStatus::kBusy:
        return "busy";
    case refuzz::core::channel_contract::ChannelSubmitStatus::kUnavailable:
        return "unavailable";
    case refuzz::core::channel_contract::ChannelSubmitStatus::kInvalid:
    default:
        return "invalid";
    }
}

refuzz::proto::TaskTrace*
MutableTrace(refuzz::core::channel_contract::ChannelEvent& event) noexcept
{
    if (auto* p = event.AsCompletion(); p != nullptr) {
        return &p->ctx.trace;
    }
    if (auto* p = event.AsAbnormal(); p != nullptr) {
        return &p->ctx.trace;
    }
    return nullptr;
}

const char* EventKindName(refuzz::core::channel_contract::ChannelEvent::Kind kind)
{
    switch (kind) {
    case refuzz::core::channel_contract::ChannelEvent::Kind::kCompletion:
        return "completion";
    case refuzz::core::channel_contract::ChannelEvent::Kind::kAbnormal:
        return "abnormal";
    case refuzz::core::channel_contract::ChannelEvent::Kind::kFault:
        return "fault";
    }
    return "unknown";
}

std::unique_ptr<ISubmitStrategy> MakeSubmitStrategy(std::string_view name)
{
    // Parser currently accepts only round_robin. Keep this factory here so
    // ExecutorConfig is the single strategy selection point when more are added.
    (void)name;
    return std::make_unique<RoundRobinStrategy>();
}

template <typename EmitFn>
void EmitHotPathLog(uint64_t sample_key, EmitFn&& emit)
{
    auto& logger = refuzz::logging::HostLogger::Instance();
    if (logger.ShouldLogHotPath(sample_key)) {
        emit(logger);
    }
}

} // namespace

// ============================================================
// 构造 / 析构
// ============================================================

Executor::Executor(ExecutorConfig config, core::metrics::MetricRegistry* registry)
    : config_(std::move(config))
    , registry_(registry)
    , submit_strategy_(MakeSubmitStrategy(config_.submit_strategy))
{
    if (registry_ != nullptr) {
        metrics_.Bind(*registry_);
    }
}

Executor::~Executor()
{
    StopThreads();
}

void Executor::SetLoopContext(refuzz::queue::InMemoryTaskQueue* task_queue,
                              refuzz::queue::InMemoryEventQueue* event_queue,
                              std::chrono::milliseconds pop_timeout,
                              std::chrono::microseconds poll_timeout)
{
    loop_task_queue_  = task_queue;
    loop_event_queue_ = event_queue;
    loop_pop_timeout_ = pop_timeout;
    loop_poll_timeout_ = poll_timeout;
}

void Executor::SetLifecycleQueue(refuzz::queue::InMemoryLifecycleQueue* lifecycle_queue)
{
    lifecycle_queue_ = lifecycle_queue;
}

// [6b-3 — 当前版本] SetSnapshotBus 已删除, 状态改经 MetricRegistry 发布

refuzz::core::ServiceResult Executor::Init()
{
    std::lock_guard<std::mutex> lock(channels_mu_);
    if (channels_.empty()) {
        return std::unexpected(
            refuzz::core::ComponentError::Init("executor", "no channels"));
    }
    return {};
}

refuzz::core::ServiceResult Executor::Start()
{
    if (loop_task_queue_ == nullptr || loop_event_queue_ == nullptr) {
        return std::unexpected(
            refuzz::core::ComponentError::Init("executor", "loop queues not set (SetLoopContext)"));
    }
    if (!StartThreads(*loop_task_queue_, *loop_event_queue_, loop_pop_timeout_, loop_poll_timeout_)) {
        return std::unexpected(
            refuzz::core::ComponentError::Init("executor", "thread start failed"));
    }
    return {};
}

refuzz::core::ServiceResult Executor::Stop()
{
    StopThreads();
    return {};
}

bool Executor::IsRunning() const
{
    return submit_running_.load(std::memory_order_acquire)
        || completion_running_.load(std::memory_order_acquire);
}

// ============================================================
// Channel 管理
// ============================================================

void Executor::AddChannel(refuzz::channel::IChannel* channel)
{
    if (channel == nullptr) return;

    // 从 Channel 获取 ID；返回 0 时分配本地 ID
    const auto snap = channel->ObserveSnapshot();
    uint32_t cid = snap.channel_id;

    {
        std::lock_guard<std::mutex> lock(channels_mu_);

        // 检查重复（同指针或同 ID）
        for (const auto& entry : channels_) {
            if (entry.channel == channel || entry.channel_id == cid) {
                refuzz::logging::HostLogger::Instance().Log(
                    "Executor",
                    "channel_register_skip",
                    {refuzz::logging::Field("channel_id", cid),
                     refuzz::logging::Field("reason", "duplicate")});
                return;
            }
        }

        if (cid == 0) {
            cid = next_local_channel_id_++;
        }

        ChannelEntry entry;
        entry.channel    = channel;
        entry.channel_id = cid;
        channels_.push_back(std::move(entry));
        channels_generation_.fetch_add(1, std::memory_order_release);

        refuzz::logging::HostLogger::Instance().Log(
            "Executor",
            "channel_registered",
            {refuzz::logging::Field("channel_id", cid),
             refuzz::logging::Field("total_channels", channels_.size())});
    }
    PublishSnapshot();
}

void Executor::ClearChannels()
{
    size_t old_size = 0;
    {
        std::lock_guard<std::mutex> lock(channels_mu_);
        old_size = channels_.size();
        channels_.clear();
        channels_generation_.fetch_add(1, std::memory_order_release);
    }
    refuzz::logging::HostLogger::Instance().Log(
        "Executor",
        "channels_cleared",
        {refuzz::logging::Field("previous_total", old_size)});
    PublishSnapshot();
}

void Executor::SetSubmitStrategy(std::unique_ptr<ISubmitStrategy> strategy)
{
    // nullptr 回退到默认 RR,避免 submit 线程解引用空指针
    if (strategy == nullptr) {
        submit_strategy_ = std::make_unique<RoundRobinStrategy>();
    } else {
        submit_strategy_ = std::move(strategy);
    }
    refuzz::logging::HostLogger::Instance().Log(
        "Executor",
        "submit_strategy_set",
        {refuzz::logging::Field("name", submit_strategy_->Name())});
}

bool Executor::StopRequested() const
{
    return stop_requested_.load(std::memory_order_acquire);
}

// ============================================================
// 内部工具
// ============================================================

const Executor::ChannelCache& Executor::ChannelsSnapshot(ChannelCache& cache) const
{
    const uint64_t observed_generation =
        channels_generation_.load(std::memory_order_acquire);
    if (cache.generation == observed_generation) {
        return cache;
    }

    std::lock_guard<std::mutex> lock(channels_mu_);
    const uint64_t locked_generation =
        channels_generation_.load(std::memory_order_relaxed);

    cache.entries = channels_;
    cache.views.clear();
    cache.views.reserve(cache.entries.size());
    for (const auto& entry : cache.entries) {
        cache.views.push_back(ChannelView{entry.channel_id});
    }
    cache.generation = locked_generation;
    return cache;
}

// [6b-3 — 当前版本] PublishSnapshot 直接发到 MetricRegistry, 无中间 ExecutorSnapshot struct
void Executor::PublishSnapshot()
{
    const int64_t pending = active_task_queue_ != nullptr
        ? static_cast<int64_t>(active_task_queue_->PendingSize())
        : 0;
    size_t total_channels_count = 0;
    {
        std::lock_guard<std::mutex> lock(channels_mu_);
        total_channels_count = channels_.size();
    }
    if (metrics_.dispatch_pending) metrics_.dispatch_pending->Set(pending);
    if (metrics_.channels_total)   metrics_.channels_total->Set(static_cast<int64_t>(total_channels_count));
    if (metrics_.stop_requested)   metrics_.stop_requested->Set(StopRequested() ? 1 : 0);
}

// ============================================================
// 跨线程唤醒
// ============================================================

void Executor::WaitForWakeOrTimeout(uint64_t max_wait_us)
{
    std::unique_lock<std::mutex> lock(wake_mu_);
    wake_cv_.wait_for(
        lock,
        std::chrono::microseconds{max_wait_us},
        [this] {
            return wake_signal_ ||
                   stop_requested_.load(std::memory_order_acquire);
        });
    wake_signal_ = false;
}

void Executor::NotifySubmitThread()
{
    {
        std::lock_guard<std::mutex> lock(wake_mu_);
        wake_signal_ = true;
    }
    wake_cv_.notify_one();
}

// ============================================================
// Submit 路径
// ============================================================

bool Executor::ProcessSubmitOnce(refuzz::queue::InMemoryTaskQueue& task_queue,
                                  std::chrono::milliseconds pop_timeout)
{
    // 1. 停止请求：把 pending 任务推回队列
    if (StopRequested()) {
        if (pending_.has_value()) {
            // payload 已从 task 移到 request，移回再推入队列
            pending_->task.trace = pending_->request.trace;
            pending_->task.payload = std::move(pending_->request.payload);
            task_queue.Push(std::move(pending_->task));
            pending_.reset();
            refuzz::logging::HostLogger::Instance().Log(
                "Executor",
                "submit_pending_requeued",
                {refuzz::logging::Field("reason", "stop_requested")});
        }
        return false;
    }

    // 2. 无 pending 任务时从队列 Pop
    if (!pending_.has_value()) {
        auto task_opt = task_queue.Pop(pop_timeout);
        if (!task_opt.has_value()) {
            return false;  // 队列空
        }

        PendingSubmit ps;
        ps.task = std::move(*task_opt);

        // 构造 ChannelDispatchRequest（payload 从 task 移入 / 从 artifact 物化）
        ps.request.executor_id    = ps.task.executor_id;
        ps.request.seed_id        = ps.task.seed_id;
        ps.request.origin_seed_id = ps.task.origin_seed_id;

        // §3.10 step 7 (D8): the executor submit boundary is the only
        // production exec-wire materialization point. Stages on the V2
        // typed pipeline leave `task.payload` empty and only set
        // `task.artifact`; here we materialize exec-wire bytes (varint
        // stream — the worker KernelWireDriver input shape after V1 retirement).
        // Paths that already carry exec-wire bytes (e.g. minimize
        // candidate from serialize_for_exec) set task.payload and skip
        // materialization.
        //
        // [v1 partial-wire path — ROLLBACK: uncomment 整段(if/else 旧版)+ 删
        //  下面 v2 PR-11 B1 fail-closed 块。旧版 MaterializeExecWire 失败时
        //  payload 保持空,继续走 Submit 把空 payload 发给 worker → worker
        //  ChildExecuteTask 拒 input_len<4 返 status=-1,host 报 abnormal_exit。
        //  Step 8 corpus 1.5% exec_error 即此根因(在 PR-10 encoder fail-closed
        //  之后变成 input_len=0 干净路径,但 host stage 仍计入 exec_error)。]
        // // if (ps.task.payload.empty() && ps.task.artifact.valid()) {
        // //     auto bytes_or = ::refuzz::program::MaterializeExecWire(ps.task.artifact);
        // //     if (bytes_or.has_value()) {
        // //         ps.request.payload = std::move(*bytes_or);
        // //     }
        // // } else {
        // //     ps.request.payload = std::move(ps.task.payload);
        // // }
        //
        // [v2 Epic 7 PR-11 B1 — 当前版本] submit 边界 fail-closed:
        //   MaterializeExecWire 失败 → **不**构造空 payload 也不 Submit,改为
        //   合成 host-side AbnormalCompletion (kExecError) 推回 event_queue_,
        //   让上游 stage 收到一个干净的 "host-rejected" 事件而不是 worker 端
        //   的"empty payload exec_error"。同时计 metric `materialize_exec_wire_failed_`
        //   + log tag,后续 mutator IR-invariant audit (Step B2) 据此追溯。
        if (ps.task.payload.empty() && ps.task.artifact.valid()) {
            auto bytes_or = ::refuzz::program::MaterializeExecWire(ps.task.artifact);
            if (!bytes_or.has_value()) {
                materialize_exec_wire_failed_.fetch_add(1, std::memory_order_relaxed);
                // [v2 PR-11 B1 expose — 当前版本] 同步发布到 MetricRegistry。
                // atomic counter 是 process-internal,metric counter 是 ops-observable;
                // 两个都 Inc 以保 internal stat / external metric 一致(将来若彻底
                // 改读 registry,可去 atomic;暂时保兼容)。
                if (metrics_.materialize_failed) {
                    metrics_.materialize_failed->Inc();
                }
                // 合成 host-side AbnormalCompletion 推回 event_queue_。worker_id=0
                // (无 worker 参与);output 空(没 dispatch);dispatch_gen=0;
                // event_id 用 host_event_id_counter_ 避免和 channel-side 冲突。
                if (event_queue_ != nullptr) {
                    refuzz::core::channel_contract::ChannelEvent evt;
                    evt.kind = refuzz::core::channel_contract::ChannelEvent::Kind::kAbnormal;
                    evt.event_id = host_event_id_counter_.fetch_add(
                        1, std::memory_order_relaxed);
                    evt.channel_id = 0;
                    evt.generation = 0;
                    refuzz::core::channel_contract::AbnormalCompletion abnormal;
                    // host 侧 MaterializeExecWire 失败:artifact 无法序列化成 wire —
                    // 基础设施/wiring 问题,不是程序执行结果 → kInfraFault
                    // (diagnostics.error_code 用 ERR_INVALID_INPUT 表"输入无法物化")。
                    abnormal.kind = refuzz::core::channel_contract::AbnormalKind::kInfraFault;
                    abnormal.diagnostics.error_code = ERR_INVALID_INPUT;
                    abnormal.ctx.executor_id    = ps.task.executor_id;
                    abnormal.ctx.seed_id        = ps.task.seed_id;
                    abnormal.ctx.origin_seed_id = ps.task.origin_seed_id;
                    abnormal.ctx.worker_id      = 0;  // host-rejected,无 worker
                    abnormal.ctx.dispatch_gen   = 0;
                    abnormal.ctx.generation     = 0;
                    abnormal.ctx.submit_ts_us   = 0;
                    abnormal.ctx.trace          = ps.task.trace;
                    // program_payload 留空 (无 wire bytes);output 空 (无 dispatch)。
                    evt.payload = std::move(abnormal);
                    (void)event_queue_->Push(std::move(evt));
                }
                refuzz::logging::HostLogger::Instance().Log(
                    "Executor",
                    "materialize_exec_wire_failed",
                    {refuzz::logging::Field("executor_id", ps.task.executor_id),
                     refuzz::logging::Field("seed_id", ps.task.seed_id),
                     refuzz::logging::Field("err", bytes_or.error().message)});
                // [request-window] host fail-closed:该 executor_id 从未 Submit 到 channel、拿不到
                //   kAccepted,须发 kRejected 释放它占的 dispatch 窗口 credit,否则窗口慢性泄漏、
                //   最终卡死 scheduler pull。走同一条 lifecycle 线(与合成的 abnormal 结果事件分开)。
                if (lifecycle_queue_ != nullptr) {
                    lifecycle_queue_->Push(
                        refuzz::core::channel_contract::RequestLifecycleEvent{
                            ps.task.executor_id,
                            refuzz::core::channel_contract::RequestLifecyclePhase::kRejected,
                            0});
                }
                // 不 set pending_ → 直接 return,下一轮 Pop 下一个 task。
                // 已 host-rejected 的 task 不进 inflight_artifacts_,不会进 retry 循环。
                return true;
            }
            ps.request.payload = std::move(*bytes_or);
        } else {
            ps.request.payload = std::move(ps.task.payload);
        }

        ps.request.timeout_ms     = ps.task.opts.timeout_ms;
        // [v2 Epic 5 PR-5-B] proto::ExecOpts.flags → ChannelDispatchRequest.exec_flags
        // (TaskSlot.flags wire encoding). Bit values differ — proto bit 3 vs
        // wire bit 4 — so translate explicitly. Add cases here as new flags
        // ship; everything not on the allowlist drops to 0.
        ps.request.exec_flags = 0;
        const bool task_collects_comps =
            (ps.task.opts.flags & ::refuzz::proto::kExecFlagCollectComps) != 0;
        if (task_collects_comps) {
            ps.request.exec_flags |= TASK_FLAG_COLLECT_COMPS;
        }
        // [v2 Epic 7 PR-4.6] domain kExecFlagIntraThreaded → wire
        // TASK_FLAG_INTRA_THREADED (= 1u, INTRA_MASK bits 0..1)。三种来源:
        //   (a) per-task: opts.flags 显式带 kExecFlagIntraThreaded (stage
        //       opt-in,eg. 未来的 race triage stage)
        //   (b) global:  config_.default_intra_threaded == true (操作员配
        //       target.intra_task_mode = "threaded",所有 task 一律 threaded)
        // 任意一项满足即 OR 上 TASK_FLAG_INTRA_THREADED。CollectComps 与
        // intra-task mode 是正交位:Step 7 之后 CMP threaded merge 由 worker
        // KcovSink 的 kCoverageKcovCmp emission path 处理,所以 global
        // threaded 配置也应覆盖 hints/CMP replay。
        // 默认两项都假 → TASK_FLAG_INTRA_SERIAL = 0,行为等价历史。
        //
        // worker 端 driver 看到 INTRA_THREADED 但 thread_count == 1 时返
        // exec_error (KernelThreadPool 未构造);需操作员同时配
        // target.thread_count > 1 (Epic 7 PR-4.5) 才能真正触发 threaded path。
        // config_parser 在 target.intra_task_mode=threaded 但 thread_count=1
        // 时 fail-closed,避免运维误配。
        const bool task_wants_threaded =
            (ps.task.opts.flags & ::refuzz::proto::kExecFlagIntraThreaded) != 0;
        if (task_wants_threaded || config_.default_intra_threaded) {
            ps.request.exec_flags |= TASK_FLAG_INTRA_THREADED;
        }
        // [RTT] carry the per-task RTT-trace sampling opt-in to the wire so the
        // guest gates its worker_started_executor_id marker + start-ping on it.
        if ((ps.task.opts.flags & ::refuzz::proto::kExecFlagTraceSampled) != 0) {
            ps.request.exec_flags |= TASK_FLAG_TRACE_SAMPLED;
        }
        ps.request.trace          = ps.task.trace;
        // [RTT] prep_done: payload materialized + wire flags translated +
        // request assembled; everything after this until data_plane_call is
        // waiting for a free worker slot, not host CPU work. Stamped only for
        // sampled tasks so unsampled ones keep the field at 0.
        if (ps.request.trace.sampled) {
            ps.request.trace.dispatch_prep_done_ts_us = refuzz::core::MonotonicNowUs();
        }
        ps.started_at             = std::chrono::steady_clock::now();
        ps.retries                = 0;
        ps.backoff_logged         = false;

        pending_ = std::move(ps);
        // post-V1-retirement artifact-first universal contract — race-free
        // pre-registration:
        //   原实现在 kAccepted 之后才把 artifact 写入 inflight_artifacts_，
        //   但 Channel::Submit 是非阻塞入队 + 唤醒 wake_loop 后立即返回，
        //   worker 完成快时（mock backend 尤其明显）event 线程的 DrainEvents
        //   可能先于 submit 线程的 map 插入运行 → ctx.artifact 漏注入 +
        //   map 永久残留无人 erase。
        //   修复：在 Pop 后、Submit 前预注册。executor_id 在 retry 链中不变
        //   （pending_ 跨 kBusy/kUnavailable 多轮重试），map 条目自然贯穿
        //   retry 直到某次 kAccepted 后由 ForwardEvents 配对取出。
        //   shared_ptr 用 copy 而非 move：ProgramArtifact 内部就是
        //   shared_ptr<State>，copy 极廉价；让 pending_->task.artifact 在
        //   requeue/stop 路径仍然 valid（shutdown 时另由 StopThreads 统一
        //   clear() inflight 表）。
        if (pending_->task.artifact.valid()) {
            auto sp = std::make_shared<const ::refuzz::program::ProgramArtifact>(
                pending_->task.artifact);
            std::lock_guard<std::mutex> lk(inflight_artifacts_mu_);
            inflight_artifacts_[pending_->request.executor_id] = std::move(sp);
        }
        // [Phase G] 每个 PendingSubmit 只打一条 submit_started(代替旧版 task_popped)。
        //            配合 submit_accepted 里带的 retries/wait_us_total,
        //            就能拼出每任务完整时间线,而不必看逐次 submit_try 日志。
        EmitHotPathLog(pending_->request.executor_id, [&](auto& logger) {
            logger.Log(
                "Executor",
                "submit_started",
                {refuzz::logging::Field("executor_id", pending_->request.executor_id),
                 refuzz::logging::Field("seed_id", pending_->request.seed_id),
                 refuzz::logging::Field("origin_seed_id", pending_->request.origin_seed_id),
                 refuzz::logging::Field("timeout_ms", pending_->request.timeout_ms),
                 refuzz::logging::Field("payload_size", pending_->request.payload.size())});
        });
    }

    // 3. 刷新本线程 channel 缓存；generation 未变化时不复制 channels_/views。
    const auto& snapshot = ChannelsSnapshot(submit_channel_cache_);
    const auto& channels = snapshot.entries;
    if (channels.empty()) {
        return false;
    }

    // 4. 由 ISubmitStrategy 决定本轮遍历顺序;executor 负责真正 Submit + 日志 + 重试
    //    [Phase H] 无限重试语义:
    //      - kAccepted         → submit_accepted(retries + wait_us_total),通知 strategy,清理 pending_
    //      - kBusy             → 递增 retries(热路径不打日志)
    //      - kUnavailable/Invalid → 真异常,打 submit_rejected
    //      wait_for_slot 统一传 0:Channel 内部 deferred 已改为无限重试(deadline 废弃),
    //      所以这个参数当前不再产生副作用,传 0 是语义最清晰的表达(非阻塞)。
    const size_t n = channels.size();
    submit_strategy_->BeginCycle(snapshot.views);
    bool saw_rejected = false;
    size_t idx = 0;

    while (submit_strategy_->NextIndex(&idx)) {
        if (idx >= n) continue;  // 防御:策略返回越界索引时跳过
        // [当前版本 defer-move] rvalue overload + std::move:Channel::Submit 只在
        //   accept 提交点才消费 request；kBusy/kUnavailable/kInvalid 都不 move，
        //   故 pending_->request 在本轮其它 channel / 下一轮 cycle 重试时仍完整。
        //   省去原 const overload 每次 submit 尝试的一次 payload deep-copy
        //   （backpressure 下每次 kBusy 重试都要拷一份）。kAccepted 后只读
        //   request 的 scalar 字段（executor_id/seed_id，move 不影响）；payload
        //   已转移，accept 分支不再读它。
        const auto result =
            channels[idx].channel->Submit(std::move(pending_->request),
                                          std::chrono::milliseconds{0});

        if (result.status == refuzz::core::channel_contract::ChannelSubmitStatus::kAccepted) {
            submit_strategy_->OnAccepted(idx);
            tasks_submitted_.fetch_add(1, std::memory_order_relaxed);
            if (metrics_.tasks_submitted) metrics_.tasks_submitted->Inc(); // [v2 metric bus — 当前版本]
            const auto wait_us = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - pending_->started_at).count();
            if (metrics_.dispatch_submit_wait_us) {
                metrics_.dispatch_submit_wait_us->Inc(static_cast<uint64_t>(wait_us));
            }
            const bool was_in_backoff = pending_->backoff_logged;
            EmitHotPathLog(pending_->request.executor_id, [&](auto& logger) {
                logger.Log(
                    "Executor",
                    "submit_accepted",
                    {refuzz::logging::Field("executor_id", pending_->request.executor_id),
                     refuzz::logging::Field("channel_id", channels[idx].channel_id),
                     refuzz::logging::Field("generation", result.generation),
                     refuzz::logging::Field("retries", pending_->retries),
                     refuzz::logging::Field("wait_us_total", static_cast<uint64_t>(wait_us))});
            });
            // [Phase H] 边沿日志:若曾进入 backoff,退出时配一条 exit 便于观察"堵塞期"时长
            if (was_in_backoff) {
                // [Stage 1] 单独计算 backoff 区间时长(accept - backoff_enter_at),
                //   比 wait_us(= accept - started_at)更精确:排除第一次 kBusy 之前的
                //   正常处理窗口。累计到 atomic counter 供 snapshot 读取。
                const auto backoff_us = std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::steady_clock::now() - pending_->backoff_enter_at).count();
                submit_backoff_wait_us_total_.fetch_add(
                    static_cast<uint64_t>(backoff_us), std::memory_order_relaxed);
                if (metrics_.dispatch_backoff_wait_us) metrics_.dispatch_backoff_wait_us->Inc(static_cast<uint64_t>(backoff_us)); // [v2 metric bus — 当前版本]
                submit_backoff_episodes_.fetch_add(1, std::memory_order_relaxed);
                if (metrics_.dispatch_backoff_episodes) metrics_.dispatch_backoff_episodes->Inc(); // [v2 metric bus — 当前版本]
                EmitHotPathLog(pending_->request.executor_id, [&](auto& logger) {
                    logger.Log(
                        "Executor",
                        "submit_backoff_exit",
                        {refuzz::logging::Field("executor_id", pending_->request.executor_id),
                         refuzz::logging::Field("retries", pending_->retries),
                         refuzz::logging::Field("wait_us_total", static_cast<uint64_t>(wait_us)),
                         refuzz::logging::Field("backoff_us", static_cast<uint64_t>(backoff_us))});
                });
            }
            submit_strategy_->OnCycleEnd(SubmitCycleOutcome::kAccepted);
            // [request-window] 通知控制侧:该 executor_id 已被执行侧接管 → 释放一个 dispatch
            //   窗口 credit(FuzzerLoop drain → JobScheduler::MarkAccepted)。这是与 result/routing
            //   (完成事件走 event_queue_)分开的另一条线;lifecycle_queue_ 未注入(单测直驱)则跳过。
            //   必须在 pending_.reset() 之前读 request.executor_id。
            if (lifecycle_queue_ != nullptr) {
                lifecycle_queue_->Push(
                    refuzz::core::channel_contract::RequestLifecycleEvent{
                        pending_->request.executor_id,
                        refuzz::core::channel_contract::RequestLifecyclePhase::kAccepted,
                        result.generation});
            }
            // post-V1-retirement: artifact 已在 Pop 时预注册到 inflight_artifacts_
            //   （见上文 Pop 块），此处只 reset pending_。预注册避免了
            //   "kAccepted → 完成事件先到达 → ForwardEvents miss" 的竞态。
            pending_.reset();
            PublishSnapshot();
            return true;
        }
        if (result.status == refuzz::core::channel_contract::ChannelSubmitStatus::kUnavailable ||
            result.status == refuzz::core::channel_contract::ChannelSubmitStatus::kInvalid) {
            saw_rejected = true;
            EmitHotPathLog(pending_->request.executor_id, [&](auto& logger) {
                logger.Log(
                    "Executor",
                    "submit_rejected",
                    {refuzz::logging::Field("executor_id", pending_->request.executor_id),
                     refuzz::logging::Field("channel_id", channels[idx].channel_id),
                     refuzz::logging::Field("status", SubmitStatusName(result.status)),
                     refuzz::logging::Field("generation", result.generation)});
            });
            // 真异常:channel 不可用/参数非法。task 不能送到这个 channel,
            // 但下一轮循环会尝试其他 channel 或等待 event 唤醒。继续往下走,
            // 不 drop pending_(符合"task 不丢"的设计)。
        } else if (result.status == refuzz::core::channel_contract::ChannelSubmitStatus::kBusy) {
            if (metrics_.dispatch_busy_results) metrics_.dispatch_busy_results->Inc();
        }
    }

    // 5. 本轮无 accept:通知 strategy,递增 retries,第一次进入 backoff 打一条,
    //    之后静默。[Phase H] 无限重试:pending_ 永不 drop,一直等到某个 channel 释放 slot
    //    (由 event 线程唤醒)。若 wake 未到就靠 idle_sleep_us 兜底(1s),
    //    防止 NotifySubmitThread 漏发导致的死锁——正常路径下根本到不了这条兜底。
    submit_strategy_->OnCycleEnd(
        saw_rejected ? SubmitCycleOutcome::kAnyRejected : SubmitCycleOutcome::kAllBusy);
    pending_->retries++;
    if (!pending_->backoff_logged) {
        pending_->backoff_logged = true;
        pending_->backoff_enter_at = std::chrono::steady_clock::now();
        EmitHotPathLog(pending_->request.executor_id, [&](auto& logger) {
            logger.Log(
                "Executor",
                "submit_backoff_enter",
                {refuzz::logging::Field("executor_id", pending_->request.executor_id),
                 refuzz::logging::Field("total_channels", n),
                 refuzz::logging::Field("idle_sleep_us", config_.idle_sleep_us)});
        });
    }

    WaitForWakeOrTimeout(config_.idle_sleep_us);
    return false;
}

void Executor::SubmitLoop(refuzz::queue::InMemoryTaskQueue* task_queue,
                           std::chrono::milliseconds pop_timeout)
{
    while (submit_running_.load(std::memory_order_acquire) &&
           !StopRequested()) {
        ProcessSubmitOnce(*task_queue, pop_timeout);
    }

    // 退出前：把 pending 任务推回队列
    if (pending_.has_value() && task_queue != nullptr) {
        pending_->task.trace = pending_->request.trace;
        pending_->task.payload = std::move(pending_->request.payload);
        task_queue->Push(std::move(pending_->task));
        pending_.reset();
    }
}

// ============================================================
// Event 路径
// ============================================================

void Executor::AttachArtifactToEvent(
    refuzz::core::channel_contract::ChannelEvent& event)
{
    namespace cc = refuzz::core::channel_contract;
    // [v1 Fault 跳过 artifact attach — ROLLBACK: uncomment, remove v2]
    // cc::CompletionContext* ctx = nullptr;
    // if (auto* p = event.AsCompletion(); p != nullptr) {
    //     ctx = &p->ctx;
    // } else if (auto* p = event.AsAbnormal(); p != nullptr) {
    //     ctx = &p->ctx;
    // }
    // if (ctx == nullptr) return;  // Fault 不带 executor_id，跳过
    // std::shared_ptr<const ::refuzz::program::ProgramArtifact> artifact;
    // {
    //     std::lock_guard<std::mutex> lk(inflight_artifacts_mu_);
    //     auto it = inflight_artifacts_.find(ctx->executor_id);
    //     if (it != inflight_artifacts_.end()) {
    //         artifact = std::move(it->second);
    //         inflight_artifacts_.erase(it);
    //     }
    // }
    // if (artifact) {
    //     ctx->artifact = std::move(artifact);
    // }
    //
    // [v2 Epic 6 D-7 §3.10 fix — Fault path artifact propagation]
    // Fault 事件本身不携带 executor_id (FaultOrigin::kHeartbeat /
    // kSerialPattern / kHealthInternal 等多数路径无具体 task)。但
    // fault-induced kernel crash 路径(由 fault inject 或 program 触发的
    // panic)经过 channel-side scene capture 时 candidate_window 已经填好;
    // 用 last entry 的 executor_id 反查 inflight_artifacts_,把 artifact
    // 绑到该 ChannelTaskSnapshot 上,下游 BuildCombinedFromFault 透传到
    // CombinedCrashEvent.crash_origin_artifact,StageMinimize 才不会
    // 因 artifact==nullptr fail-close。
    cc::CompletionContext* ctx = nullptr;
    std::vector<cc::ChannelTaskSnapshot>* fault_window = nullptr;
    if (auto* p = event.AsCompletion(); p != nullptr) {
        ctx = &p->ctx;
    } else if (auto* p = event.AsAbnormal(); p != nullptr) {
        ctx = &p->ctx;
    } else if (auto* p = event.AsFault(); p != nullptr) {
        if (!p->scene.candidate_window.empty()) {
            fault_window = &p->scene.candidate_window;
        }
    }

    std::lock_guard<std::mutex> lk(inflight_artifacts_mu_);
    if (ctx != nullptr) {
        // Completion / Abnormal — find + move + erase(每个 task 仅一个 Completion
        // 或 Abnormal,erase 把 inflight artifact 从 map 移走,正常释放生命周期)。
        auto it = inflight_artifacts_.find(ctx->executor_id);
        if (it != inflight_artifacts_.end()) {
            // [async-crash-reproduction Phase 1] erase 前把 typed artifact 复制进
            // recent_artifacts_ 环:程序完成即从 inflight_artifacts_ 移走,但它可能是
            // 未来某 async crash 的 history 一员,届时需要 typed view 才能 minimize。
            // FIFO 容量上限 kRecentArtifactsCap。
            recent_artifacts_.emplace_back(ctx->executor_id, it->second);
            if (recent_artifacts_.size() > kRecentArtifactsCap) {
                recent_artifacts_.pop_front();
            }
            ctx->artifact = std::move(it->second);
            inflight_artifacts_.erase(it);
        }
    } else if (fault_window != nullptr) {
        // Fault — 给 candidate_window 每个 entry(不只 back())绑 typed view,来源
        // (inflight | recent):in-flight entry 命中 inflight_artifacts_,已完成的
        // history entry(已从 inflight 移走)命中 recent_artifacts_ 环。COPY 不 erase
        // ——channel 在 EmitFaultEvent 后仍对每个 inflight task 发 Abnormal,其
        // find+erase 仍要 hit inflight artifact。下游 BuildCombinedFromFault 把每个
        // entry 的 artifact 透传到 program_log,StageExtract 据此设 selected_artifact。
        for (auto& snap : *fault_window) {
            if (snap.artifact) continue;
            auto inf = inflight_artifacts_.find(snap.executor_id);
            if (inf != inflight_artifacts_.end()) {
                snap.artifact = inf->second;  // shared_ptr copy, no erase
                continue;
            }
            for (auto rit = recent_artifacts_.rbegin();
                 rit != recent_artifacts_.rend(); ++rit) {
                if (rit->first == snap.executor_id) {
                    snap.artifact = rit->second;
                    break;
                }
            }
        }
    }
}

size_t Executor::ForwardEvents(refuzz::channel::EventList& events)
{
    if (event_queue_ == nullptr) return 0;

    size_t forwarded = 0;
    for (auto& event : events) {
        const auto kind = EventKindName(event.kind);
        const uint64_t event_id = event.event_id;
        // 全量转发：Completion / Abnormal / Fault
        const auto forward_start = std::chrono::steady_clock::now();
        if (auto* trace = MutableTrace(event); trace != nullptr && trace->sampled) {
            trace->executor_event_forwarded_ts_us = refuzz::core::MonotonicNowUs();
        }
        // post-V1-retirement artifact-first universal contract:
        //   把 inflight_artifacts_ 中按 executor_id 缓存的 ProgramArtifact
        //   注入到 Completion/Abnormal 事件的 ctx.artifact 字段。channel 不知道
        //   ProgramArtifact，channeldispatcher 这一层是 submit→completion 配对
        //   的天然位置。Fault 事件不带 executor_id（不属于具体 task），不处理。
        //   miss 容忍：v1 path / payload-only submit 不入表，ctx.artifact 留 nullptr。
        AttachArtifactToEvent(event);
        if (event_queue_->Push(std::move(event))) {
            ++forwarded;
            if (metrics_.events_forward_latency_us) {
                const auto latency_us = std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::steady_clock::now() - forward_start).count();
                metrics_.events_forward_latency_us->Inc(static_cast<uint64_t>(latency_us));
            }
            EmitHotPathLog(event_id, [&](auto& logger) {
                logger.Log(
                    "Executor",
                    "event_forwarded",
                    {refuzz::logging::Field("event_id", event_id),
                     refuzz::logging::Field("kind", kind),
                     refuzz::logging::Field("forwarded_total", forwarded)});
            });
        }
    }
    events_forwarded_.fetch_add(forwarded, std::memory_order_relaxed);
    if (metrics_.events_forwarded) metrics_.events_forwarded->Inc(forwarded); // [v2 metric bus — 当前版本]
    return forwarded;
}

bool Executor::ProcessEventsOnce(std::chrono::microseconds poll_timeout)
{
    const auto& snapshot = ChannelsSnapshot(event_channel_cache_);
    const auto& channels = snapshot.entries;
    if (channels.empty()) {
        return false;
    }

    size_t total_forwarded = 0;

    // 1. 非阻塞轮询全部 channel
    bool had_any_events = false;
    for (const auto& entry : channels) {
        refuzz::channel::EventList events;
        const bool ok = entry.channel->DrainEvents(events,
                                                    std::chrono::microseconds{0});
        if (!ok || events.empty()) continue;

        had_any_events = true;
        EmitHotPathLog(events.front().event_id, [&](auto& logger) {
            logger.Log(
                "Executor",
                "events_drained",
                {refuzz::logging::Field("channel_id", entry.channel_id),
                 refuzz::logging::Field("count", events.size()),
                 refuzz::logging::Field("mode", "non_blocking")});
        });
        total_forwarded += ForwardEvents(events);
    }

    // 2. 无事件时阻塞等待一个 channel（轮转选择）
    if (!had_any_events && poll_timeout.count() > 0) {
        const size_t n = channels.size();
        const size_t idx = event_rr_cursor_ % n;
        event_rr_cursor_ = (event_rr_cursor_ + 1) % n;

        const auto actual_timeout =
            std::min(poll_timeout,
                     std::chrono::microseconds{
                         static_cast<int64_t>(config_.event_blocking_timeout_us)});

        refuzz::channel::EventList events;
        channels[idx].channel->DrainEvents(events, actual_timeout);

        if (!events.empty()) {
            EmitHotPathLog(events.front().event_id, [&](auto& logger) {
                logger.Log(
                    "Executor",
                    "events_drained",
                    {refuzz::logging::Field("channel_id", channels[idx].channel_id),
                     refuzz::logging::Field("count", events.size()),
                     refuzz::logging::Field("mode", "blocking")});
            });
            total_forwarded += ForwardEvents(events);
        }
    }

    // 3. 有事件转发 → 唤醒 submit 线程（资源释放信号）
    if (total_forwarded > 0) {
        NotifySubmitThread();
        PublishSnapshot();
    }

    return total_forwarded > 0;
}

void Executor::EventLoop(std::chrono::microseconds poll_timeout)
{
    while (completion_running_.load(std::memory_order_acquire) &&
           !StopRequested()) {
        ProcessEventsOnce(poll_timeout);
    }
    // 最终非阻塞排干
    while (ProcessEventsOnce(std::chrono::microseconds{0})) {
    }
}

// ============================================================
// 线程管理
// ============================================================

bool Executor::StartThreads(refuzz::queue::InMemoryTaskQueue& task_queue,
                              refuzz::queue::InMemoryEventQueue& event_queue,
                              std::chrono::milliseconds pop_timeout,
                              std::chrono::microseconds poll_timeout)
{
    StopThreads();

    {
        std::lock_guard<std::mutex> lock(channels_mu_);
        if (channels_.empty()) {
            refuzz::logging::HostLogger::Instance().Log(
                "Executor",
                "threads_start_failed",
                {refuzz::logging::Field("reason", "no_channels")});
            return false;
        }
    }

    stop_requested_.store(false, std::memory_order_release);
    active_task_queue_ = &task_queue;
    event_queue_       = &event_queue;

    // 启动 event 线程
    completion_running_.store(true, std::memory_order_release);
    completion_thread_ = std::thread([this, poll_timeout]() {
        EventLoop(poll_timeout);
    });

    // 启动 submit 线程
    submit_running_.store(true, std::memory_order_release);
    submit_thread_ = std::thread([this, &task_queue, pop_timeout]() {
        SubmitLoop(&task_queue, pop_timeout);
    });

    refuzz::logging::HostLogger::Instance().Log(
        "Executor",
        "threads_started",
        {refuzz::logging::Field("pop_timeout_ms", pop_timeout.count()),
         refuzz::logging::Field("poll_timeout_us", poll_timeout.count())});
    PublishSnapshot();

    return true;
}

void Executor::StopThreads()
{
    submit_running_.store(false, std::memory_order_release);
    completion_running_.store(false, std::memory_order_release);

    // 唤醒可能在等待的 submit 线程
    NotifySubmitThread();

    if (submit_thread_.joinable()) {
        submit_thread_.join();
    }
    if (completion_thread_.joinable()) {
        completion_thread_.join();
    }

    if (event_queue_ != nullptr) {
        event_queue_->Close();
    }

    active_task_queue_ = nullptr;
    event_queue_       = nullptr;
    pending_.reset();
    {
        // post-V1-retirement: drop any in-flight artifact references on stop.
        // 没回流的 completion 不再有意义；shared_ptr 析构会释放上游持有的 typed view。
        std::lock_guard<std::mutex> lk(inflight_artifacts_mu_);
        inflight_artifacts_.clear();
    }
    stop_requested_.store(false, std::memory_order_release);

    refuzz::logging::HostLogger::Instance().Log(
        "Executor",
        "threads_stopped",
        {refuzz::logging::Field("events_forwarded", events_forwarded_.load(std::memory_order_relaxed)),
         refuzz::logging::Field("tasks_submitted", tasks_submitted_.load(std::memory_order_relaxed))});
    PublishSnapshot();
}

// ============================================================
// 单线程兼容接口
// ============================================================

bool Executor::ProcessOnce(refuzz::queue::InMemoryTaskQueue& task_queue,
                             refuzz::queue::InMemoryEventQueue& event_queue,
                             std::chrono::milliseconds pop_timeout,
                             std::chrono::microseconds poll_timeout)
{
    event_queue_ = &event_queue;

    {
        std::lock_guard<std::mutex> lock(channels_mu_);
        if (channels_.empty()) {
            return false;
        }
    }

    bool progressed = false;
    // 先排干事件（收割优先，释放资源），再提交
    progressed |= ProcessEventsOnce(poll_timeout);
    progressed |= ProcessSubmitOnce(task_queue, pop_timeout);
    return progressed;
}

static_assert(refuzz::core::ServiceLike<refuzz::channeldispatcher::Executor>);

} // namespace channeldispatcher
} // namespace refuzz

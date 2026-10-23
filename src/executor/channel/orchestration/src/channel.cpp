// Channel 编排层实现（IChannel 的 QEMU/ivshmem 具体实现）
//
// 文件组织演进：
//   - v2：qemu_channel.cpp，类叫 QemuChannel
//   - v3 Phase 7：类改名 QemuChannel → Channel，文件名未动
//   - v3 Phase 9：`using QemuChannel = Channel;` 兼容 alias 删除
//   - v3 Phase 10（本次收尾）：文件 qemu_channel.cpp → channel.cpp；
//     对应头文件由 qemu_channel.hpp → channel_impl.hpp。

#include "refuzz/channel/channel_impl.hpp"
#include "refuzz/channel/control/ivshmem_control_plane.hpp"
#include "refuzz/channel/data/ivshmem_data_plane.hpp"
#include "refuzz/channel/evidence/console_endpoint.hpp"
#include "refuzz/channel/evidence/ivshmem_step_event_source.hpp"
#include "refuzz/channel/evidence/unix_serial_console_source.hpp"
#include "refuzz/channel/health/console_sensor.hpp"
#include "refuzz/channel/health/heartbeat_sensor.hpp"
#include "refuzz/channel/health/vm_alive_sensor.hpp"
#include "refuzz/channel/internal/worker_start_sequence.hpp"
#include "refuzz/logging/host_logger.hpp"
#include "refuzz/proto_wire/error_codes.h"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstring>
#include <iterator>
#include <unordered_set>

namespace refuzz::channel {

namespace {

constexpr uint64_t kObserveSnapshotHeartbeatUs = 250'000;

// [v2 PR-B abnormal console snapshot — ROLLBACK: hardcoded constant]
// constexpr std::size_t kAbnormalConsoleSnapshotLines = 50;
//   注释说"和 HeartbeatSensor 默认 50 对齐"但 HeartbeatSensor 实际默认 80,
//   注释和数值不一致。PR-E 把行数抽到 ChannelConfig.abnormal_console_snapshot_lines,
//   默认 80 真正与 HeartbeatSensor 对齐,且支持 JSON 配置覆盖。

const char* EventKindName(cc::ChannelEvent::Kind kind)
{
    switch (kind) {
    case cc::ChannelEvent::Kind::kCompletion:
        return "completion";
    case cc::ChannelEvent::Kind::kAbnormal:
        return "abnormal";
    case cc::ChannelEvent::Kind::kFault:
        return "fault";
    }
    return "unknown";
}

template <typename EmitFn>
void EmitHotPathLog(uint64_t sample_key, EmitFn&& emit)
{
    auto& logger = refuzz::logging::HostLogger::Instance();
    if (logger.ShouldLogHotPath(sample_key)) {
        emit(logger);
    }
}

refuzz::proto::TaskTrace*
MutableTrace(cc::ChannelEvent& event) noexcept
{
    if (auto* p = event.AsCompletion(); p != nullptr) {
        return &p->ctx.trace;
    }
    if (auto* p = event.AsAbnormal(); p != nullptr) {
        return &p->ctx.trace;
    }
    return nullptr;
}

std::vector<const DispatchRecord*> OrderedDispatchRecords(
    const std::unordered_map<uint64_t, DispatchRecord>& records)
{
    std::vector<const DispatchRecord*> ordered;
    ordered.reserve(records.size());
    for (const auto& [executor_id, record] : records) {
        (void)executor_id;
        ordered.push_back(&record);
    }
    std::sort(ordered.begin(), ordered.end(),
              [](const DispatchRecord* lhs, const DispatchRecord* rhs) {
                  if (lhs->submit_ts_us != rhs->submit_ts_us) {
                      return lhs->submit_ts_us < rhs->submit_ts_us;
                  }
                  return lhs->executor_id < rhs->executor_id;
              });
    return ordered;
}

} // namespace

// ============================================================
// 时间工具
// ============================================================

uint64_t Channel::NowUs()
{
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch())
        .count());
}

// ============================================================
// 构造与析构
// ============================================================

// [v3.5 Phase D/E/F] Channel 唯一构造路径：接受已装配的 ChannelComponents。
//
// 装配责任在 IChannelAssembler（Shm/Substrate/CP/DP/Console/Steps/Health/Recovery）；
// 校验 + 构造责任在 ChannelBuilder::Build。此构造器仅做"所有权接收"。
// Boot 只做时序编排（StartVM / DeployArtifacts / DP.Prepare / BeginSession / ...）。
//
// 全部运行参数读 channel_cfg_（ChannelConfig，中性字段）。
Channel::Channel(ChannelComponents components)
    : shm_(std::move(components.shm)),
      substrate_(std::move(components.substrate)),
      cp_(std::move(components.control)),
      dp_(std::move(components.data)),
      health_monitor_(std::move(components.health)),
      recovery_(std::move(components.recovery)),
      console_source_(std::move(components.console)),
      step_event_source_(std::move(components.steps)),
      // §3.11-B — 接管 ConsoleRingBuffer 所有权。Sensor（在
      //   health_monitor_ 内）拿的是 raw pointer；这里持有 unique_ptr
      //   让 ring 的 lifetime 跟 Channel 对齐，析构时 health_monitor_
      //   先被销毁（成员声明顺序：health_monitor_ 在 console_ring_
      //   之前），sensor 线程已 stop+join，之后 console_ring_ 才析构。
      //
      //   Bug 历史：早期版本忘了 move 这个字段 → ring 在 ChannelComponents
      //   析构时被释放 → sensor raw pointer 悬空 → 运行期 mutex 访问
      //   freed 内存触发 "Owner died"。phase5 smoke 显式复现。
      console_ring_(std::move(components.console_ring)),
      // 聚合前进时钟：同 console_ring_ 的 ownership 语义（声明在 health_monitor_
      //   之后 → 析构更晚 → sensor 停掉后才销毁，raw pointer 不悬空）。
      progress_clock_(std::move(components.progress_clock)),
      channel_cfg_(std::move(components.channel_cfg))
{
    // channel_cfg_ 已由 Assembler 完整填充。此构造器不做任何默认兜底 —
    // 如果 Assembler 漏填导致字段为零值，应由 ChannelBuilder::Build 的校验阶段拦截。
    transport_results_.reserve(channel_cfg_.n_workers);

    // [crash-execution-history-ring] Layer-2 history ring. depth 0 → disabled
    // (zero-overhead, Layer-1 in-flight-only behavior). n_workers 0 → also no-op.
    recent_programs_ = RecentProgramRing(channel_cfg_.n_workers,
                                         channel_cfg_.crash_history_depth);
}

Channel::~Channel()
{
    if (phase_.load() != cc::ChannelLifecycleState::kClosed) {
        Close();
    }
}

// ============================================================
// Boot — 按依赖顺序启动全部组件（§8）
// ============================================================

refuzz::channel::Result<void> Channel::Boot()
{
    refuzz::logging::HostLogger::Instance().Log(
        "Channel",
        "boot",
        {refuzz::logging::Field("channel_id", channel_cfg_.channel_id),
         refuzz::logging::Field("workers", channel_cfg_.n_workers)});
    SetLifecycleState(cc::ChannelLifecycleState::kBooting);

    if (initial_corpus_triaged_.load(std::memory_order_acquire) && shm_) {
        shm_->WriteCorpusTriaged(1);
    }

    // 组件已由 Assembler 装配好（shm_/substrate_/cp_/dp_/console_/steps_/health_/recovery_）。
    // Boot 仅编排时序，不再 make_unique 任何组件。

    // 1. DP.StartServer()：启动 host 侧服务端点（如 ivshmem-doorbell 的 DoorbellServer）。
    //    必须先于 StartVM，否则 QEMU 启动时 socket 不存在会立即退出（已在 v3.G 之前出现
    //    "0 字节 serial.log + SSH timeout"的症状）。plain/无 server 实现默认 no-op。
    auto r_start_srv = dp_->StartServer();
    if (!r_start_srv.ok()) {
        SetLifecycleState(cc::ChannelLifecycleState::kFailed);
        return Error{r_start_srv.error().kind,
                     "DataPlane.StartServer failed: " + r_start_srv.error().message};
    }

    // 2. StartVM：启动 VM 进程（SSH 可用后返回；QEMU 作为 peer 0 连 DoorbellServer）
    auto r_start = substrate_->StartVM(0);
    if (!r_start.ok()) {
        SetLifecycleState(cc::ChannelLifecycleState::kFailed);
        return Error{r_start.error().kind,
                     "Substrate.StartVM failed: " + r_start.error().message};
    }

    // 3. DeployArtifacts：部署 worker binary（从 channel_cfg_.deploy_bundle 取）
    if (!channel_cfg_.deploy_bundle.artifacts.empty()) {
        auto r_deploy = substrate_->DeployArtifacts(0, channel_cfg_.deploy_bundle);
        if (!r_deploy.ok()) {
            SetLifecycleState(cc::ChannelLifecycleState::kFailed);
            return Error{r_deploy.error().kind,
                         "Substrate.DeployArtifacts failed: " + r_deploy.error().message};
        }
    }

    // 4. Evidence: 打开 console（StartVM 后 socket 才存在；不在 Assembler 里做）
    if (console_source_) {
        evidence::ConsoleEndpoint ep = substrate_->DefaultConsoleEndpoint(0);
        auto r_open = console_source_->Open(ep);
        if (!r_open.ok()) {
            SetLifecycleState(cc::ChannelLifecycleState::kFailed);
            return Error{r_open.error().kind,
                         "ConsoleSource.Open failed: " + r_open.error().message};
        }
    }

    // 5. DP.Prepare()：host 作为 peer 1 连回 DoorbellServer，完成握手 + 建 epoll（plain 模式 no-op）
    auto r_dp = dp_->Prepare();
    if (!r_dp.ok()) {
        SetLifecycleState(cc::ChannelLifecycleState::kFailed);
        return Error{r_dp.error().kind,
                     "DataPlane.Prepare failed: " + r_dp.error().message};
    }

    // 6. HealthMonitor.BindChannelSignals + Start —— 必须在 worker 注册序列之前:
    // ConsoleSensor 的读线程是 console socket 唯一的 drain 者(§4 evidence 设计,
    // UnixSerialConsoleSource 的 fd 由 ConsoleSensor::ThreadMain 的 ReadLine 循环
    // 消费)。worker 0 boot(sandbox/netdevice/bonding 等设备初始化)期间会产生
    // 大量 guest console 输出;若 drain 线程要等 worker 注册完成后才启动,这段
    // 窗口内 socket 接收缓冲无人读取,一旦 QEMU 侧写不进去,guest 的 8250
    // console 写路径会在等 THRE 时死等 —— 持锁自旋可耗尽一颗 vCPU,2vCPU
    // guest 下即整机失联(SSH 也连带无响应)。此处提前到 worker 注册之前,让
    // console 在 worker 启动前就被持续消费,不再有这个死锁窗口。HeartbeatSensor
    // 通过 SampleHeartbeat(valid=false) 跳过尚未注册的 worker,并在 rearm 后用
    // grace_rounds_after_rearm 吸收已注册 worker 的冷启动抖动。
    // VmAliveSensor 只看 QEMU 进程存活(StartVM 起就为真),WedgeRelaySensor/
    // AcceptanceTapSensor 不依赖 worker 注册状态 —— 提前启动对它们均安全。
    health_monitor_->BindChannelSignals(health::HealthMonitorView{
        .loop_cv  = &loop_cv_,
        .vm_epoch = &vm_epoch_,
        .wake_poller = [this] { WakeLoopPoller(); },
    });

    auto rh = health_monitor_->Start();
    if (!rh.ok()) {
        SetLifecycleState(cc::ChannelLifecycleState::kFailed);
        return Error{rh.error().kind,
                     "HealthMonitor.Start failed: " + rh.error().message};
    }

    // 7. 注册协议序列：BeginSession → (StartWorker → WaitWorkerReady) × N。
    // worker 0 完成 VM 级初始化和 domain startup 后才启动后续 worker。
    auto r_begin = cp_->BeginSession();
    if (!r_begin.ok()) {
        SetLifecycleState(cc::ChannelLifecycleState::kFailed);
        return Error{r_begin.error().kind,
                     "ControlPlane.BeginSession failed: " + r_begin.error().message};
    }

    auto r_workers = internal::StartWorkersAndWaitReady(
        *substrate_, *cp_, 0, channel_cfg_.n_workers,
        channel_cfg_.wait_ready_timeout);
    if (!r_workers.ok()) {
        SetLifecycleState(cc::ChannelLifecycleState::kFailed);
        return Error{r_workers.error().kind,
                     "worker startup sequence failed: " +
                         r_workers.error().message};
    }

    // 8. channel_generation(dispatch_gen) 初始化（与 reg_epoch 解耦）
    generation_.store(1);

    // 9. 启动编排循环
    boot_ts_us_ = NowUs();
    SetLifecycleState(cc::ChannelLifecycleState::kRunning);
    running_.store(true);
    loop_thread_ = std::thread([this] { LoopMain(); });
    PublishObserveSnapshot();

    refuzz::logging::HostLogger::Instance().Log(
        "Channel",
        "boot_ready",
        {refuzz::logging::Field("channel_id", channel_cfg_.channel_id),
         refuzz::logging::Field("generation", generation_.load()),
         refuzz::logging::Field("workers", channel_cfg_.n_workers)});

    return Result<void>::Ok();
}

void Channel::PublishInitialCorpusTriaged()
{
    initial_corpus_triaged_.store(true, std::memory_order_release);
    if (shm_) {
        shm_->WriteCorpusTriaged(1);
    }
}

// ============================================================
// Close — 停止全部组件（§9）
// ============================================================

void Channel::Close()
{
    if (!running_.load() && phase_.load() == cc::ChannelLifecycleState::kClosed) return;

    refuzz::logging::HostLogger::Instance().Log(
        "Channel",
        "close_begin",
        {refuzz::logging::Field("channel_id", channel_cfg_.channel_id),
         refuzz::logging::Field("lifecycle", cc::ChannelLifecycleStateName(phase_.load()))});

    // 停止编排循环
    running_.store(false);
    WakeLoopPoller();
    if (loop_thread_.joinable()) loop_thread_.join();


    // loop_thread_ 已退出，recovery_thread_ 可能仍在运行异步恢复
    // 等待其结束，避免访问已析构的成员
    if (recovery_thread_.joinable()) recovery_thread_.join();
    worker_recovery_pending_.store(false);
    active_worker_recovery_worker_id_ = UINT32_MAX;
    worker_recovery_queue_.clear();
    worker_recovery_queued_.clear();

    // Close 时丢弃所有未完成的 SubmitSlot（Submit() 已非阻塞，无需 resolve promise）。
    // loop_thread_ 已结束，无需加锁访问 deferred_submissions_;不过把所有清理 + metric
    // 同步整段挪进锁内,让 force-exit / clear / depth=0 一次性完成,语义更紧凑(loop 已 join,
    // 不会引入实际竞争)。
    // 注意：此时不再发 cc::AbnormalCompletion，因为 output_queue_ 的消费者（DrainEvents）
    // 在 running_=false 后已不再等待——任何新 event 也不会被看到。
    {
        std::lock_guard<std::mutex> lock(io_mutex_);
        // 若 close 时仍处于 input_full_,结清当前饱和 episode,避免 full_us 累积漏算。
        ForceExitInputFullEpisodeLocked();

        deferred_submissions_.clear();
        deferred_count_.store(0, std::memory_order_relaxed);
        while (!input_queue_.empty()) {
            active_executor_ids_.erase(input_queue_.front()->request.executor_id);
            input_queue_.pop();
        }
        active_executor_ids_.clear();

        if (metrics_ != nullptr && metrics_->input_queue_depth != nullptr) {
            metrics_->input_queue_depth->Set(0);
        }
    }

    // 停止 Health 子组件
    // if (serial_console_watcher_) serial_console_watcher_->Stop();
    if (health_monitor_) health_monitor_->Stop();

    // [v3 Phase 5] 关闭 Evidence 源（Sensor 在 HealthMonitor::Stop 中已 join，此时安全）
    if (console_source_) {
        console_source_->Close();
        console_source_.reset();
    }
    step_event_source_.reset();

    // 关闭 Runtime / DataPlane / ControlPlane
    //
    // 顺序：先 substrate_->Close()（停 VM 进程，避免看到 socket 断开时打日志），
    //       再 dp_->Close()（关 doorbell client fd 与 DoorbellServer），
    //       最后 cp_->EndSession() + reset。
    if (substrate_) substrate_->Close();

    if (dp_) dp_->Close();

    if (cp_) (void)cp_->EndSession();

    dp_.reset();
    cp_.reset();

    // shm_ 是 shared_ptr，析构时若无其他 shared 持有则 munmap（D4 确认：无 Cleanup()）

    SetLifecycleState(cc::ChannelLifecycleState::kClosed);
    PublishObserveSnapshot();
    refuzz::logging::HostLogger::Instance().Log(
        "Channel",
        "close_done",
        {refuzz::logging::Field("channel_id", channel_cfg_.channel_id)});
}

// ============================================================
// LoopMain — 编排循环（loop_thread_ 入口）（§2）
// ============================================================

void Channel::LoopMain()
{
    while (running_.load()) {
        // 先非阻塞收割已就绪完成事件，再判断故障门铃：
        //   - HealthMonitor 有待处理事件 → HandleFault，不发送新任务
        //   - 无待处理事件 → 正常发送
        DrainTransport();
        if (!running_.load()) break;

        if (HasPendingFaultEvents()) {
            HandleFault();
        } else {
            DrainInputAndSend();
        }
        CheckWorkerRecoveryComplete();  // [v2] 检查异步单 worker 恢复完成信号

        MaybeNoteHealthy();
        MaybePublishObserveSnapshot();

        if (!running_.load()) break;

        bool has_recovery_signal = false;
        {
            std::lock_guard<std::mutex> lock(recovery_signal_mutex_);
            has_recovery_signal = recovery_signal_.has_value();
        }
        if (input_pending_.load(std::memory_order_acquire) ||
            has_recovery_signal ||
            HasPendingFaultEvents()) {
            continue;
        }

        // Completion 等待下沉到 IDataPlane::Poll(timeout)。doorbell 模式由 eventfd
        // 即时唤醒；plain 模式由 data plane 自己的短 sleep/wake flag 控制有界延迟。
        // loop_interval 这里只是低频 maintenance / observe 的最长静默窗口。
        DrainTransport(std::chrono::duration_cast<std::chrono::microseconds>(
            channel_cfg_.loop_interval));
    }
}

bool Channel::HasPendingFaultEvents() const
{
    return !internal_crash_events_.empty() ||
           (health_monitor_ && health_monitor_->HasPendingCrashEvents());
}

// ============================================================
// input_queue metric helpers (调用方需持 io_mutex_)
// ============================================================
//
// 不变量:任何时刻 deferred_count_.load() == deferred_submissions_.size()。
// 由 DrainInputAndSend 搬迁后 store / erase 后 fetch_sub / 末尾兜底 store / Close
// / 非服务相位 clear 五处共同维护。这些 helper 默认相信不变量,直接相加得 depth。

int64_t Channel::ComputeInputQueueDepthLocked() const noexcept
{
    return static_cast<int64_t>(input_queue_.size())
         + static_cast<int64_t>(deferred_count_.load(std::memory_order_relaxed));
}

void Channel::PublishInputQueueDepthLocked()
{
    if (metrics_ != nullptr && metrics_->input_queue_depth != nullptr) {
        metrics_->input_queue_depth->Set(ComputeInputQueueDepthLocked());
    }
}

void Channel::ForceExitInputFullEpisodeLocked()
{
    if (!input_full_) return;
    if (metrics_ != nullptr && metrics_->input_queue_full_us != nullptr) {
        metrics_->input_queue_full_us->Inc(NowUs() - input_full_enter_us_);
    }
    input_full_              = false;
    input_full_enter_us_     = 0;
    input_full_busy_rejects_ = 0;
}

// ============================================================
// DrainInputAndSend — input_queue_ → Transport.TrySend()
// ============================================================

// 1. 从 input_queue_ 移入 deferred_submissions_ 尾部
// 2. 遍历 deferred_submissions_：
//    - 找到可发送 worker → TrySend → 写 pending_（Submit 已返回 kAccepted，此处无需 resolve）
//    - 无可用 worker → 保留在 deferred_submissions_，下一轮 loop 继续重试（无限重试语义）
// 3. 非服务状态时：cc::AbnormalCompletion(kCancelled) 代替旧的 resolve kUnavailable
//    （此时 slot 确实无法送达，必须显式清理让 scheduler 退回 seed）
// [Phase H] 移除了基于 slot->deadline 的淘汰分支，配合 executor 无限重试语义。
void Channel::DrainInputAndSend()
{
    auto current_phase = phase_.load();
    if (current_phase != cc::ChannelLifecycleState::kRunning &&
        current_phase != cc::ChannelLifecycleState::kDegraded) {
        // 非服务状态：发出 cc::AbnormalCompletion(kCancelled)，替代旧 resolve kUnavailable
        // 先收集 deferred_submissions_ 的 executor_id（遍历不需要 io_mutex_）
        std::vector<uint64_t> deferred_ids;
        for (auto& slot : deferred_submissions_) {
            deferred_ids.push_back(slot->request.executor_id);
        }
        // 清理 active_executor_ids_（需要 io_mutex_）
        // 进入非服务相位:若处于 input_full_,在抹平队列前强制结清当前 episode,
        // 避免相位切换的等待时间被错算到 full_us。
        {
            std::lock_guard<std::mutex> lk(io_mutex_);
            ForceExitInputFullEpisodeLocked();
            for (auto eid : deferred_ids) {
                active_executor_ids_.erase(eid);
            }
        }
        deferred_submissions_.clear();
        deferred_count_.store(0, std::memory_order_relaxed);
        // 收集 input_queue_ 的 executor_id，释放锁后再 EmitAbnormalCompletion（避免锁嵌套）
        std::vector<uint64_t> input_ids;
        {
            std::lock_guard<std::mutex> lock(io_mutex_);
            while (!input_queue_.empty()) {
                auto& s = input_queue_.front();
                input_ids.push_back(s->request.executor_id);
                active_executor_ids_.erase(s->request.executor_id);
                input_queue_.pop();
            }
            input_pending_.store(false, std::memory_order_release);
            // 队列已空,depth gauge 同步到 0 (此时 deferred_count_ 也已 store(0))
            if (metrics_ != nullptr && metrics_->input_queue_depth != nullptr) {
                metrics_->input_queue_depth->Set(0);
            }
        }
        // 锁外发出取消事件（QueueEvent 内部会锁 io_mutex_）
        for (auto eid : deferred_ids) {
            EmitAbnormalCompletion(eid, cc::AbnormalKind::kCancelled);
        }
        for (auto eid : input_ids) {
            EmitAbnormalCompletion(eid, cc::AbnormalKind::kCancelled);
        }
        return;
    }

    // 步骤 1：将 input_queue_ 中的新请求移入 deferred_submissions_ 尾部
    {
        std::lock_guard<std::mutex> lock(io_mutex_);
        while (!input_queue_.empty()) {
            deferred_submissions_.push_back(std::move(input_queue_.front()));
            input_queue_.pop();
        }
        // 立即把 deferred_count_ 同步到搬迁后的实际大小,维护
        // deferred_count_ == deferred_submissions_.size() 不变量。
        // (旧版只在 drain 末尾 store 一次,搬迁→erase 这段窗口里 Submit 读到的
        //  cur=input_queue.size() + stale_deferred_count 会低估占用,小 cap 下能突破上限。)
        deferred_count_.store(static_cast<uint32_t>(deferred_submissions_.size()),
                              std::memory_order_relaxed);
        input_pending_.store(false, std::memory_order_release);
        PublishInputQueueDepthLocked();
    }

    if (deferred_submissions_.empty()) return;

    // 步骤 2：遍历 deferred_submissions_，尝试发送
    const uint32_t n = channel_cfg_.n_workers;

    // [Phase H] 无限重试语义:slot 一旦进到 deferred,就留在这里直到发出去
    //   或相位切换被清理。slot->deadline 字段保留但不再读取。
    auto it = deferred_submissions_.begin();
    while (it != deferred_submissions_.end()) {
        auto& slot = *it;

        // 步骤 A：路由到 worker。两种模式:
        //   * round-robin (target_worker_id == kAnyWorkerId): 沿用既有遍历。
        //   * strict affinity (target_worker_id < n_workers): 只尝试该 slot;
        //     该 slot 被 quarantine 或 dp_ 拒绝 → 不 fallback,留 deferred 下轮重试。
        //     指定 procid 时 affinity 是其 lane owner；指定 worker 时是调用者
        //     的 transport placement 约束。两者都不允许静默 fallback。
        bool sent = false;
        const uint32_t requested_proc = slot->request.target_proc_id;
        const uint32_t affinity = requested_proc != cc::kAnyProcId
            ? requested_proc % n
            : slot->request.target_worker_id;
        const bool has_affinity = (affinity != cc::kAnyWorkerId);
        const uint32_t loop_count = has_affinity ? 1u : n;
        for (uint32_t attempt = 0; attempt < loop_count; ++attempt) {
            const uint32_t wid = has_affinity
                                     ? affinity
                                     : (next_worker_rr_ + attempt) % n;

            // 被隔离的 worker 正在异步恢复中，不应向其发送新任务
            if (quarantined_workers_.count(wid)) continue;

            data::IDataPlane::SubmitInput req;
            req.worker_id     = wid;
            req.proc_id       = requested_proc;
            req.executor_id   = slot->request.executor_id;
            req.dispatch_gen  = generation_.load();
            req.wait_for_slot = std::chrono::microseconds{0};
            req.payload_data  = slot->request.payload.data();
            req.payload_size  = slot->request.payload.size();
            // [v2 Epic 5 PR-5-B] forward wire-flags (collect_comps etc.)
            req.exec_flags    = slot->request.exec_flags;
            if (slot->request.trace.sampled) {
                slot->request.trace.data_plane_call_ts_us = NowUs();
            }
            auto outcome = dp_->Submit(req);

            if (outcome != data::SubmitOutcome::kSent) {
                continue;
            }

            const uint64_t sent_ts_us = NowUs();

            // 发送成功：创建 DispatchRecord
            DispatchRecord rec;
            rec.executor_id    = slot->request.executor_id;
            rec.seed_id        = slot->request.seed_id;
            rec.origin_seed_id = slot->request.origin_seed_id;
            rec.slot_id        = wid;
            rec.dispatch_gen   = generation_.load();
            rec.generation     = generation_.load();
            rec.submit_ts_us   = sent_ts_us;
            rec.trace          = slot->request.trace;
            rec.payload        = std::move(slot->request.payload);
            // [v2 Epic 5 PR-5-B] preserve wire-flags across retries
            rec.exec_flags     = slot->request.exec_flags;
            // Preserve affinity so the recovery rebuild path doesn't pick a
            // different worker on retry — see DispatchRecord.target_worker_id.
            rec.target_worker_id = slot->request.target_worker_id;
            rec.target_proc_id = slot->request.target_proc_id;

            pending_[slot->request.executor_id] = std::move(rec);
            inflight_count_.fetch_add(1, std::memory_order_relaxed);
            // Only advance round-robin cursor for non-affined sends; an
            // affined send shouldn't bias the round-robin clock used by
            // non-affined callers.
            if (!has_affinity) {
                next_worker_rr_ = (wid + 1) % n;
            }

            {
                std::lock_guard<std::mutex> lk(stats_mutex_);
                ++total_submissions_;
            }

            // [v3] TrySend 成功：已写 pending_，Submit() 早已返回 kAccepted，无需 resolve promise
            sent = true;
            break;
        }

        if (sent) {
            // 发送成功：移出队列。立即同步 deferred_count_ (维护 deferred_count_ ==
            // deferred_submissions_.size() 不变量,避免 Submit 路径在 drain 进行中读到 stale 值
            // 把容量看小,导致 depth 短暂越过 capacity)。
            it = deferred_submissions_.erase(it);
            deferred_count_.fetch_sub(1, std::memory_order_relaxed);
        } else {
            // [Phase H] 语义变更:deferred 层不再基于 deadline 做淘汰。
            //   原因:新语义下 task 不可丢——executor 层的 Submit 已改为非阻塞
            //   立即返回 kBusy(wait_for_slot=0,deadline 仅保留字段不再读取),
            //   由 executor 负责重试直到 Channel accept。一旦 slot 进到这里,
            //   说明 Channel 已经"接管"它,必须发给 worker 或在相位切换/reboot
            //   时显式清理(非服务相位分支仍保留 EmitAbnormalCompletion)。
            //   因此运行相位下 send 失败就一直留在 deferred 队列,下轮 loop 继续。
            ++it;
        }
    }

    // 更新 deferred 计数兜底 (drain 中已逐次 fetch_sub, 这里再 store 一次保持
    // deferred_count_ == deferred_submissions_.size() 不变量, 防御 race / 漏改)。
    {
        std::lock_guard<std::mutex> lock(io_mutex_);
        deferred_count_.store(static_cast<uint32_t>(deferred_submissions_.size()),
                              std::memory_order_relaxed);

        // [migrated] input_queue_full_exit event → channel.input_queue.full_us counter
        //            (累计饱和时长; 退出边沿在锁内一次性结清, 见 020_naming_catalog §4.6)
        if (input_full_) {
            const uint32_t cap = channel_cfg_.input_queue_capacity;
            const size_t cur   = static_cast<size_t>(ComputeInputQueueDepthLocked());
            if (cur < cap) {
                if (metrics_ != nullptr && metrics_->input_queue_full_us != nullptr) {
                    metrics_->input_queue_full_us->Inc(NowUs() - input_full_enter_us_);
                }
                input_full_              = false;
                input_full_enter_us_     = 0;
                input_full_busy_rejects_ = 0;
            }
        }

        PublishInputQueueDepthLocked();
    }
}

// ============================================================
// DrainTransport — Transport.Poll(timeout) → output_queue_
// ============================================================

void Channel::DrainTransport(std::chrono::microseconds timeout)
{
    if (!dp_) return;

    // [v3 Phase 4.4] DP.Poll 返回语义级 DispatchOutcome：
    //   - kind：Ok / ExecError / Timeout / Cancelled / WorkerSignaled
    //   - error_code / crash_signal：透传 worker 诊断信息给 cc::AbnormalCompletion.diagnostics
    //   - vendor_status：wire 原始 COMP_STATUS_* 码（debug/telemetry 可选）
    transport_results_.clear();
    dp_->Poll(transport_results_, timeout);

    for (auto& recv : transport_results_) {
        auto it = pending_.find(recv.executor_id);
        if (it == pending_.end()) continue;  // 未知 executor_id，丢弃

        // [completion path heap churn 减少 2026-05-22] 之前 const ref, 现在
        // 改 non-const 让 program_payload 可以 std::move (pending_.erase 紧
        // 跟在后 line 743, payload ownership 转给 event 而不是 copy + 双 free).
        auto& rec = it->second;

        // V2 规则：仅按 completion.dispatch_gen 与 channel_generation 等值过滤
        if (recv.dispatch_gen != generation_.load()) {
            continue;
        }
        if (rec.dispatch_gen != recv.dispatch_gen) {
            continue;
        }

        const bool proc_id_mismatch =
            rec.target_proc_id != cc::kAnyProcId &&
            recv.proc_id != rec.target_proc_id;
        if (proc_id_mismatch) {
            recv.kind = data::DispatchOutcomeKind::kHarnessFatal;
            recv.error_code = ERR_HARNESS_FORK_SERVER_PROTOCOL;
            recv.crash_signal = 0;
            recv.output.clear();
        }

        // [crash-execution-history-ring] Layer-2: retain every completed program
        // (continuous accumulation). 只有 worker 显式判定的 **HUNG**（daemon
        // watchdog / 执行阶段 kill-reap 未完成 / 恢复失败的 ERR_DOMAIN_*，
        // 即"程序可能仍在内核里"）进永久 hanged side-list；防御性兼容旧
        // TIMEOUT + ERR_DOMAIN_WATCHDOG_TIMEOUT。普通 program watchdog 超时
        // （ERR_TIMEOUT）数据有效、走 Completion 侧，与正常完成一样进 evictable
        // per-worker ring（镜像 syzkaller LastExecuting：只有顶层进程在
        // Executing 态死亡才记 Hanged）。
        // Copy here — rec.payload is moved into the completion below.
        RecentProgramRecord hist_rec{rec.executor_id, rec.seed_id,
                                     rec.origin_seed_id, rec.submit_ts_us,
                                     rec.payload};
        const bool replacement_start_failed =
            recv.error_code == ERR_DOMAIN_REPLACEMENT_START_FAILED;
        const bool ownership_unreclaimed =
            recv.error_code == ERR_DOMAIN_OWNERSHIP_UNRECLAIMED;
        const bool task_hang =
            recv.kind == data::DispatchOutcomeKind::kHang ||
            (recv.kind == data::DispatchOutcomeKind::kTimeout &&
             recv.error_code != ERR_TIMEOUT);
        // 进池只看 status 是否为 HUNG（含防御性 TIMEOUT+非-ERR_TIMEOUT）。
        // error 15 不单独决定进池：kTimeout/kHang+15 已被 task_hang 覆盖；
        // HARNESS_FATAL+15（rebind / 未执行 / infra 恢复失败）程序从未执行或
        // 已证明退出，绝不能进永久池。
        if (task_hang) {
            recent_programs_.NoteHanged(std::move(hist_rec));
        } else {
            recent_programs_.Note(recv.worker_id, std::move(hist_rec));
        }

        const bool trigger_internal_recovery =
            recv.kind == data::DispatchOutcomeKind::kHarnessFatal ||
            replacement_start_failed ||
            ownership_unreclaimed;
        const uint32_t recovery_worker_id = recv.worker_id;

        // Any validated guest terminal proves that the execution machinery
        // advanced, regardless of whether the task completed normally or as
        // a hang/infra abnormal. Host-synthesized terminals never enter this
        // transport path and therefore do not refresh VM progress.
        if (progress_clock_ != nullptr) {
            progress_clock_->Note();
        }

        cc::ChannelEvent evt;
        evt.event_id   = next_event_id_++;
        evt.channel_id = channel_cfg_.channel_id;
        evt.generation = generation_.load();

        // [两层语义 — completion error_code 的唯一分类点]
        // COMP_STATUS_TIMEOUT 现在**只**是 program watchdog（ERR_TIMEOUT，数据
        // 有效、走 Completion）；daemon task hang 由 worker 显式判为
        // COMP_STATUS_HUNG（DispatchOutcomeKind::kHang），不再与 TIMEOUT 共用：
        //   ERR_TIMEOUT                 = program watchdog(worker 内 per-program
        //       看门狗)。程序被 SIGKILL,但它在被杀前按 RELEASE 序发布的 progress
        //       数据完整可信(worker 已如实带出 output)→ **data-bearing**,走
        //       Completion 侧,与 kPartial 同等处理(覆盖计入、不 hard_stop),标签
        //       保留为 CompletionKind::kTimeout。
        //   kHang（COMP_STATUS_HUNG）+ ERR_DOMAIN_WATCHDOG_TIMEOUT（或执行阶段
        //       恢复失败的 ERR_DOMAIN_* / reap 类 ERR_HARNESS_*）=
        //       worker 判定的 task hang / 结果丢失 → Abnormal(kHang)，且任务
        //       已在上方 NoteHanged 进池，由后续 kKernelCrash 统一收获。
        //   防御性兼容：旧 wire 的 TIMEOUT + ERR_DOMAIN_WATCHDOG_TIMEOUT 仍按
        //       kHang 结算；ERR_DOMAIN_OWNERSHIP_UNRECLAIMED 防御性到达时也按
        //       abnormal 结算（不 retained、不等内核输出）。
        // 标签(为什么结束)与处理(走哪条路)分离:program timeout 有自己的标签,但处理
        // 路径与 partial 完全相同 —— 它不是异常,只是没跑完。
        // program watchdog 超时:数据有效,走 Completion。它按契约 crash_signal==0
        // (program_runtime.cpp 该路径恒置零),所以**不**给它加 crash_signal 门 ——
        // 加了会在将来某天该路径开始带信号时把有效 timeout 静默误判成 task hang。
        const bool is_program_timeout =
            recv.kind == data::DispatchOutcomeKind::kTimeout &&
            recv.error_code == ERR_TIMEOUT;
        // clean completion(kOk/kPartial)才需要 crash_signal==0 兜底:防止某个本应
        // 干净完成的结果意外带了信号还被当成功。
        const bool is_clean_completion =
            (recv.kind == data::DispatchOutcomeKind::kOk ||
             recv.kind == data::DispatchOutcomeKind::kPartial) &&
            recv.error_code == 0 && recv.crash_signal == 0;
        // [方案 A — 归类修正] program-child 自身 crash 是 data-bearing 的 Completion:
        // 用户态测试进程崩溃 ≠ 内核崩溃,crash 前已提交到 KCOV 的覆盖有效,应当消费
        // (对齐 syzkaller reply_execute(0))。它**带非零 crash_signal**,故独立识别
        // (不经 crash_signal 门),并在下面把 crash 事实作为 Completion::crash_diagnostic
        // 旁路携带,诊断落盘不丢。
        const bool is_child_abort_completion =
            recv.kind == data::DispatchOutcomeKind::kChildAborted;
        const bool is_success_completion =
            is_clean_completion || is_program_timeout || is_child_abort_completion;
        if (is_success_completion) {
            evt.kind = cc::ChannelEvent::Kind::kCompletion;
            cc::Completion comp;
            comp.ctx.executor_id     = rec.executor_id;
            comp.ctx.seed_id         = rec.seed_id;
            comp.ctx.origin_seed_id  = rec.origin_seed_id;
            comp.ctx.worker_id       = recv.worker_id;
            comp.ctx.proc_id         = recv.proc_id;
            comp.ctx.dispatch_gen    = recv.dispatch_gen;
            comp.ctx.generation      = rec.generation;
            comp.ctx.submit_ts_us    = rec.submit_ts_us;
            // [heap churn 减少 2026-05-22] std::move payload, pending_.erase
            // 紧跟在 line 743 后销毁 moved-from vector (空). 比 deep copy 省
            // O(payload size) bytes memcpy + 1 次 KASAN heap shadow check.
            comp.ctx.program_payload = std::move(rec.payload);
            comp.ctx.trace           = rec.trace;
            comp.ctx.trace.worker_start_ts_us = recv.worker_start_ts_us;
            comp.ctx.trace.worker_start_ack_host_ts_us = recv.worker_start_ack_host_ts_us;  // [RTT]
            comp.ctx.trace.completion_observed_host_ts_us =
                recv.completion_observed_host_ts_us;
            comp.ctx.trace.output_copied_host_ts_us =
                recv.output_copied_host_ts_us;
            comp.ctx.trace.worker_done_ts_us  = recv.worker_done_ts_us;
            comp.ctx.trace.worker_clock_is_guest_monotonic =
                recv.worker_clock_is_guest_monotonic;
            // 标签保留"为什么结束";各 kind 的处理路径相同(见 CompletionKind 注释)。
            comp.kind =
                is_child_abort_completion ? cc::CompletionKind::kChildAborted
                : is_program_timeout ? cc::CompletionKind::kTimeout
                : (recv.kind == data::DispatchOutcomeKind::kPartial)
                    ? cc::CompletionKind::kPartial
                    : cc::CompletionKind::kNormal;
            // [方案 A] 把 crash 事实作为诊断旁路挂上,让 FaultSignal 仍能建 crash_payload
            // 落盘 —— 覆盖走 Completion 消费,诊断照记,两不误。
            if (is_child_abort_completion) {
                comp.crash_diagnostic = cc::CompletionCrashDiagnostic{
                    .crash_signal = recv.crash_signal,
                    .error_code   = recv.error_code,
                };
            }
            comp.output              = std::move(recv.output);
            comp.vendor_aux          = recv.vendor_aux;
            comp.vendor_status       = recv.vendor_status;
            comp.vendor_flags        = recv.vendor_flags;
            // [XiUOS leak 一等公民化 Phase 5] resource residue parallel to vendor_flags.
            comp.vendor_resource_residue = recv.vendor_resource_residue;
            evt.payload              = std::move(comp);

            {
                std::lock_guard<std::mutex> lk(stats_mutex_);
                ++total_completions_;
            }

        } else {
            evt.kind = cc::ChannelEvent::Kind::kAbnormal;
            cc::AbnormalCompletion abnormal;
            abnormal.ctx.executor_id     = rec.executor_id;
            abnormal.ctx.seed_id         = rec.seed_id;
            abnormal.ctx.origin_seed_id  = rec.origin_seed_id;
            abnormal.ctx.worker_id       = recv.worker_id;
            abnormal.ctx.proc_id         = recv.proc_id;
            abnormal.ctx.dispatch_gen    = recv.dispatch_gen;
            abnormal.ctx.generation      = rec.generation;
            abnormal.ctx.submit_ts_us    = rec.submit_ts_us;
            // [heap churn 减少 2026-05-22] 同 success path: 紧跟 erase 销毁.
            abnormal.ctx.program_payload = std::move(rec.payload);
            abnormal.ctx.trace           = rec.trace;
            abnormal.ctx.trace.worker_start_ts_us = recv.worker_start_ts_us;
            abnormal.ctx.trace.worker_start_ack_host_ts_us = recv.worker_start_ack_host_ts_us;  // [RTT]
            abnormal.ctx.trace.completion_observed_host_ts_us =
                recv.completion_observed_host_ts_us;
            abnormal.ctx.trace.output_copied_host_ts_us =
                recv.output_copied_host_ts_us;
            abnormal.ctx.trace.worker_done_ts_us  = recv.worker_done_ts_us;
            abnormal.ctx.trace.worker_clock_is_guest_monotonic =
                recv.worker_clock_is_guest_monotonic;
            abnormal.output              = std::move(recv.output);

            // [v2 +kChildAborted 优先于 kWorkerSignaled — 当前版本]
            // 语义级 kind 翻译：kHang（含 domain-hang HarnessFatal）归 task Hang；
            // 其它 HarnessFatal > Cancelled > Timeout > ChildAborted > WorkerSignaled > ExecError
            // - kChildAborted 由 worker 上报 COMP_STATUS_CHILD_ABORTED 派生（program 行为致 child 退出/被信号）
            //   即便 crash_signal != 0 也不应再升级为 kWorkerSignaled，否则会被 crash pipeline 错升级为 worker_dead
            // - 真正的 kWorkerSignaled 只剩：worker 上报 COMP_STATUS_CRASHED（daemon-child 协议错的真信号）
            //   或 host 侧检测到 worker/kernel 异常
            // - [两层语义] 本分支的 kHang/kTimeout 都是 abnormal：program watchdog
            //   的超时(ERR_TIMEOUT)已在上面被 is_program_timeout 分流到 Completion
            //   侧；kHang 是 worker 显式判定，kTimeout 只剩防御性兼容（daemon
            //   watchdog / replacement failure / ownership-unreclaimed）。
            //   EmitAbnormalCompletion(host 侧判 worker 死)同样用
            //   ERR_DOMAIN_WATCHDOG_TIMEOUT 这个配对。
            if (recv.kind == data::DispatchOutcomeKind::kHarnessFatal) {
                abnormal.kind = cc::AbnormalKind::kHarnessFatal;
            } else if (recv.kind == data::DispatchOutcomeKind::kHarnessRecovered) {
                abnormal.kind = cc::AbnormalKind::kHarnessRecovered;
            } else if (recv.kind == data::DispatchOutcomeKind::kCancelled) {
                abnormal.kind = cc::AbnormalKind::kCancelled;
            } else if (recv.kind == data::DispatchOutcomeKind::kHang) {
                abnormal.kind = cc::AbnormalKind::kHang;
            } else if (recv.kind == data::DispatchOutcomeKind::kTimeout) {
                abnormal.kind = cc::AbnormalKind::kHang;
            } else if (recv.kind == data::DispatchOutcomeKind::kChildAborted) {
                // [dead branch — 有意保留] kChildAborted 恒被上面的
                // is_child_abort_completion 领去 Completion 侧(方案 A),永远到不了这里。
                // 保留是为了:(a) 若将来有人给 is_child_abort_completion 误加
                // crash_signal 门而让它漏下来,这里仍有正确归类兜底;(b) 让 kind 覆盖
                // 完整、可读。**不要**据此以为 child-abort 还会以 Abnormal 出现。
                abnormal.kind = cc::AbnormalKind::kChildAborted;
            } else if (recv.kind == data::DispatchOutcomeKind::kWorkerSignaled) {
                abnormal.kind = cc::AbnormalKind::kWorkerSignaled;
            } else if (recv.kind == data::DispatchOutcomeKind::kNoResult) {
                abnormal.kind = cc::AbnormalKind::kNoResult;
            } else if (recv.kind == data::DispatchOutcomeKind::kInfraFault) {
                abnormal.kind = cc::AbnormalKind::kInfraFault;
            } else {
                // 兜底:kOk/kPartial 已被上面的 is_success_completion 领走,能落到
                // 这里的只剩 kUnknown 或将来新增却忘了接的 kind —— 两者都是 bug 信号。
                // 曾兜底成 kExecError,把"不该发生"伪装成一次普通执行错误静默吞掉。
                abnormal.kind = cc::AbnormalKind::kUnknown;
            }
            abnormal.diagnostics.worker_id    = recv.worker_id;
            abnormal.diagnostics.error_code   = recv.error_code;
            abnormal.diagnostics.crash_signal = recv.crash_signal;
            // [XiUOS leak 一等公民化 Phase 4] carry the per-program vendor fields on
            // the abnormal path too (success path does this above). A leaky program
            // whose last call errors lands here; without this its leak delta
            // (vendor_flags) is dropped and the leak goes unseen.
            abnormal.vendor_aux    = recv.vendor_aux;
            abnormal.vendor_status = recv.vendor_status;
            abnormal.vendor_flags  = recv.vendor_flags;
            // [XiUOS leak 一等公民化 Phase 5] resource residue parallel to vendor_flags.
            abnormal.vendor_resource_residue = recv.vendor_resource_residue;

            // [v2 PR-B abnormal console snapshot — 当前版本]
            // 同 EmitAbnormalCompletion: 抓 ring buffer 最近若干行 console。
            // 这里命中 worker 上报 ChildAborted/Timeout/ExecError/WorkerSignaled 路径,
            // 是绝大多数 abnormal incident 的来源,console 上下文最有调试价值。
            // [v2 PR-E 行数从 channel_cfg_.abnormal_console_snapshot_lines 取 — 当前版本]
            if (console_ring_ != nullptr &&
                channel_cfg_.abnormal_console_snapshot_lines > 0) {
                abnormal.console_snapshot = console_ring_->SnapshotJoined(
                    channel_cfg_.abnormal_console_snapshot_lines);
            }
            evt.payload = std::move(abnormal);
        }

        const uint64_t completed_executor_id = recv.executor_id;
        pending_.erase(it);
        {
            std::lock_guard<std::mutex> lk(io_mutex_);
            active_executor_ids_.erase(completed_executor_id);
        }
        inflight_count_.fetch_sub(1, std::memory_order_relaxed);
        QueueEvent(std::move(evt));

        if (trigger_internal_recovery) {
            PendingFaultInput recovery_event;
            // 15（ownership unreclaimed）= 旧域可能还活着，单 worker restart 不够，
            // 必须升级 VM reboot（kExecutionDomainHung）；10/14 仍是 worker 级
            // 故障/替换失败，走单 worker restart。
            recovery_event.reason_override = ownership_unreclaimed
                ? cc::ChannelFaultReason::kExecutionDomainHung
                : cc::ChannelFaultReason::kWorkerHarnessFatal;
            recovery_event.source = cc::ChannelFaultSource::kChannelInternal;
            recovery_event.origin = cc::FaultOrigin::kChannelInternal;
            recovery_event.event.vm_epoch = vm_epoch_.load(std::memory_order_relaxed);
            recovery_event.event.detected_ts_us = NowUs();
            recovery_event.event.fragment.kind = health::CrashKind::kWorkerDead;
            recovery_event.event.fragment.source_worker_id = recovery_worker_id;
            recovery_event.event.fragment.title = ownership_unreclaimed
                ? "worker domain ownership unreclaimed"
                : "worker harness recovery failed";
            recovery_event.event.checker_name = ownership_unreclaimed
                ? "worker-maintenance"
                : "worker-harness-fatal";
            recovery_event.event.inferred = false;
            internal_crash_events_.push_back(std::move(recovery_event));
        }
    }

    DrainWorkerMaintenanceFaults();
}

void Channel::QueueWorkerMaintenanceFault(uint32_t worker_id,
                                          uint32_t error_code)
{
    PendingFaultInput recovery_event;
    // 15 必须升级 VM reboot（旧域未证明隔离，单 worker restart 会与可能还活着
    // 的旧域重叠）；10/14 保持单 worker restart。
    recovery_event.reason_override =
        error_code == ERR_DOMAIN_OWNERSHIP_UNRECLAIMED
            ? cc::ChannelFaultReason::kExecutionDomainHung
            : cc::ChannelFaultReason::kWorkerHarnessFatal;
    recovery_event.source = cc::ChannelFaultSource::kChannelInternal;
    recovery_event.origin = cc::FaultOrigin::kChannelInternal;
    recovery_event.event.vm_epoch =
        vm_epoch_.load(std::memory_order_relaxed);
    recovery_event.event.detected_ts_us = NowUs();
    recovery_event.event.fragment.kind = health::CrashKind::kWorkerDead;
    recovery_event.event.fragment.source_worker_id = worker_id;
    switch (error_code) {
    case ERR_DOMAIN_REPLACEMENT_START_FAILED:
        recovery_event.event.fragment.title = "worker domain replacement failed";
        break;
    case ERR_DOMAIN_OWNERSHIP_UNRECLAIMED:
        recovery_event.event.fragment.title = "worker domain ownership unreclaimed";
        break;
    case ERR_HARNESS_FORK_SERVER_PROTOCOL:
        recovery_event.event.fragment.title = "worker completion publication failed";
        break;
    default:
        recovery_event.event.fragment.title = "worker maintenance fault";
        break;
    }
    recovery_event.event.checker_name = "worker-maintenance";
    recovery_event.event.inferred = false;
    internal_crash_events_.push_back(std::move(recovery_event));

    refuzz::logging::HostLogger::Instance().Log(
        "Channel", "worker_maintenance_fault",
        {refuzz::logging::Field("channel_id", channel_cfg_.channel_id),
         refuzz::logging::Field("worker_id", worker_id),
         refuzz::logging::Field("error_code", error_code)});
}

void Channel::DrainWorkerMaintenanceFaults()
{
    if (cp_ == nullptr) {
        return;
    }
    for (uint32_t worker_id = 0; worker_id < cp_->MaxWorkerSlots();
         ++worker_id) {
        const uint32_t error_code = cp_->ConsumeWorkerError(worker_id);
        if (error_code == ERR_OK) {
            continue;
        }
        QueueWorkerMaintenanceFault(worker_id, error_code);
    }
}

// ============================================================
// EmitFaultEvent — 构建 cc::Fault 事件并入 output_queue_（§20 I6）
// ============================================================

void Channel::EmitFaultEvent(cc::ChannelFaultReason reason,
                             const health::CrashFragment& fragment,
                             cc::FaultOrigin origin)
{
    cc::Fault fault_event;

    // cc::FaultKind 从 CrashKind 映射
    fault_event.kind = reason == cc::ChannelFaultReason::kNoOutput
        ? cc::FaultKind::kNoOutput
        : MapCrashKindToFaultKind(fragment.kind);
    // §3.11-A — origin 透传：health 侧 sensor 的来源信息保留到 cc::Fault，
    //           下游 CrashPipeline 用来 gate evidence-coercion（heartbeat
    //           触发的 worker_dead 不应被相邻 console buffer 残留误改写为
    //           kernel_crash）。
    fault_event.origin = origin;

    fault_event.channel_ctx.channel_id        = channel_cfg_.channel_id;
    fault_event.channel_ctx.generation        = generation_.load();
    fault_event.channel_ctx.state_before_fault = MapLifecycleToState(phase_.load());
    fault_event.channel_ctx.detected_ts_us    = NowUs();

    // scene.console 直接赋值 health::CrashFragment（C1 fix：cc::CrashScene.console 类型即 health::CrashFragment）
    fault_event.scene.console = fragment;

    // 当前 inflight 任务状态快照
    // 为保持 crash scene 的可读性与确定性，按 submit_ts_us（再按 executor_id）排序。
    const auto ordered_records = OrderedDispatchRecords(pending_);

    auto append_record = [&fault_event](const DispatchRecord* rec) {
        // [当前版本 fault payload 去重] worker_states 是 metadata-only 快照:
        //   scene.worker_states 全链路无消费方(仅此处填充),其 payload 字段尤其
        //   从不被读。crash 时实际被消费的 program payload 走 candidate_window
        //   (fault_signal 对每个 candidate 取 .payload → program_payload)。所以
        //   这里**不**再把 rec->payload 拷进 wts —— 避免 fault 路径上 O(inflight ×
        //   payload) 的死拷贝(原先 worker_states + candidate_window 各拷一份 = ×2)。
        cc::WorkerTaskState wts;
        wts.worker_id    = rec->slot_id;
        wts.executor_id  = rec->executor_id;
        wts.dispatch_gen = rec->dispatch_gen;
        wts.seed_id      = rec->seed_id;
        wts.submit_ts_us = rec->submit_ts_us;
        wts.was_inflight = true;
        fault_event.scene.worker_states.push_back(std::move(wts));

        cc::ChannelTaskSnapshot task;
        task.executor_id    = rec->executor_id;
        task.seed_id        = rec->seed_id;
        task.origin_seed_id = rec->origin_seed_id;
        task.payload        = rec->payload;   // 消费路径:fault_signal → crash pipeline
        fault_event.scene.candidate_window.push_back(std::move(task));
    };

    for (const DispatchRecord* rec : ordered_records) {
        append_record(rec);
    }

    // [crash-execution-history-ring] Layer-2 harvest. Gated to confirmed kernel
    // crashes (real bugs) — the high-volume noise (exec_error / timeout / abnormal)
    // must NOT pull the history. Prepend the recent COMPLETED-program history
    // (time-sorted, excluding the in-flight Layer-1 entries) BEFORE the in-flight
    // block, so the in-flight "guilty" program stays last (crash_index ==
    // candidate_window.size()-1, see fault_signal.cpp). This restores context for
    // async/deferred-trigger bugs whose triggering syscall already left pending_.
    if (reason == cc::ChannelFaultReason::kKernelCrash &&
        recent_programs_.enabled()) {
        std::unordered_set<uint64_t> inflight_ids;
        inflight_ids.reserve(ordered_records.size());
        for (const DispatchRecord* r : ordered_records) {
            inflight_ids.insert(r->executor_id);
        }
        auto history = recent_programs_.Collect(inflight_ids);
        if (!history.empty()) {
            std::vector<cc::ChannelTaskSnapshot> hist_snaps;
            hist_snaps.reserve(history.size());
            for (auto& h : history) {
                cc::ChannelTaskSnapshot task;
                task.executor_id    = h.executor_id;
                task.seed_id        = h.seed_id;
                task.origin_seed_id = h.origin_seed_id;
                task.payload        = std::move(h.payload);
                hist_snaps.push_back(std::move(task));
            }
            auto& cw = fault_event.scene.candidate_window;
            cw.insert(cw.begin(),
                      std::make_move_iterator(hist_snaps.begin()),
                      std::make_move_iterator(hist_snaps.end()));
        }
    }

    cc::ChannelEvent evt;
    evt.kind        = cc::ChannelEvent::Kind::kFault;
    evt.event_id    = next_event_id_++;
    evt.channel_id  = channel_cfg_.channel_id;
    evt.generation  = generation_.load();
    fault_event.incident_id = (static_cast<uint64_t>(channel_cfg_.channel_id) << 48)
                              | evt.event_id;
    evt.payload = std::move(fault_event);

    // reason 用于日志标注（当前通过 fault_event.kind 携带等价信息）
    (void)reason;

    QueueEvent(std::move(evt));
}

// ============================================================
// HandleFault — 故障处理 + 级联恢复循环（§20）
// ============================================================

// [v2 HandleFault — 当前版本]
// 替换单槽 TakeCrashFragment() 为 DrainCrashEvents() FIFO 批量消费（§18.4.1）
// 替换 fault_tracker_.* 为 recovery_->ObserveFault() / ExecuteRecovery() / Complete*()
// 新增 health_internal 强恢复门控路径（§18.4.2）
void Channel::HandleFault()
{
    std::vector<PendingFaultInput> events;
    events.reserve(internal_crash_events_.size());
    while (!internal_crash_events_.empty()) {
        events.push_back(std::move(internal_crash_events_.front()));
        internal_crash_events_.pop_front();
    }
    if (health_monitor_) {
        auto health_events = health_monitor_->DrainCrashEvents();
        events.reserve(events.size() + health_events.size());
        for (auto& event : health_events) {
            PendingFaultInput input;
            input.origin = static_cast<cc::FaultOrigin>(event.origin);
            input.event = std::move(event);
            events.push_back(std::move(input));
        }
    }
    if (events.empty()) return;

    for (auto& input : events) {
        const auto& event = input.event;
        // 检查 channel 是否已进入终态（失败/关闭），停止处理剩余事件
        auto current_phase = phase_.load();
        if (current_phase == cc::ChannelLifecycleState::kFailed ||
            current_phase == cc::ChannelLifecycleState::kClosed) {
            break;
        }

        // ─── 归一化：内部故障携带明确 reason；health 事件再按 origin/kind 映射 ───
        cc::ChannelFaultReason reason;
        if (input.reason_override.has_value()) {
            reason = *input.reason_override;
        } else if (event.origin == health::CrashEventOrigin::kHealthInternal) {
            reason = cc::ChannelFaultReason::kHealthInternal;
        } else {
            reason = MapCrashKindToFaultReason(event.fragment.kind);
        }

        // [Task2 syz-parity suppression] kKernelCrash 但 console 只是 benign(匹配 crash-title
        //   却非真崩的 deprecation/notice/mitigation WARNING,如 "mand mount option has been
        //   deprecated")→ 丢弃,绝不 reboot。镜像 syzkaller:detect → 若 suppressed 则 caller
        //   丢弃。判定数据(suppression 表)住在 crash 子系统;谓词由 orchestrator 在 linux
        //   target 上注入。谓词为空(未注入/非 kernel target)→ 按真崩处理,保持旧行为。
        if (reason == cc::ChannelFaultReason::kKernelCrash &&
            channel_cfg_.is_real_kernel_crash &&
            !channel_cfg_.is_real_kernel_crash(event.fragment.console_output)) {
            refuzz::logging::HostLogger::Instance().Log(
                "Channel", "kernel_crash_suppressed_benign",
                {refuzz::logging::Field("channel_id", channel_cfg_.channel_id),
                 refuzz::logging::Field("title", event.fragment.title)});
            continue;
        }

        // ─── health_internal 强恢复门控路径 ───────────────
        if (reason == cc::ChannelFaultReason::kHealthInternal) {
            // 预排干序列：先 Pause 再 DrainTransport，清掉已完成未收割的结果
            // 此后 pending_ 中剩余 = 真正 in-flight
            dp_->Pause();
            DrainTransport();

            // 标记所有 in-flight 任务为 kUntrusted
            // 不向 fuzzer 发出 cc::AbnormalCompletion；任务对 fuzzer 侧仍在"待结果"状态
            for (auto& [exec_id, rec] : pending_) {
                rec.state = DispatchState::kUntrusted;
            }

            health_monitor_->SuspendMonitoring();

            worker_recovery_queue_.clear();
            worker_recovery_queued_.clear();
            active_worker_recovery_worker_id_ = UINT32_MAX;
            SetLifecycleState(cc::ChannelLifecycleState::kRecovering);

            const cc::FaultKind fk = cc::FaultKind::kHealthInternal;  // 精确映射(不再借 kWorkerDead)
            EmitObserveFaultDetected(fk, reason);

            recovery::FaultContext context;
            context.source_worker_id = event.fragment.source_worker_id;
            context.total_workers = channel_cfg_.n_workers;
            context.unusable_workers = static_cast<uint32_t>(quarantined_workers_.size());

            uint64_t trigger_fault_event_id = next_event_id_++;
            auto obs_result = recovery_->ObserveFault(
                trigger_fault_event_id,
                reason,
                input.source,
                context);
        
            if (!obs_result.accepted ||
                obs_result.recovery_action != cc::RecoveryAction::kRestartHealthMonitor) {
                // 策略未接受或动作不是 kRestartHealthMonitor → 中止 kUntrusted 任务后恢复门控
                for (auto& [exec_id, rec] : pending_) {
                    if (rec.state == DispatchState::kUntrusted) {
                        EmitAbnormalCompletion(exec_id, cc::AbnormalKind::kCancelled);
                    }
                }
                {
                    std::lock_guard<std::mutex> lk(io_mutex_);
                    for (auto& [exec_id, rec] : pending_) {
                        if (rec.state == DispatchState::kUntrusted) {
                            active_executor_ids_.erase(exec_id);
                        }
                    }
                }
                // 移除所有 kUntrusted 记录
                for (auto it = pending_.begin(); it != pending_.end();) {
                    if (it->second.state == DispatchState::kUntrusted) {
                        inflight_count_.fetch_sub(1, std::memory_order_relaxed);
                        it = pending_.erase(it);
                    } else { ++it; }
                }
                // 恢复 transport，切回 kRunning（或 kFailed 由策略决定）
                health_monitor_->ResumeMonitoring();
                dp_->Resume();
                SetLifecycleState(cc::ChannelLifecycleState::kDegraded);
                break;  // 不处理本批次剩余事件
            }

            EmitObserveRecoveryStarted(cc::RecoveryAction::kRestartHealthMonitor, reason);
            auto rec = recovery_->ExecuteRecovery(reason, cc::RecoveryAction::kRestartHealthMonitor);
            const bool success = rec.ok();
            std::string err_msg = success ? std::string{} : rec.error().message;
            recovery_->CompleteFullChannelRecovery(trigger_fault_event_id,
                                                   cc::RecoveryAction::kRestartHealthMonitor,
                                                   success);
            EmitObserveRecoveryCompleted(cc::RecoveryAction::kRestartHealthMonitor, reason, success,
                                         std::move(err_msg));

            {
                std::lock_guard<std::mutex> lk(stats_mutex_);
                if (success) ++total_recoveries_ok_; else ++total_recoveries_fail_;
            }

            if (success) {
                // kRestartHealthMonitor 成功：ResumeMonitoring + 重建 kUntrusted 任务（§18.4.2）
                health_monitor_->ResumeMonitoring();

                // 两阶段重建：先 TrySend，再统一清理无法重建的任务
                // 不能在迭代 pending_ 时 erase，所以收集需要取消的 executor_id
                const uint32_t n = channel_cfg_.n_workers;
                std::vector<uint64_t> to_cancel;
                for (auto& [exec_id, rec] : pending_) {
                    if (rec.state != DispatchState::kUntrusted) continue;
                    bool rebuilt = false;
                    // Affinity-aware rebuild — mirror DrainInputAndSend's
                    // strict-affinity loop. Affined tasks must rebuild to
                    // the same slot or be cancelled; rebuilding to a
                    // different worker would silently violate the slot
                    // identity contract the original Submit promised.
                    const uint32_t affinity = rec.target_proc_id != cc::kAnyProcId
                        ? rec.target_proc_id % n
                        : rec.target_worker_id;
                    const bool has_affinity = (affinity != cc::kAnyWorkerId);
                    const uint32_t loop_count = has_affinity ? 1u : n;
                    for (uint32_t attempt = 0; attempt < loop_count; ++attempt) {
                        const uint32_t wid = has_affinity
                                                 ? affinity
                                                 : (next_worker_rr_ + attempt) % n;
                        if (quarantined_workers_.count(wid)) continue;
                        data::IDataPlane::SubmitInput req;
                        req.worker_id     = wid;
                        req.proc_id       = rec.target_proc_id;
                        req.executor_id   = rec.executor_id;
                        req.dispatch_gen  = generation_.load();
                        req.wait_for_slot = std::chrono::microseconds{0};
                        req.payload_data  = rec.payload.data();
                        req.payload_size  = rec.payload.size();
                        // [v2 Epic 5 PR-5-B] forward wire-flags on re-dispatch
                        req.exec_flags    = rec.exec_flags;
                        if (rec.trace.sampled) {
                            rec.trace.data_plane_call_ts_us = NowUs();
                        }
                        auto outcome = dp_->Submit(req);
                        if (outcome == data::SubmitOutcome::kSent) {
                            const uint64_t sent_ts_us = NowUs();
                            rec.state = DispatchState::kActive;
                            rec.last_dispatch_ts_us = sent_ts_us;
                            rec.submit_ts_us = sent_ts_us;
                            rec.trace.submit_attempt += 1;
                            rec.slot_id = wid;
                            rec.dispatch_gen = generation_.load();
                            if (!has_affinity) {
                                next_worker_rr_ = (wid + 1) % n;
                            }
                            rebuilt = true;
                            break;
                        }
                    }
                    if (!rebuilt) {
                        to_cancel.push_back(exec_id);
                    }
                }
                // 统一取消无法重建的任务
                for (uint64_t exec_id : to_cancel) {
                    EmitAbnormalCompletion(exec_id, cc::AbnormalKind::kCancelled);
                    pending_.erase(exec_id);
                    inflight_count_.fetch_sub(1, std::memory_order_relaxed);
                }
                {
                    std::lock_guard<std::mutex> lk(io_mutex_);
                    for (uint64_t exec_id : to_cancel) {
                        active_executor_ids_.erase(exec_id);
                    }
                }
            } else {
                // kRestartHealthMonitor 失败：中止所有 kUntrusted 任务
                for (auto& [exec_id, rec] : pending_) {
                    if (rec.state == DispatchState::kUntrusted) {
                        EmitAbnormalCompletion(exec_id, cc::AbnormalKind::kCancelled);
                    }
                }
                {
                    std::lock_guard<std::mutex> lk(io_mutex_);
                    for (auto& [exec_id, rec] : pending_) {
                        if (rec.state == DispatchState::kUntrusted) {
                            active_executor_ids_.erase(exec_id);
                        }
                    }
                }
                for (auto it = pending_.begin(); it != pending_.end();) {
                    if (it->second.state == DispatchState::kUntrusted) {
                        inflight_count_.fetch_sub(1, std::memory_order_relaxed);
                        it = pending_.erase(it);
                    } else { ++it; }
                }
                SetLifecycleState(cc::ChannelLifecycleState::kFailed);
                return;  // 不处理剩余事件
            }

            dp_->Resume();
            SetLifecycleState(cc::ChannelLifecycleState::kRunning);
            break;  // health_internal 处理完成，不处理本批次剩余事件（下轮 loop 继续）
        }

        // ─── 非 health_internal 路径（kVmDead / kKernelCrash / kWorkerDead）───
        // 所有 health/internal fault 都走这里立即决策；ownership-unreclaimed
        // 已作为任务级 abnormal 结算，不再进入 fault 分类。
        const cc::FaultKind fk = reason == cc::ChannelFaultReason::kNoOutput
            ? cc::FaultKind::kNoOutput
            : MapCrashKindToFaultKind(event.fragment.kind);
        EmitObserveFaultDetected(fk, reason);

        recovery::FaultContext context;
        context.source_worker_id = event.fragment.source_worker_id;
        context.total_workers = channel_cfg_.n_workers;
        context.unusable_workers = static_cast<uint32_t>(quarantined_workers_.size());
        if (event.fragment.source_worker_id < channel_cfg_.n_workers &&
            quarantined_workers_.count(event.fragment.source_worker_id) == 0) {
            ++context.unusable_workers;
        }
        // [佐证分级] CrashEvent.inferred 直通策略：佐证型(qemu 退 / console panic·KASAN /
        //   heartbeat，inferred=false) → corroborated=true，VM 路径立即 reboot 不受阻尼；
        //   推断型(检测器 A 聚合冻结，inferred=true) → corroborated=false，受 cascade 阻尼。
        context.corroborated = !event.inferred;

        uint64_t trigger_fault_event_id = next_event_id_++;

        // 替换 fault_tracker_.Observe() → recovery_->ObserveFault()
        auto result = recovery_->ObserveFault(
            trigger_fault_event_id,
            reason,
            input.source,
            context);
        if (!result.accepted) {
            continue;
        }

        const bool source_worker_valid = event.fragment.source_worker_id < channel_cfg_.n_workers;
        if (result.recovery_action == cc::RecoveryAction::kRestartSingleWorker &&
            source_worker_valid &&
            result.target_worker_id == event.fragment.source_worker_id) {
            HandleWorkerFault(event.fragment,
                              reason,
                              trigger_fault_event_id,
                              result.target_worker_id,
                              input.origin);
            continue;  // 单 worker 故障已处理，继续看下一个事件
        }
        
        //worker和事件对不上，这里让策略在「没有可信的单 worker 来源」的路径上重新决策
        if (result.recovery_action == cc::RecoveryAction::kRestartSingleWorker) {
            auto full_context = context;
            full_context.source_worker_id = UINT32_MAX;
            trigger_fault_event_id = next_event_id_++;
            result = recovery_->ObserveFault(
                trigger_fault_event_id,
                reason,
                cc::ChannelFaultSource::kChannelInternal,
                full_context);
            if (!result.accepted) {
                continue;
            }
            context = full_context;
        }

        // [v2 Epic 6 PR-6-A §3.10 fix — emit 先于 abort,scene 必须从未清空的 pending_ 捕获]
        // 旧顺序在 kKernelCrash → kRebootVm/kFailChannel → kChannel 范围 abort
        // 时把 pending_ 清空了再调 EmitFaultEvent,导致 fault_event.scene.candidate_window
        // 总是空的(EmitFaultEvent 内部从 pending_ 构建 candidate_window,见
        // EmitFaultEvent 注释 line 740-771)。下游 channeldispatcher::AttachArtifactToEvent
        // 的 Fault 分支(D-7)依赖 candidate_window.back() 反查 inflight artifact —
        // scene 空就拿不到 artifact,fault-induced kernel crash 仍 fail-close。
        // 翻转顺序后 channel 输出事件流变成 [Fault, Abnormal×N](从 [Abnormal×N, Fault]
        // 改),Fault 在前更符合"故障是因、Abnormal 是果"的语义,且 Tn 的 Abnormal 仍
        // 走 Completion 路径取得 artifact(see channeldispatcher.cpp Fault 分支不再 erase
        // inflight artifact,留给后续 Abnormal 取)。
        EmitFaultEvent(reason, event.fragment, input.origin);
        AbortPendingByScope(result.abort_scope, event.fragment.source_worker_id);

        {
            std::lock_guard<std::mutex> lk(stats_mutex_);
            ++total_faults_;
        }

        if (result.recovery_action == cc::RecoveryAction::kNone) {
            continue;
        }

        if (result.recovery_action == cc::RecoveryAction::kFailChannel) {
            // [v2 new-approach — 当前版本]
            // 替换 fault_tracker_.CompleteRecovery() → recovery_->CompleteFullChannelRecovery()
            recovery_->CompleteFullChannelRecovery(
                trigger_fault_event_id,
                cc::RecoveryAction::kFailChannel,
                true);
            SetLifecycleState(cc::ChannelLifecycleState::kFailed);
            return;
        }

        // ② 进入全通道恢复状态
        worker_recovery_queue_.clear();
        worker_recovery_queued_.clear();
        active_worker_recovery_worker_id_ = UINT32_MAX;
        SetLifecycleState(cc::ChannelLifecycleState::kRecovering);

        dp_->Pause();
        DrainTransport();  // drain 残余 inflight

        // [v2 new-approach — 当前版本]
        health_monitor_->SuspendMonitoring();

        // ③ 级联恢复循环（§20）
        cc::RecoveryAction action = result.recovery_action;
        // [bug fix — target_worker_id UINT32_MAX crash]
        //   while 循环里 follow.recovery_action 可能是 kRestartSingleWorker（当
        //   context.source_worker_id 合法 + history.source_worker_failed_recovery_count<max 时
        //   policy 会"降级"回单 worker）。之前只保存 action 丢弃 target_worker_id → 下一轮
        //   ExecuteRecovery 用默认 UINT32_MAX → StopSingleWorker(UINT32_MAX) 立即 out-of-range。
        //   保存并按轮传递 target_worker_id 修复此路径。
        uint32_t target_worker_id = result.target_worker_id;
        bool success = false;
        bool did_reboot = false;  // [T3-A/T3-B] 本轮恢复是否真做了 VM reboot（决定是否重开 console / 重标 worker）
        uint64_t active_trigger_fault_event_id = trigger_fault_event_id;

        while (action != cc::RecoveryAction::kNone && action != cc::RecoveryAction::kFailChannel) {

            if (action == cc::RecoveryAction::kRebootVm) {
                DrainHealthyInflightBeforeReboot(static_cast<uint32_t>(channel_cfg_.pre_reboot_drain.count()));
            }

            EmitObserveRecoveryStarted(action, reason);

            // [v2 new-approach — 当前版本]
            // 替换 recovery_->Execute() → recovery_->ExecuteRecovery()
            auto rec = recovery_->ExecuteRecovery(reason, action, target_worker_id);
            success = rec.ok();
            std::string err_msg = success ? std::string{} : rec.error().message;

            // [v2 new-approach — 当前版本]
            // 替换 fault_tracker_.CompleteRecovery() → recovery_->CompleteFullChannelRecovery()
            recovery_->CompleteFullChannelRecovery(
                active_trigger_fault_event_id,
                action,
                success);
            EmitObserveRecoveryCompleted(action, reason, success, std::move(err_msg));

            {
                std::lock_guard<std::mutex> lk(stats_mutex_);
                if (success) ++total_recoveries_ok_;
                else         ++total_recoveries_fail_;
            }

            if (success) {
                // kRebootVm 成功时 VM 身份变化 → 递增 vm_epoch_（§18.5.3）
                if (action == cc::RecoveryAction::kRebootVm) {
                    ++vm_epoch_;
                    did_reboot = true;
                    // [crash-execution-history-ring] fresh kernel after reboot —
                    // pre-reboot programs can't have caused a future crash.
                    recent_programs_.Reset();
                }
                {
                    // [crash-terminal] TASK_READY (submitted, never ran) → innocent
                    // → kCancelled (re-run); TASK_TAKEN (was executing) → crash-
                    // suspect → kWorkerCrashed (terminal, dropped in verify).
                    const auto& idle_ids = rec.value().inflight_idle_executor_ids;
                    for (auto executor_id : rec.value().inflight_executor_ids) {
                        const bool idle = std::find(idle_ids.begin(), idle_ids.end(),
                                                    executor_id) != idle_ids.end();
                        EmitAbnormalCompletionAndSettleIfPending(
                            executor_id,
                            idle ? cc::AbnormalKind::kCancelled
                                 : cc::AbnormalKind::kWorkerCrashed);
                    }
                }
                break;
            }

            // 恢复失败 → 请求升级动作
            if (context.source_worker_id < channel_cfg_.n_workers &&
                quarantined_workers_.count(context.source_worker_id) == 0) {
                context.unusable_workers =
                    static_cast<uint32_t>(quarantined_workers_.size() + 1);
            } else {
                context.unusable_workers =
                    static_cast<uint32_t>(quarantined_workers_.size());
            }

            const uint64_t next_trigger_fault_event_id = next_event_id_++;
            // [v2 new-approach — 当前版本]
            // 替换 fault_tracker_.Observe() → recovery_->ObserveFault()
            const auto follow = recovery_->ObserveFault(
                next_trigger_fault_event_id,
                reason,
                cc::ChannelFaultSource::kChannelInternal,
                context);
            if (!follow.accepted) break;
            action = follow.recovery_action;
            target_worker_id = follow.target_worker_id;  // [bug fix] 跟随 action 一起保存
            active_trigger_fault_event_id = next_trigger_fault_event_id;
        }

        // ④ 恢复结果
        if (action == cc::RecoveryAction::kFailChannel) {
            recovery_->CompleteFullChannelRecovery(
                active_trigger_fault_event_id,
                cc::RecoveryAction::kFailChannel,
                true);
            SetLifecycleState(cc::ChannelLifecycleState::kFailed);
            return;
        }

        if (success) {
            // [console-drain-before-workers] did_reboot：console 重开到新 qemu serial + HealthMonitor
            //   .Reboot()=Stop()+Start() 已在 RecoveryExe::ExecuteRebootInstance 里、worker 注册序列之前
            //   完成（否则 worker 0 冷启动的 console 洪峰无人 drain → guest 8250 写路径死等 THRE → 耗尽
            //   vCPU → WaitAllWorkersReady 卡 GUEST_REG_CLAIMED 超时；旧序把重开+重启放在这里、worker 已
            //   启动完，正好晚一步）。走到这里 monitor 已是全新运行态：parked_count_ 清零（清 ghost）、
            //   worker_alive_bits_ 全活、新基线、新 ConsoleSensor 接管新 serial——无需再 Close/Open 或
            //   Reboot，仅收尾 quarantine 状态即可。
            if (did_reboot) {
                quarantined_workers_.clear();
            } else {
                // [Brick 4a step 3b] kReloadSnapshot：同一 qemu 回滚快照，serial 不死、sensor 线程
                //   存活——只需重标活 + 重置基线，再 ResumeMonitoring 让同一批 sensor 续跑。
                if (action == cc::RecoveryAction::kReloadSnapshot) {
                    quarantined_workers_.clear();
                    for (uint32_t w = 0; w < channel_cfg_.n_workers && health_monitor_; ++w) {
                        health_monitor_->SetWorkerAlive(w, true);
                        health_monitor_->RearmSingleWorker(w);
                    }
                }
                if (health_monitor_) health_monitor_->ResumeMonitoring();
            }
            // [聚合前进时钟] 全通道恢复（可能含 reboot，墙钟过了数十秒~分钟）后重置
            //   时钟基线：停采期间没有 Note()，不重置会让检测器 A 把这段恢复墙钟算进
            //   "聚合冻结时长"，恢复后立刻误判 VM 死。policy 的 in_recovery_window 也会
            //   兜住，但重置能免掉那段事件churn。
            if (progress_clock_) progress_clock_->Reset();
            dp_->Resume();
            const uint32_t old_gen = generation_.load();
            generation_.fetch_add(1);
            const uint32_t new_gen = generation_.load();
            EmitObserveGenerationReset(old_gen, new_gen);

            SetLifecycleState(cc::ChannelLifecycleState::kRunning);
        }

        // [v2 stuck-recovery safeguard — 当前版本]
        // while(action!=kNone && action!=kFailChannel) 可经两条非 kFailChannel 路径
        // 退出而 success=false:
        //   (1) ObserveFault.accepted=false —— tracker 在 window 内拒绝或 TryBeginRecovery 失败
        //   (2) follow.recovery_action=kNone —— policy 主动收敛/放弃升级
        // 旧注释假设 "Recovery 内部保证最终升级"，但上述两条路径都让 Recovery 停止升级，
        // 导致 dp/hm 保持 Pause/Suspend，channel 永留 kRecovering，dispatcher 每秒 1 次
        // submit_rejected 空转（run-20260421T143941Z-251208 实测 33s 无产出）。
        // 兜底升级为 kFailed，对外语义等同 kFailChannel 终态。
        else {
            SetLifecycleState(cc::ChannelLifecycleState::kFailed);
            return;
        }

        break;  // 处理完一次全通道恢复事件，退出事件循环（下轮 loop 继续）
    }
}

// ============================================================
// HandleWorkerFault — 单 worker 故障处理，进入 kDegraded（§20 v2）
// ============================================================

void Channel::HandleWorkerFault(
    const health::CrashFragment& fragment,
    cc::ChannelFaultReason reason,
    uint64_t trigger_fault_event_id,
    uint32_t worker_id,
    cc::FaultOrigin origin)
{
    
    // [v2 Epic 6 PR-6-A §3.10 fix — emit 先于 abort,scene 含未清空的 pending_]
    // 同 HandleFault line 1032 注释:翻转顺序让 candidate_window 含 worker slot 上
    // 的 inflight 任务。kSlot 范围只清该 worker 的任务,跨 worker 的其它 inflight
    // 也仍在 candidate_window 中(EmitFaultEvent 从全 pending_ 构建)— 这点跟旧
    // 行为一致,只是确保了**当前 worker** 的 task 也包含进 scene。
    EmitFaultEvent(reason, fragment, origin);
    AbortPendingByScope(cc::ChannelAbortScope::kSlot, worker_id);

    {
        std::lock_guard<std::mutex> lk(stats_mutex_);
        ++total_faults_;
    }

    // 2. 撤销该 worker 注册，阻止 Transport 继续向其发送请求
    if (cp_) cp_->RevokeWorker(worker_id);

    // 3. 将 worker 加入隔离集（loop_thread_ 独占写读，无需加锁）
    quarantined_workers_.insert(worker_id);

    // 4. 更新 health 侧 worker 存活状态，防止重复触发故障
    if (health_monitor_) health_monitor_->SetWorkerAlive(worker_id, false);

    // 5. 状态降级（仅从 kRunning → kDegraded；其他状态不干预）
    if (phase_.load() == cc::ChannelLifecycleState::kRunning) {
        SetLifecycleState(cc::ChannelLifecycleState::kDegraded);
    }

    // 6. 入队并尝试启动恢复；若已有恢复在进行则等待轮到该 worker
    EnqueueWorkerRecovery(worker_id, reason, trigger_fault_event_id);
    TryStartNextWorkerRecovery();
}
//去重入队（同一 worker 不重复排队、已在恢复中的不入队）
void Channel::EnqueueWorkerRecovery(uint32_t worker_id,
                                        cc::ChannelFaultReason reason,
                                        uint64_t trigger_fault_event_id)
{
    if (worker_id >= channel_cfg_.n_workers) {
        return;
    }
    if (worker_id == active_worker_recovery_worker_id_) {
        return;
    }
    if (worker_recovery_queued_.count(worker_id) != 0) {
        return;
    }

    worker_recovery_queue_.push_back(PendingWorkerRecovery{
        .worker_id = worker_id,
        .reason = reason,
        .trigger_fault_event_id = trigger_fault_event_id,
    });
    worker_recovery_queued_.insert(worker_id);
}
//检查"当前有没有恢复在跑"，有则不启动
bool Channel::TryStartNextWorkerRecovery()
{
    if (worker_recovery_pending_.load()) {
        return false;
    }

    while (!worker_recovery_queue_.empty()) {
        const auto pending = worker_recovery_queue_.front();
        worker_recovery_queue_.pop_front();
        worker_recovery_queued_.erase(pending.worker_id);

        if (pending.worker_id >= channel_cfg_.n_workers) {
            continue;
        }
        if (quarantined_workers_.count(pending.worker_id) == 0) {
            continue;
        }

        EmitObserveRecoveryStarted(cc::RecoveryAction::kRestartSingleWorker, pending.reason);
        worker_recovery_pending_.store(true);
        active_worker_recovery_worker_id_ = pending.worker_id;
        if (recovery_thread_.joinable()) recovery_thread_.join();
        recovery_thread_ = std::thread(
            [this, pending] {
                AsyncRecoverWorker(
                    pending.worker_id,
                    pending.reason,
                    pending.trigger_fault_event_id);
            });
        return true;
    }
    return false;
}

void Channel::MaybeRestoreRunningFromDegraded()
{
    if (phase_.load() != cc::ChannelLifecycleState::kDegraded) {
        return;
    }
    if (worker_recovery_pending_.load()) {
        return;
    }
    if (!worker_recovery_queue_.empty()) {
        return;
    }
    if (!quarantined_workers_.empty()) {
        return;
    }
    SetLifecycleState(cc::ChannelLifecycleState::kRunning);
}

// ============================================================
// AsyncRecoverWorker — 后台线程执行单 worker 恢复序列
// ============================================================
// 注意：此方法运行在 recovery_thread_ 上，不可访问 loop_thread_ 独占状态
// （如 next_event_id_、quarantined_workers_ 等）。仅通过 recovery_signal_ 通知 loop_thread_。
//实际执行恢复（SSH 操作，耗时数秒），跑完后设 signal 唤醒 loop_thread_ 
void Channel::AsyncRecoverWorker(uint32_t worker_id,
                                     cc::ChannelFaultReason reason,
                                     uint64_t trigger_fault_event_id)
{

    // 仅执行实际恢复操作（SSH 相关，可能耗时数秒）
    // 不访问任何 loop_thread_ 独占状态
    // 替换 recovery_->Execute() → recovery_->ExecuteRecovery()
    auto rec = recovery_->ExecuteRecovery(reason, cc::RecoveryAction::kRestartSingleWorker, worker_id);
    bool success = rec.ok();
    std::string err_msg = success ? std::string{} : rec.error().message;
    // [当前版本 ssh-dead-escalation] 失败时把 ErrorKind 带回 loop_thread_：
    // 后者识别 kTimeout/kConnection 时按 VM 已死处理，直接 ObserveFault(kVmDead)
    // 升级到 kRebootVm，跳过剩余的 SSH-bound RestartSingleWorker 尝试。
    ErrorKind error_kind = success ? ErrorKind::kRecovery : rec.error().kind;

    // [single-worker inflight leak] StopWorker already destroyed this worker's slot,
    // so its in-flight tasks can never complete on their own. Hand them to
    // loop_thread_ (the only thread allowed to EmitAbnormalCompletion) so they reach
    // a terminal event instead of being silently dropped. Taken even when recovery
    // FAILED: the slot is gone either way, and a failed restart escalates to reboot,
    // whose own bulk path would emit for a snapshot taken later -- after these ids
    // have already left the data plane.
    std::vector<uint64_t> target_inflight_ids;
    std::vector<uint64_t> target_inflight_idle_ids;
    if (rec.ok()) {
        target_inflight_ids      = std::move(rec.value().target_worker_inflight_executor_ids);
        target_inflight_idle_ids = std::move(rec.value().target_worker_inflight_idle_executor_ids);
    }

    {
        std::lock_guard<std::mutex> lk(stats_mutex_);
        if (success) ++total_recoveries_ok_;
        else         ++total_recoveries_fail_;
    }

    // 设置恢复完成信号，唤醒 loop_thread_ 处理结果
    {
        std::lock_guard<std::mutex> lock(recovery_signal_mutex_);
        recovery_signal_ = RecoverySignal{
            worker_id,
            success,
            reason,
            trigger_fault_event_id,
            std::move(err_msg),
            error_kind,
            std::move(target_inflight_ids),
            std::move(target_inflight_idle_ids),
        };
    }
    // 先清除 pending 标记，再 notify，防止 loop_thread_ 发现 pending=true 后二次启动
    worker_recovery_pending_.store(false);
    WakeLoopPoller();
}

// ============================================================
// CheckWorkerRecoveryComplete — loop_thread_ 检查单 worker 恢复完成信号
// ============================================================
// 每轮 LoopMain 调用，负责在 loop_thread_ 上完成 fault_tracker 更新、
// observe 事件发布，以及恢复成功/失败后的状态迁移。

void Channel::CheckWorkerRecoveryComplete()
{
    RecoverySignal signal;
    {
        std::lock_guard<std::mutex> lock(recovery_signal_mutex_);
        if (!recovery_signal_.has_value()) return;
        signal = *recovery_signal_;
        recovery_signal_.reset();
    }

    const uint32_t worker_id = signal.worker_id;
    const bool success = signal.success;
    auto reason = signal.reason;
    uint64_t trigger_fault_event_id = signal.trigger_fault_event_id;
    active_worker_recovery_worker_id_ = UINT32_MAX;

    // [v2 new-approach — 当前版本]
    // 替换 fault_tracker_.NoteSingleWorkerRecoveryComplete() → recovery_->CompleteSingleWorkerRecovery()
    recovery_->CompleteSingleWorkerRecovery(worker_id, success);
    EmitObserveRecoveryCompleted(cc::RecoveryAction::kRestartSingleWorker, reason, success,
                                 std::move(signal.error_message));

    // [single-worker inflight leak] Terminate the restarted worker's own in-flight
    // tasks. Same running/idle split as the bulk recovery path: idle (TASK_READY,
    // never picked up) is innocent → kCancelled (re-run); running (TASK_TAKEN) is a
    // crash suspect → kWorkerCrashed (terminal). Only this worker's ids are here --
    // the whole-channel snapshot must NOT be emitted (§13.10 row 8), which is why
    // recovery returns the two sets separately.
    if (!signal.target_inflight_ids.empty()) {
        const auto& idle_ids = signal.target_inflight_idle_ids;
        for (auto eid : signal.target_inflight_ids) {
            const bool idle =
                std::find(idle_ids.begin(), idle_ids.end(), eid) != idle_ids.end();
            EmitAbnormalCompletionAndSettleIfPending(
                eid, idle ? cc::AbnormalKind::kCancelled
                          : cc::AbnormalKind::kWorkerCrashed);
        }
        refuzz::logging::HostLineBuilder("Channel", "single_worker_inflight_terminated")
            << "worker=" << worker_id
            << " terminated=" << signal.target_inflight_ids.size()
            << " idle=" << idle_ids.size() << "\n";
    }

    if (success) {
        // [diag] Rearm 前打一条时间戳，给 "recovery 完成 → sensor 判死" diff 提供锚点
        refuzz::logging::HostLogger::Instance().Log(
            "Channel",
            "single_worker_recovery_success",
            {refuzz::logging::Field("channel_id", channel_cfg_.channel_id),
             refuzz::logging::Field("worker_id", worker_id),
             refuzz::logging::Field("trigger_fault_event_id", trigger_fault_event_id),
             refuzz::logging::Field("ts_us", NowUs())});

        // 恢复成功：取消隔离，更新 health 侧 worker 存活状态
        quarantined_workers_.erase(worker_id);

        if (health_monitor_) {
            health_monitor_->SetWorkerAlive(worker_id, true);
            // [bug fix] HeartbeatSensor 在发 worker_dead 事件时会把该 worker
            //   observed=false 防重复上报。过去只有 Reboot() 全量重建 sensor 才
            //   能恢复,单 worker recovery 路径缺这一环 → 同 channel 第二次 worker
            //   卡死不再触发 heartbeat_lost → recovery,"阈值才 boot channel"
            //   的多 worker 容错策略前提被打破,channel 挂死。
            //   这里显式 rearm,让 sensor 以新 worker 的 heartbeat 计数重建基线。
            health_monitor_->RearmSingleWorker(worker_id);
        }

        // 成功恢复后 bump generation，通知上层 inflight 任务已过时
        const uint32_t old_gen = generation_.load();
        generation_.fetch_add(1);
        const uint32_t new_gen = generation_.load();
        EmitObserveGenerationReset(old_gen, new_gen);

        TryStartNextWorkerRecovery();
        MaybeRestoreRunningFromDegraded();
        return;
    }

    recovery::FaultContext context;
    context.source_worker_id = worker_id;
    context.total_workers = channel_cfg_.n_workers;
    context.unusable_workers = static_cast<uint32_t>(quarantined_workers_.size());
    if (worker_id < channel_cfg_.n_workers &&
        quarantined_workers_.count(worker_id) == 0) {
        ++context.unusable_workers;
    }

    // [ssh-dead 升级为 *推断型* kVmDead,不再当佐证] SSH timeout/connection 失败
    //   **不是** VM 死亡的证据 —— 在 CPU 争抢(mount-heavy + 2vCPU)下,过载但活着的
    //   guest 一样会让 SSH 超时。曾把它当 corroborated=true → 绕过 cascade/ceiling →
    //   无限 reboot 风暴(实测 4516 次)。现在:single-worker SSH 杀不掉 → 升级 kVmDead
    //   但走 **inferred(corroborated=false)** 路径,受 recovery-window + cascade budget
    //   治理(预算耗尽→kFailChannel,见 fault_policy RebootOrDamp),绝不无限重启。
    //   VM 真死的判定交给:qemu 进程退出(is_alive)/ console crash / 聚合进度冻结 5min。
    // 注意：reason 变量仍用原始 kWorkerHeartbeatLost 给后续 Emit* 事件,保留
    // "故障来源 = worker 心跳丢失" 的语义；只有 ObserveFault 走 follow_reason。
    cc::ChannelFaultReason follow_reason = reason;
    const bool ssh_dead =
        (signal.error_kind == ErrorKind::kTimeout ||
         signal.error_kind == ErrorKind::kConnection);
    if (ssh_dead) {
        follow_reason = cc::ChannelFaultReason::kVmDead;
        // kVmDead 路径不绑定单 worker；置 INVALID 让 policy 沿全 channel 分支走。
        context.source_worker_id = UINT32_MAX;
        // 推断型:不绕过阻尼,受 cascade budget 封顶。
        context.corroborated = false;
    }

    trigger_fault_event_id = next_event_id_++;
    // 替换 fault_tracker_.Observe() → recovery_->ObserveFault()
    auto follow = recovery_->ObserveFault(
        trigger_fault_event_id,
        follow_reason,
        cc::ChannelFaultSource::kChannelInternal,
        context);
    if (!follow.accepted) {
        TryStartNextWorkerRecovery();
        MaybeRestoreRunningFromDegraded();
        return;
    }

    if (follow.recovery_action == cc::RecoveryAction::kNone) {
        TryStartNextWorkerRecovery();
        MaybeRestoreRunningFromDegraded();
        return;
    }

    if (follow.recovery_action == cc::RecoveryAction::kRestartSingleWorker &&
        follow.target_worker_id < channel_cfg_.n_workers) {
        const uint32_t retry_worker_id = follow.target_worker_id;

        if (cp_) cp_->RevokeWorker(retry_worker_id);
        quarantined_workers_.insert(retry_worker_id);

        if (health_monitor_) health_monitor_->SetWorkerAlive(retry_worker_id, false);

        EnqueueWorkerRecovery(retry_worker_id, reason, trigger_fault_event_id);
        TryStartNextWorkerRecovery();
        MaybeRestoreRunningFromDegraded();
        return;
    }

    if (follow.recovery_action == cc::RecoveryAction::kFailChannel) {

        // 替换 fault_tracker_.CompleteRecovery() → recovery_->CompleteFullChannelRecovery()
        recovery_->CompleteFullChannelRecovery(
            trigger_fault_event_id,
            cc::RecoveryAction::kFailChannel,
            true);
        SetLifecycleState(cc::ChannelLifecycleState::kFailed);
        return;
    }

    worker_recovery_queue_.clear();
    worker_recovery_queued_.clear();
    SetLifecycleState(cc::ChannelLifecycleState::kRecovering);
    dp_->Pause();
    DrainTransport();


    if (health_monitor_) health_monitor_->SuspendMonitoring();

    cc::RecoveryAction action = follow.recovery_action;
    // [bug fix — 同 line ~944 的 target_worker_id 传递修复]
    uint32_t target_worker_id = follow.target_worker_id;
    bool rec_success = false;
    bool did_reboot  = false;  // [fix vm-reboot-resume-deadlock] 本轮是否真做了 VM reboot
    // [当前版本 ssh-dead-escalation] loop_reason 从 prelude 的 follow_reason
    // 继承：若 async 阶段已经诊断为 SSH 不可达 → 已经是 kVmDead。
    // 进入 while 后每次 ExecuteRecovery 失败若仍是 kTimeout/kConnection，钉住
    // kVmDead 防止 policy 在 runtime_restart_count budget 未用完时回到
    // kRestartAllWorkers（同样要走 SSH，注定再 timeout 一遍）。
    cc::ChannelFaultReason loop_reason = follow_reason;
    if (loop_reason == cc::ChannelFaultReason::kVmDead) {
        // 进入 while 时 source 已经在 prelude 置 INVALID，这里再确认一次。
        context.source_worker_id = UINT32_MAX;
    }

    while (action != cc::RecoveryAction::kNone &&
           action != cc::RecoveryAction::kFailChannel) {
        if (action == cc::RecoveryAction::kRebootVm) {
            DrainHealthyInflightBeforeReboot(static_cast<uint32_t>(channel_cfg_.pre_reboot_drain.count()));
        }

        EmitObserveRecoveryStarted(action, reason);
        // 替换 recovery_->Execute() → recovery_->ExecuteRecovery()
        auto rec = recovery_->ExecuteRecovery(reason, action, target_worker_id);
        rec_success = rec.ok();
        std::string err_msg = rec_success ? std::string{} : rec.error().message;
        // [当前版本 ssh-dead-escalation] 在 message 移走前抓 ErrorKind，
        // 给下一轮 ObserveFault 用。
        const ErrorKind rec_error_kind =
            rec_success ? ErrorKind::kRecovery : rec.error().kind;
        // 替换 fault_tracker_.CompleteRecovery() → recovery_->CompleteFullChannelRecovery()
        recovery_->CompleteFullChannelRecovery(trigger_fault_event_id, action, rec_success);
        EmitObserveRecoveryCompleted(action, reason, rec_success, std::move(err_msg));

        {
            std::lock_guard<std::mutex> lk(stats_mutex_);
            if (rec_success) ++total_recoveries_ok_;
            else             ++total_recoveries_fail_;
        }

        if (rec_success) {
            if (action == cc::RecoveryAction::kRebootVm) {
                ++vm_epoch_;
                did_reboot = true;
                // [crash-execution-history-ring] fresh kernel after reboot.
                recent_programs_.Reset();
            }
            {
                // [crash-terminal] see split rationale above: idle (TASK_READY) →
                // kCancelled (re-run); running (TASK_TAKEN) → kWorkerCrashed.
                const auto& idle_ids = rec.value().inflight_idle_executor_ids;
                for (auto eid : rec.value().inflight_executor_ids) {
                    const bool idle = std::find(idle_ids.begin(), idle_ids.end(),
                                                eid) != idle_ids.end();
                    EmitAbnormalCompletionAndSettleIfPending(
                        eid, idle ? cc::AbnormalKind::kCancelled
                                  : cc::AbnormalKind::kWorkerCrashed);
                }
            }
            break;
        }

        // [当前版本 ssh-dead-escalation] SSH 仍然不可达 → 钉死 kVmDead。
        if (rec_error_kind == ErrorKind::kTimeout ||
            rec_error_kind == ErrorKind::kConnection) {
            loop_reason = cc::ChannelFaultReason::kVmDead;
            context.source_worker_id = UINT32_MAX;
        }

        if (context.source_worker_id < channel_cfg_.n_workers &&
            quarantined_workers_.count(context.source_worker_id) == 0) {
            context.unusable_workers =
                static_cast<uint32_t>(quarantined_workers_.size() + 1);
        } else {
            context.unusable_workers =
                static_cast<uint32_t>(quarantined_workers_.size());
        }

        trigger_fault_event_id = next_event_id_++;
        // 替换 fault_tracker_.Observe() → recovery_->ObserveFault()
        const auto next = recovery_->ObserveFault(
            trigger_fault_event_id,
            loop_reason,
            cc::ChannelFaultSource::kChannelInternal,
            context);
        if (!next.accepted) {
            break;
        }
        action = next.recovery_action;
        target_worker_id = next.target_worker_id;  // [bug fix] 跟随 action 一起保存
    }

    if (action == cc::RecoveryAction::kFailChannel) {
        // 替换 fault_tracker_.CompleteRecovery() → recovery_->CompleteFullChannelRecovery()
        recovery_->CompleteFullChannelRecovery(
            trigger_fault_event_id,
            cc::RecoveryAction::kFailChannel,
            true);
        SetLifecycleState(cc::ChannelLifecycleState::kFailed);
        return;
    }

    if (rec_success) {
        quarantined_workers_.clear();
        worker_recovery_queue_.clear();
        worker_recovery_queued_.clear();
        active_worker_recovery_worker_id_ = UINT32_MAX;

        // [console-drain-before-workers] 与主恢复路径对称：本 worker 升级路径同样可升到 kRebootVm。
        //   did_reboot 时 console 重开到新 qemu serial + HealthMonitor.Reboot()=Stop()+Start() 已在
        //   RecoveryExe::ExecuteRebootInstance 里、worker 注册序列之前完成（否则 worker 0 冷启动 console
        //   洪峰无人 drain → GUEST_REG_CLAIMED 握手超时；旧序放在这里正好晚一步）。走到这里 monitor 已全新
        //   运行态（清 ghost parked_count_ + worker_alive_bits_ 全活 + 新 ConsoleSensor 接管新 serial），
        //   无需再重开/Reboot。非 reboot 分支 monitor 仍 suspended，需 Resume 让同一批 sensor 续跑。
        if (!did_reboot) {
            if (health_monitor_) health_monitor_->ResumeMonitoring();
        }
        // [聚合前进时钟] 同上：全通道恢复（可能含 reboot）后重置时钟基线。
        if (progress_clock_) progress_clock_->Reset();
        dp_->Resume();

        const uint32_t old_gen = generation_.load();
        generation_.fetch_add(1);
        EmitObserveGenerationReset(old_gen, generation_.load());

        SetLifecycleState(cc::ChannelLifecycleState::kRunning);
    }
    // [v2 stuck-recovery safeguard — 当前版本]
    // 同 HandleFault 变体:while(action!=kNone && action!=kFailChannel) 可能以
    // !next.accepted 或 action=kNone 退出;若未 rec_success,channel 停留 kRecovering,
    // dp/hm 保持 Pause/Suspend,dispatcher 每秒 1 次 submit_rejected 空转。
    // 兜底升级为 kFailed(函数尾部无需 return)。
    else {
        SetLifecycleState(cc::ChannelLifecycleState::kFailed);
    }
}

void Channel::DrainHealthyInflightBeforeReboot(uint32_t budget_ms)
{
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(budget_ms);

    auto has_healthy_inflight = [this]() -> bool {
        for (const auto& [executor_id, record] : pending_) {
            (void)executor_id;
            if (quarantined_workers_.count(record.slot_id) == 0) {
                return true;
            }
        }
        return false;
    };

    while (has_healthy_inflight()) {
        DrainTransport();
        if (std::chrono::steady_clock::now() >= deadline) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

}

// ============================================================
// MaybeNoteHealthy — 节流调用 recovery_->NoteHealthy()（§18.3.3）
// ============================================================
// 按 health_check_interval 节流，累积 consecutive_healthy 计数，
// 达到阈值后 Recovery 内部 FaultTracker 自动重置故障窗口计数器。

void Channel::MaybeNoteHealthy()
{
    const uint64_t now = NowUs();
    const uint64_t interval_us =
        static_cast<uint64_t>(channel_cfg_.health_check_interval.count()) * 1000;
    if (now - health_check_last_us_ < interval_us) return;
    health_check_last_us_ = now;


    if (recovery_) recovery_->NoteHealthy();
}

// ============================================================
// Submit — 提交请求到 input_queue_（§14）
// ============================================================

// [v3 nonblocking-submit — 当前版本]
// Submit 非阻塞：入队后立即返回 kAccepted，loop_thread_ 异步处理 TrySend。
// TrySend 失败（deadline 到期或 channel 不可用）→ 通过 DrainEvents 发出 cc::AbnormalCompletion(kCancelled)。
// 设计来源：design.md §12.3 "Submit() 为阻塞接口 → 补充异步语义"
//
// [submit path heap churn 减少 2026-05-22] const& overload 转发到 rvalue
// overload, 复制一次 caller's request 到 local temp 然后 std::move 进 slot.
// 等价旧 "slot->request = request" deep copy 行为, 但 hot replayer 路径用
// rvalue overload 直接 std::move 跳过这一次 copy.
cc::ChannelSubmitResult Channel::Submit(const cc::ChannelDispatchRequest& request,
                                         std::chrono::microseconds wait_for_slot)
{
    return Submit(cc::ChannelDispatchRequest(request), wait_for_slot);
}

cc::ChannelSubmitResult Channel::Submit(cc::ChannelDispatchRequest&& request,
                                         std::chrono::microseconds wait_for_slot)
{
    // 前置校验（executor_id=0 非法；payload 超限）
    if (request.executor_id == 0) {
        return cc::ChannelSubmitResult{cc::ChannelSubmitStatus::kInvalid, 0};
    }
    // Payload upper bound source priority:
    //   1. channel_cfg_.max_payload_size (set by Assembler — required for any
    //      backend that uses shm_ == nullptr, e.g. XiUOS UART)
    //   2. shm_->MaxInput() fallback for ivshmem backends that haven't yet
    //      been migrated to populate max_payload_size
    //   3. 0 (fail-closed: every non-empty payload rejected). Prevents the
    //      shm_ nullptr deref that bit XiUOS before this fix.
    const std::size_t max_payload =
        channel_cfg_.max_payload_size != 0
            ? channel_cfg_.max_payload_size
            : (shm_ ? static_cast<std::size_t>(shm_->MaxInput()) : std::size_t{0});
    if (request.payload.size() > max_payload) {
        return cc::ChannelSubmitResult{cc::ChannelSubmitStatus::kInvalid, 0};
    }
    // Strict worker-slot affinity bound check. kAnyWorkerId = no affinity →
    // existing round-robin. Specific value must be a valid slot index;
    // out-of-range is a caller bug, reject up front so the request never
    // enters the queue under an impossible target (would otherwise stick
    // forever in deferred since no worker matches).
    if (request.target_worker_id != cc::kAnyWorkerId &&
        request.target_worker_id >= channel_cfg_.n_workers) {
        return cc::ChannelSubmitResult{cc::ChannelSubmitStatus::kInvalid, 0};
    }
    if (request.target_proc_id != cc::kAnyProcId) {
        if (request.target_proc_id >= cc::kMaxProcIds ||
            channel_cfg_.n_workers == 0) {
            return cc::ChannelSubmitResult{cc::ChannelSubmitStatus::kInvalid, 0};
        }
        const uint32_t owner = request.target_proc_id % channel_cfg_.n_workers;
        if (request.target_worker_id != cc::kAnyWorkerId &&
            request.target_worker_id != owner) {
            return cc::ChannelSubmitResult{cc::ChannelSubmitStatus::kInvalid, 0};
        }
    }

    // 1. 相位门禁：仅在运行或降级状态下接受提交
    auto current_phase = phase_.load();
    if (current_phase != cc::ChannelLifecycleState::kRunning &&
        current_phase != cc::ChannelLifecycleState::kDegraded) {
        return cc::ChannelSubmitResult{cc::ChannelSubmitStatus::kUnavailable, 0};
    }

    // 2. 构造 SubmitSlot（无 promise，仅含 request + deadline）
    // [Phase H] 语义变更:deferred 层已改为无限重试,deadline 字段保留但不被读取。
    //   保留字段是为了 ABI 稳定 + 便于将来需要时再启用 slot 级 deadline。
    //   当前 wait_for_slot 参数来自 executor,executor 已统一传 0。
    // [当前版本 defer-move] 先分配空 slot（锁外），request 只在 accept 提交点
    //   （容量 + 重复 ID 检查都通过后）才 std::move 进 slot。这样所有 reject 路径
    //   (kBusy/kInvalid/kUnavailable/相位门禁) 都**不**消费 caller 的 request，
    //   调用方（executor dispatcher / replayer）可原样重试同一 request，省去
    //   reject 前的一次 payload deep-copy / 重填。
    //   旧版在容量检查前就 move，导致 kBusy 时 request 被掏空 → caller 必须先
    //   deep-copy（const overload）或手动重填 payload 才能重试。
    auto slot = std::make_unique<SubmitSlot>();
    slot->deadline = std::chrono::steady_clock::now() + wait_for_slot;

    // 3. 容量检查、重复 ID 检查并入队
    // [migrated] input_queue_full_enter event → channel.input_queue.full_episodes counter
    //            busy_rejects_total field    → channel.input_queue.busy_rejects counter
    //            (见 020_naming_catalog §4.6;消费者派生 full_pct / rejects_per_episode)
    const uint32_t cur_gen = generation_.load();
    {
        std::lock_guard<std::mutex> lock(io_mutex_);
        // 总容量 = input_queue_ + deferred_submissions_
        const uint32_t cap = channel_cfg_.input_queue_capacity;
        const size_t cur = input_queue_.size()
                         + deferred_count_.load(std::memory_order_relaxed);
        if (cur >= cap) {
            ++input_full_busy_rejects_;  // 内部累计 (debug / 兜底), counter 是平行管道
            if (metrics_ != nullptr && metrics_->input_queue_busy_rejects != nullptr) {
                metrics_->input_queue_busy_rejects->Inc();
            }
            if (!input_full_) {
                input_full_          = true;
                input_full_enter_us_ = NowUs();
                if (metrics_ != nullptr && metrics_->input_queue_full_episodes != nullptr) {
                    metrics_->input_queue_full_episodes->Inc();
                }
            }
            return cc::ChannelSubmitResult{cc::ChannelSubmitStatus::kBusy, cur_gen};
        }
        // 防重复：同一 executor_id 在 input/deferred/pending 任一阶段已存在时拒绝。
        //   request 尚未 move，直接读 request.executor_id（scalar）。
        if (active_executor_ids_.count(request.executor_id)) {
            return cc::ChannelSubmitResult{cc::ChannelSubmitStatus::kInvalid, 0};
        }
        // accept 提交点：此处才取得 request 所有权（reject 路径绝不到这里）。
        slot->request = std::move(request);
        active_executor_ids_.insert(slot->request.executor_id);
        input_queue_.push(std::move(slot));
        PublishInputQueueDepthLocked();
    }

    // 4. 通知 loop_thread_，触发 DrainInputAndSend 异步处理
    input_pending_.store(true, std::memory_order_release);
    WakeLoopPoller();

    // 5. 非阻塞返回：kAccepted 表示"已入队，将异步尝试发送"
    // [Phase H] 一旦 kAccepted,Channel 就对这个 slot 负责到底:
    //   - 送达 worker → 走 completion 路径
    //   - 非服务相位/reboot → EmitAbnormalCompletion(kCancelled)
    //   没有 deadline 级淘汰,executor 层不需要补偿性重试。
    return cc::ChannelSubmitResult{cc::ChannelSubmitStatus::kAccepted, cur_gen};
}

// ============================================================
// DrainEvents — 从 output_queue_ 取出事件（§13）
// ============================================================

bool Channel::DrainEvents(EventList& events, std::chrono::microseconds timeout)
{
    std::unique_lock<std::mutex> lock(io_mutex_);
    output_cv_.wait_for(lock, timeout,
        [this] { return !output_queue_.empty() || !running_.load(); });

    if (output_queue_.empty()) return false;

    while (!output_queue_.empty()) {
        events.push_back(std::move(output_queue_.front()));
        output_queue_.pop_front();
    }
    return true;
}

// ============================================================
// ObserveSnapshot / DrainObserveEvents（观测平面）
// ============================================================

void Channel::AttachObservabilityPublishers(
    refuzz::core::BroadcastBus<cc::ChannelSnapshot>* snapshot_bus,
    refuzz::core::BroadcastBus<cc::ChannelObserveEvent>* event_bus,
    core::metrics::ChannelMetrics* metrics,
    core::metrics::MetricRegistry* registry)
{
    observe_snapshot_bus_ = snapshot_bus;
    observe_event_bus_ = event_bus;
    metrics_  = metrics;
    registry_ = registry;

    // [v2 metric bus — 当前版本]
    // 把 ChannelMetrics* 注入到 HealthMonitor 和 Recovery（→ FaultTracker），
    // 使 health_crash[N]->Inc() / recovery_runtime_restart->Inc() 生效。
    //
    // 注意：Channel 对 health_monitor_ / recovery_ 持的是接口指针（IHealthMonitor /
    // IRecovery），SetMetrics 通过接口虚函数调用，不需要 dynamic_cast。
    // FaultTracker 不对 Channel 可见；Channel 只与 IRecovery 交互，
    // Recovery::SetMetrics 内部转发给 tracker_->SetMetrics。
    if (health_monitor_) health_monitor_->SetMetrics(metrics);
    if (recovery_)       recovery_->SetMetrics(metrics);

    // capacity gauge 一次性发布 (channel_cfg_.input_queue_capacity 是构造期常量;
    // 若将来支持运行时改 cap, 在改值处再 Set 一次即可)。
    // 注:此 metric 仅在 Attach 后可观测;测试 harness 应 Attach → Boot → 采样。
    if (metrics_ != nullptr && metrics_->input_queue_capacity != nullptr) {
        metrics_->input_queue_capacity->Set(
            static_cast<int64_t>(channel_cfg_.input_queue_capacity));
    }

    PublishObserveSnapshot();
}

cc::ChannelSnapshot Channel::ObserveSnapshot() const
{
    cc::ChannelSnapshot snap;
    snap.channel_id = channel_cfg_.channel_id;
    snap.lifecycle_state = phase_.load(std::memory_order_acquire);
    snap.generation = generation_.load(std::memory_order_relaxed);
    snap.boot_ts_us = boot_ts_us_;
    return snap;
}

bool Channel::DrainObserveEvents(cc::ChannelObserveEventList& events,
                                     std::chrono::microseconds timeout)
{
    std::unique_lock<std::mutex> lock(observe_mu_);
    observe_cv_.wait_for(lock, timeout, [this] {
        return !observe_queue_.empty() || !running_.load(std::memory_order_acquire);
    });
    if (observe_queue_.empty()) {
        return false;
    }
    while (!observe_queue_.empty()) {
        events.push_back(std::move(observe_queue_.front()));
        observe_queue_.pop_front();
    }
    return true;
}


// ============================================================
// 辅助方法
// ============================================================

void Channel::QueueEvent(cc::ChannelEvent event)
{
    EmitHotPathLog(event.event_id, [&](auto& logger) {
        logger.Log(
            "Channel",
            "event_queued",
            {refuzz::logging::Field("channel_id", channel_cfg_.channel_id),
             refuzz::logging::Field("event_id", event.event_id),
             refuzz::logging::Field("kind", EventKindName(event.kind)),
             refuzz::logging::Field("generation", event.generation)});
    });
    {
        std::lock_guard<std::mutex> lock(io_mutex_);
        output_queue_.push_back(std::move(event));
        if (auto* trace = MutableTrace(output_queue_.back());
            trace != nullptr && trace->sampled) {
            trace->channel_event_queued_ts_us = NowUs();
        }
    }
    output_cv_.notify_one();
}

void Channel::WakeLoopPoller() noexcept
{
    loop_cv_.notify_one();
    if (dp_) {
        dp_->WakePoller();
    }
}

void Channel::AbortPendingByScope(cc::ChannelAbortScope scope,
                                       uint32_t target_slot_id)
{
    if (scope == cc::ChannelAbortScope::kNone) return;

    if (scope == cc::ChannelAbortScope::kChannel) {
        const int count = static_cast<int>(pending_.size());
        for (auto& [exec_id, rec] : pending_) {
            EmitAbnormalCompletion(exec_id, cc::AbnormalKind::kWorkerCrashed);
        }
        {
            std::lock_guard<std::mutex> lk(io_mutex_);
            for (auto& [exec_id, rec] : pending_) {
                active_executor_ids_.erase(exec_id);
            }
        }
        pending_.clear();
        inflight_count_.fetch_sub(count, std::memory_order_relaxed);
    } else if (scope == cc::ChannelAbortScope::kSlot) {
        auto it = pending_.begin();
        while (it != pending_.end()) {
            if (it->second.slot_id == target_slot_id) {
                const uint64_t exec_id = it->first;
                EmitAbnormalCompletion(exec_id, cc::AbnormalKind::kWorkerCrashed);
                inflight_count_.fetch_sub(1, std::memory_order_relaxed);
                it = pending_.erase(it);
                {
                    std::lock_guard<std::mutex> lk(io_mutex_);
                    active_executor_ids_.erase(exec_id);
                }
            } else {
                ++it;
            }
        }
    }
}

void Channel::EmitAbnormalCompletion(uint64_t executor_id, cc::AbnormalKind kind)
{
    const auto it = pending_.find(executor_id);
    if (it != pending_.end()) {
        EmitAbnormalCompletion(it->second, kind);
        return;
    }

    DispatchRecord record;
    record.executor_id = executor_id;
    EmitAbnormalCompletion(record, kind);
}

void Channel::EmitAbnormalCompletionAndSettleIfPending(uint64_t executor_id,
                                                       cc::AbnormalKind kind)
{
    const auto it = pending_.find(executor_id);
    if (it == pending_.end()) {
        return;
    }
    EmitAbnormalCompletion(it->second, kind);
    pending_.erase(it);
    {
        std::lock_guard<std::mutex> lk(io_mutex_);
        active_executor_ids_.erase(executor_id);
    }
    inflight_count_.fetch_sub(1, std::memory_order_relaxed);
}

void Channel::EmitAbnormalCompletion(const DispatchRecord& record,
                                     cc::AbnormalKind kind)
{
    cc::ChannelEvent evt;
    evt.kind       = cc::ChannelEvent::Kind::kAbnormal;
    evt.event_id   = next_event_id_++;
    evt.channel_id = channel_cfg_.channel_id;
    evt.generation = generation_.load();

    cc::AbnormalCompletion abnormal;
    abnormal.kind = kind;
    switch (kind) {
    case cc::AbnormalKind::kCancelled:
        abnormal.diagnostics.error_code = ERR_TASK_CANCELLED;
        break;
    case cc::AbnormalKind::kWorkerCrashed:
    case cc::AbnormalKind::kWorkerSignaled:
        abnormal.diagnostics.error_code = ERR_WORKER_CRASHED;
        break;
    case cc::AbnormalKind::kChildAborted:
        abnormal.diagnostics.error_code = ERR_PROGRAM_CHILD_CRASHED;
        break;
    case cc::AbnormalKind::kHang:
        abnormal.diagnostics.error_code = ERR_DOMAIN_WATCHDOG_TIMEOUT;
        break;
    case cc::AbnormalKind::kHarnessFatal:
    case cc::AbnormalKind::kHarnessRecovered:
        abnormal.diagnostics.error_code = ERR_HARNESS_FORK_SERVER_PROTOCOL;
        break;
    case cc::AbnormalKind::kInfraFault:
        abnormal.diagnostics.error_code = ERR_EXECUTOR_ERROR;
        break;
    case cc::AbnormalKind::kNoResult:
        abnormal.diagnostics.error_code = ERR_OK;   // 没结果不是错误
        break;
    case cc::AbnormalKind::kUnknown:
    default:
        abnormal.diagnostics.error_code = ERR_UNKNOWN;
        break;
    }

    abnormal.ctx.executor_id     = record.executor_id;
    abnormal.ctx.seed_id         = record.seed_id;
    abnormal.ctx.origin_seed_id  = record.origin_seed_id;
    abnormal.ctx.worker_id       = record.slot_id;
    abnormal.ctx.dispatch_gen    = record.dispatch_gen;
    abnormal.ctx.generation      = record.generation;
    abnormal.ctx.submit_ts_us    = record.submit_ts_us;
    abnormal.ctx.program_payload = record.payload;
    abnormal.ctx.trace           = record.trace;
    abnormal.diagnostics.worker_id = record.slot_id;

    // [v2 PR-B abnormal console snapshot — 当前版本]
    // 抓最近若干行 console buffer 给下游 crash pipeline 用。
    // ring buffer 为 null/空时退化到原行为(snapshot 为空字符串)。
    // recovery 路径 EmitAbnormalCompletion(kCancelled/kWorkerCrashed) 也走这里,
    // 让所有 abnormal 落盘都带 console 上下文。
    // [v2 PR-E 行数从 channel_cfg_.abnormal_console_snapshot_lines 取 — 当前版本]
    if (console_ring_ != nullptr &&
        channel_cfg_.abnormal_console_snapshot_lines > 0) {
        abnormal.console_snapshot = console_ring_->SnapshotJoined(
            channel_cfg_.abnormal_console_snapshot_lines);
    }

    evt.payload = std::move(abnormal);
    QueueEvent(std::move(evt));
}

cc::ChannelState Channel::MapLifecycleToState(cc::ChannelLifecycleState lifecycle_state)
{
    switch (lifecycle_state) {
    case cc::ChannelLifecycleState::kRunning:      return cc::ChannelState::kReady;
    case cc::ChannelLifecycleState::kRecovering:   return cc::ChannelState::kDegraded;

    // kDegraded 表示部分 worker 隔离中，健康 worker 仍可服务，对外呈现 kDegraded
    case cc::ChannelLifecycleState::kDegraded:     return cc::ChannelState::kDegraded;
    case cc::ChannelLifecycleState::kStopped:
    case cc::ChannelLifecycleState::kBooting:
    case cc::ChannelLifecycleState::kFailed:
    case cc::ChannelLifecycleState::kClosed:
    default:                                   return cc::ChannelState::kDown;
    }
}

cc::FaultKind Channel::MapCrashKindToFaultKind(health::CrashKind kind)
{
    switch (kind) {
    case health::CrashKind::kKernelCrash:           return cc::FaultKind::kKernelCrash;
    case health::CrashKind::kVmDead:                return cc::FaultKind::kVmDead;
    case health::CrashKind::kNoOutput:              return cc::FaultKind::kNoOutput;
    case health::CrashKind::kWorkerDead:            return cc::FaultKind::kWorkerDead;
    default:                                        return cc::FaultKind::kWorkerDead;
    }
}

cc::ChannelFaultReason Channel::MapCrashKindToFaultReason(health::CrashKind kind)
{
    switch (kind) {
    case health::CrashKind::kKernelCrash:       return cc::ChannelFaultReason::kKernelCrash;
    case health::CrashKind::kVmDead:            return cc::ChannelFaultReason::kVmDead;
    case health::CrashKind::kNoOutput:          return cc::ChannelFaultReason::kNoOutput;
    case health::CrashKind::kWorkerDead:        return cc::ChannelFaultReason::kWorkerHeartbeatLost;
    case health::CrashKind::kHealthInternalFault: return cc::ChannelFaultReason::kHealthInternal;
    }
    return cc::ChannelFaultReason::kWorkerHeartbeatLost;
}


// ============================================================
// 收集现在的channel Snapshot
// ============================================================

cc::ChannelRuntimeSnapshot Channel::CollectRuntimePart() const
{
    // free_slots 直接查询 Transport，考虑 registered + !paused + slot empty
    cc::ChannelRuntimeSnapshot runtime;
    runtime.total_slots = channel_cfg_.n_workers;
    runtime.inflight = static_cast<uint32_t>(
        std::max(0, inflight_count_.load(std::memory_order_relaxed)));
    runtime.free_slots         = dp_ ? dp_->CountSendableWorkers() : 0;
    runtime.registered_workers = cp_ ? cp_->RegisteredWorkerCount() : 0;
    // quarantined_workers_ 由 loop_thread_ 独占写，CollectRuntimePart 可能从任意线程调用
    // 此处仅做 size() 读取，不涉及遍历，对轻微不一致可接受
    runtime.quarantined_workers = static_cast<uint32_t>(quarantined_workers_.size());
    return runtime;
}

cc::HealthMonitorSnapshot Channel::CollectHealthPart(
    cc::ChannelLifecycleState lifecycle_state) const
{
    // 直接查询 HealthMonitor：worker 存活 bitmask + CrashKind 累计计数。
    // lifecycle_state 参数保留用于未来扩展（当前 GetSnapshot 不依赖生命周期状态）。
    (void)lifecycle_state;
    if (health_monitor_) {
        return health_monitor_->GetSnapshot();
    }
    return cc::HealthMonitorSnapshot{};
}

// [v2 new-approach — 当前版本]
// Boot() 成功路径在 Recovery::Create 之后必然持有 recovery_；optional 易误解为「未发生恢复」。
// 与 CollectHealthPart 一致：无组件实例时返回默认 cc::ChannelRecoverySnapshot{}（仅构造后 / Boot 失败早期）。
cc::ChannelRecoverySnapshot Channel::CollectRecoveryPart() const
{
    if (!recovery_) {
        return cc::ChannelRecoverySnapshot{};
    }

    const auto snap = recovery_->GetSnapshot();

    cc::ChannelRecoverySnapshot out;
    out.runtime_restart_count = snap.runtime_restart_count;
    out.vm_reboot_count       = snap.vm_reboot_count;
    out.consecutive_healthy   = snap.consecutive_healthy;
    out.last_fault_ts_us      = snap.last_fault_ts_us;
    out.offline               = snap.offline;
    out.recovery_in_progress  = snap.recovery_in_progress;
    out.active_action         = snap.active_recovery_action;
    out.policy                = snap.policy;  // 策略名 + 当前阈值参数
    return out;
}


// ============================================================
// 发送可观测事件到telemetry
// ============================================================
void Channel::QueueObserveEvent(cc::ChannelObserveEvent event)
{
    // [v2 metric bus — Step 5a] §4.5 event counter: Inc before move
    if (metrics_ != nullptr) {
        const auto idx = static_cast<size_t>(event.kind);
        if (idx < metrics_->event_kind.size() && metrics_->event_kind[idx] != nullptr) {
            metrics_->event_kind[idx]->Inc();
        }
    }
    if (observe_event_bus_ != nullptr) {
        observe_event_bus_->Publish(event);
    }
    {
        std::lock_guard<std::mutex> lock(observe_mu_);
        observe_queue_.push_back(std::move(event));
    }
    observe_cv_.notify_one();
}

void Channel::PublishObserveSnapshot()
{
    if (observe_snapshot_bus_ == nullptr && metrics_ == nullptr) {
        return;
    }
    last_snapshot_publish_us_ = NowUs();
    auto snap = ObserveSnapshot();
    // [v2 metric bus — Step 5a] 必须在 bus Publish 之前推 metric,
    // 保证 reader 看到的 samples 不比 snapshot 旧。
    // [6b-3 — ChannelSnapshot 精简] 3 个子结构改为本地构造, 不再存入 snap。
    if (metrics_ != nullptr && registry_ != nullptr) {
        const auto runtime_part  = CollectRuntimePart();
        const auto health_part   = CollectHealthPart(snap.lifecycle_state);
        const auto recovery_part = CollectRecoveryPart();
        metrics_->PublishFromSnapshot(snap, runtime_part, health_part,
                                      recovery_part, *registry_);
    }
    if (observe_snapshot_bus_ != nullptr) {
        observe_snapshot_bus_->Publish(std::move(snap));
    }
}

void Channel::MaybePublishObserveSnapshot()
{
    const uint64_t now = NowUs();
    if (now - last_snapshot_publish_us_ < kObserveSnapshotHeartbeatUs) {
        return;
    }
    PublishObserveSnapshot();
}

void Channel::SetLifecycleState(cc::ChannelLifecycleState new_state)
{
    const cc::ChannelLifecycleState old_state =
        phase_.exchange(new_state, std::memory_order_acq_rel);
    if (old_state == new_state) {
        return;
    }

    // [Phase G] 只在边沿时向 HostLogger 打一条 phase_transition。
    //           既回答"channel 是不是在恢复/降级",也给 SRE 抓时间线时
    //           每次 状态变化都有一条事件(频率极低,非热路径)。
    refuzz::logging::HostLogger::Instance().Log(
        "Channel",
        "phase_transition",
        {refuzz::logging::Field("channel_id", channel_cfg_.channel_id),
         refuzz::logging::Field("from", cc::ChannelLifecycleStateName(old_state)),
         refuzz::logging::Field("to", cc::ChannelLifecycleStateName(new_state)),
         refuzz::logging::Field("generation", generation_.load(std::memory_order_relaxed))});

    cc::ChannelObserveEvent event;
    event.kind = cc::ChannelObserveEventKind::kLifecycleChanged;
    event.event_id = next_observe_event_id_++;
    event.ts_us = NowUs();
    event.channel_id = channel_cfg_.channel_id;
    event.generation = generation_.load(std::memory_order_relaxed);
    event.old_lifecycle_state = old_state;
    event.new_lifecycle_state = new_state;
    QueueObserveEvent(std::move(event));
    PublishObserveSnapshot();
}

void Channel::EmitObserveFaultDetected(cc::FaultKind fault_kind,
                                           cc::ChannelFaultReason fault_reason)
{
    cc::ChannelObserveEvent event;
    event.kind = cc::ChannelObserveEventKind::kFaultDetected;
    event.event_id = next_observe_event_id_++;
    event.ts_us = NowUs();
    event.channel_id = channel_cfg_.channel_id;
    event.generation = generation_.load(std::memory_order_relaxed);
    event.fault_kind = fault_kind;
    event.fault_reason = fault_reason;
    QueueObserveEvent(std::move(event));
    PublishObserveSnapshot();
}

void Channel::EmitObserveRecoveryStarted(cc::RecoveryAction action,
                                             cc::ChannelFaultReason reason)
{
    cc::ChannelObserveEvent event;
    event.kind = cc::ChannelObserveEventKind::kRecoveryStarted;
    event.event_id = next_observe_event_id_++;
    event.ts_us = NowUs();
    event.channel_id = channel_cfg_.channel_id;
    event.generation = generation_.load(std::memory_order_relaxed);
    event.recovery_action = action;
    event.fault_reason = reason;
    QueueObserveEvent(std::move(event));
    PublishObserveSnapshot();

    // [D13] recovery 开始打 host log。便于 runtime 追踪 channel
    // 反复 recovery 的 case (eg. repro VM SSH timeout 反复 restart_single_worker)。
    refuzz::logging::HostLogger::Instance().Log(
        "Channel",
        "recovery_started",
        {refuzz::logging::Field("channel_id", channel_cfg_.channel_id),
         refuzz::logging::Field("generation", static_cast<int64_t>(event.generation)),
         refuzz::logging::Field("event_id", static_cast<int64_t>(event.event_id)),
         refuzz::logging::Field("action", static_cast<int64_t>(action)),
         refuzz::logging::Field("fault_reason", static_cast<int64_t>(reason)),
         refuzz::logging::Field("ts_us", event.ts_us)});
}

void Channel::EmitObserveRecoveryCompleted(cc::RecoveryAction action,
                                               cc::ChannelFaultReason reason,
                                               bool success,
                                               std::string error_message)
{
    cc::ChannelObserveEvent event;
    event.kind = cc::ChannelObserveEventKind::kRecoveryCompleted;
    event.event_id = next_observe_event_id_++;
    event.ts_us = NowUs();
    event.channel_id = channel_cfg_.channel_id;
    event.generation = generation_.load(std::memory_order_relaxed);
    event.recovery_action = action;
    event.fault_reason = reason;
    event.recovery_success = success;
    event.error_message = std::move(error_message);

    // [D13] recovery 结束打 host log,含 success/error_message。
    // 在 QueueObserveEvent / move 前 log,error_message 还可读。
    refuzz::logging::HostLogger::Instance().Log(
        "Channel",
        "recovery_completed",
        {refuzz::logging::Field("channel_id", channel_cfg_.channel_id),
         refuzz::logging::Field("generation", static_cast<int64_t>(event.generation)),
         refuzz::logging::Field("event_id", static_cast<int64_t>(event.event_id)),
         refuzz::logging::Field("action", static_cast<int64_t>(action)),
         refuzz::logging::Field("fault_reason", static_cast<int64_t>(reason)),
         refuzz::logging::Field("success", success ? 1 : 0),
         refuzz::logging::Field("error_message", event.error_message),
         refuzz::logging::Field("ts_us", event.ts_us)});

    QueueObserveEvent(std::move(event));
    PublishObserveSnapshot();
}

void Channel::EmitObserveGenerationReset(uint32_t old_generation,
                                             uint32_t new_generation)
{
    cc::ChannelObserveEvent event;
    event.kind = cc::ChannelObserveEventKind::kGenerationReset;
    event.event_id = next_observe_event_id_++;
    event.ts_us = NowUs();
    event.channel_id = channel_cfg_.channel_id;
    event.generation = new_generation;
    event.old_generation = old_generation;
    event.new_generation = new_generation;
    QueueObserveEvent(std::move(event));
    PublishObserveSnapshot();
}



} // namespace refuzz::channel

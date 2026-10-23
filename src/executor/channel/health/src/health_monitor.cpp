// health_monitor.cpp — HealthMonitor 实现
//
// 职责：health 子系统唯一入口，管理一组 IHealthSensor 的生命周期 + 提供统一
//        上报 / 消费接口。
//
// 并发契约（§18.4.2）：
//   monitor_mutex_ 唯一保护 pending_events_（单 mutex）；
//   PublishCrashEvent：lock → enqueue → update bits → unlock → notify_one(loop_cv)；
//   DrainCrashEvents：lock → swap → clear has_pending_ → unlock（无 wait）。
//
// SuspendMonitoring quiesce（§18.6）：
//   set suspended_=true → Poke 各 Sensor → wait(quiesce_cv_) until parked_count==n_threads_
// ResumeMonitoring：
//   set suspended_=false → broadcast quiesce_cv_ → wait until parked_count==0
//
// 设计来源：health/design.md §18.3.1 / §18.4 / §18.6 / §18.7 / §18.8 / §18.9

#include "refuzz/channel/health/health_monitor.hpp"

#include "refuzz/core/metrics/channel_metrics.hpp"  // [v2 metric bus]

#include <cassert>
#include <chrono>

namespace refuzz::channel::health {

// ============================================================
// 构造 / 析构
// ============================================================

HealthMonitor::HealthMonitor(HealthMonitorView    view,
                             HealthMonitorConfig  config)
    : view_(view)
    , config_(std::move(config)) {
    // 期待调用序：AddSensor * N → Start()
}

HealthMonitor::~HealthMonitor() {
    Stop();
}

// ============================================================
// AddSensor — Sensor 注册
// ============================================================

void HealthMonitor::AddSensor(std::unique_ptr<IHealthSensor> sensor) {
    // 调用约束：Start() 之前、装配线程单线程调用
    sensors_.push_back(std::move(sensor));
}

// ============================================================
// BindChannelSignals — 注入 Channel 级别 cv/epoch
// ============================================================
//
// Assembler 构造 HealthMonitor 时传空 view（Channel 尚未存在），
// Channel::Boot 调用此方法把真实 view 绑定上来。必须在 Start 之前调用。

void HealthMonitor::BindChannelSignals(HealthMonitorView view) noexcept {
    view_ = view;
}

// ============================================================
// Start() — 启动所有已注册 Sensor
// ============================================================
//
// 语义：遍历已 AddSensor 的全部 Sensor，依次调 Start(*this)；
//       任一失败则把已启动的 Stop 后返回错误。

Result<void> HealthMonitor::Start() {
    if (started_) {
        return Error{ErrorKind::kInfra, "HealthMonitor::Start() called while already started"};
    }
    if (sensors_.empty()) {
        return Error{ErrorKind::kInfra,
                     "HealthMonitor::Start(): no sensors registered (call AddSensor first)"};
    }

    // 重置 quiesce 状态
    parked_count_.store(0, std::memory_order_relaxed);
    suspended_.store(false, std::memory_order_relaxed);

    // 重置 CrashKind 累计计数（每轮 Start 作为计数周期起点）

    // 初始化 worker_alive_bits_：默认全 worker 存活
    const uint32_t n = config_.expected_worker_count;
    if (n > 0 && n <= 64) {
        uint64_t mask = (n < 64) ? ((1ULL << n) - 1) : UINT64_MAX;
        worker_alive_bits_.store(mask, std::memory_order_release);
    }

    // 依次启动 Sensor；任一失败回滚
    for (size_t i = 0; i < sensors_.size(); ++i) {
        auto r = sensors_[i]->Start(*this);
        if (!r.ok()) {
            for (size_t j = 0; j < i; ++j) {
                sensors_[j]->Stop();
            }
            return Error{r.error().kind,
                         std::string("HealthMonitor: Sensor[")
                             + std::string(sensors_[i]->Name())
                             + "].Start failed: " + r.error().message};
        }
    }

    n_threads_ = static_cast<int>(sensors_.size());
    started_   = true;
    return Result<void>::Ok();
}

// ============================================================
// Stop — 停止全部 Sensor
// ============================================================

void HealthMonitor::Stop() noexcept {
    if (!started_) return;

    // 若当前处于 suspended 状态，先 resume 让 Sensor 线程可以正常响应 stop 信号
    if (suspended_.load(std::memory_order_acquire)) {
        suspended_.store(false, std::memory_order_release);
        quiesce_cv_.notify_all();
    }

    // 反序 Stop（Start 时正序启动）
    for (auto it = sensors_.rbegin(); it != sensors_.rend(); ++it) {
        if (*it) (*it)->Stop();
    }

    n_threads_ = 0;
    started_   = false;
}

// ============================================================
// Reboot — 全量重启 health 子系统（cross_component_design.md §3.1）
// ============================================================

Result<void> HealthMonitor::Reboot() {
    if (!started_) {
        return Error{ErrorKind::kInfra,
                     "HealthMonitor::Reboot() called but health monitor is not started"};
    }
    Stop();
    return Start();
}

// ============================================================
// SuspendMonitoring — 挂起监控，阻塞到所有 Sensor parked
// ============================================================

void HealthMonitor::SuspendMonitoring() {
    // 设置 suspended_，Poke 各 Sensor 唤醒，等待 parked_count == n_threads_
    {
        std::unique_lock<std::mutex> lock(quiesce_mutex_);
        suspended_.store(true, std::memory_order_release);

        for (auto& s : sensors_) { if (s) s->Poke(); }

        quiesce_cv_.wait(lock, [this] {
            return parked_count_.load(std::memory_order_acquire) >= n_threads_;
        });
    }
}

// ============================================================
// ResumeMonitoring — 恢复监控，广播唤醒，阻塞到所有 Sensor 离开 park
// ============================================================

void HealthMonitor::ResumeMonitoring() {
    {
        std::unique_lock<std::mutex> lock(quiesce_mutex_);
        suspended_.store(false, std::memory_order_release);
        // 广播唤醒所有在 ParkUntilResumed 内等待的 Sensor 线程
        quiesce_cv_.notify_all();

        // 等待所有 Sensor 离开 park（parked_count 归零）
        quiesce_cv_.wait(lock, [this] {
            return parked_count_.load(std::memory_order_acquire) == 0;
        });
    }
    // 此时：所有线程已离开 ParkUntilResumed，正在重建基线
    // 注：聚合前进时钟（evidence::ProgressClock）的 Reset 由 Channel 在 resume/reboot
    //     完成后调用——它是 Channel 拥有的中立信号，不在 health 子系统内。
}

// ============================================================
// SyncObservedWorkers — 转发给所有 Sensor
// ============================================================

void HealthMonitor::SyncObservedWorkers(const std::vector<bool>& observed) {
    // 调用约束：SuspendMonitoring 生效期间（Sensor 已 parked，无并发写）
    for (auto& s : sensors_) { if (s) s->SyncObservedWorkers(observed); }
}

// ============================================================
// RearmSingleWorker — 单 worker recovery 成功时恢复观察集
// ============================================================

void HealthMonitor::RearmSingleWorker(uint32_t worker_id) {
    // 调用时机:Channel::HandleSingleWorkerRecoveryComplete success 分支。
    //          与 sensor 线程并发,由 sensor 内部加锁保护。
    for (auto& s : sensors_) { if (s) s->RearmSingleWorker(worker_id); }
}

// ============================================================
// SetWorkerAlive — 更新单 worker 存活 bit（Channel recovery 后调用）
// ============================================================

void HealthMonitor::SetWorkerAlive(uint32_t worker_id, bool alive) noexcept {
    if (worker_id >= 64) return;
    uint64_t bit = 1ULL << worker_id;
    if (alive) {
        // 置位：fetch_or（原子读改写）
        worker_alive_bits_.fetch_or(bit, std::memory_order_release);
    } else {
        worker_alive_bits_.fetch_and(~bit, std::memory_order_release);
    }
}

// ============================================================
// PublishCrashEvent — 构造 CrashEvent，入队，notify Channel loop_cv
// ============================================================

void HealthMonitor::PublishCrashEvent(CrashEventOrigin origin,
                                      CrashFragment&&  fragment,
                                      std::string      checker_name,
                                      int              errno_value) {
    // 构造 CrashEvent（在调用线程本地完成，不引入共享竞争，§18.4.2）
    CrashEvent event;
    event.event_id       = NextEventId();
    event.origin         = origin;
    event.vm_epoch       = view_.vm_epoch
                               ? view_.vm_epoch->load(std::memory_order_acquire)
                               : 0;
    event.detected_ts_us = NowUs();
    event.fragment       = std::move(fragment);
    event.checker_name   = std::move(checker_name);
    event.errno_value    = errno_value;

    // 更新 per-worker 存活 bitmask（在锁内完成，确保与入队的原子性）
    const auto kind     = event.fragment.kind;
    const auto src_wid  = event.fragment.source_worker_id;

    {
        std::lock_guard<std::mutex> lock(monitor_mutex_);

        // 按 CrashKind 更新 worker_alive_bits_（§18.4 "按事件类型更新"）
        if (kind == CrashKind::kWorkerDead && src_wid < 64) {
            worker_alive_bits_.fetch_and(~(1ULL << src_wid), std::memory_order_release);
        } else if (kind == CrashKind::kVmDead ||
                   kind == CrashKind::kNoOutput) {
            // VM 级事件（进程死亡 / 无进展冻结）：全部 worker 均不可用
            worker_alive_bits_.store(0, std::memory_order_release);
        }
        // kKernelCrash / kHealthInternalFault：不在 health 层修改 alive bits，由消费侧决策

        // [v2 metric bus — 当前版本]
        // 源头单调 Counter：事件在此分类并 Inc 一次，channel.health.crash{kind=...} 直接出数。
        // 注意：metrics_ 在锁内读取；SetMetrics() 在装配线程写入（Start 之前），
        //       所以 PublishCrashEvent 运行时 metrics_ 已稳定，无 race。
        if (metrics_ != nullptr) {
            switch (kind) {
                case CrashKind::kKernelCrash:
                    if (metrics_->health_crash[0]) metrics_->health_crash[0]->Inc(); break;
                case CrashKind::kVmDead:
                    if (metrics_->health_crash[1]) metrics_->health_crash[1]->Inc(); break;
                case CrashKind::kWorkerDead:
                    if (metrics_->health_crash[2]) metrics_->health_crash[2]->Inc(); break;
                case CrashKind::kHealthInternalFault:
                    if (metrics_->health_crash[3]) metrics_->health_crash[3]->Inc(); break;
                case CrashKind::kNoOutput:
                    if (metrics_->health_crash[4]) metrics_->health_crash[4]->Inc(); break;
            }
        }

        pending_events_.push_back(std::move(event));
        has_pending_.store(true, std::memory_order_release);
    }

    // 锁外 notify（notify_one 不需要持锁，§18.4.2）
    if (view_.loop_cv) view_.loop_cv->notify_one();
    if (view_.wake_poller) view_.wake_poller();
}

// ============================================================
// Publish — HealthPublisher::Publish 实现
// ============================================================
//
// 语义：Sensor 已自行构造 CrashEvent（含 sensor_name / errno），
//       HealthMonitor 补齐 event_id / vm_epoch / detected_ts_us 字段，
//       入队、更新 bitmap / 统计，并 notify_one(loop_cv)。

void HealthMonitor::Publish(CrashEvent event) {
    // 补齐 HealthMonitor 负责的字段（Sensor 不知道这些值）
    if (event.event_id == 0) {
        event.event_id = NextEventId();
    }
    if (event.vm_epoch == 0 && view_.vm_epoch) {
        event.vm_epoch = view_.vm_epoch->load(std::memory_order_acquire);
    }
    if (event.detected_ts_us == 0) {
        event.detected_ts_us = NowUs();
    }

    const auto kind    = event.fragment.kind;
    const auto src_wid = event.fragment.source_worker_id;

    {
        std::lock_guard<std::mutex> lock(monitor_mutex_);

        if (kind == CrashKind::kWorkerDead && src_wid < 64) {
            worker_alive_bits_.fetch_and(~(1ULL << src_wid), std::memory_order_release);
        } else if (kind == CrashKind::kVmDead ||
                   kind == CrashKind::kNoOutput) {
            worker_alive_bits_.store(0, std::memory_order_release);
        }

        // [v2 metric bus — 当前版本]
        // Publish() 与 PublishCrashEvent() 是两条独立路径（Sensor 直接提交 vs. HealthMonitor 构造）；
        // 两条路径都需要 Counter Inc，确保所有 crash 事件都被计入单调 Counter。
        if (metrics_ != nullptr) {
            switch (kind) {
                case CrashKind::kKernelCrash:
                    if (metrics_->health_crash[0]) metrics_->health_crash[0]->Inc(); break;
                case CrashKind::kVmDead:
                    if (metrics_->health_crash[1]) metrics_->health_crash[1]->Inc(); break;
                case CrashKind::kWorkerDead:
                    if (metrics_->health_crash[2]) metrics_->health_crash[2]->Inc(); break;
                case CrashKind::kHealthInternalFault:
                    if (metrics_->health_crash[3]) metrics_->health_crash[3]->Inc(); break;
                case CrashKind::kNoOutput:
                    if (metrics_->health_crash[4]) metrics_->health_crash[4]->Inc(); break;
            }
        }

        pending_events_.push_back(std::move(event));
        has_pending_.store(true, std::memory_order_release);
    }

    if (view_.loop_cv) view_.loop_cv->notify_one();
    if (view_.wake_poller) view_.wake_poller();
}

// ============================================================
// DrainCrashEvents — 批量取走全部待处理事件（无 wait）
// ============================================================

std::vector<CrashEvent> HealthMonitor::DrainCrashEvents() {
    std::vector<CrashEvent> drained;
    {
        std::lock_guard<std::mutex> lock(monitor_mutex_);
        drained.swap(pending_events_);
        if (pending_events_.empty()) {
            has_pending_.store(false, std::memory_order_release);
        }
    }
    return drained;
}

// ============================================================
// HasPendingCrashEvents — lock-free 快速检查（loop cv 谓词用）
// ============================================================

bool HealthMonitor::HasPendingCrashEvents() const noexcept {
    return has_pending_.load(std::memory_order_acquire);
}

// ============================================================
// WorkerAlive — lock-free per-worker 存活查询（热路径）
// ============================================================

bool HealthMonitor::WorkerAlive(uint32_t worker_id) const {
    if (worker_id >= 64) return false;
    return (worker_alive_bits_.load(std::memory_order_acquire) >> worker_id) & 1U;
}

// ============================================================
// GetSnapshot — 构造当前 health 状态快照（供 Channel::CollectHealthPart 调用）
// ============================================================

refuzz::core::channel_contract::HealthMonitorSnapshot HealthMonitor::GetSnapshot() const {
    refuzz::core::channel_contract::HealthMonitorSnapshot snap;
    snap.sampled_ts_us = NowUs();

    // worker_liveness size 由 config_.expected_worker_count 决定（Assembler 在装配时填入）
    const uint32_t n = config_.expected_worker_count;
    const uint64_t alive_bits = worker_alive_bits_.load(std::memory_order_acquire);
    snap.worker_liveness.reserve(n);
    for (uint32_t i = 0; i < n && i < 64; ++i) {
        refuzz::core::channel_contract::WorkerLivenessEntry entry;
        entry.worker_id = i;
        entry.is_alive  = (alive_bits >> i) & 1U;
        // is_alive 只是判死之后的终态。向 Sensor 拉一次连续量，让面板能看见 stall 的
        // **过程**而不是 300s 后的一次跳变。第一个应答的 Sensor 说了算（当前只有
        // HeartbeatSensor 实现此语义，其余默认返回 false）。
        for (const auto& s : sensors_) {
            IHealthSensor::WorkerProgress prog{};
            if (s && s->GetWorkerProgress(i, &prog)) {
                entry.silent_s        = prog.silent_s;
                entry.silent_budget_s = prog.silent_budget_s;
                entry.proc_epoch      = prog.proc_epoch;
                entry.recovering      = prog.recovering;
                entry.slot            = prog.slot;
                break;
            }
        }
        snap.worker_liveness.push_back(entry);
    }

    // [crash 计数已移出 snapshot] 这里曾填 snap.crash_stats 的四路计数,是第二套账本:
    //   事件在 Publish/PublishCrashEvent 里已经按 kind 分类并 Inc 了源头 Counter
    //   (channel.health.crash{kind=kernel|vm|worker|internal}),那条路才是出数的。
    //   snapshot 这份从头到尾没有任何消费方——PublishFromSnapshot 不碰它,renderer 也不读。
    return snap;
}

// ============================================================
// IsSuspended — Sensor 轮询检查（lock-free）
// ============================================================

bool HealthMonitor::IsSuspended() const {
    return suspended_.load(std::memory_order_acquire);
}

// ============================================================
// ParkUntilResumed — Sensor 进入 park，等待 ResumeMonitoring
// ============================================================

void HealthMonitor::ParkUntilResumed() {
    std::unique_lock<std::mutex> lock(quiesce_mutex_);

    // 1. 递增 parked_count，notify SuspendMonitoring() 的等待侧
    parked_count_.fetch_add(1, std::memory_order_release);
    quiesce_cv_.notify_all();

    // 2. 等待 ResumeMonitoring 设置 suspended_=false 并 broadcast
    quiesce_cv_.wait(lock, [this] {
        return !suspended_.load(std::memory_order_acquire);
    });

    // 3. 离开 park：递减 parked_count，notify ResumeMonitoring() 的等待侧
    parked_count_.fetch_sub(1, std::memory_order_release);
    quiesce_cv_.notify_all();

    // 返回后：Sensor 负责重建基线（armed=false 已在进入 park 前设置）
}

// ============================================================
// NotifyThreadExiting — Sensor 异常退出路径的"永久 park"通知
// ============================================================

void HealthMonitor::NotifyThreadExiting() {
    // Sensor 线程因不可恢复错误（如 poll() 失败）即将退出 ThreadMain，
    // 此时该线程不会再调 ParkUntilResumed()。
    //
    // 问题：若随后 Channel 调 SuspendMonitoring()，它会等待 parked_count == n_threads_。
    //       已死线程永远不会 park，导致 SuspendMonitoring 卡住。
    //
    // 修复（Q3 方案 A）：把 parked_count_ +1，相当于"我已永久 park，不会再运行"。
    // SuspendMonitoring 的等待条件满足后正常返回；
    // Reboot() 调 Stop()+Start() 时，Start() 内部重置 parked_count_=0，清除累积。
    //
    // 调用时机：ThreadMain 因不可恢复错误 return 之前，在 PublishCrashEvent 之后调用。
    parked_count_.fetch_add(1, std::memory_order_release);
    quiesce_cv_.notify_all();
}

// ============================================================
// SetMetrics — 注入 ChannelMetrics* 指针（metric bus 5b）
// ============================================================

// [v2 metric bus — 当前版本]
// 由 Channel::AttachObservabilityPublishers 在 Attach 时调用（Boot 之前或之后均可，
// PublishCrashEvent 在持锁后读取 metrics_ 指针，null 检查保证线程安全）。
void HealthMonitor::SetMetrics(refuzz::core::metrics::ChannelMetrics* metrics) noexcept {
    metrics_ = metrics;
}

// ============================================================
// 内部工具
// ============================================================

uint64_t HealthMonitor::NextEventId() {
    return next_event_id_.fetch_add(1, std::memory_order_relaxed);
}

uint64_t HealthMonitor::NowUs() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

} // namespace refuzz::channel::health

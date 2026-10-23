// HeartbeatSensor 实现
//
// 读心跳的动作统一走 IControlPlane::SampleHeartbeat —— 具体如何读由 CP 决定
// （ivshmem 直读 ctrl.heartbeat_counter / vsock 走 RPC）；Sensor 对此无感。

#include "refuzz/channel/health/heartbeat_sensor.hpp"

#include "refuzz/logging/host_logger.hpp"  // [diag] rearm / stall 时序日志

#include <algorithm>
#include <chrono>

namespace refuzz::channel::health {

HeartbeatSensor::HeartbeatSensor(control::IControlPlane*       cp,
                                 evidence::IStepEventSource*   step_source,
                                 HeartbeatSensorConfig         config,
                                 evidence::ConsoleRingBuffer*  ring_buffer,
                                 evidence::ProgressClock*      progress_clock) noexcept
    : cp_(cp)
    , step_source_(step_source)
    , config_(std::move(config))
    , ring_buffer_(ring_buffer)
    , progress_clock_(progress_clock) {
    // worker_states_ 在 Start() 时按 config_.worker_count 初始化
}

HeartbeatSensor::~HeartbeatSensor() {
    Stop();
}

Result<void> HeartbeatSensor::Start(HealthPublisher& publisher) {
    if (thread_running_) {
        return Error{ErrorKind::kInfra,
                     "HeartbeatSensor::Start() called while already running"};
    }
    if (cp_ == nullptr) {
        return Error{ErrorKind::kInfra,
                     "HeartbeatSensor::Start(): control plane is null"};
    }
    if (config_.worker_count == 0) {
        return Error{ErrorKind::kInfra,
                     "HeartbeatSensor::Start(): worker_count == 0"};
    }

    publisher_ = &publisher;

    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        worker_states_.assign(config_.worker_count, WorkerState{});
        cursor_worker_id_ = 0;
    }

    stop_flag_.store(false, std::memory_order_relaxed);
    thread_        = std::thread(&HeartbeatSensor::ThreadMain, this);
    thread_running_ = true;

    return Result<void>::Ok();
}

void HeartbeatSensor::Stop() {
    if (!thread_running_) return;

    {
        std::lock_guard<std::mutex> lock(cv_mutex_);
        stop_flag_.store(true, std::memory_order_release);
    }
    cv_.notify_all();

    if (thread_.joinable()) thread_.join();
    thread_running_ = false;
}

void HeartbeatSensor::Poke() {
    cv_.notify_all();
}

void HeartbeatSensor::SyncObservedWorkers(const std::vector<bool>& observed) {
    // 调用约束：SuspendMonitoring() 生效期间或 Stop() 之后；ThreadMain 无并发写
    std::lock_guard<std::mutex> lock(state_mutex_);
    for (size_t i = 0; i < observed.size() && i < worker_states_.size(); ++i) {
        bool new_observed = observed[i];
        if (new_observed && !worker_states_[i].observed) {
            // 从 un-observed → observed 视作"这个 worker 需要重建基线",等同 Rearm:
            // 放宽 grace_rounds_after_rearm 轮,避免冷启动/重接入期间被误判。
            worker_states_[i].armed             = false;
            worker_states_[i].consecutive_miss  = 0;
            worker_states_[i].last_counter      = 0;
            worker_states_[i].grace_rounds_left = config_.grace_rounds_after_rearm;
        }
        worker_states_[i].observed = new_observed;
    }
}

static uint64_t NowUs() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

void HeartbeatSensor::RearmSingleWorker(uint32_t worker_id) {
    // 调用约束:可与 ThreadMain 并发(Channel loop_thread_ 在 single worker recovery
    //          成功后调用),用 state_mutex_ 保护 worker_states_。
    // 语义:纯状态重置,不触发 Publish。armed=false 让下一轮采样以新 counter 重建基线
    //      —— 重启后 worker 的进度令牌与旧的没有可比性(proc_epoch 会跨重启递增,
    //      exec_seq 却随新进程归零),沿用旧 last_counter 无意义。
    //   grace_rounds_left = config_.grace_rounds_after_rearm:吸收 rearm 到首个令牌变化
    //   之间的空窗。注意这层兜底在心跳重定义后已不吃重 —— 它原本防的是"RT 心跳线程首次
    //   被调度前的百 ms 级延迟",而令牌由执行路径写、没有那个线程;真正决定误判与否的是
    //   miss_threshold(见 orchestrator_config.cpp 的地板推导)。留着无害。
    uint64_t observed_counter = 0;
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        if (worker_id >= worker_states_.size()) return;
        auto& s = worker_states_[worker_id];
        s.observed          = true;
        s.armed             = false;
        s.consecutive_miss  = 0;
        s.last_counter      = 0;
        s.grace_rounds_left = config_.grace_rounds_after_rearm;
    }
    // [diag] 采样一次当前 counter，只用于日志，不修改 state
    if (cp_ != nullptr) {
        auto sample = cp_->SampleHeartbeat(worker_id);
        if (sample.valid) observed_counter = sample.counter;
    }
    refuzz::logging::HostLogger::Instance().Log(
        "HeartbeatSensor",
        "rearm",
        {refuzz::logging::Field("worker_id", worker_id),
         refuzz::logging::Field("grace_rounds", config_.grace_rounds_after_rearm),
         refuzz::logging::Field("poll_interval_ms",
             static_cast<int64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(config_.poll_interval).count())),
         refuzz::logging::Field("miss_threshold", config_.miss_threshold),
         refuzz::logging::Field("counter_at_rearm", observed_counter),
         refuzz::logging::Field("ts_us", NowUs())});
}

bool HeartbeatSensor::GetWorkerProgress(uint32_t worker_id, WorkerProgress* out) const {
    if (out == nullptr) return false;
    std::lock_guard<std::mutex> lock(state_mutex_);
    if (worker_id >= worker_states_.size()) return false;
    const auto& s = worker_states_[worker_id];

    const uint64_t poll_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(config_.poll_interval).count());

    // 静默时长 = 连续 miss 轮数 × 轮间隔。取整到秒:轮间隔 250ms 而预算是 300s,
    // 亚秒分辨率是噪声。
    out->silent_s = static_cast<uint32_t>(
        (static_cast<uint64_t>(s.consecutive_miss) * poll_ms) / 1000ULL);
    out->silent_budget_s = static_cast<uint32_t>(
        (static_cast<uint64_t>(config_.miss_threshold) * poll_ms) / 1000ULL);
    out->proc_epoch = s.last_proc_epoch;
    out->slot       = s.last_slot;

    // recovering:daemon 在**这段静默期内**去轮换过 domain。
    //   daemon 只要活着,程序 hang 到点必然触发 watchdog → 轮换 domain → proc_epoch +1。
    //   所以 epoch 涨了 = 它活着、正在自救、卡的是被测程序(合法,最长 65s);
    //        epoch 冻着 = 连自救都没做 = 卡的是 daemon 自己。
    //   没有这个对比,silent_s 是无法解读的 —— 分不清正在正确履职和已经死了。
    out->recovering = (s.consecutive_miss > 0) &&
                      (s.last_proc_epoch != s.proc_epoch_at_miss_start);
    return true;
}

void HeartbeatSensor::ThreadMain() {
    while (true) {
        // 1. 等待 poll_interval 或 stop/suspended 信号
        {
            std::unique_lock<std::mutex> lock(cv_mutex_);
            cv_.wait_for(lock, config_.poll_interval, [this] {
                return stop_flag_.load(std::memory_order_acquire) ||
                       (publisher_ && publisher_->IsSuspended());
            });
        }

        if (stop_flag_.load(std::memory_order_acquire)) return;

        // 2. 处理 suspended：重置基线，park 等待 resume
        if (publisher_ && publisher_->IsSuspended()) {
            {
                std::lock_guard<std::mutex> lock(state_mutex_);
                for (auto& s : worker_states_) {
                    s.armed            = false;
                    s.consecutive_miss = 0;
                }
            }
            publisher_->ParkUntilResumed();
            if (stop_flag_.load(std::memory_order_acquire)) return;
            continue;
        }

        // 3. round-robin 轮询；先在锁内收集 Report 再锁外 Publish
        struct Report {
            uint32_t      wid;
            CrashFragment fragment;
            // [diag] 判死时的快照，用于锁外 HostLogger
            uint64_t      last_counter = 0;
            uint64_t      current_counter = 0;
            uint32_t      consecutive_miss = 0;
            // [心跳重定义] counter 现在是进度令牌（不透明哈希），单看它说明不了任何事。
            //   真正有诊断价值的是令牌的分量，它能区分心跳时代永远分不清的两种情况：
            //     proc_epoch 相比派活时 **变了** → daemon 是活的，watchdog 到点去轮换了
            //       domain，卡的是**被测程序**（内核里大概率有个 D 住的 task）
            //     proc_epoch **纹丝不动**        → 连自救都没做 → 卡的是 **daemon 自己**
            //   两者的正确处置完全不同，所以必须落进判死日志。
            refuzz::core::channel_contract::WorkerSlotState slot{};
            uint32_t      proc_epoch = 0;
            uint32_t      guest_state = 0;
        };
        std::vector<Report> to_report;

        {
            std::lock_guard<std::mutex> lock(state_mutex_);
            const auto n = static_cast<uint32_t>(worker_states_.size());
            if (n == 0) continue;

            // workers_per_round=0 约定为"刷全部"——默认路径,避免大集群 polling 压力由
            // 配置显式降级(设置为 >0 的 round-robin 值)。
            const uint32_t steps = (config_.workers_per_round == 0)
                ? n
                : std::min(config_.workers_per_round, n);

            for (uint32_t i = 0; i < steps; ++i) {
                uint32_t wid = (cursor_worker_id_ + i) % n;
                auto& state  = worker_states_[wid];
                if (!state.observed) continue;

                auto sample = cp_->SampleHeartbeat(wid);
                if (!sample.valid) continue;

                // 面板要的分量:每轮无条件留存。放在下面几个 early-continue 之前 ——
                // 否则 !armed / grace 分支下面板读到的是上一轮的陈旧值。
                state.last_slot       = sample.slot;
                state.last_proc_epoch = sample.proc_epoch;

                if (!state.armed) {
                    state.last_counter = sample.counter;
                    state.armed        = true;
                    // 基线建立轮也算一次 grace 消耗(避免"基线轮 + grace 轮"叠加)。
                    if (state.grace_rounds_left > 0) state.grace_rounds_left--;
                    continue;
                }

                // [Rearm grace] 先看是否在宽容期:grace_rounds_left > 0 时,即使 counter
                //   未变化,也只刷新基线,不累 consecutive_miss。原本用来吸收"新 worker 冷
                //   启动期间心跳线程被 vCPU 争抢饿一段时间";心跳重定义后没有那个线程了,
                //   这层已不吃重(误判与否由 miss_threshold 决定),留着无害。
                //   grace 期间如果 counter 推进了,也同步更新 last_counter(跟稳态等价)。
                if (state.grace_rounds_left > 0) {
                    state.last_counter     = sample.counter;
                    state.consecutive_miss = 0;
                    state.grace_rounds_left--;
                    continue;
                }

                if (sample.counter != state.last_counter) {
                    state.last_counter    = sample.counter;
                    state.consecutive_miss = 0;
                    // [聚合时钟只由 completion 喂,不再由心跳喂] 心跳现在是 SCHED_FIFO 实时线程,
                    //   只要进程活着就一直推进(=存在性信号),若也喂聚合时钟,Detector A 的
                    //   "聚合冻结→vm_dead" 会永不触发 → 全局 5min 兜底失效。聚合时钟 = 真实
                    //   进度(completion,channel.cpp DrainTransport 喂);心跳 = 进程存在(本
                    //   sensor 判 per-worker 死)。两者解耦,对齐 syz "NoOutput 由执行重置"。
                } else {
                    state.consecutive_miss++;
                    if (state.consecutive_miss == 1) {
                        // [检测器 B] 进入连续 miss：快照聚合前进时钟，作相对判定起点。
                        if (progress_clock_ != nullptr) {
                            state.miss_start_progress_us = progress_clock_->LastUs();
                        }
                        // 同时快照 proc_epoch：与当前值一比就知道 daemon 在这段静默里有没有
                        // 去轮换 domain(= 有没有在自救)。面板用它把"静默 60s"解释清楚 ——
                        // 涨了=卡的是被测程序(合法),冻着=卡的是 daemon 自己。
                        state.proc_epoch_at_miss_start = state.last_proc_epoch;
                    }
                    if (state.consecutive_miss >= config_.miss_threshold) {
                        // [检测器 B 相对进度门控] 仅当注入了聚合时钟时启用（有时钟的
                        //   后端=ivshmem/linux）；无时钟的后端退回纯绝对墙钟判定。
                        //   本 worker 整窗冻结期间，聚合前进时钟（别的 worker 心跳 /
                        //   completion）有没有推进？
                        //   - 推进了：guest 在跑、唯独这个 worker 不动 → 真卡 → 上报。
                        //   - 没推进：聚合也冻着 = 全局停顿（2 vCPU 抢占等），不是本
                        //     worker 的锅 → 不上报，重启相对窗口，VM 整体死没死交给
                        //     检测器 A（VmAliveSensor 聚合冻结 + vm_dead_timeout）。
                        if (progress_clock_ != nullptr &&
                            progress_clock_->LastUs() <= state.miss_start_progress_us) {
                            refuzz::logging::HostLogger::Instance().Log(
                                "HeartbeatSensor",
                                "worker_stall_global_suppressed",
                                {refuzz::logging::Field("worker_id", wid),
                                 refuzz::logging::Field("consecutive_miss",
                                     state.consecutive_miss),
                                 refuzz::logging::Field("miss_threshold",
                                     config_.miss_threshold),
                                 refuzz::logging::Field("ts_us", NowUs())});
                            state.consecutive_miss = 0;  // 重启相对窗口
                            continue;
                        }
                        // [D13] worker dead 探测点 — 心跳累计连续 miss
                        // 到 threshold,即将上报 CrashKind::kWorkerDead。
                        // 这一行让运行时直接在 host log 看到判死时刻 + 工
                        // 干 (consecutive_miss / last_counter / threshold),
                        // 不再依赖事后解析 host_events.txt 的 CrashPipeline。
                        refuzz::logging::HostLogger::Instance().Log(
                            "HeartbeatSensor",
                            "worker_dead_detected",
                            {refuzz::logging::Field("worker_id", wid),
                             refuzz::logging::Field("consecutive_miss",
                                 state.consecutive_miss),
                             refuzz::logging::Field("miss_threshold",
                                 config_.miss_threshold),
                             refuzz::logging::Field("last_counter",
                                 state.last_counter),
                             refuzz::logging::Field("current_counter",
                                 sample.counter),
                             // 令牌分量:回答"卡的是 daemon 还是被测程序"
                             refuzz::logging::Field("slot",
                                 refuzz::core::channel_contract::WorkerSlotStateName(sample.slot)),
                             refuzz::logging::Field("proc_epoch", sample.proc_epoch),
                             refuzz::logging::Field("guest_state", sample.guest_state),
                             refuzz::logging::Field("ts_us", NowUs())});

                        CrashFragment fragment;
                        fragment.kind             = CrashKind::kWorkerDead;
                        fragment.source_worker_id = wid;
                        fragment.type             = refuzz::channel::CrashType::kUnknown;
                        fragment.title            = "worker heartbeat stalled";

                        // [§3.11-B 移除] 原先在此抓 console 快照当"内核 hint"证据,现移除。
                        //   (1) 停摆瞬间内核 watchdog 通常还没 fire,抓到的是空/旧 console;
                        //   (2) 与 ConsoleSensor(串口唯一权威 reader)抢采同一份证据(冲突);
                        //   (3) 可能抓到同 channel 上其它 incident 的 console 回响 → 误判标题
                        //       (正是 §3.11-A 警告的那种回响)。而且心跳 origin 不是
                        //       kSerialPattern,§3.11-A 的 kWorkerDead→kKernelCrash 升级本就
                        //       不吃这份抓取,它顶多污染 title。
                        // 内核 hang 的检测/分类/命名统一交给 ConsoleSensor 的 live 解析
                        //   (已支持 hung_task / rcu stall / softlockup 等模式);心跳只上报
                        //   "worker 存活丢失"。fragment.serial_lines / console_output 留空。

                        if (config_.capture_step_events && step_source_ != nullptr
                            && step_source_->IsAvailable()) {
                            fragment.step_event_snapshot = step_source_->Snapshot();
                        }
                        // [diag] 捕获判死快照
                        Report r;
                        r.wid              = wid;
                        r.fragment         = std::move(fragment);
                        r.last_counter     = state.last_counter;
                        r.current_counter  = sample.counter;
                        r.consecutive_miss = state.consecutive_miss;
                        r.slot             = sample.slot;
                        r.proc_epoch       = sample.proc_epoch;
                        r.guest_state      = sample.guest_state;
                        to_report.push_back(std::move(r));

                        // 内部置 observed=false，防止在上层 Sync 前重复上报
                        state.observed          = false;
                        state.armed             = false;
                        state.consecutive_miss  = 0;
                        state.grace_rounds_left = 0;
                    }
                }
            }
            cursor_worker_id_ = (cursor_worker_id_ + steps) % n;
        }

        // 4. 锁外 Publish
        if (publisher_ == nullptr) continue;
        for (auto& r : to_report) {
            // [diag] 判死时打一条：counter 是否推进是区分 A(worker 真挂) / B(时序太紧) 的关键
            refuzz::logging::HostLogger::Instance().Log(
                "HeartbeatSensor",
                "stall_detected",
                {refuzz::logging::Field("worker_id", r.wid),
                 refuzz::logging::Field("last_counter", r.last_counter),
                 refuzz::logging::Field("current_counter", r.current_counter),
                 refuzz::logging::Field("consecutive_miss", r.consecutive_miss),
                 refuzz::logging::Field("miss_threshold", config_.miss_threshold),
                 // 令牌分量:回答"卡的是 daemon 还是被测程序"
                 refuzz::logging::Field("slot",
                     refuzz::core::channel_contract::WorkerSlotStateName(r.slot)),
                 refuzz::logging::Field("proc_epoch", r.proc_epoch),
                 refuzz::logging::Field("guest_state", r.guest_state),
                 refuzz::logging::Field("ts_us", NowUs())});

            CrashEvent ev;
            ev.event_id       = 0;  // HealthMonitor::Publish 会填
            ev.origin         = CrashEventOrigin::kHeartbeat;
            ev.vm_epoch       = 0;  // HealthMonitor::Publish 会填
            ev.detected_ts_us = NowUs();
            ev.fragment       = std::move(r.fragment);
            ev.checker_name.clear();
            ev.errno_value    = 0;
            publisher_->Publish(std::move(ev));

            // Sensor 明确知道 wid 死亡，主动更新 alive bitmap
            publisher_->SetWorkerAlive(r.wid, false);
        }
    }
}

} // namespace refuzz::channel::health

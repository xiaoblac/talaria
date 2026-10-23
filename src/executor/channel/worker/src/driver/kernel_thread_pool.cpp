// Copyright 2026 reFuzz project author -------youngkk.
//
// KernelThreadPool implementation — see header for design.

#include "worker/driver/kernel_thread_pool.hpp"
#include "worker/log/log_macros.hpp"
#include "worker/perf/worker_perf.hpp"

#include <cerrno>
#include <cassert>
#include <pthread.h>
#include <unistd.h>
#include <utility>

namespace refuzz::worker {

namespace {

// state machine values 见 WorkerThread::State 下方。集中 enum 值确保
// 不被 padding 重排 / 误判。
enum class WorkerState : std::uint8_t {
    kIdle           = 0,  // 等下条 cmd
    kPendingCmd     = 1,  // main 写了 cmd,等 worker 拾起
    kBusy           = 2,  // worker 处理中
    kDone           = 3,  // worker 完成,等 main 读 out + ack
    kExitRequested  = 4,  // dtor 信号,worker 退出
};

enum class WorkerCmd : std::uint8_t {
    kCall    = 0,
    kEndTask = 1,
    kExit    = 2,
};

constexpr std::size_t kWorkerThreadStackBytes = 128u << 10;

}  // namespace

// ---- WorkerThread —————————————————————————————————————————————
//
// 单 thread 状态机 + per-thread 资源(KcovCollector borrow,
// PseudoRuntimeContext owned)。线程同步用 cv + state enum;driver 只在
// syzkaller threaded mode 下使用这个池,可同时让多个 tid 处于 Busy/Done。
struct KernelThreadPool::WorkerThread {
    explicit WorkerThread(
        int tid_in,
        IKcovCollectorProvider* kcov_provider,
        IDispatcher* dispatcher,
        const refuzz::fuzzer::syz::SyzTargetTables* target_tables,
        uint32_t proc_slot_id,
        InjectFaultFn   inject_fault_fn,
        FaultInjectedFn fault_injected_fn)
        : tid(tid_in)
        , kcov_provider_(kcov_provider)
        , dispatcher_(dispatcher)
        , inject_fault_fn_(inject_fault_fn)
        , fault_injected_fn_(fault_injected_fn)
        , ctx(target_tables, proc_slot_id)
    {}

    ~WorkerThread()
    {
        // RequestExit 应在 ~KernelThreadPool 显式调过。这里保留兜底，避免
        // 测试/异常路径提前析构时留下 joinable pthread。
        if (th_joinable) {
            RequestExit();
        }
    }

    WorkerThread(const WorkerThread&) = delete;
    WorkerThread& operator=(const WorkerThread&) = delete;

    int tid;

    // 同步原语
    std::mutex              mtx;
    std::condition_variable cv;
    WorkerState             state = WorkerState::kIdle;
    std::atomic<WorkerState> observed_state{WorkerState::kIdle};

    // input(state == kPendingCmd 时由 main 写,worker 拾起)
    WorkerCmd          cmd       = WorkerCmd::kCall;
    WorkerThreadInput  in        = {};
    KcovMode           task_mode = KcovMode::kPc;

    // output (state == kDone 时 main 读)
    WorkerThreadOutput out                 = {};
    std::vector<std::uint64_t> drained;     // for kEndTask
    bool               end_task_succeeded  = false;

    // long-lived
    bool used_in_task = false;   // current task 内 ScheduleCall 过没?
    bool task_active  = false;   // KCOV Begin 已成功调过吗?

    // [sync_gap split 2026-05-22] main 在 TrySubmit 完成 (PublishState
    // kPendingCmd 之后) 写 NowUs(); worker 在 Run() 拿到 cmd 进 kCall 时
    // 读, 算 pickup_gap_us. 写读都 under mtx, 无需 atomic.
    uint64_t schedule_done_us = 0;
    KcovCollector* collector = nullptr;

    // ref'd resources(pool 持,thread borrow)
    IKcovCollectorProvider* kcov_provider_;
    IDispatcher*            dispatcher_;
    InjectFaultFn           inject_fault_fn_;
    FaultInjectedFn         fault_injected_fn_;

    PseudoRuntimeContext    ctx;

    pthread_t th{};
    bool th_joinable = false;

    void Run();
    static void* ThreadMain(void* arg)
    {
        static_cast<WorkerThread*>(arg)->Run();
        return nullptr;
    }

    // main thread API。
    void PublishState(WorkerState next)
    {
        state = next;
        observed_state.store(next, std::memory_order_release);
    }

    bool IsDone() const
    {
        return observed_state.load(std::memory_order_acquire) ==
               WorkerState::kDone;
    }

    bool Spawn()
    {
        // lazy spawn — 第一次需要该 thread 时调。
        if (th_joinable) {
            return true;
        }
        pthread_attr_t attr;
        if (pthread_attr_init(&attr) != 0) {
            return false;
        }
        if (pthread_attr_setstacksize(&attr, kWorkerThreadStackBytes) != 0) {
            pthread_attr_destroy(&attr);
            return false;
        }
        int rc = 0;
        for (int i = 0; i < 100; ++i) {
            rc = pthread_create(&th, &attr, &WorkerThread::ThreadMain, this);
            if (rc == 0) {
                th_joinable = true;
                pthread_attr_destroy(&attr);
                return true;
            }
            if (rc == EAGAIN) {
                usleep(50);
                continue;
            }
            break;
        }
        pthread_attr_destroy(&attr);
        return false;
    }

    // [sync 优化 2026-05-22] 三处统一改造:
    //   1. notify_all → notify_one (每 worker 1 cv, main/worker 单 waiter)
    //   2. notify 移出 mtx (避免 wake 后 waiter 立刻竞争同 lock 再 block)
    //   3. 记 schedule_done_us / done_ready_us 拆 sync_gap
    bool TrySubmit(WorkerCmd c, const WorkerThreadInput* in_ptr, KcovMode mode)
    {
        {
            std::unique_lock<std::mutex> lk(mtx);
            if (state != WorkerState::kIdle) {
                return false;
            }
            cmd = c;
            if (in_ptr != nullptr) {
                in = *in_ptr;
            }
            task_mode = mode;
            if (c == WorkerCmd::kCall) {
                used_in_task = true;
                // [perf gate fix 2026-05-22] 只当 worker 要 measure pickup_gap
                // 时才打点; perf-off 路径 0 NowUs() overhead.
                schedule_done_us = (in_ptr != nullptr && in_ptr->collect_perf)
                    ? ::refuzz::worker::perf::NowUs() : 0;
            }
            PublishState(WorkerState::kPendingCmd);
        }
        cv.notify_one();
        return true;
    }

    bool WaitDone(std::chrono::milliseconds timeout, WorkerThreadOutput* out_ptr)
    {
        std::unique_lock<std::mutex> lk(mtx);
        const bool ok = cv.wait_for(lk, timeout, [this]{
            return state == WorkerState::kDone;
        });
        if (!ok) {
            return false;  // timeout — caller may poll again later.
        }
        if (out_ptr != nullptr) {
            *out_ptr = std::move(out);
        }
        PublishState(WorkerState::kIdle);
        // [dead notify removed 2026-05-22] worker cv.wait predicate ==
        // kPendingCmd || kExitRequested, kIdle 不是 wake 条件. 之前的
        // cv.notify_one() 只会让 worker wake → predicate false → 立刻 sleep,
        // 每 syscall 完成多一次无意义 futex_wake + worker wake-sleep round trip.
        return true;
    }

    bool WaitEndTaskDone(std::vector<std::uint64_t>* drained_out)
    {
        std::unique_lock<std::mutex> lk(mtx);
        // EndTask 不带 timeout(End/EndAsCmp 是 KCOV_DISABLE + memcpy area_,
        // 不会 block syscall)。 thread 健康时立刻完成。
        cv.wait(lk, [this]{ return state == WorkerState::kDone; });
        if (drained_out != nullptr) {
            *drained_out = std::move(drained);
        }
        const bool ok = end_task_succeeded;
        PublishState(WorkerState::kIdle);
        // [dead notify removed 2026-05-22] 同上, kIdle 不 wake worker.
        return ok;
    }

    void RequestExit()
    {
        {
            std::unique_lock<std::mutex> lk(mtx);
            PublishState(WorkerState::kExitRequested);
        }
        cv.notify_one();
        if (th_joinable) {
            pthread_join(th, nullptr);
            th_joinable = false;
        }
    }

    // [sync_gap fast path 2026-05-22] TryTakeDone: 已知 state==kDone 时不进
    // cv.wait_for, 直接 lock + move output + 置 idle. 替代 zero-time
    // WaitCallDone(0) poll 路径. caller 应先 atomic IsDone() 检查.
    bool TryTakeDone(WorkerThreadOutput* out_ptr)
    {
        std::unique_lock<std::mutex> lk(mtx);
        if (state != WorkerState::kDone) {
            return false;  // race: 中间状态变了, caller 走 slow path
        }
        if (out_ptr != nullptr) {
            *out_ptr = std::move(out);
        }
        PublishState(WorkerState::kIdle);
        // [dead notify removed 2026-05-22] kIdle 不 wake worker.
        return true;
    }
};

void KernelThreadPool::WorkerThread::Run()
{
    // 第一次进 Run 时拿 collector;此后跨 task 不变(provider 池稳定)。
    collector = (kcov_provider_ != nullptr) ? kcov_provider_->GetCollector(tid)
                                            : nullptr;
    // Bind the collector into the pseudo runtime context so pseudo handlers
    // can drop a mid-call cursor reset (mirror upstream cover_reset(0) at
    // common_linux.h:3064 / :3171). Stable for thread lifetime — provider
    // pool is stable per kernel_thread_pool.hpp invariants.
    ctx.set_kcov_collector(collector);

    for (;;) {
        WorkerCmd current_cmd;
        WorkerThreadInput current_in;
        KcovMode current_mode;
        uint64_t current_schedule_done_us = 0;
        {
            std::unique_lock<std::mutex> lk(mtx);
            cv.wait(lk, [this]{
                return state == WorkerState::kPendingCmd ||
                       state == WorkerState::kExitRequested;
            });
            if (state == WorkerState::kExitRequested) {
                return;
            }
            current_cmd  = cmd;
            current_in   = in;        // 拷贝走,释放 mtx
            current_mode = task_mode;
            current_schedule_done_us = schedule_done_us;
            PublishState(WorkerState::kBusy);
        }

        if (current_cmd == WorkerCmd::kExit) {
            return;
        }

        if (current_cmd == WorkerCmd::kCall) {
            // [perf 采样 gate fix 2026-05-22] collect_perf=false 时 worker 内
            // 全部 NowUs() 跳过, raw 路径 0 instrumentation overhead. 这是 perf
            // overhead 不对称 bug (之前 main gate 跳, worker unconditional 跑)
            // 的修复. NowUs() = vDSO clock_gettime, KASAN+LOCKDEP kernel 上每
            // 调用 1-5us, 8 个 calls/syscall × 2 syscalls/prog = 80-160us 节省.
            const bool track_perf = current_in.collect_perf;
            const uint64_t worker_t0 =
                track_perf ? ::refuzz::worker::perf::NowUs() : 0;

            WorkerThreadOutput local_out;
            // pickup_gap = worker 进 kCall (worker_t0) - main TrySubmit
            // 完成时 (schedule_done_us). 反映 main→worker handoff 路径成本.
            if (track_perf && current_schedule_done_us != 0 &&
                worker_t0 > current_schedule_done_us) {
                local_out.pickup_gap_us = worker_t0 - current_schedule_done_us;
            }

            if (collector != nullptr && !task_active) {
                const uint64_t t = track_perf ?
                    ::refuzz::worker::perf::NowUs() : 0;
                if (collector->Enabled() && collector->Begin(current_mode)) {
                    task_active = true;
                    if (current_mode == KcovMode::kPc) {
                        collector->BeginCallSession();
                    }
                } else if (collector->ChildMode() ==
                           KcovChildMode::kInheritedFromLoop) {
                    local_out.kcov_failed = true;
                }
                if (track_perf) {
                    local_out.kcov_begin_us =
                        ::refuzz::worker::perf::NowUs() - t;
                }
            }

            local_out.has_kcov = (collector != nullptr && task_active);
            if (!local_out.kcov_failed) {
                ctx.set_diagnostic_executor_id(current_in.executor_id);

            // per-call KCOV boundary — PC mode only.
            if (collector != nullptr && task_active) {
                const uint64_t t = track_perf ?
                    ::refuzz::worker::perf::NowUs() : 0;
                collector->ResetForCall();
                if (track_perf) {
                    local_out.kcov_reset_us =
                        ::refuzz::worker::perf::NowUs() - t;
                }
                // [kcov-window log suppression] 同 kernel_wire_driver:窗口内
                // 静默 WorkerLog 避免 handler log → ttyS0 → kernel tty PC 污染。
                // thread_local flag,每 worker 线程独立。
                ::refuzz::worker::log::SetWorkerLogSuppressed(true);
            }

            // fault inject — 在 worker thread 内 open /proc/thread-self/fail-nth.
            int fail_fd = -1;
            if (current_in.fail_nth > 0 && inject_fault_fn_ != nullptr) {
                const uint64_t t = track_perf ?
                    ::refuzz::worker::perf::NowUs() : 0;
                fail_fd = inject_fault_fn_(static_cast<int>(current_in.fail_nth));
                if (track_perf) {
                    local_out.fault_inject_us =
                        ::refuzz::worker::perf::NowUs() - t;
                }
            }

            // dispatch — 真 syscall + pseudo handler.
            const uint64_t dispatch_t0 = track_perf ?
                ::refuzz::worker::perf::NowUs() : 0;
            PseudoResult r = dispatcher_->Dispatch(
                current_in.call_nr,
                current_in.args,
                current_in.argc,
                &ctx);
            if (track_perf) {
                local_out.dispatch_us =
                    ::refuzz::worker::perf::NowUs() - dispatch_t0;
            }

            // per-call collect — zero-copy view.
            if (collector != nullptr && task_active) {
                const uint64_t t = track_perf ?
                    ::refuzz::worker::perf::NowUs() : 0;
                auto view = collector->CollectForCallView();
                local_out.per_call_cov_data = view.data;
                local_out.per_call_cov_size = view.size;
                if (track_perf) {
                    local_out.kcov_collect_us =
                        ::refuzz::worker::perf::NowUs() - t;
                }
                // [kcov-window log suppression] 出窗口恢复。
                ::refuzz::worker::log::SetWorkerLogSuppressed(false);
            }
            local_out.cov_entries = local_out.per_call_cov_size;

                local_out.ret = static_cast<int64_t>(r.ret);
                local_out.err = r.err;
                if (fail_fd >= 0 && fault_injected_fn_ != nullptr) {
                    const uint64_t t = track_perf ?
                        ::refuzz::worker::perf::NowUs() : 0;
                    local_out.fault_injected = fault_injected_fn_(fail_fd);
                    if (track_perf) {
                        local_out.fault_check_us =
                            ::refuzz::worker::perf::NowUs() - t;
                    }
                } else {
                    local_out.fault_injected = false;
                }
            } else {
                local_out.ret = -1;
                local_out.err = EIO;
            }

            // done_ready_us = worker 真正完成时间, main 在 WaitDone 返回后
            // 会算 done_gap = NowUs() - done_ready_us.
            const uint64_t worker_done_t = track_perf ?
                ::refuzz::worker::perf::NowUs() : 0;
            if (track_perf) {
                local_out.worker_total_us = worker_done_t - worker_t0;
                local_out.done_ready_us = worker_done_t;
            }

            {
                std::unique_lock<std::mutex> lk(mtx);
                // [teardown race fix] RequestExit() (pool dtor) may have set
                // kExitRequested while we were inside a long / never-completing
                // Dispatch (e.g. a blocked syscall the driver gave up on at the
                // end-drain deadline). Honor it here instead of clobbering it
                // with kDone: otherwise we loop back to cv.wait() whose predicate
                // (kPendingCmd||kExitRequested) is already false (state==kDone)
                // and RequestExit()'s notify_one already fired before we
                // re-waited, so pthread_join() would block forever. Mirrors the
                // kExitRequested check at the top of the loop, for the
                // mid-dispatch case.
                if (state == WorkerState::kExitRequested) {
                    return;
                }
                out = std::move(local_out);
                PublishState(WorkerState::kDone);
            }
            // [sync 优化 2026-05-22] notify_one + unlock 后 notify: 避免 main
            // 被 wake 后立刻竞争 worker 还持的 lock。
            cv.notify_one();
            continue;
        }

        if (current_cmd == WorkerCmd::kEndTask) {
            std::vector<std::uint64_t> local_drained;
            bool ok = false;
            if (collector != nullptr && task_active) {
                if (current_mode == KcovMode::kCmp) {
                    collector->EndAsCmp(&local_drained);
                } else {
                    collector->End(&local_drained);
                }
                task_active = false;
                ok = true;
            } else {
                // 该 thread 本 task 没用过,drained 空。视作"成功 no-op"。
                ok = true;
            }
            // Cleanup ctx — 释放 owned_fds / cleanup_callbacks / named_regions。
            ctx.Cleanup();

            {
                std::unique_lock<std::mutex> lk(mtx);
                drained = std::move(local_drained);
                end_task_succeeded = ok;
                PublishState(WorkerState::kDone);
                cv.notify_all();
            }
            continue;
        }
    }
}

// ---- KernelThreadPool —————————————————————————————————————————

KernelThreadPool::KernelThreadPool(
    int size,
    IKcovCollectorProvider* kcov_provider,
    IDispatcher* dispatcher,
    const refuzz::fuzzer::syz::SyzTargetTables* target_tables,
    uint32_t proc_slot_id,
    InjectFaultFn   inject_fault_fn,
    FaultInjectedFn fault_injected_fn)
    : kcov_provider_(kcov_provider)
    , dispatcher_(dispatcher)
    , target_tables_(target_tables)
    , proc_slot_id_(proc_slot_id)
    , inject_fault_fn_(inject_fault_fn)
    , fault_injected_fn_(fault_injected_fn)
{
    if (size < 1) size = 1;
    // [lazy init] N 个空槽;每个 WorkerThread 在 EnsureWorker(tid)(首次
    // ScheduleCall)时才构造,OS 线程再由 WorkerThread::Spawn() 懒起。
    workers_.resize(static_cast<size_t>(size));
}

KernelThreadPool::WorkerThread& KernelThreadPool::EnsureWorker(int tid)
{
    auto& slot = workers_[static_cast<size_t>(tid)];
    if (!slot) {
        slot = std::make_unique<WorkerThread>(
            tid, kcov_provider_, dispatcher_, target_tables_,
            proc_slot_id_, inject_fault_fn_, fault_injected_fn_);
        // 套用调度前已设置的 per-thread 配置(见 Set*AllThreads),否则中途
        // 懒构造的 worker 会漏掉 loop-mask cursor / defer-mount。
        slot->ctx.set_loop_devices_used_mask_cursor(pending_loop_mask_cursor_);
        slot->ctx.defer_mount_teardown = pending_defer_mount_teardown_;
    }
    return *slot;
}

KernelThreadPool::~KernelThreadPool()
{
    // 通知所有已 spawn 的 thread 退出。未 spawn 的 thread (lazy) 自然无 join。
    // 未构造的空槽(lazy)直接跳过。
    for (auto& w : workers_) {
        if (w) w->RequestExit();
    }
}

void KernelThreadPool::StartTask(KcovMode mode)
{
    current_task_mode_ = mode;
    // mode 在 ScheduleCall / EndTaskAllUsed 时随 cmd 一起传给 worker;
    // 这里只清 used flag + drained。drained 在 TakeThreadDrained 时通常
    // 已 move 走,这里只是兜底防御。
    for (auto& w : workers_) {
        if (!w) continue;  // 未构造的空槽无状态可清
        std::unique_lock<std::mutex> lk(w->mtx);
        w->used_in_task = false;
        w->drained.clear();
    }
}

bool KernelThreadPool::ScheduleCall(int tid, const WorkerThreadInput& in)
{
    if (tid < 0 || static_cast<size_t>(tid) >= workers_.size()) {
        return false;
    }
    // Syzkaller delayed-KCOV keeps 32 logical thread slots but opens fewer
    // coverage fds (kCoverOptimizedCount=8). If a coverage-required call would
    // need a thread without an opened KCOV fd, executor.cc fails instead of
    // running uncovered. Mirror that policy by making such tids unschedulable.
    if (kcov_provider_ != nullptr) {
        const int kcov_slots = kcov_provider_->ThreadCount();
        if (kcov_slots <= 0 || tid >= kcov_slots) {
            return false;
        }
    }
    auto& w = EnsureWorker(tid);  // lazy construct on first use
    if (!w.Spawn()) {  // lazy spawn on first use
        return false;
    }
    return w.TrySubmit(WorkerCmd::kCall, &in, current_task_mode_);
}

bool KernelThreadPool::IsCallDone(int tid) const
{
    if (tid < 0 || static_cast<size_t>(tid) >= workers_.size() ||
        !workers_[static_cast<size_t>(tid)]) {
        return false;
    }
    return workers_[tid]->IsDone();
}

bool KernelThreadPool::WaitCallDone(int tid,
                                    std::chrono::milliseconds timeout,
                                    WorkerThreadOutput* out)
{
    if (tid < 0 || static_cast<size_t>(tid) >= workers_.size() ||
        !workers_[static_cast<size_t>(tid)]) {
        return false;
    }
    return workers_[tid]->WaitDone(timeout, out);
}

bool KernelThreadPool::TryTakeDone(int tid, WorkerThreadOutput* out)
{
    if (tid < 0 || static_cast<size_t>(tid) >= workers_.size() ||
        !workers_[static_cast<size_t>(tid)]) {
        return false;
    }
    return workers_[tid]->TryTakeDone(out);
}

void KernelThreadPool::EndTaskAllUsed()
{
    // 先 iterate 把 kEndTask 发出去,再 wait done。已经完成并 ack 回 idle 的
    // used threads 可以并行 drain；仍 Busy/kDone 未 ack 的线程不能强行切状态。
    std::vector<int> end_submitted_tids;
    for (size_t i = 0; i < workers_.size(); ++i) {
        if (!workers_[i]) continue;  // 未构造 = 从未 used_in_task
        auto& w = *workers_[i];
        bool used = false;
        {
            std::unique_lock<std::mutex> lk(w.mtx);
            used = w.used_in_task;
        }
        if (used) {
            // used_in_task 在 ScheduleCall 成功时置位。这里 TrySubmit 失败
            // 表示该 thread 仍 busy 或已完成一个 timed-out call 但没有 main
            // thread ack；不能把它强行切回 idle,否则 KCOV session 会跨 task
            // 泄漏。DoubleFork 下 program child 随后退出；reusable topology 下
            // 该槽位保持不可调度,直到上层回收 child。
            if (w.TrySubmit(WorkerCmd::kEndTask, nullptr, current_task_mode_)) {
                end_submitted_tids.push_back(static_cast<int>(i));
            }
        }
    }
    for (int tid : end_submitted_tids) {
        auto& w = *workers_[tid];
        std::unique_lock<std::mutex> lk(w.mtx);
        // End/EndAsCmp 是 KCOV_DISABLE + area_ copy,不应阻塞;timeout 是
        // 防御性保护,避免异常 worker 状态卡住 child main loop。
        const bool ok = w.cv.wait_for(lk, std::chrono::seconds(10), [&w]{
            return w.state == WorkerState::kDone;
        });
        if (ok) {
            // drained 不在这里 move 走(留给 TakeThreadDrained);状态归 kIdle。
            w.PublishState(WorkerState::kIdle);
            // [dead notify removed 2026-05-22] kIdle 不 wake worker (predicate
            // 是 kPendingCmd || kExitRequested), 之前 notify_one 是 dead wake.
        }
        // ok==false → 放弃 drained,该 worker 后续因 state != kIdle 被跳过。
    }
}

void KernelThreadPool::SetLoopDevicesUsedMaskCursorAllThreads(uint32_t* cursor)
{
    pending_loop_mask_cursor_ = cursor;  // 之后懒构造的 worker 在 EnsureWorker 里套用
    for (auto& worker : workers_) {
        if (worker) worker->ctx.set_loop_devices_used_mask_cursor(cursor);
    }
}

void KernelThreadPool::SetDeferMountTeardownAllThreads(bool defer)
{
    // [R1] Called before scheduling while all usable workers are idle.
    pending_defer_mount_teardown_ = defer;  // 之后懒构造的 worker 在 EnsureWorker 里套用
    for (auto& wp : workers_) {
        if (wp) wp->ctx.defer_mount_teardown = defer;
    }
}

uint32_t KernelThreadPool::TakeAggregatedLoopMask()
{
    // [#15 threaded loop-mask aggregation] 调用时机:ExecuteThreaded 末尾
    // EndTaskAllUsed 之后 —— used thread 已 kEndTask → kDone → kIdle(或 hung
    // 未 ack)。idle 线程的 ctx mask 已被 EndTaskAllUsed 的 w.mtx acquire 同步
    // 可见,可安全读。任一 used thread 仍非 idle(hung/abandoned)→ 整体退回
    // UINT32_MAX(其部分 mask 不可信,保守全扫,绝不漏 pin 着的 loop)。
    // 无条件清零各线程 mask,防跨 program 累积(Cleanup() 不清它)。
    uint32_t agg = 0;
    bool any_hung = false;
    for (auto& wp : workers_) {
        if (!wp) continue;  // 未构造 = 从未 used_in_task
        auto& w = *wp;
        std::unique_lock<std::mutex> lk(w.mtx);
        if (!w.used_in_task) {
            continue;
        }
        if (w.state != WorkerState::kIdle) {
            any_hung = true;
        }
        agg |= w.ctx.LoopDevicesUsedMask();
        w.ctx.ClearLoopDevicesUsedMask();
    }
    return any_hung ? UINT32_MAX : agg;
}

std::vector<std::uint64_t> KernelThreadPool::TakeThreadDrained(int tid)
{
    if (tid < 0 || static_cast<size_t>(tid) >= workers_.size() ||
        !workers_[static_cast<size_t>(tid)]) {
        return {};
    }
    auto& w = *workers_[tid];
    std::unique_lock<std::mutex> lk(w.mtx);
    return std::move(w.drained);
}

bool KernelThreadPool::ThreadUsedInLastTask(int tid) const
{
    if (tid < 0 || static_cast<size_t>(tid) >= workers_.size() ||
        !workers_[static_cast<size_t>(tid)]) {
        return false;
    }
    auto& w = *workers_[tid];
    std::unique_lock<std::mutex> lk(w.mtx);
    return w.used_in_task;
}

bool KernelThreadPool::WorkerDeferMountTeardownForTesting(int tid) const
{
    if (tid < 0 || static_cast<size_t>(tid) >= workers_.size() ||
        !workers_[static_cast<size_t>(tid)]) {
        return false;
    }
    return workers_[tid]->ctx.defer_mount_teardown;
}

}  // namespace refuzz::worker

// Copyright 2026 reFuzz project author -------youngkk.
//
// KernelThreadPool: kernel-family driver 内部的 worker thread 池,为
// IntraTaskMode::kThreaded task 提供 per-thread KCOV fd / per-thread dispatch
// 上下文 (PseudoRuntimeContext)。
//
// 模块位置:driver/ 下,因为线程调度需要理解 wire dispatch 语义
// (IDispatcher / WireCall / call_props / fault inject);engine/ 不知道
// driver internal,放 engine 会破坏分层 (per memory feedback "适配架构
// 三层 — 模块边界 ... driver vs engine 不可破")。
//
// 设计要点:
//   - 池大小固定(KernelWireDriver 构造时传入,profile 配置 default 1)。
//   - **lazy spawn**:thread 在第一次 ScheduleCall(tid) 时 pthread_create,
//     stack size follows upstream syzkaller's 128 KiB executor thread stack;
//     此后跨 task 复用;Cleanup() 由 worker thread 自己在 EndTask 时调,
//     ctx 状态归零,KCOV 通过 collector.End*() 关闭。
//   - **KCOV invariant**:Begin/ResetForCall/CollectForCall/End/EndAsCmp
//     必须在 KCOV_ENABLE 它的 worker thread 调用 (Linux kernel 把 KCOV
//     绑 current task),所以全部下沉到 worker thread main loop。
//   - **fault_inject thread-local**:inject_fault 通过
//     `/proc/thread-self/fail-nth` 内核 API 自动绑 TID;只要 inject_fault
//     / fault_injected 调用在 worker thread 内,就 thread-local 生效,
//     无需改 helper。本 pool 把这两个 helper 调用挪到 worker thread。
//   - **per-call timeout**:WaitCallDone timeout 不改 worker 状态。driver 可
//     之后继续用 WaitCallDone(0) poll 完成；在被 ack 成 kIdle 前,
//     ScheduleCall 看到 state != kIdle 会跳过该槽位。
//   - **task end drain**:main 调 EndTaskAllUsed → 每 used thread 收
//     kEndTask cmd → 在 thread 内 collector.End/EndAsCmp + ctx.Cleanup,
//     drained 缓存在 thread struct;main 通过 TakeThreadDrained(tid) 取出。
//   - **concurrent syscall execution**:driver 可同时 ScheduleCall 到多个
//     idle tid (async / timed-out calls remain in-flight) and later collect
//     completions, matching syzkaller's threaded executor model.
//
// 不在当前范围:
//   - program-child 退出前仍未完成的线程不会在 pool 内强制复活；DoubleFork
//     让整个 program child 退出，等价 syzkaller fork-server test child teardown。

#pragma once

#include "refuzz/program/syz/pseudo/limits.hpp"  // kSyzMaxArgs
#include "refuzz/program/syz/pseudo/target_view.hpp"
#include "worker/backend/pseudo/pseudo_runtime.hpp"
#include "worker/coverage/kcov_collector.hpp"
#include "worker/coverage/kcov_collector_provider.hpp"
#include "worker/dispatcher/dispatcher.hpp"
#include "worker/driver/fault_inject.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <vector>

namespace refuzz::worker {

// 一条 syscall schedule 时 main thread 写,worker thread 读。
// args 是 main thread 在 schedule 时 resolve 完成的 intptr_t 数组,
// 长度 ≤ kSyzMaxArgs;worker thread 不再 touch wire,只跑 dispatch。
struct WorkerThreadInput {
    uint64_t executor_id = 0;
    int      call_index = 0;
    uint64_t call_nr    = 0;
    uint32_t argc       = 0;
    intptr_t args[::refuzz::fuzzer::syz::kSyzMaxArgs] = {};
    // fail_nth: > 0 → worker thread 在 dispatch 前 inject_fault(fail_nth),
    // dispatch 后 fault_injected(fd) 决定 result.fault_injected。0 = skip。
    uint32_t fail_nth   = 0;
    // [perf 采样 gate fix 2026-05-22] worker thread Run() 内每 syscall 走
    // 8+ 个 NowUs() vDSO clock_gettime (kcov_begin/reset/collect + dispatch
    // + fault_inject/check + worker_total)。main 通过 collect_perf gate 跳过,
    // 但 worker 之前 unconditional 跑。设 false 则 worker 也跳, perf-off 时
    // 真正 raw 路径 (zero instrumentation overhead).
    bool     collect_perf = false;
};

// 一条 syscall 完成后 worker thread 写,main thread 在 WaitCallDone 后读。
struct WorkerThreadOutput {
    int64_t  ret             = 0;
    int32_t  err             = 0;
    bool     fault_injected  = false;
    // [当前版本 zero-copy-pc-cov] per-call KCOV slice 以 zero-copy view 返回:
    // worker thread CollectForCallView 取本次 syscall 在 area_ 内的 PC 范围,
    // 不 push_back 也不 vector 分配;主线程 complete_tid → append_call_coverage
    // 直接 memcpy 从 area_ 到 output tail。
    //   per_call_cov_data: 指向 collector area_[per_call_cursor+1] (kcov mmap 内)。
    //                     有效期 = 从 worker 进 kDone 到 main 调 WaitCallDone 后
    //                     再 ScheduleCall 之前(state machine 保证 area_ 不被改)。
    //   per_call_cov_size: 本次 syscall 产生的 PC 条数 (uint64 个数)。
    // CMP mode 或非 PC session 返回 size=0 data=nullptr。
    const std::uint64_t* per_call_cov_data = nullptr;
    std::uint32_t        per_call_cov_size = 0;

    // [当前版本 worker-thread-perf-回传] worker thread 自己在 kCall 分支内量
    // 各段 NowUs() 差,通过 out 字段回传给主线程。主线程在 complete_tid 时
    // AddSaturating 累加到 WorkerPerfSample。语义:
    //   worker_total_us  = 从拾起 cmd 到 set state=Done 的全程
    //                      (含 collector.Begin lazy / fault open / dispatch /
    //                       collect / fault_check)。跟主线程 thread_wait_us
    //                      差值 = condvar wake latency + 调度延迟。
    //   dispatch_us      = dispatcher_->Dispatch 单调用 (真 syscall + pseudo handler)
    //   kcov_reset_us    = collector->ResetForCall() — 通常 ns 级 (area_[0]=0)
    //   kcov_collect_us  = collector->CollectForCallView() — zero-copy view 提取
    //   fault_inject_us  = inject_fault_fn(fail_nth) 当 fail_nth > 0
    //   fault_check_us   = fault_injected_fn(fail_fd) 当 fail_fd >= 0
    //   cov_entries      = per_call_cov_size — 这次 syscall 收的 PC 数
    //   has_kcov         = 该 thread 实际拿到 collector 且 task_active。生产
    //                      threaded+kcov 配置要求每个 worker 都有 collector;
    //                      false 主要覆盖测试 fixture 或 Begin 失败。
    // 所有 us 字段为 0 → worker 没量(perf sample==nullptr 或路径没走)。
    uint64_t worker_total_us = 0;
    uint64_t dispatch_us     = 0;
    uint64_t kcov_reset_us   = 0;
    uint64_t kcov_collect_us = 0;
    uint64_t fault_inject_us = 0;
    uint64_t fault_check_us  = 0;
    // [fork-breakdown 2026-05-21] KCOV Begin (= KCOV_ENABLE ioctl) +
    // BeginCallSession 第一次 call lazy 调用的时间. 通常只有 task 内第一次
    // call 走完整 Begin 路径, 后续 call task_active=true 跳过; per-program
    // 累加值 ≈ 单次 Begin 成本.
    uint64_t kcov_begin_us   = 0;
    // [sync_gap split 2026-05-22] sync_gap 拆 pickup_gap + done_gap:
    //   pickup_gap_us : main TrySubmit 完成 → worker 拿到 cmd 开始 kCall 的延迟
    //                   = main notify_one wake worker + worker 重新 acquire mtx
    //                     + worker 进 kCall 分支前 schedule 延迟
    //   done_ready_us : worker 在 publish kDone 时的 NowUs(), main 在 WaitDone
    //                   返回后算 done_gap = NowUs() - done_ready_us = worker
    //                   notify → main wake + acquire mtx + WaitDone return 的延迟
    uint64_t pickup_gap_us   = 0;
    uint64_t done_ready_us   = 0;
    uint32_t cov_entries     = 0;
    bool     has_kcov        = false;
    bool     kcov_failed     = false;
};

class KernelThreadPool {
public:
    // size: thread 池大小,profile 配置(>=1)。
    // kcov_provider: 借 collector 用,nullptr → KCOV 完全 skip(测试 fixture)。
    // dispatcher: pool 不 own,生命周期由 driver 保证。
    // available_caps: 每个 WorkerThread 自己持的 PseudoRuntimeContext 用。
    // proc_slot_id: driver 的 active execution-domain resource identity,
    //   propagated into every WorkerThread's PseudoRuntimeContext. Same value
    //   per pool — mirrors upstream syzkaller's "one executor procid covers
    //   all its threads" semantics. Pseudo handlers that mirror upstream's
    //   per-process resource naming (e.g. /dev/loop<procid> in
    //   common_linux.h:3054/:3129) read it from PseudoContext.proc_slot_id.
    //   Production: ExecutionEngine assigns proc_id and threads inherit;
    //   oracle replay sets target_proc_id from trace Executing.proc_id. This
    //   remains independent of worker placement and is not a payload attribute.
    // inject_fault_fn / fault_injected_fn: 测试 seam(prod 用 fault_inject.hpp
    //   默认实现);worker thread 内调用,自动 thread-local。
    KernelThreadPool(int size,
                     IKcovCollectorProvider* kcov_provider,
                     IDispatcher* dispatcher,
                     const refuzz::fuzzer::syz::SyzTargetTables* target_tables,
                     uint32_t proc_slot_id,
                     InjectFaultFn   inject_fault_fn,
                     FaultInjectedFn fault_injected_fn);

    ~KernelThreadPool();

    KernelThreadPool(const KernelThreadPool&) = delete;
    KernelThreadPool& operator=(const KernelThreadPool&) = delete;
    KernelThreadPool(KernelThreadPool&&) = delete;
    KernelThreadPool& operator=(KernelThreadPool&&) = delete;

    int Size() const { return static_cast<int>(workers_.size()); }

    // Test-only (lazy init): number of WorkerThread slots actually constructed.
    // A fresh pool is 0; only tids passed to ScheduleCall get built.
    int ConstructedWorkerCountForTesting() const {
        int n = 0;
        for (const auto& w : workers_) {
            if (w) ++n;
        }
        return n;
    }
    // Test-only: read a constructed worker's applied defer-mount-teardown, to
    // verify pre-schedule Set*AllThreads config reaches lazily-built workers.
    bool WorkerDeferMountTeardownForTesting(int tid) const;

    // task lifecycle —— main thread API。
    //
    // StartTask(mode):清 used flag / drained / KCOV mode 给 worker 看;
    //   每个 worker thread 在第一次 ScheduleCall 时按 mode 调 collector.Begin。
    // ScheduleCall(tid, in):写 input → notify worker。state==kIdle 才接受,
    //   leak/busy 状态返 false。
    // IsCallDone(tid):lockless done-state probe,mirrors syzkaller event_isset().
    // WaitCallDone(tid, timeout_ms, *out):wait until kDone;timeout 返 false,
    //   不 ack worker。caller 可稍后再 IsCallDone()+WaitCallDone(0) poll；
    //   在 ack 前 state != kIdle,后续 ScheduleCall 会跳过该 tid。
    // EndTaskAllUsed():iterate used threads,发 kEndTask 让 worker 自己
    //   collector.End/EndAsCmp + ctx.Cleanup,drained 存 thread 内。
    // TakeThreadDrained(tid):从 thread 内部 move out drained。仅在
    //   EndTaskAllUsed 之后调用。
    void StartTask(KcovMode mode);
    bool ScheduleCall(int tid, const WorkerThreadInput& in);
    bool IsCallDone(int tid) const;
    bool WaitCallDone(int tid, std::chrono::milliseconds timeout, WorkerThreadOutput* out);
    // [sync_gap fast path 2026-05-22] 已知 done (IsCallDone()=true) 时直接
    // lock + move output + 置 idle, 不进 cv.wait_for 路径。caller 必须先
    // IsCallDone() 检查; 不是 done 时返 false (race lost). 替代 zero-time
    // WaitCallDone(0) poll 路径减 cv timed-wait machinery。
    bool TryTakeDone(int tid, WorkerThreadOutput* out);
    void EndTaskAllUsed();
    std::vector<std::uint64_t> TakeThreadDrained(int tid);

    bool ThreadUsedInLastTask(int tid) const;

    // [#15 threaded loop-mask aggregation] 每 program(EndTaskAllUsed 之后、所有
    // used thread 已 idle)聚合各线程 ctx 的 loop mask(OR),并清零各线程 mask
    // 防跨 program 累积。任一 used thread 未回到 idle(hung/abandoned)→ 返
    // UINT32_MAX，表示本次诊断 mask 不完整。
    uint32_t TakeAggregatedLoopMask();

    // Bind the shared per-program loop mask before scheduling calls. Each
    // worker context atomically publishes successful loop attachments into it.
    void SetLoopDevicesUsedMaskCursorAllThreads(uint32_t* cursor);

    // [R1 mount/loop teardown locus] Propagate the per-program "teardown deferred
    // to loop_child" decision to every WorkerThread's pseudo ctx, so each thread's
    // MountState::Cleanup skips in-child umount when running under DoubleFork
    // (kForkClean). Invoked before any call is scheduled while threads are idle.
    void SetDeferMountTeardownAllThreads(bool defer);

private:
    struct WorkerThread;
    std::vector<std::unique_ptr<WorkerThread>> workers_;
    IKcovCollectorProvider* kcov_provider_;
    IDispatcher*            dispatcher_;
    const refuzz::fuzzer::syz::SyzTargetTables* target_tables_;
    uint32_t                proc_slot_id_;
    InjectFaultFn           inject_fault_fn_;
    FaultInjectedFn         fault_injected_fn_;
    // [Step 4] StartTask 写,ScheduleCall + EndTaskAllUsed 读。所有 main-thread
    // 调用,无锁。
    KcovMode                current_task_mode_ = KcovMode::kPc;

    // [lazy WorkerThread init — 对齐 syzkaller 固定 thread_t[32] + 懒初始化]
    // workers_ 起始为 N 个空槽(nullptr);EnsureWorker(tid) 在首次
    // ScheduleCall(tid) 时才构造。多数 program 只用 1–2 个 tid,省下 ~30 个
    // 从不使用的 WorkerThread/PseudoRuntimeContext 的构造(每个 ctx 一次 fcntl)。
    // 调度前设置的 per-thread 配置(loop-mask cursor / defer-mount teardown)记在
    // 这里,并在懒构造时套用,保证 program 中途才建的 worker 也拿到。
    WorkerThread& EnsureWorker(int tid);
    uint32_t*               pending_loop_mask_cursor_ = nullptr;
    bool                    pending_defer_mount_teardown_ = false;
};

}  // namespace refuzz::worker

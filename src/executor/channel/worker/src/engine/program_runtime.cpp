// ProgramRuntime 实现 — 一条 program 的执行体 + crash handler 全局状态。
//
// 之前这部分逻辑在 execution_engine.cpp 的 ChildExecuteTask + anonymous
// namespace 里(crash handler globals + engine_child_crash_handler +
// install_engine_child_crash_handlers)。P1 拆分目的:让 ProgramRuntime
// 跟 LoopRuntime 解耦,以便 P4 时 fork-per-program child 复用同一份 inline
// 执行体,不重写 ChildExecuteTask。
//
// 行为约束:byte-equal 现状(Reusable topology 路径)。

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "worker/engine/program_runtime.hpp"

#include "worker/backend/exec_backend.hpp"
#include "worker/engine/execution_engine.hpp"  // ChildExecuteTask 仍 declared 在这里
#include "worker/engine/fork_server_reaper.hpp"
#include "worker/exec_mode.hpp"
#include "worker/log/log_macros.hpp"
#include "worker/observation/observation_bus.hpp"
#include "worker/perf/worker_perf.hpp"
#include "worker/sandbox/device_init/device_init.hpp"
#include "worker/topology/topology_probe.hpp"

#include "refuzz/proto_wire/ivshmem_protocol.h"  // now_us / task_flags_get_collect_comps

#include <errno.h>
#include <execinfo.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/eventfd.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <cstdlib>

#define LOG(fmt, ...) ::refuzz::worker::log::WorkerLog("[Worker] " fmt "\n", ##__VA_ARGS__)

namespace refuzz::worker::engine {

namespace {

// [ExecTL round-2] sample this process's consumed CPU and the main thread's
// cumulative runqueue wait (/proc/self/schedstat; needs CONFIG_SCHED_INFO,
// reads 0 when absent). Both start ~0 at fork, so the values at B are the
// child-setup split and C-B is the execution split:
// wall = cpu + runqueue + blocked.
void TlCpuSample(uint64_t* cpu_us, uint64_t* rq_us)
{
    *cpu_us = 0;
    *rq_us = 0;
    if (!::refuzz::worker::perf::Enabled()) {
        return;
    }
    struct timespec ts;
    if (::clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts) == 0) {
        *cpu_us = static_cast<uint64_t>(ts.tv_sec) * 1000000ULL +
                  static_cast<uint64_t>(ts.tv_nsec) / 1000ULL;
    }
    const int fd = ::open("/proc/self/schedstat", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return;
    }
    char buf[96] = {};
    const ssize_t n = ::read(fd, buf, sizeof(buf) - 1);
    ::close(fd);
    if (n <= 0) {
        return;
    }
    char* end = nullptr;
    (void)::strtoull(buf, &end, 10);
    if (end != nullptr) {
        *rq_us = ::strtoull(end, nullptr, 10) / 1000ULL;
    }
}

// crash handler 跨 signal-handler 边界访问的全局状态。
// fork 后 program child 继承(POSIX signal handler 跨 fork 保留),
// ProgramRuntimeRunInline 每条 prog 入口刷新指针;snapshot 路径异步安全。
IObservationBus* g_engine_bus = nullptr;
uint8_t* g_engine_child_output_buf = nullptr;
uint32_t g_engine_child_output_cap = 0;
uint32_t* g_engine_child_crash_output_len = nullptr;

class ReaperStatsAccumulator {
public:
    void Add(uint32_t worker_id,
             const ForkServerReaperStats& sample,
             bool force_report)
    {
        ++tasks_;
        totals_.descendants_reaped += sample.descendants_reaped;
        totals_.stopped_children_killed += sample.stopped_children_killed;
        totals_.outer_fork_eagain += sample.outer_fork_eagain;
        totals_.harness_fatal += sample.harness_fatal;
        if (force_report || tasks_ % 4096 == 0) {
            ::refuzz::worker::log::WorkerLog(
                "[WorkerReaper] wid=%u tasks=%llu descendants_reaped=%llu "
                "stopped_children_killed=%llu outer_fork_eagain=%llu "
                "harness_fatal=%llu\n",
                worker_id,
                static_cast<unsigned long long>(tasks_),
                static_cast<unsigned long long>(totals_.descendants_reaped),
                static_cast<unsigned long long>(totals_.stopped_children_killed),
                static_cast<unsigned long long>(totals_.outer_fork_eagain),
                static_cast<unsigned long long>(totals_.harness_fatal));
        }
    }

private:
    std::uint64_t tasks_ = 0;
    ForkServerReaperStats totals_{};
};

ReaperStatsAccumulator& ReaperAccumulator()
{
    static ReaperStatsAccumulator accumulator;
    return accumulator;
}

const char* HarnessFatalReasonName(HarnessFatalReason reason)
{
    switch (reason) {
    case HarnessFatalReason::kNone: return "none";
    case HarnessFatalReason::kOuterForkEagain: return "outer_fork_eagain";
    case HarnessFatalReason::kOuterForkFailed: return "outer_fork_failed";
    case HarnessFatalReason::kMainChildReapFailed: return "main_child_reap_failed";
    case HarnessFatalReason::kStoppedDescendantReapTimeout:
        return "stopped_descendant_reap_timeout";
    case HarnessFatalReason::kForkServerProtocol: return "fork_server_protocol";
    case HarnessFatalReason::kDomainWatchdogTimeout:
        return "domain_watchdog_timeout";
    case HarnessFatalReason::kExecutionDomainCleanupFailed:
        return "execution_domain_cleanup_failed";
    case HarnessFatalReason::kKcovStateInvalid:
        return "kcov_state_invalid";
    }
    return "unknown";
}

void SetHarnessFatal(DoneMsg* done, HarnessFatalReason reason)
{
    done->output_len = 0;
    done->status = -1;
    done->flags = 0;
    done->result_kind = RuntimeResultKind::kHarnessFatal;
    done->crash_signal = 0;
    done->fatal_reason = reason;
}

bool EnvFlagEnabled(const char* name)
{
    const char* v = std::getenv(name);
    return v != nullptr && v[0] == '1' && v[1] == '\0';
}

bool EmptyForkBenchEnabled()
{
    return EnvFlagEnabled("REFUZZ_EMPTY_FORK_BENCH");
}



// 跨进程读取 result page 的 (executor_id, dispatch_gen)。program child 在
// CommitResultPage 里先写这两个字段、再 release-store state；这里用 acquire
// load 才能跟那个 release 形成 happens-before。x86 TSO 下普通 load 也碰巧正确，
// 但 ARM/RISC-V 上必须 acquire；统一上 acquire 零成本（x86 release-store +
// acquire-load 都是普通 mov）且消除 UB。
bool ResultPageMatches(const ProgramResultPageV3* page,
                       uint64_t executor_id,
                       uint32_t dispatch_gen)
{
    if (page == nullptr) return false;
    const uint64_t page_eid =
        __atomic_load_n(&page->executor_id, __ATOMIC_ACQUIRE);
    const uint32_t page_gen =
        __atomic_load_n(&page->dispatch_gen, __ATOMIC_ACQUIRE);
    return page_eid == executor_id && page_gen == dispatch_gen;
}

uint32_t LoadPublishedLoopDevicesUsedMask(const ProgramResultPageV3* page,
                                          uint64_t executor_id,
                                          uint32_t dispatch_gen)
{
    if (!ResultPageMatches(page, executor_id, dispatch_gen)) {
        return UINT32_MAX;
    }
    return __atomic_load_n(&page->loop_devices_used_mask, __ATOMIC_ACQUIRE);
}

// [early-publish] committed 判定:executor_id/dispatch_gen 匹配 + state==COMMITTED
// + commit_seq!=0,全部 acquire load,与 CommitResultPage 的 release store 形成
// happens-before。InitProgramResultPage 每轮 fork 前把 state/commit_seq 归零,所以
// reap 之前在 watchdog 循环里轮询它不会误读上一条 program 的 stale commit。
bool ResultPageCommitted(const ProgramResultPageV3* page,
                         uint64_t executor_id,
                         uint32_t dispatch_gen)
{
    return ResultPageMatches(page, executor_id, dispatch_gen) &&
           program_result_load_state_v3(page) == PROGRAM_RESULT_COMMITTED &&
           program_result_load_commit_seq_v3(page) != 0;
}

// [early-publish] 把 committed result page 的功能字段 + child 时间戳快照进 DoneMsg。
// 两处复用:watchdog 循环检测到 commit 时的提前投递(reap 之前),以及 reap 之后的
// committed 读取。parent 侧遥测(fork/reap/rusage)由 caller 在 reap 后另填 —— 提前
// 投递给 daemon 的 DoneMsg 不带这些,daemon 也不消费它们。
void FillDoneFromCommittedPage(const ProgramResultPageV3* page,
                               uint64_t executor_id,
                               uint32_t dispatch_gen,
                               DoneMsg* out)
{
    out->output_len = page->output_len;
    out->status = page->status;
    out->flags = page->flags;
    out->result_kind = static_cast<RuntimeResultKind>(page->result_kind);
    out->crash_signal = page->crash_signal;
    out->fatal_reason = static_cast<HarnessFatalReason>(page->fatal_reason);
    out->loop_devices_used_mask =
        LoadPublishedLoopDevicesUsedMask(page, executor_id, dispatch_gen);
    out->tl_b_ts_us = page->tl_b_ts_us;
    out->tl_c_ts_us = page->tl_c_ts_us;
    out->tl_b_cpu_us = page->tl_b_cpu_us;
    out->tl_b_rq_us = page->tl_b_rq_us;
    out->tl_c_cpu_us = page->tl_c_cpu_us;
    out->tl_c_rq_us = page->tl_c_rq_us;
}

void CommitResultPage(ProgramResultPageV3* page,
                      uint64_t executor_id,
                      uint32_t dispatch_gen,
                      const DoneMsg& done,
                      ::refuzz::worker::perf::WorkerPerfSample* perf)
{
    if (page == nullptr) {
        return;
    }
    const uint64_t publish_start_us =
        perf != nullptr ? ::refuzz::worker::perf::NowUs() : 0;
    page->executor_id = executor_id;
    page->dispatch_gen = dispatch_gen;
    page->result_kind = static_cast<uint32_t>(done.result_kind);
    page->status = done.status;
    page->flags = done.flags;
    page->output_len = done.output_len;
    page->crash_signal = done.crash_signal;
    page->fatal_reason = static_cast<uint32_t>(done.fatal_reason);
    // [Step A] surface precision-sweep mask from program-child → loop-child
    // via shared result page. loop-child copies back into DoneMsg on read.
    __atomic_store_n(&page->loop_devices_used_mask,
                     done.loop_devices_used_mask,
                     __ATOMIC_RELEASE);
    if (done.result_kind == RuntimeResultKind::kCrash) {
        page->crash_len = done.output_len;
    }
    page->tl_b_ts_us = done.tl_b_ts_us;
    page->tl_c_ts_us = done.tl_c_ts_us;
    page->tl_b_cpu_us = done.tl_b_cpu_us;
    page->tl_b_rq_us = done.tl_b_rq_us;
    page->tl_c_cpu_us = done.tl_c_cpu_us;
    page->tl_c_rq_us = done.tl_c_rq_us;
    page->perf_valid = perf != nullptr ? 1U : 0U;
    if (perf != nullptr) {
        ::refuzz::worker::perf::StoreWorkerPerfSampleV3(&page->perf, *perf);
        const uint64_t ready_us = ::refuzz::worker::perf::NowUs();
        const uint64_t finish_start_us = perf->runtime_end_ts_us != 0
            ? perf->runtime_end_ts_us
            : publish_start_us;
        page->perf.child_finish_us = ready_us - finish_start_us;
        page->perf.result_ready_ts_us = ready_us;
    }
    program_result_store_commit_seq_v3(page, 1);
    program_result_store_state_v3(page, PROGRAM_RESULT_COMMITTED);
}

void engine_child_crash_handler(int sig)
{
    // [v2 R2] bus 替代单 collector;crash snapshot 协调多 sink
    if (g_engine_bus != nullptr &&
        g_engine_child_output_buf != nullptr &&
        g_engine_child_crash_output_len != nullptr) {
        const uint32_t crash_out_len = g_engine_bus->SnapshotAllForCrash(
            g_engine_child_output_buf, g_engine_child_output_cap);
        // RELEASE-store 对偶 loop child 在 crash 分支里的 acquire-load
        // (program_runtime.cpp 读 page->crash_len + adapter.cpp::GetCrashOutputLen)。
        // signal handler 内 syscall-safe，async-safety 由内核 store atomicity
        // 保证；__atomic_store_n 在 4 字节对齐 uint32 上 lock-free 等价于
        // 普通 mov + compiler 屏障。
        __atomic_store_n(g_engine_child_crash_output_len,
                         crash_out_len,
                         __ATOMIC_RELEASE);
    }
    ::refuzz::worker::log::WorkerCrashLogSignalAsyncSafe(sig);
    // 仅 5 个真代码 bug 信号 dump backtrace 到 ttyS0(SIGTERM 等控制信号不打,
    // 避免污染 console)。逻辑跟 execution_engine.cpp 旧 v2 PR-G 完全一致,
    // 这里搬来后行为不变。
    if (sig == SIGABRT || sig == SIGSEGV || sig == SIGBUS ||
        sig == SIGILL || sig == SIGFPE) {
        void* frames[32];
        const int n = ::backtrace(frames, 32);
        const int log_fd = ::refuzz::worker::log::WorkerLogFd();
        constexpr char kPrefix[] = "[WORKER] backtrace begin\n";
        constexpr char kSuffix[] = "[WORKER] backtrace end\n";
        (void)::write(log_fd, kPrefix, sizeof(kPrefix) - 1);
        ::backtrace_symbols_fd(frames, n, log_fd);
        (void)::write(log_fd, kSuffix, sizeof(kSuffix) - 1);
    }
    _exit(128 + sig);
}

} // namespace

// Epic 7 PR-9 allowlist: 5 个真代码 bug 信号一致装 handler;其它信号走默认。
// 行为跟 execution_engine.cpp 旧 install_engine_child_crash_handlers byte-equal。
void ProgramRuntimeInstallCrashHandlers(IObservationBus* bus_for_crash)
{
    g_engine_bus = bus_for_crash;
    g_engine_child_output_buf = nullptr;
    g_engine_child_output_cap = 0;
    g_engine_child_crash_output_len = nullptr;

    constexpr int kCrashSignals[] = {SIGSEGV, SIGABRT, SIGBUS, SIGILL, SIGFPE};
    for (int sig : kCrashSignals) {
        signal(sig, engine_child_crash_handler);
    }
}

// [per-program workdir isolation — 见 program_runtime.hpp ProgramRuntimeInput.workdir]
// input.workdir 只在 double-fork 路径设(loop_runtime.cpp:1179)。该路径下
// ProgramRuntimeRunInline 跑在 fork 出来的 program-child 里,跑完 _exit,cwd 随子
// 进程消亡;loop_child 的 cwd 从没动过 → RemoveDirRecursive + fchdir(baseline) 由
// LoopRuntime 在 loop_child 内统一做。所以这里**只 chdir 进 workdir,不自存/自还原**。
//
// 旧实现入口 open(".") 存 cwd、退出 dtor fchdir 回:那个 fd 拿到 fd 3,紧接着
// SetupCgroupsTest 的 close_range(3,30)(cgroups.cpp:355,syz-parity fd-table 清理)
// 必然把它关掉 → dtor fchdir **每条 program 都 EBADF + 刷一行 LOG**(死还原,非真兜底)。已删。
void ProgramRuntimeRunInline(const ProgramRuntimeInput& input,
                             IExecBackend& backend,
                             IObservationBus& bus,
                             uint32_t worker_id,
                             uint32_t proc_id,
                             DoneMsg* out_done)
{
    ::refuzz::worker::perf::ScopedCurrentSample current_sample(input.perf_sample);
    ::refuzz::worker::perf::RuntimeStageTimeline runtime_timeline(
        input.perf_sample);
    const bool collect_exec_timeline =
        ::refuzz::worker::perf::Enabled();

    // [per-program workdir] 进 per-program 隔离目录;不自存/自还原 cwd(见上注释:
    // 还原由 LoopRuntime 统一兜,自还原冗余且 fd 必被 close_range(3,30) 误伤)。
    // input.workdir == nullptr → 不切,保持旧行为(testing fallback)。
    bool workdir_active = false;
    if (input.workdir != nullptr) {
        if (::chdir(input.workdir) != 0) {
            LOG("ProgramRuntime: chdir(%s) failed errno=%d — fall back to baseline cwd",
                input.workdir, errno);
        } else {
            workdir_active = true;
        }
    }

    // 依赖 per-program cwd 的 setup_test 部分。PDEATHSIG/setpgrp/oom_score_adj
    // 属于 forked program-child 的进程契约，由 ForkingProgramExecutor 在 fork
    // 分支无条件执行；不能放在这个同时服务 InlineProgramExecutor 的函数里。
    if (workdir_active) {
        ::refuzz::worker::sandbox::device_init::SetupTestWorkdir(
            static_cast<std::uint64_t>(proc_id));
        // [F4 fix] 对齐 syzkaller setup_test 里 flush_tun() (common_linux.h:2302):
        // 读 tun fd 200 直到 EAGAIN/EBADF,清掉前一 program 留下的 packet,
        // 避免跨 program packet bleed-through 污染本 program 的 recvfrom + KCOV。
        ::refuzz::worker::sandbox::device_init::FlushTun();
    }

    ::refuzz::worker::topology::EmitTopologyProbeSelf(
        "program-after-setup", worker_id, input.executor_id,
        input.dispatch_gen);

    // 更新 crash handler 全局指针,让 signal 异步路径能写当前 prog 的 output buf。
    g_engine_child_output_buf = input.output;
    g_engine_child_output_cap = input.output_cap;
    g_engine_child_crash_output_len = input.crash_len_ptr;

    // ExecFlagsAreSupported(input.flags) 在 daemon side 已在
    // execution_engine.cpp:332 (LoopRuntime task loop) 检查并 fail-fast 过,
    // unsupported task 不会派发到 child。这里删除冗余 child-side check 省
    // 一次 inline 函数 + branch(每 program fork 后 hot path 跑一次)。
    // 注:测试 fixture 直接调 ProgramRuntimeRunInline 不经 daemon — fixture
    // 自身负责传 supported flags(threaded_smoke / 单元测试已对齐)。

    ExecMode mode = ExecModeFromFlags(input.flags);
    mode.scratch_reset = input.scratch_reset;
    const bool collect_comps_flag =
        task_flags_get_collect_comps(input.flags) != 0;

    // [v1 per-call shmem progress — 2026-05-13] 注入 caller 准备的 cursors。
    // DoubleFork bridge 路径下指针位于 crash_len memfd;Inline/Reusable 路径下
    // 通常 nullptr(无 partial-fallback 需求,child 死等于整个 worker 死)。
    // Execute 返回后复位 nullptr 防 stale ptr。
    backend.SetProgressCursors(input.progress_completed_calls,
                               input.progress_output_len);
    uint32_t* loop_mask_cursor = input.result_page != nullptr
        ? &input.result_page->loop_devices_used_mask
        : nullptr;
    const bool publishes_live_loop_mask =
        backend.SetLoopDevicesUsedMaskCursor(loop_mask_cursor);
    if (publishes_live_loop_mask && loop_mask_cursor != nullptr) {
        __atomic_store_n(loop_mask_cursor, 0u, __ATOMIC_RELEASE);
    }
    backend.SetDiagnosticExecutorId(input.executor_id);
    const uint64_t started_us = now_us();
    // [ExecTL] B: child setup done; coverage arm + wire walk start inside
    // ChildExecuteTask.
    if (collect_exec_timeline) {
        out_done->tl_b_ts_us = started_us;
        TlCpuSample(&out_done->tl_b_cpu_us, &out_done->tl_b_rq_us);
    }
    uint32_t out_len = 0;
    runtime_timeline.Transition(
        ::refuzz::worker::perf::WorkerStage::kExecuteTask);
    ExecTaskFailure exec_failure = ExecTaskFailure::kNone;
    int status = ChildExecuteTask(backend, bus, input.input, input.input_len,
                                  input.output, input.output_cap, &out_len, mode,
                                  worker_id, input.executor_id, collect_comps_flag,
                                  &exec_failure);
    // [ExecTL] C: feedback packed into the output buffer.
    if (collect_exec_timeline) {
        out_done->tl_c_ts_us = now_us();
        TlCpuSample(&out_done->tl_c_cpu_us, &out_done->tl_c_rq_us);
    }
    runtime_timeline.Transition(
        ::refuzz::worker::perf::WorkerStage::kRuntimeFinalize);
    backend.SetProgressCursors(nullptr, nullptr);
    backend.SetLoopDevicesUsedMaskCursor(nullptr);
    backend.SetDiagnosticExecutorId(0);
    RuntimeFailure runtime_failure = bus.RuntimeFailureState();
    if (runtime_failure == RuntimeFailure::kNone) {
        runtime_failure = backend.RuntimeFailureState();
    }
    const uint64_t elapsed_ms = (now_us() - started_us) / 1000ULL;
    if (status != 0 || elapsed_ms >= 1000) {
        LOG("child[%d]: exec executor_id=%llu input_len=%u status=%d out_len=%u elapsed_ms=%llu flags=0x%x",
            getpid(),
            static_cast<unsigned long long>(input.executor_id),
            input.input_len,
            status,
            out_len,
            static_cast<unsigned long long>(elapsed_ms),
            input.flags);
    }

    if (runtime_failure == RuntimeFailure::kKcovStateInvalid) {
        SetHarnessFatal(out_done, HarnessFatalReason::kKcovStateInvalid);
        out_done->loop_devices_used_mask = backend.TakeLoopDevicesUsedMask();
        return;
    }

    out_done->output_len = out_len;
    out_done->status = status;
    out_done->flags = 0;
    // ChildExecuteTask 失败 = **worker 侧**问题(wire 输入非法 / observation sink /
    // backend 执行失败),程序无罪 → 基础设施故障,按归属选 kInvalidInput(配置协议错)
    // 或 kInfraFault(运行时故障)。曾一律报 kNoResult,把它跟"程序真的没产出"混在
    // 一起,最终都塌成 exec_error —— 两者的处理完全不同(前者确定性、重试无意义)。
    // 被测程序自己的行为(exit_group / crash / 卡死)不经过这里,由上层
    // ForkingProgramExecutor 的 waitpid 分流判定。
    if (status == 0) {
        out_done->result_kind = RuntimeResultKind::kNormal;
    } else if (exec_failure == ExecTaskFailure::kInvalidInput) {
        out_done->result_kind = RuntimeResultKind::kInvalidInput;
    } else {
        out_done->result_kind = RuntimeResultKind::kInfraFault;
    }
    out_done->crash_signal = 0;
    out_done->fatal_reason = HarnessFatalReason::kNone;
    // [Step A 2026-05-20] precision /dev/loop sweep mask from backend
    // KernelWireDriver tracks candidates via pseudo_ctx; backends without live
    // diagnostic publication retain UINT32_MAX.
    out_done->loop_devices_used_mask = backend.TakeLoopDevicesUsedMask();
}

void ForkingProgramExecutor::ExecuteProgram(const ProgramRuntimeInput& input,
                                            DoneMsg* out_done)
{
    out_done->output_len = 0;
    out_done->status = -1;
    out_done->flags = 0;
    out_done->result_kind = RuntimeResultKind::kNoResult;
    out_done->crash_signal = 0;
    out_done->fatal_reason = HarnessFatalReason::kNone;
    out_done->loop_devices_used_mask = 0;

    const bool collect_perf = input.perf_trace != nullptr;
    const bool collect_exec_timeline =
        ::refuzz::worker::perf::Enabled();
    ::refuzz::worker::perf::ParentPerfSample ignored_parent_perf{};
    ::refuzz::worker::perf::ParentPerfSample& parent_perf = collect_perf
        ? input.perf_trace->parent
        : ignored_parent_perf;
    if (collect_perf) {
        input.perf_trace->parent_valid = true;
    }
    ::refuzz::worker::perf::ParentStageTimeline parent_timeline(
        collect_perf ? &parent_perf : nullptr);

    // [当前版本 devnull 预开] 在 loop_parent 里一次性打开 /dev/null,fork 后每个
    //   program-child 继承复用 —— 省掉 child 内 per-program 的 open+close 两次
    //   syscall(高频 per-program 路径)。fork 前打开,不计入 fork_us。这是
    //   reFuzz-internal fd hygiene(下面切断 fd 0/1 继承链防 ssh stdio 死锁),
    //   非 syzkaller parity 行为 —— 优化"怎么开"不改可观察执行。
    if (devnull_fd_ < 0) {
        devnull_fd_ = ::open("/dev/null", O_RDWR | O_CLOEXEC);
    }
    // [early-publish ordering] Lazily create the commit-signal eventfd once per
    // loop-child lifetime (mirrors devnull_fd_ above). Must land at fd>=31:
    // ProgramRuntimeRunInline's SetupTestWorkdir → CloseProgramFds() does
    // close_range(3,30) inside every program-child, and if this fd's number
    // fell in that band the child's post-commit write() would silently EBADF,
    // defeating the whole mechanism in production (workdir is normally
    // active). eventfd() returns whatever the kernel hands out (often < 31,
    // since the loop-child's one-time startup sweep freed that range), so it's
    // moved explicitly via F_DUPFD_CLOEXEC. Failure just leaves it at -1 —
    // ExecuteProgram degrades to the memory-poll fallback, not fatal.
    if (commit_evt_fd_ < 0) {
        const int raw = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
        if (raw >= 0) {
            const int moved = ::fcntl(raw, F_DUPFD_CLOEXEC, 31);
            if (moved >= 0) {
                commit_evt_fd_ = moved;
            }
            ::close(raw);
        }
    }

    parent_timeline.Transition(
        ::refuzz::worker::perf::ParentStage::kIsolation);
    // [ExecTL round-2] fork wall/CPU belongs to the worker_perf probe set.
    const uint64_t fork_start_us = collect_exec_timeline
        ? ::refuzz::worker::perf::NowUs() : 0;
    parent_perf.fork_start_ts_us = collect_perf ? fork_start_us : 0;
    const uint64_t fork_cpu_start = collect_exec_timeline
        ? ::refuzz::worker::perf::ThreadCpuNowUs() : 0;
    const pid_t pid = ::fork();
    if (pid != 0) {
        uint64_t fork_wall_us = 0;
        uint64_t fork_cpu_us = 0;
        uint64_t fork_cpu_end = 0;
        if (collect_exec_timeline) {
            fork_wall_us = ::refuzz::worker::perf::NowUs() - fork_start_us;
            fork_cpu_end = ::refuzz::worker::perf::ThreadCpuNowUs();
            fork_cpu_us =
                (fork_cpu_start != 0 && fork_cpu_end >= fork_cpu_start)
                    ? fork_cpu_end - fork_cpu_start
                    : 0;
            out_done->fork_wall_us = fork_wall_us;
            out_done->fork_cpu_us = fork_cpu_us;
        }
        if (collect_perf) {
            parent_timeline.Transition(
                ::refuzz::worker::perf::ParentStage::kWatch);
            if (fork_cpu_start != 0 && fork_cpu_end >= fork_cpu_start) {
                parent_perf.fork_cpu_us = fork_cpu_us;
                parent_perf.fork_offcpu_us =
                    fork_wall_us > fork_cpu_us ? fork_wall_us - fork_cpu_us : 0;
                parent_perf.fork_cpu_valid = 1;
            }
        }
    }
    if (pid < 0) {
        const int err = errno;
        const HarnessFatalReason reason = err == EAGAIN
            ? HarnessFatalReason::kOuterForkEagain
            : HarnessFatalReason::kOuterForkFailed;
        SetHarnessFatal(out_done, reason);
        // The program child was never created, so it could not attach a loop.
        out_done->loop_devices_used_mask = 0;
        ForkServerReaperStats reaper_stats{};
        reaper_stats.outer_fork_eagain = err == EAGAIN ? 1 : 0;
        reaper_stats.harness_fatal = 1;
        ReaperAccumulator().Add(worker_id_, reaper_stats, true);
        LOG("ForkingProgramExecutor: harness fatal reason=%s errno=%d",
            HarnessFatalReasonName(reason), err);
        ::refuzz::worker::topology::EmitTopologyFatalCgroupSnapshot(
            "fork-server-fatal", worker_id_, proc_id_, input.executor_id,
            input.dispatch_gen, 32);
        parent_perf.status = -1;
        return;
    }

    if (pid == 0) {
        // [fork-breakdown 2026-05-21] child entry timestamp:整个 if(pid==0)
        // 分支第一行,measure fork() return → driver invoke 的 user-space setup
        // 时长 (child_setup_us),以及 driver done → CommitResultPage 完成的
        // 时长 (child_finish_us)。child 内的 timing 必须在 child_perf init 前
        // 算 (因 child_perf 后于 dup2/EmptyForkBench 创建,但 setup time
        // 要含整个 child 从 entry 到 driver 调用前的全部时间)。
        const uint64_t t_child_entry =
            collect_perf ? ::refuzz::worker::perf::NowUs() : 0;
        ::refuzz::worker::perf::WorkerPerfSample child_perf{};
        child_perf.child_entry_ts_us = t_child_entry;

        // [fd hygiene] program_child 不需要 stdin/stdout — 走 result_page +
        // done_pipe 跟 loop_parent 通信。若 syscall 进 D-state 持着继承自
        // daemon 的 fd 0/1(stdio profile 下是 ssh pipe),即使 SIGKILL 也得
        // 等 syscall return 才 reap → 这段时间 fd ref 不释放 → daemon exit
        // 后 sshd 仍读不到 stdout EOF → host ssh client do_poll → syzgen
        // close()/Wait 死锁(netrom corpus 全量观测过的现场)。
        //
        // 把 0/1 重定向到 /dev/null 切断这条 fd 继承链。stderr (fd 2) 保留:
        // crash backtrace / WorkerLog 仍需 console。这里 child 路径里调,不
        // 影响 loop_parent / daemon。
        {
            // 用 loop_parent 预开、fork 继承下来的 /dev/null fd:dup2 到 0/1 后
            // **close child 自己继承的那份**。fork 后父子 fd 表是独立副本,child
            // close 不影响 loop_parent 的副本(仍开着供下条 program-child 继承)。
            // 这样 child 的 fd 表与旧版逐 fd 等价(0/1→/dev/null,helper fd 关闭),
            // 不会因残留 fd 改变 corpus 程序对该 fd 的 close/fcntl errno(防 parity
            // drift)。净省:child 不再 per-program open(loop_parent 只开一次)。
            // 预开失败时回落到 per-program open(行为与旧版一致)。
            if (devnull_fd_ >= 0) {
                ::dup2(devnull_fd_, 0);
                ::dup2(devnull_fd_, 1);
                if (devnull_fd_ > 2) {
                    ::close(devnull_fd_);
                }
            } else {
                int devnull = ::open("/dev/null", O_RDWR | O_CLOEXEC);
                if (devnull >= 0) {
                    ::dup2(devnull, 0);
                    ::dup2(devnull, 1);
                    if (devnull > 2) {
                        ::close(devnull);
                    }
                }
            }
        }
        // Mirror syzkaller setup_test before executing any program code. This
        // must not depend on per-program chdir success: the parent watchdog
        // always sends both kill(-pid) and kill(pid), so PGID=pid must be the
        // normal contract while the direct-pid signal covers the setup race.
        ::refuzz::worker::sandbox::device_init::SetupTestProcess();
        ::refuzz::worker::topology::EmitTopologyProbeSelf(
            "program-child", worker_id_, input.executor_id, input.dispatch_gen);
        // [debug] empty-fork benchmark:跳过 ProgramRuntimeRunInline,直接 commit
        // 空结果并 _exit。给 isolation / completion
        // 的纯 fork+exit floor 量个底,不被 ChildExecuteTask / KCOV /
        // syz_exec_runner 等业务路径污染。set REFUZZ_EMPTY_FORK_BENCH=1 启用。
        // env 在 child 已存在(fork 继承 parent envp),getenv 同步访问安全。
        if (EmptyForkBenchEnabled()) {
            DoneMsg done{};
            done.output_len = 0;
            done.status = 0;
            done.flags = 0;
            done.result_kind = RuntimeResultKind::kNormal;
            done.crash_signal = 0;
            if (collect_perf) {
                const uint64_t runtime_us =
                    ::refuzz::worker::perf::NowUs();
                ::refuzz::worker::perf::AddStage(
                    &child_perf,
                    ::refuzz::worker::perf::WorkerStage::kChildBootstrap,
                    runtime_us - t_child_entry);
                child_perf.runtime_start_ts_us = runtime_us;
                child_perf.runtime_end_ts_us = runtime_us;
            }
            CommitResultPage(input.result_page,
                             input.executor_id,
                             input.dispatch_gen,
                             done,
                             collect_perf ? &child_perf : nullptr);
            // [early-publish ordering] signal parent the instant the page is
            // committed, before teardown. See commit_evt_fd_ comment
            // (program_runtime.hpp) for why this fd is guaranteed to survive
            // the fd-table sweeps above. -1 (creation failed) => no-op, parent
            // falls back to its per-tick memory poll.
            if (commit_evt_fd_ >= 0) {
                const uint64_t one = 1;
                (void)::write(commit_evt_fd_, &one, sizeof(one));
            }
            _exit(0);
        }

        ProgramRuntimeInput child_input = input;
        child_input.scratch_reset = ScratchResetMode::kForkClean;
        child_input.perf_sample = collect_perf ? &child_perf : nullptr;

        if (collect_perf) {
            ::refuzz::worker::perf::AddStage(
                &child_perf,
                ::refuzz::worker::perf::WorkerStage::kChildBootstrap,
                ::refuzz::worker::perf::NowUs() - t_child_entry);
        }

        DoneMsg done{};
        ProgramRuntimeRunInline(child_input, backend_, bus_, worker_id_,
                                proc_id_, &done);

        CommitResultPage(input.result_page,
                         input.executor_id,
                         input.dispatch_gen,
                         done,
                         collect_perf ? &child_perf : nullptr);
        // [early-publish ordering] see the EmptyForkBench branch above.
        if (commit_evt_fd_ >= 0) {
            const uint64_t one = 1;
            (void)::write(commit_evt_fd_, &one, sizeof(one));
        }
        _exit(0);
    }

    // The fork-server reaper owns both pidfd wakeups and wait-any draining.
    // Keeping those operations in one object preserves the main child's real
    // status even when a descendant becomes ready first.
    ForkServerReaper reaper(pid);
    parent_perf.pidfd_used = reaper.PidfdActive() ? 1u : 0u;

    auto fail_harness = [&](HarnessFatalReason reason, int error_number) {
        SetHarnessFatal(out_done, reason);
        out_done->loop_devices_used_mask = reaper.MainExited()
            ? LoadPublishedLoopDevicesUsedMask(
                  input.result_page, input.executor_id, input.dispatch_gen)
            : UINT32_MAX;
        ForkServerReaperStats stats = reaper.Stats();
        ++stats.harness_fatal;
        ReaperAccumulator().Add(worker_id_, stats, true);
        LOG("ForkingProgramExecutor: harness fatal reason=%s errno=%d pid=%d",
            HarnessFatalReasonName(reason), error_number, pid);
        ::refuzz::worker::topology::EmitTopologyFatalCgroupSnapshot(
            "fork-server-fatal", worker_id_, proc_id_, input.executor_id,
            input.dispatch_gen, 32);
        parent_perf.status = -1;
    };

    ::refuzz::worker::topology::EmitTopologyProbeProgramFork(
        "program-parent", worker_id_, input.executor_id, input.dispatch_gen,
        pid);

    parent_timeline.Transition(
        ::refuzz::worker::perf::ParentStage::kWaitForChild);
    // [activity-watchdog — 镜像 syz fork-server common.h:700-726]
    // 把"盲等满 timeout_ms_"换成活跃度感知轮询。timeout_ms_(单条 prog 强杀
    // 阈值,= exec_timeout_ms)仍是**硬上限**(对齐 syz `now-start >
    // program_timeout → 无条件 kill`),不删除;只是在它之内额外加一条提前路径:
    // 过了 min_active_ms 下限后,若 inactive_ms 内 progress_completed_calls 没
    // 推进(syscall 不再完成 = 卡死),立即判 timed_out → 走下面同一套 SIGKILL+reap。
    // 持续完成 syscall 的程序(进度在动)仍可用满 timeout_ms_。卡死程序恢复
    // 从 5s 降到 ~min_active_ms。阈值映射 syz:min = program_timeout*3/5;
    // inactive = syscall_timeout*20(reFuzz 对齐配置 per_call=50/exec=5000 下
    // timeout_ms_/5 = 1000ms = 50*20,数值一致)。progress 计数器是 loop_child 与
    // program-child 间的共享 page 字段(SetProgressCursors wire,program-child
    // publish_progress 每完成一 call 自增),parent 这里跨进程 acquire-load 判活。
    const bool has_progress_signal = input.progress_completed_calls != nullptr;
    const uint32_t min_active_ms = timeout_ms_ * 3u / 5u;
    const uint32_t inactive_ms = timeout_ms_ / 5u;
    const uint64_t wd_start_us = now_us();
    uint64_t last_progress_us = wd_start_us;
    uint32_t last_completed = has_progress_signal
        ? __atomic_load_n(input.progress_completed_calls, __ATOMIC_ACQUIRE)
        : 0;
    constexpr uint32_t kPollMs = 10;
    bool timed_out = false;
    // [early-publish] program child 一旦 commit 最终结果,就在 reap 之前把 DoneMsg
    // 投递给 daemon(D);此后本 child 只剩正常 _exit + teardown,循环转为纯 reap 等待。
    bool result_committed = false;
    // [early-publish ordering] 收敛成一个闭包,两处调用点(kExtraFdReady 命中时、
    // 每 tick 末尾的内存轮询兜底)共用同一份判断+投递逻辑,不会出现字段漂移。
    // result_committed 守卫保证全程最多真正投递一次。
    auto try_early_publish = [&]() {
        if (result_committed || input.publish_result == nullptr) {
            return;
        }
        if (!ResultPageCommitted(input.result_page, input.executor_id,
                                 input.dispatch_gen)) {
            return;
        }
        DoneMsg early{};
        FillDoneFromCommittedPage(input.result_page, input.executor_id,
                                  input.dispatch_gen, &early);
        (void)input.publish_result(input.publish_result_ctx, early);
        result_committed = true;
    };
    for (;;) {
        // Existing watchdog cadence supplies the upper bound. A pidfd-ready
        // main child still wakes immediately. commit_evt_fd_ rides in the SAME
        // poll() call (fork_server_reaper.hpp): when the child signals commit,
        // WaitFor returns kExtraFdReady WITHOUT draining/reaping, so
        // try_early_publish() below is guaranteed to run before the deferred
        // Drain() — a structural guarantee, not a timing accident (this closes
        // the gap where a fast-teardown child could otherwise be reaped by the
        // unconditional drain inside WaitFor before the commit was ever
        // checked). commit_evt_fd_ == -1 (creation failed) makes this behave
        // exactly like the original pidfd-only WaitFor(kPollMs).
        bool extra_ready = false;
        const ForkServerWaitResult wait_result =
            reaper.WaitFor(kPollMs, commit_evt_fd_, &extra_ready);
        if (wait_result == ForkServerWaitResult::kError) {
            ::kill(-pid, SIGKILL);
            ::kill(pid, SIGKILL);
            fail_harness(HarnessFatalReason::kMainChildReapFailed,
                         reaper.ErrorNumber());
            return;
        }

        if (wait_result == ForkServerWaitResult::kExtraFdReady) {
            // Drain the eventfd counter so it never leaks into the next
            // program's fork (the fd is reused for the loop-child's lifetime).
            uint64_t ignored = 0;
            while (::read(commit_evt_fd_, &ignored, sizeof(ignored)) > 0) {
            }
            try_early_publish();
            // Perform the reap WaitFor deferred. The child may already be a
            // reapable zombie by now or may not — either is fine; what matters
            // is that try_early_publish() above unconditionally ran first.
            if (!reaper.Drain()) {
                ::kill(-pid, SIGKILL);
                ::kill(pid, SIGKILL);
                fail_harness(HarnessFatalReason::kMainChildReapFailed,
                             reaper.ErrorNumber());
                return;
            }
        }

        if (reaper.MainExited()) {
            break;
        }

        // [early-publish] Fallback net: commit is a memory release-store, not
        // an fd event, so also check it directly every tick regardless of
        // which fd (if any) woke this iteration. This is what keeps behavior
        // correct when commit_evt_fd_ creation failed, or this tick's wakeup
        // was the plain pidfd/timeout path.
        try_early_publish();

        const uint64_t now = now_us();
        if (has_progress_signal) {
            const uint32_t current = __atomic_load_n(
                input.progress_completed_calls, __ATOMIC_ACQUIRE);
            if (current != last_completed) {
                last_completed = current;
                last_progress_us = now;
            }
        }
        const uint64_t elapsed_ms = (now - wd_start_us) / 1000ULL;
        if (elapsed_ms >= timeout_ms_) {
            timed_out = true;
            break;
        }
        // 进度不活跃强杀只在**未 commit** 时生效:已 commit 的 child 停止推进进度是
        // 正常的(程序跑完了),它只是在 teardown,绝不能被当卡死 SIGKILL。硬上限
        // timeout_ms_ 仍是 teardown 卡死(D-state)的兜底,daemon watchdog 是终裁。
        if (!result_committed && has_progress_signal &&
            elapsed_ms >= min_active_ms &&
            (now - last_progress_us) / 1000ULL >= inactive_ms) {
            timed_out = true;
            break;
        }
    }

    bool timeout_reaped = reaper.MainExited();
    if (timed_out) {
        // 对齐 syzkaller kill_and_wait():先 group kill 清整个 PGID,再 single
        // kill 兜底 group leader；给 100ms 非阻塞回收宽限。仍未退出时 abort
        // 当前 execution domain 可见的全部 FUSE connections，然后阻塞 wait-any。
        // daemon 的 3×program-timeout watchdog 是最终裁决者：若这里仍卡住，
        // daemon 会杀掉 loop PID1 并重建 L2-L4。
        ::kill(-pid, SIGKILL);
        ::kill(pid, SIGKILL);
        const uint64_t reap_deadline_us = now_us() + 100'000ULL;
        while (!reaper.MainExited() && now_us() < reap_deadline_us) {
            if (reaper.WaitFor(1) == ForkServerWaitResult::kError) {
                fail_harness(HarnessFatalReason::kMainChildReapFailed,
                             reaper.ErrorNumber());
                return;
            }
        }

        // Close the deadline edge: a SIGKILLed child can become Z after the
        // final timed poll but before the wall-clock check. Reap once more at
        // zero timeout before escalating to FUSE abort.
        if (!reaper.MainExited() &&
            reaper.WaitFor(0) == ForkServerWaitResult::kError) {
            fail_harness(HarnessFatalReason::kMainChildReapFailed,
                         reaper.ErrorNumber());
            return;
        }

        if (!reaper.MainExited()) {
            (void)::refuzz::worker::sandbox::device_init::AbortFuseConnections();
            if (!reaper.WaitForMainBlocking()) {
                fail_harness(HarnessFatalReason::kMainChildReapFailed,
                             reaper.ErrorNumber());
                return;
            }
        }
        timeout_reaped = reaper.MainExited();
    }

    if (timed_out) {
        parent_perf.timed_out = 1;
        if (!timeout_reaped) {
            fail_harness(HarnessFatalReason::kMainChildReapFailed,
                         reaper.ErrorNumber() != 0 ? reaper.ErrorNumber()
                                                   : ETIMEDOUT);
            return;
        }
    }

    if (collect_perf) {
        parent_perf.child_reaped_ts_us =
            ::refuzz::worker::perf::NowUs();
    }
    parent_timeline.Transition(
        ::refuzz::worker::perf::ParentStage::kReclamation);

    // [post-exit cgroup diag] program-child 已 waitpid 收尸,如果 cgroup
    // 内还有 process 残留(grand-child reparent 到 loop_child subreaper),
    // dump 一次看 state/pgid/sid。env REFUZZ_DUMP_POST_EXIT=1 时启用,
    // 生产 no-op。诊断完保留,验证 reap 是否清零用。
    {
        static std::atomic<uint64_t> kPostExitSeq{0};
        const uint64_t seq = kPostExitSeq.fetch_add(1, std::memory_order_relaxed);
        ::refuzz::worker::sandbox::device_init::DumpCgroupSnapshotPostExit(
            proc_id_, seq);
    }

    // WUNTRACED is intentionally used only after the main child is gone.
    // Reap descendants that are already terminal and SIGKILL stopped residue,
    // but do not wait for the killed PIDs. A later program's wait-any pass will
    // reap them once they become zombies; outer-fork EAGAIN remains the
    // fail-stop boundary that rebuilds this execution domain. Descendant-only
    // cleanup syscall failures are recorded by the reaper but do not invalidate
    // the already completed main program result.
    if (!reaper.SignalStoppedDescendants()) {
        fail_harness(HarnessFatalReason::kForkServerProtocol,
                     reaper.ErrorNumber());
        return;
    }
    const ForkServerReaperStats reaper_stats = reaper.Stats();
    ::refuzz::worker::topology::EmitTopologyProbeCleanupSummary(
        "program-cleanup", worker_id_, input.executor_id, input.dispatch_gen,
        pid, timed_out, timeout_reaped, reaper.MainStatus(),
        static_cast<int>(reaper_stats.descendants_reaped),
        static_cast<int>(reaper_stats.stopped_children_killed),
        reaper.ErrorNumber());
    ::refuzz::worker::topology::EmitTopologyProbeCgroup(
        "program-cleanup", worker_id_, proc_id_, input.executor_id,
        input.dispatch_gen, 16);
    ReaperAccumulator().Add(worker_id_, reaper_stats, false);
    parent_timeline.Transition(
        ::refuzz::worker::perf::ParentStage::kResult);

    if (collect_exec_timeline) {
        // Reap-time accounting from the reaper: main-child reap timestamp and
        // whole-life rusage.
        out_done->reap_ts_us = reaper.MainReapTsUs();
        if (reaper.MainRusageValid()) {
            const struct rusage& tl_ru = reaper.MainRusage();
            out_done->child_cpu_us =
                static_cast<uint64_t>(tl_ru.ru_utime.tv_sec) * 1000000ULL +
                static_cast<uint64_t>(tl_ru.ru_utime.tv_usec) +
                static_cast<uint64_t>(tl_ru.ru_stime.tv_sec) * 1000000ULL +
                static_cast<uint64_t>(tl_ru.ru_stime.tv_usec);
            out_done->child_nivcsw = static_cast<uint64_t>(tl_ru.ru_nivcsw);
            out_done->child_minflt = static_cast<uint64_t>(tl_ru.ru_minflt);
        }
    }

    ::refuzz::worker::perf::WorkerPerfSample child_perf{};
    bool have_child_perf = false;
    ProgramResultPageV3* page = input.result_page;
    const bool committed =
        ResultPageCommitted(page, input.executor_id, input.dispatch_gen);
    // timed_out 不在此处提前分流:child 死于我们发的 SIGKILL,交给下面统一的 waitpid
    // ground-truth 分类(WIFSIGNALED+SIGKILL → kKilledOrCleanExit),在那里按 timed_out
    // 打 kTimeout / kPartial 标签并如实带上 progress 数据。committed(SIGKILL 落地前
    // child 已提交最终结果的竞态)照常读 result page —— 它其实跑完了。
    //
    // [early-publish] fast path 下 watchdog 循环已用同一个 FillDoneFromCommittedPage
    // 把功能结果投递给 daemon;这里再填一次 out_done(逐字节相同)是为了给 loop 的 TL
    // 记录补上 parent 侧遥测。同一 helper 保证"提前投递"与"事后读取"永不漂移。
    if (committed) {
        FillDoneFromCommittedPage(page, input.executor_id, input.dispatch_gen,
                                  out_done);
        parent_perf.result_read = 1;
        parent_perf.status = page->status;
        parent_perf.output_len = page->output_len;
        if (page->perf_valid != 0) {
            child_perf =
                ::refuzz::worker::perf::LoadWorkerPerfSampleV3(page->perf);
            have_child_perf = true;
        }
    } else {
        // The backend publishes successful attachments before final commit,
        // so crash/no-commit paths retain the precise cleanup set. Backends
        // without live publication leave the UINT32_MAX sentinel intact.
        out_done->loop_devices_used_mask = LoadPublishedLoopDevicesUsedMask(
            page, input.executor_id, input.dispatch_gen);
        // [v3 — waitpid status as ground truth — 2026-05-13]
        //
        // child 没 commit result page 就死了。**只有 waitpid status 是可靠 source of truth**
        // — 由 kernel fork/exit 协议保证,不依赖 child 内部任何代码跑没跑通。
        // 之前 v1/v2 用 crash_len / crash_signal cursor 猜 child 状态都有 false
        // positive (handler 可能 SnapshotForCrash 返 0,kernel-killed 路径 handler
        // 根本没跑) — 删了那套,改 ChildWaiter::ExitStatus() 单 source。
        //
        // 对齐 syzkaller upstream executor.cc:1862-1869:WIFEXITED/WIFSIGNALED 分类。
        //
        // 分类表:
        //   WIFSIGNALED + sig ∈ {SEGV,ABRT,BUS,ILL,FPE}  → 真 crash (handler 没跑)
        //   WIFEXITED   + status ∈ {128+5sigs}            → 真 crash (handler 跑了 _exit)
        //   WIFSIGNALED + SIGKILL                         → uncatchable kill,允许 partial
        //   WIFEXITED   + status == 0                     → 程序 syscall 走了 exit_group,允许 partial
        //   其它(WIFEXITED+非零非128+sig / WIFSIGNALED+其它 sig) → abnormal,不救
        //
        // partial 救回的语义跟 syzkaller upstream `reply_execute(0)` 一致(loop
        // parent waitpid + 非 kFailStatus → 当 success);driver head 已 zero-init,
        // 未执行 slot 留 flags==0 == empty_call,下游用 kCallFlagExecuted 区分。
        //
        // crash 路径:buffer 可能已被 SnapshotForCrash 覆盖(或没覆盖,看 handler
        // 跑没跑、sinks 写没写),反正 **不能** 当干净 partial。crash_len_ptr 仅作
        // 透出 crash snapshot 字节数给 host 做诊断的辅助;不参与分流决策。
        const int wstatus = reaper.MainStatus();
        auto is_crash_signal = [](int sig) {
            return sig == SIGSEGV || sig == SIGABRT || sig == SIGBUS ||
                   sig == SIGILL  || sig == SIGFPE;
        };

        enum class ChildEnd { kCrashed, kKilledOrCleanExit, kAbnormal };
        ChildEnd kind = ChildEnd::kAbnormal;
        // [分流依据:crash handler 有没有动过 buffer]
        //
        // program-child 自己只有两个出口:正常路径 CommitResultPage + _exit(0)(那会走
        // 上面的 committed 分支),以及 crash handler 的 _exit(128+sig)。所以走到这里、
        // 且 **不是** crash 信号的退出码/信号,只可能是**被测程序自己**的行为
        // (exit_group(N) / raise(SIGTERM) 等)—— harness 在本层不用 _exit(1..6)
        // (那些是 loop_runtime 的,另一层进程)。
        //
        //   kCrashed            = SEGV/ABRT/BUS/ILL/FPE:handler 跑过,可能已用
        //                         SnapshotForCrash 覆盖 driver 写的 partial → buffer
        //                         **不可信**,不读 progress。
        //   kKilledOrCleanExit  = 其余全部(exit_group(任意码) / SIGKILL / SIGTERM 等
        //                         无 handler 的信号):buffer 没人动过 → progress
        //                         cursors 可信 → 读出来当 partial 带走。
        //                         对齐 syzkaller:fork-server parent 只在
        //                         `WEXITSTATUS == kFailStatus` 时 fail,其余一律
        //                         reply_execute(0) = Success(common.h:736-740)。
        //                         `exit_group(非零)` 是**程序行为**,不是异常。
        //
        // 曾把 `exit_group(非零)` 和无 handler 的信号归 kAbnormal → kNoResult →
        // exec_error,既丢了数据,又把程序行为误报成执行错误。
        int term_sig = 0;
        if (WIFSIGNALED(wstatus)) {
            const int sig = WTERMSIG(wstatus);
            term_sig = sig;
            kind = is_crash_signal(sig) ? ChildEnd::kCrashed
                                        : ChildEnd::kKilledOrCleanExit;
        } else if (WIFEXITED(wstatus)) {
            const int code = WEXITSTATUS(wstatus);
            if (code >= 128 && is_crash_signal(code - 128)) {
                kind = ChildEnd::kCrashed;
                term_sig = code - 128;
            } else {
                kind = ChildEnd::kKilledOrCleanExit;
            }
        }

        if (kind == ChildEnd::kCrashed) {
            // 真 crash:status=-1 把 abnormal 信号上报,output_len 用 crash_len 把
            // snapshot 透出给 host(没 snapshot 就 0)。**不读 progress cursors** —
            // crash handler 可能已经把 driver 写的 partial 覆盖了。
            uint32_t crash_len = 0;
            if (ResultPageMatches(page, input.executor_id, input.dispatch_gen)) {
                crash_len = __atomic_load_n(&page->crash_len,
                                            __ATOMIC_ACQUIRE);
            } else if (input.crash_len_ptr != nullptr) {
                crash_len = __atomic_load_n(input.crash_len_ptr,
                                            __ATOMIC_ACQUIRE);
            }
            out_done->output_len = crash_len;
            out_done->status = -1;
            out_done->flags = 0;
            out_done->result_kind = RuntimeResultKind::kCrash;
            out_done->crash_signal = static_cast<uint32_t>(term_sig);
            parent_perf.no_result = 1;
            parent_perf.status = -1;
            parent_perf.output_len = crash_len;
            ::refuzz::worker::log::WorkerLog(
                "[KCOV] Forking parent: crash sig=%d crash_len=%u wstatus=0x%x pid=%d\n",
                term_sig, crash_len, wstatus, pid);
        } else if (kind == ChildEnd::kKilledOrCleanExit) {
            // 程序自杀 / exit_group / 被本层 program watchdog SIGKILL:三者都是
            // uncatchable kill 或干净退出,buffer 没被 crash handler 动过 →
            // progress cursors 可信(driver 在数据写完后按 RELEASE 序发布,宣告的
            // 字节必然已落盘)。有 partial 就带上,没有就空。
            //
            // [两层语义 — 标签与处理分离] result_kind 只陈述**为什么结束**,不决定
            // 下游怎么处理:
            //   timed_out=true  → kTimeout:本层 program watchdog 判的超时
            //   timed_out=false → kPartial:程序自己提前结束
            // 两者的数据处理完全相同(都如实带上 progress),差别只在标签 —— 事实层
            // 不做信息压缩,超时是事实、已发布的数据也是事实,两个都上报。
            //
            // 真正的 task hang 是**上一层** daemon watchdog(domain_supervisor 的
            // CollectKind::kTimeout → COMP_STATUS_HUNG + ERR_DOMAIN_WATCHDOG_TIMEOUT),
            // 不是这里;TIMEOUT 只属于本层 program watchdog。最终的分类
            // (Completion vs Abnormal)由 channel 读 (status, error_code) 二元组决定。
            //
            // 此处曾在上游用 `if (timed_out)` 提前 return + 清 output_len,使超时
            // 执行既丢数据、又与真 hang 不可区分(hard_stop → 整条 job 中止;
            // feedback from_abnormal → 覆盖全丢)。
            uint32_t completed = 0;
            uint32_t partial_len = 0;
            if (ResultPageMatches(page, input.executor_id, input.dispatch_gen)) {
                completed = __atomic_load_n(&page->progress_completed_calls,
                                            __ATOMIC_ACQUIRE);
                partial_len = __atomic_load_n(&page->progress_output_len,
                                              __ATOMIC_ACQUIRE);
            } else {
                if (input.progress_completed_calls != nullptr) {
                    completed = __atomic_load_n(input.progress_completed_calls,
                                                __ATOMIC_ACQUIRE);
                }
                if (input.progress_output_len != nullptr) {
                    partial_len = __atomic_load_n(input.progress_output_len,
                                                  __ATOMIC_ACQUIRE);
                }
            }
            if (completed > 0 && partial_len > 0) {
                out_done->output_len = partial_len;
                out_done->status = 0;
                out_done->flags = 0;
                out_done->result_kind = timed_out ? RuntimeResultKind::kTimeout
                                                  : RuntimeResultKind::kPartial;
                out_done->crash_signal = 0;
                parent_perf.partial_shmem = 1;
                parent_perf.status = 0;
                parent_perf.output_len = partial_len;
                ::refuzz::worker::log::WorkerLog(
                    "[KCOV] Forking parent: %s shmem fallback "
                    "completed=%u partial_len=%u wstatus=0x%x pid=%d\n",
                    timed_out ? "timeout" : "partial",
                    completed, partial_len, wstatus, pid);
            } else {
                // 没有 progress = 没有结果 → kNoResult(默认),下游直接不消费。
                // 超时与否在这里不影响标签:kTimeout 的契约是"**有数据**、只是没跑完",
                // 空数据打 kTimeout 会逼下游再判一次 output_len 是否为 0。没结果就是
                // 没结果 —— 标签自己说清楚该不该消费,不留二次判断。
                // (超时事实仍记在 parent_perf.timed_out,上面已设。)
                parent_perf.no_result = 1;
                parent_perf.status = -1;
                ::refuzz::worker::log::WorkerLog(
                    "[KCOV] Forking parent: no progress (completed=%u partial_len=%u "
                    "timed_out=%d) wstatus=0x%x pid=%d\n",
                    completed, partial_len, timed_out ? 1 : 0, wstatus, pid);
            }
        } else {
            // kAbnormal:wstatus 既不是 WIFEXITED 也不是 WIFSIGNALED —— child 只可能
            // 退出或被信号杀,走到这里说明 waitpid 状态不可解释。这是**兜底**,不是
            // 正常终态,如实报 kUnknown 让它在 telemetry 里显形,而不是伪装成某种
            // 常规执行错误被静默吞掉。
            out_done->output_len = 0;
            out_done->status = -1;
            out_done->flags = 0;
            out_done->result_kind = RuntimeResultKind::kUnknown;
            out_done->crash_signal = 0;
            parent_perf.no_result = 1;
            parent_perf.status = -1;
            ::refuzz::worker::log::WorkerLog(
                "[KCOV] Forking parent: uninterpretable wait status "
                "wstatus=0x%x pid=%d\n",
                wstatus, pid);
        }
    }
    if (collect_perf && have_child_perf) {
        input.perf_trace->child = child_perf;
        input.perf_trace->child_valid = true;
    }
}

} // namespace refuzz::worker::engine

// ProgramRuntime: short-lived program 执行体抽象。
//
// 一条 program 的执行分两层:
//   - LoopRuntime  : 长 loop 进程,fd 表/sandbox/crash handler 已 ready,
//                    while loop 读 ReadyMsg
//   - ProgramRuntime: 跑一条 prog,封装"更新 crash output buf 指针 +
//                     ChildExecuteTask + 返 DoneMsg"
//
// 两种 dispatch 模式:
//   - 同进程内联(Reusable / Recycle topology): ProgramRuntimeRunInline
//   - fork program child(DoubleFork topology, P4 加): RunForkedChild
//     [P1 阶段只 ship inline,fork 入口在 P4 装配]
//
// crash handler 状态全局在 program_runtime.cpp anonymous namespace,
// LoopRuntime 进 sandbox 前调用 ProgramRuntimeInstallCrashHandlers 一次,
// fork 后 program child 继承(POSIX signal handler 跨 fork 保留)。

#pragma once

#include "worker/engine/runtime_messages.hpp"
#include "worker/exec_mode.hpp"
#include "worker/perf/worker_perf.hpp"
#include "worker/program_buffers.hpp"
#include "refuzz/proto_wire/ivshmem_protocol.h"

#include <cstddef>
#include <cstdint>

namespace refuzz::worker {
class IExecBackend;
class IObservationBus;
} // namespace refuzz::worker

namespace refuzz::worker::engine {

// 一条 prog 的输入参数(从 ReadyMsg 解码)。
struct ProgramRuntimeInput {
    const uint8_t* input = nullptr;
    uint32_t input_len = 0;
    uint8_t* output = nullptr;
    uint32_t output_cap = 0;
    uint32_t* crash_len_ptr = nullptr;
    uint32_t flags = 0;
    uint64_t executor_id = 0;
    uint32_t dispatch_gen = 0;
    ProgramResultPageV3* result_page = nullptr;
    // [Phase 1 descriptor IPC] 描述输入/输出/crash_len 在共享区里的位置 ——
    // 当前 resolver 不使用,只为后续可能的 child-local mapping 留 hook。
    ::refuzz::worker::ProgramBufferDescriptor buffers;
    // Topology-selected local execution policy. Inline/reusable keeps the
    // default full clear; DoubleFork's program child switches to kForkClean.
    ScratchResetMode scratch_reset = ScratchResetMode::kFullClear;
    // Optional child/runtime detail sample for the current program.
    ::refuzz::worker::perf::WorkerPerfSample* perf_sample = nullptr;
    // Loop-owned trace that joins loop, parent, and child stages.
    ::refuzz::worker::perf::ProgramPerfSample* perf_trace = nullptr;
    // [v1 per-call shmem progress — 2026-05-13]
    // driver 每完成一个 syscall 后按 RELEASE 顺序 atomic store 当前进度:
    //   progress_completed_calls = 已完成 syscall 数 (从 0 开始)
    //   progress_output_len      = 已写 output buf 字节数 (固定 head + 累积 tail)
    //
    // 在 DoubleFork bridge 路径下,两个指针位于 crash_len memfd 内
    // (loop_runtime 布局 [crash_len:4][completed:4][output_len:4]):driver in
    // program child C 写;ForkingProgramExecutor parent in loop child B 在 child
    // 早退(POLLHUP no result)时 ACQUIRE 读,构造 partial DoneMsg(output_len=
    // progress_output_len, status=0)— 对齐 syzkaller upstream reply_execute(0)
    // 语义,partial 不计 abnormal/diagnostics。
    //
    // 任一指针为 nullptr → driver 跳过 progress 写,行为完全 backward-compat
    // (Inline / Reusable / stdio 等非 DoubleFork 路径走此分支)。
    uint32_t* progress_completed_calls = nullptr;
    uint32_t* progress_output_len      = nullptr;

    // [per-program workdir isolation — 镜像 syzkaller common.h:609-751 loop()]
    // LoopRuntime 在每条 prog 入口 mkdir("./<iter>"),把 path 传进来;
    // ProgramRuntimeRunInline 入口 open(., O_PATH) 保存 baseline cwd,然后
    // chdir(workdir),返回前 fchdir(saved)+close,保证 Inline/Reusable 路径
    // 下 loop parent cwd 不漂。
    //
    // lifetime: caller (LoopRuntime) 拥有 buffer,在 ExecuteProgram 调用期间
    // 必须稳定 (LoopRuntime 用栈上 char workdir_buf[32])。nullptr 时不切 cwd,
    // 保持旧行为(unit test / 早期回归窗口 fallback)。
    //
    // 与 mount_dispatcher 的 saved_cwd_fd (mount_state.cpp:48) 嵌套:
    //   LoopRuntime: mkdir("./5") → ProgramRuntimeRunInline: chdir("./5")
    //     program 跑:mount 内部 save_cwd=open(.) → chdir(target) → fchdir(save) 回 "./5"
    //   ProgramRuntimeRunInline: fchdir(saved) 回 baseline "/"
    //   LoopRuntime: RemoveDirRecursive("./5")
    // 两层 save/restore 互不干扰。
    const char* workdir = nullptr;

    // [early-publish — 把结果投递与 child reap 解耦]
    // 可选钩子,ForkingProgramExecutor 在**功能结果已知的最早时刻**恰好回调一次:
    // fast path 是 program child commit result page 的瞬间(child 还没死、还没
    // reap),crash/kill path 是 reap + 分类之后。loop child 用它立刻把 DoneMsg
    // 写给 daemon,于是 publish(D)不再等 ~36ms 的 child teardown+reap;reap 转而
    // 与 daemon 派发下一条任务的往返重叠(下一条 ReadyMsg 在 pipe 里缓冲,reap 完
    // 直接取到,idle R→A2 收敛到 ~0)。
    //
    // 返回 false = 投递失败(done pipe 断) → executor 仍会先把 child reap 干净再
    // 返回,由 caller 决定 teardown。nullptr(InlineProgramExecutor / 单元测试)→
    // executor 只填 out_done,由 caller 在返回后自己 publish(向后兼容)。
    //
    // 关键不变式:early-publish 只投递功能字段(读自 committed page 的 acquire
    // 快照);fork/reap/rusage 等 parent 侧遥测仍由 executor 在 reap 后填进
    // out_done,给 loop 的 TL 记录用 —— daemon 不消费遥测字段。
    bool (*publish_result)(void* ctx, const DoneMsg& done) = nullptr;
    void* publish_result_ctx = nullptr;
};

// 装 SIGSEGV/SIGABRT/SIGBUS/SIGILL/SIGFPE handler,注入 bus 给 crash 路径。
// 在 LoopRuntime 进 sandbox 前调一次,fork 后 program child 自动继承。
void ProgramRuntimeInstallCrashHandlers(IObservationBus* bus_for_crash);

// 同进程内联执行一条 program(Reusable / Recycle topology 用)。
// out_done 必非空;写完 output_len/status/flags 后返。crash 由 signal
// handler 在子进程内处理(本函数返时已 valid)。
void ProgramRuntimeRunInline(const ProgramRuntimeInput& input,
                             IExecBackend& backend,
                             IObservationBus& bus,
                             uint32_t worker_id,
                             uint32_t proc_id,
                             DoneMsg* out_done);

// IProgramExecutor: LoopRuntime 注入点。
// Reusable / Recycle -> InlineProgramExecutor 同进程跑
// DoubleFork (P4)   -> ForkingProgramExecutor 真 fork + V3 result page
class IProgramExecutor {
public:
    virtual ~IProgramExecutor() = default;
    virtual void ExecuteProgram(const ProgramRuntimeInput& input,
                                DoneMsg* out_done) = 0;
};

// 同进程内联 executor,直接转发到 ProgramRuntimeRunInline。
class InlineProgramExecutor : public IProgramExecutor {
public:
    InlineProgramExecutor(IExecBackend& backend, IObservationBus& bus,
                          uint32_t worker_id, uint32_t proc_id)
        : backend_(backend), bus_(bus), worker_id_(worker_id),
          proc_id_(proc_id) {}

    void ExecuteProgram(const ProgramRuntimeInput& input,
                        DoneMsg* out_done) override
    {
        ProgramRuntimeRunInline(input, backend_, bus_, worker_id_, proc_id_,
                                out_done);
        if (input.perf_trace != nullptr && input.perf_sample != nullptr) {
            input.perf_trace->child_valid = true;
        }
    }

private:
    IExecBackend& backend_;
    IObservationBus& bus_;
    uint32_t worker_id_;
    uint32_t proc_id_;
};

// DoubleForkTopology 用的 fork-per-program executor。
//
// ExecuteProgram 协议:
//   1. fork() program child:
//        child:调 ProgramRuntimeRunInline,把 DoneMsg/perf commit 到
//              ProgramResultPageV3,_exit
//        parent(loop child):用 pidfd/wait 作为完成事实,然后 acquire-load
//              result/progress page;timeout 命中则 SIGKILL + reap。
//   2. 不重应用 sandbox(program child 继承 loop child sandbox 状态)
//   3. 不重装 crash handler(POSIX signal handler 跨 fork 继承)
//
// 关键时序约束:host 不读 result page;loop parent wait/reap 后读取 result page,
// 再经 DoneMsg/CompletionSlot publish 给 host。
class ForkingProgramExecutor : public IProgramExecutor {
public:
    ForkingProgramExecutor(IExecBackend& backend, IObservationBus& bus,
                           uint32_t worker_id, uint32_t proc_id,
                           uint32_t timeout_ms)
        : backend_(backend), bus_(bus), worker_id_(worker_id),
          proc_id_(proc_id), timeout_ms_(timeout_ms) {}

    void ExecuteProgram(const ProgramRuntimeInput& input,
                        DoneMsg* out_done) override;

private:
    IExecBackend& backend_;
    IObservationBus& bus_;
    uint32_t worker_id_;
    uint32_t proc_id_;
    uint32_t timeout_ms_;
    // [当前版本 devnull 预开] loop_parent 一次性打开的 /dev/null fd（O_CLOEXEC）。
    //   fork 出的每个 program-child 继承它，只需 dup2 到 0/1，省掉 child 内
    //   per-program 的 open+close。-1 = 尚未打开 / 打开失败（child 走 fallback
    //   per-program open）。ForkingProgramExecutor 每 loop_child 构造一次、长寿
    //   （double_fork_topology.cpp DoubleForkLoopEntry），故该 fd 跨 program 复用。
    int devnull_fd_ = -1;
    // [early-publish ordering] loop_parent 一次性创建的 commit-signal eventfd
    // （EFD_NONBLOCK|EFD_CLOEXEC，创建后立即 dup 到 fd>=31，逃过 program-child
    // 的 close_range(3,30) 扫除 —— 否则 SetupTestWorkdir 会把它连同 fd 3-30 一起
    // 关掉，child 之后的 write() 会静默 EBADF）。fork 继承同一份 eventfd；child
    // 在 CommitResultPage 之后、_exit 之前写 1，parent 的 watchdog 循环把它跟
    // pidfd 放进同一次 poll()，命中时保证在 reap 之前处理（fork_server_reaper.hpp
    // 的 kExtraFdReady）。-1 = 创建失败，退化为纯内存轮询（正确性不受影响，只是
    // 早发布的时延保证从"结构性"退回"经验性"）。
    int commit_evt_fd_ = -1;
};

} // namespace refuzz::worker::engine

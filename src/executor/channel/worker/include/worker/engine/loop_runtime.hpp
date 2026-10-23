// LoopRuntime: long-lived loop 进程主循环。
//
// 单一职责:在已 fork 出来的 child 进程内,完成 sandbox/fd/KCOV/crash handler
// setup,然后按轮执行 mkdir workdir → reset loop → read ReadyMsg →
// 调 IProgramExecutor → write DoneMsg → cleanup。
//
// 不感知 NEWPID / fork-per-program — 这些是 topology Setup 阶段或
// IProgramExecutor 实现的事:
//   - ReusableChild / RecycleChild: InlineProgramExecutor 同进程跑
//   - DoubleFork (P4): ForkingProgramExecutor 真 fork program child
//
// 行为约束:Reusable + InlineProgramExecutor 路径必须 byte-equal 旧 ChildMain。

#pragma once

#include "worker/sandbox.hpp"
#include "worker/program_buffers.hpp"

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace refuzz::worker {
class IExecBackend;
class IObservationBus;
} // namespace refuzz::worker

namespace refuzz::worker::engine {

class IProgramExecutor;

bool IsSmapsVmaHeaderLine(std::string_view line);

// 长 loop 进程入口。永不返回 — 通过 _exit 退出。
//
// transport_shm_base/size: 旧 DoubleForkTopology(kDoubleFork,进程内 fork,非
//   exec 的历史路径)传完整多 worker BAR2 base/size(ShmHeader 布局),LoopRuntime
//   据此解析 V3 layout 并把 control/header/step-ring/其它 worker 的 data window
//   标记 MADV_DONTFORK,只让本 worker 的 data window 被 fork-per-program child
//   继承。stdio profile / kExecDoubleFork(下面)传 nullptr/0。
//
// fork_window_base/size: kExecDoubleFork(生产拓扑,ExecNsRunner → RunExecLoop)
//   传该 worker 自己已经映射好的 data window 整段(exec_loop_entry.cpp 的
//   window.mapping/window.mapping_size)—— 这是一段已经按本 worker切好的原始
//   range,不含 ShmHeader,不需要(也不能)按 ApplyV3ForkMappingPolicy 的多
//   worker 切片逻辑解析。非空时 LoopRuntime 直接对整段 MADV_DONTFORK + probe,
//   并启用 program-child 的 anon-shared staging(input/output/result page 全部
//   走 staging,child 不再继承这段 PFNMAP 窗口,省掉每程序的 fork/exit 页表税)。
//   与 transport_shm_base 是两条独立、可各自为空的路径 —— 同一次调用最多只有
//   一条非空(kDoubleFork 用前者,kExecDoubleFork 用后者,两者都不用 stdio)。
[[noreturn]] void LoopRuntimeRun(
    int ready_pipe_r,
    int done_pipe_w,
    uint32_t worker_id,
    uint32_t proc_id,
    IExecBackend& backend,
    IObservationBus& bus,
    SandboxMode sandbox_mode,
    bool allow_no_private_mount_namespace_for_tests,
    size_t transport_mapped_bytes,
    void* transport_shm_base,
    size_t transport_shm_size,
    ProgramBufferMapping program_mapping,
    int startup_ack_fd,
    IProgramExecutor& executor,
    void* fork_window_base = nullptr,
    size_t fork_window_size = 0);

} // namespace refuzz::worker::engine

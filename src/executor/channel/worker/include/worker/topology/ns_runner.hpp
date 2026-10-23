// NsRunnerSupervisor: disposable ns-runner layer for syzkaller-aligned NEWPID
// 拓扑(D12 fix to D11 setns 短期止血)。
//
// 拓扑(daemon 永不 unshare):
//
//   daemon                    ── long-lived (RPC + dispatch + supervisor)
//    │   ★ 永不 unshare(NEWPID),不持 initial_pid_ns fd
//    │   pipe2(ready,O_CLOEXEC); pipe2(done,O_CLOEXEC)
//    │   fork()  ──────────────────────────────────────────────────────►
//    │                                                                 │
//    │                                                                 ▼
//    │                                                          ns-runner ── disposable
//    │                                                          ★ 一次性 unshare(NEWPID)
//    │                                                          fork()  ─► loop_child(PID 1)
//    │                                                          close 全部 4 个 pipe fd
//    │                                                          waitpid(loop_child)
//    │                                                          _exit(WEXITSTATUS / 128+sig)
//    │
//    ▼
//   close ready_r / done_w(child 侧)
//   ChildWaiter::Watch(ns_runner_pid)
//
// 核心不变量:
//   - 每次 Spawn() / Respawn() 都 fork 一个新 ns-runner 进程。
//   - 新进程 = 新 nsproxy:`task_active_pid_ns(current) == pid_ns_for_children`
//     必然成立,unshare(NEWPID) 永远是"首次"。
//   - kernel `copy_pid_ns` EINVAL check 永远不会撞 → D11 的 setns reset 不再
//     需要。
//
// IPC pass-through:
//   - ready/done pipe 在 daemon 内创建,fork 时传给 ns-runner;ns-runner 立即
//     close 全部 4 个 fd(它不读写 pipe,持 fd 会阻 EOF);loop_child 关 daemon
//     侧(ready_w / done_r),只留 ready_r / done_w。daemon 端关 child 侧
//     (ready_r / done_w)。这样 pipe 的 reader/writer 各只有一个进程,EOF
//     语义正确。
//   - ns-runner 在 RPC 数据流上完全 invisible。
//
// 跟 ChildWaiter 复用关系(plan §10 Q1):
//   ns-runner 退出由 ChildWaiter pidfd 路径监,daemon 主循环可 epoll
//   ChildWaiter::PollFd() 跟 RPC fd / 设备 IO multiplex。fallback 仍 WNOHANG
//   waitpid 轮询。

#pragma once

#include "worker/topology/domain_handle.hpp"
#include "worker/topology/child_waiter.hpp"
#include "worker/engine/loop_worker_boot_config.hpp"

#include <cstdint>
#include <string>
#include <sys/types.h>

namespace refuzz::worker::topology {

class NsRunnerSupervisor {
public:
    // Loop child 入口。在新 PID NS 内、ns-runner fork 完后被调,以 PID 1 运行。
    //   ready_r_fd: daemon → loop_child 的 ready pipe 读端
    //   done_w_fd : loop_child → daemon 的 done pipe 写端
    //   user      : caller-provided closure 指针
    // 正常情况下入口不返回(走 LoopRuntimeRun 死循环);若返回,supervisor
    // 替 caller _exit(0)。
    using LoopChildEntry = void (*)(int ready_r_fd, int done_w_fd, void* user);

    NsRunnerSupervisor() = default;
    ~NsRunnerSupervisor();

    NsRunnerSupervisor(const NsRunnerSupervisor&) = delete;
    NsRunnerSupervisor& operator=(const NsRunnerSupervisor&) = delete;
    NsRunnerSupervisor(NsRunnerSupervisor&&) = delete;
    NsRunnerSupervisor& operator=(NsRunnerSupervisor&&) = delete;

    // 一次性 spawn ns-runner + loop_child。成功返 0,失败返非 0。
    // 失败会先走 StopDomainHandle；若该绝对 deadline 内仍无法清完，handle
    // 保留给 caller Detach 后交回 established topology，禁止遗失 ownership。
    int Spawn(LoopChildEntry entry, void* user,
              const DomainStopPlan& startup_cleanup_plan =
                  StartupCleanupStopPlan(),
              uint64_t startup_deadline_us = 0);

    // 先通过 pidfd 杀 loop PID 1，再回收 ns-runner 并关闭全部 fd。
    // 反复调安全(no-op when not spawned)。
    DomainStopResult Stop(
        const DomainStopPlan& plan = StartupCleanupStopPlan(),
        uint64_t absolute_deadline_us = 0);

    // Stop + Spawn。
    int Respawn(LoopChildEntry entry, void* user,
                const DomainStopPlan& startup_cleanup_plan =
                    StartupCleanupStopPlan(),
                uint64_t startup_deadline_us = 0);

    // 把完整 DomainHandle 所有权转给 caller。Detach 后
    // supervisor 退回未 spawn 态(析构/Stop 都 no-op),caller 负责 kill pid
    // + close fd。ChildWaiter 状态丢弃(pidfd 关闭)。
    //
    // 用法:DoubleForkTopology 在 ForkChild 里把状态交给 base class ctx_
    // 管理时用,避免双 close。
    using DetachedState = DomainHandle;
    DetachedState Detach();

    pid_t NsRunnerPid() const { return handle_.pid; }

    // daemon 写 ready msg 用这个 fd,从 done msg 读这个 fd。-1 = 未 spawn。
    int ReadyWriteFd() const { return handle_.ready_pipe_w; }
    int DoneReadFd()   const { return handle_.done_pipe_r; }
    int LoopPollFd()   const { return handle_.loop_pidfd; }
    bool LoopHasExited() const;

    // ChildWaiter 转发。ns-runner 死 = loop_child 死(因 ns-runner waitpid +
    // _exit propagate)。ExitStatus 是 ns-runner _exit code,等于 loop_child
    // 的 wstatus 解读(WEXITSTATUS / 128+sig)。
    bool HasExited();
    bool WaitFor(uint32_t timeout)  { return waiter_.WaitFor(timeout); }
    int  ExitStatus() const;
    int  PollFd() const             { return waiter_.PollFd(); }

private:
    void ReleaseWaiterToHandle();

    DomainHandle handle_;
    ChildWaiter waiter_;
};

struct ExecNsRunnerSpawnConfig {
    ::refuzz::worker::engine::LoopWorkerBootConfig boot;
    int backing_fd = -1;
    std::string executor_path;
    uint64_t startup_deadline_us = 0;
};

class ExecNsRunnerSupervisor {
public:
    ExecNsRunnerSupervisor() = default;
    ~ExecNsRunnerSupervisor();

    ExecNsRunnerSupervisor(const ExecNsRunnerSupervisor&) = delete;
    ExecNsRunnerSupervisor& operator=(const ExecNsRunnerSupervisor&) = delete;

    DomainStartResult Spawn(const ExecNsRunnerSpawnConfig& config);
    DomainStopResult Stop(
        const DomainStopPlan& plan = StartupCleanupStopPlan(),
        uint64_t absolute_deadline_us = 0);

    NsRunnerSupervisor::DetachedState Detach();
    pid_t NsRunnerPid() const { return handle_.pid; }

private:
    void ReleaseWaiterToHandle();

    DomainHandle handle_;
    ChildWaiter waiter_;
};

// Entry used by the standalone refuzz_executor binary.
int RunExecNsRunnerRole();

} // namespace refuzz::worker::topology

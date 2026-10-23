// DoubleForkTopology: syzkaller-aligned 三层进程拓扑(D12 ns-runner 实装)。
//
// 拓扑:
//   daemon                             (host pid ns, 永不 unshare)
//    │  NsRunnerSupervisor::Spawn():
//    │    pipe2(ready/done); fork()
//    ▼
//   ns-runner                          (disposable)
//    │  unshare(CLONE_NEWPID); fork()
//    │  close 全部 4 fd;waitpid(loop_child)→ _exit(propagate)
//    ▼
//   loop_child = PID 1                 (long-lived in new ns)
//     setsid; ApplySandbox(...)
//     LoopRuntime::Run(..., ForkingProgramExecutor)
//      │  loop: read task → fork() program child → wait → write done
//      ▼
//    program child                     (PID 2+, 短命 per prog)
//
// 跟 ReusableChildTopology 的 IPC 协议(daemon ↔ loop_child via ready/done pipe)
// 完全一致。ns-runner 在 RPC 数据流上 invisible — 它持的 fd 在 fork 后立即
// close,daemon 写 ready_w 直接到 loop_child read,loop_child 写 done_w 直接
// 到 daemon read。
//
// 关键 D12 不变量(替代 D11 的 daemon-内 setns 止血):
//   - daemon **永不** unshare(CLONE_NEWPID),不持 initial_pid_ns fd
//   - 每次 ForkChild 都 fork 一个新 ns-runner 进程;新进程 nsproxy 干净,
//     unshare(NEWPID) 永远是"首次",kernel `copy_pid_ns` EINVAL 永不撞
//   - DomainSupervisor 通过 Stop + Setup 重建，base 类不感知 ns-runner
//
// ctx_.pid 指 **ns-runner** 而非 loop_child。daemon SIGKILL/waitpid 都是对
// ns-runner;ns-runner 内部 waitpid + _exit propagate loop_child 退出状态。

#pragma once

#include "worker/topology/reusable_child_topology.hpp"

namespace refuzz::worker::topology {

class DoubleForkTopology : public ReusableChildTopology {
public:
    DoubleForkTopology(::refuzz::worker::IExecBackend& backend,
                       ::refuzz::worker::IObservationBus& bus);
    ~DoubleForkTopology() override = default;

    // DomainSupervisor owns periodic recycle; topology only starts/stops one
    // execution domain at a time.
    DomainStartResult Setup(const TopologyConfig& cfg) override;

protected:
    // 走 NsRunnerSupervisor::Spawn + Detach,把 ns-runner pid + ready_w /
    // done_r 交给 base ctx_。base class 后续 WaitChild / Stop 全照常工作,
    // 只把"child" 理解为 ns-runner(不感知 loop_child 在再下层)。
    DomainStartResult ForkChild() override;
    bool UnexpectedChildExitIsHarnessFatal() const override { return true; }
};

class ExecDoubleForkTopology final : public ReusableChildTopology {
public:
    ExecDoubleForkTopology() = default;
    ~ExecDoubleForkTopology() override = default;

    DomainStartResult Setup(const TopologyConfig& cfg) override;

protected:
    DomainStartResult ForkChild() override;
    bool UnexpectedChildExitIsHarnessFatal() const override { return true; }
};

} // namespace refuzz::worker::topology

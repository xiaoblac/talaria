// ReusableChildTopology: legacy reFuzz 行为 — daemon + long-lived child。
//
// Setup -> ForkChild,child 跑 LoopRuntime + InlineProgramExecutor (同进程,不
// fork 每条 prog)。Dispatch / Collect 走 ready/done pipe，只观察 completion、
// timeout/crash/cancel；DomainSupervisor 负责停止旧域、选择 proc-id 并重建。
//
// 没有 NEWPID,没有 per-program crash isolation — 那是 DoubleForkTopology
// 的事。本 topology 仅作 P1 refactor 的 byte-equal 守护 + 测试/debug/throughput
// baseline / DoubleFork fallback 选项。

#pragma once

#include "worker/topology/domain_handle.hpp"
#include "worker/topology/process_topology.hpp"
#include "worker/engine/runtime_messages.hpp"

#include <sys/types.h>
#include <cstdint>

namespace refuzz::worker {
class IExecBackend;
class IObservationBus;
} // namespace refuzz::worker

namespace refuzz::worker::topology {

class ReusableChildTopology : public ProcessTopology {
public:
    ReusableChildTopology(::refuzz::worker::IExecBackend& backend,
                          ::refuzz::worker::IObservationBus& bus);

    DomainStartResult Setup(const TopologyConfig& cfg) override;
    DispatchHandle Dispatch(const ProgramRequest& req) override;
    CollectResult Collect(DispatchHandle h, uint32_t timeout_ms,
                          CancelPredicate cancel, void* cancel_user) override;
    pid_t CurrentChildPid() const override { return ctx_.pid; }
    uint64_t CurrentChildGeneration() const override { return ctx_.generation; }
    bool ExecutionDomainExited() const override;
    DomainStopResult Stop(const DomainStopPlan& plan) override;

protected:
    ReusableChildTopology() = default;
    struct ChildContext : DomainHandle {
        uint64_t generation = 0;
    };

    // virtual so DoubleForkTopology can override with NEWPID + forking executor
    virtual DomainStartResult ForkChild();
    DomainStopResult StopChild(const DomainStopPlan& plan);

    // WaitChild: 阻塞等 done pipe / timeout / cancel / child exit。返:
    //   0 = 正常完成 (done valid)
    //   1 = daemon watchdog timeout
    //   2 = child exit (crash_signal 已 set)
    //   3 = cancel requested
    //   4 = ready/done pipe protocol failure
    //
    // CancelPredicate 周期回调(可空)。
    int WaitChild(::refuzz::worker::engine::DoneMsg& done,
                  uint32_t timeout_ms,
                  CancelPredicate cancel,
                  void* cancel_user,
                  uint32_t* crash_signal);

    virtual bool UnexpectedChildExitIsHarnessFatal() const { return false; }

    ::refuzz::worker::IExecBackend* backend_ = nullptr;
    ::refuzz::worker::IObservationBus* bus_ = nullptr;
    TopologyConfig cfg_;
    ChildContext ctx_;
    bool dispatch_failed_ = false;
};

} // namespace refuzz::worker::topology

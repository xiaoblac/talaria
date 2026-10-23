// ProcessTopology: engine-layer process topology strategy 抽象。
//
// 把"daemon 怎么 fork/wait child"这层从 ExecutionEngine / sandbox.cpp 显式
// 分离出来。四个实现:
//   - ReusableChildTopology  : daemon → long-lived child (=当前 reFuzz 行为)
//   - RecycleChildTopology   : daemon → long-lived child(N 条 prog 后 respawn)
//   - DoubleForkTopology     : daemon → loop child(PID 1)→ program child(PID 2+)
//
// 设计原则(见 docs/plans/double-fork-topology.md):
//   1) 拓扑显式 — 不藏在 sandbox.cpp/execution_engine.cpp 里
//   2) sandbox primitives 由 loop child 进程一次性应用,program child 继承
//   3) profile 决定 topology,transport(stdio/ivshmem)只是通信方式
//
// IPC 边界:
//   - L1 fork-tree 内部(同主机):OS pipe (ready/done) + V3 result/progress page
//   - L2 daemon ↔ 外部主控:transport adapter — 不进 topology

#pragma once

#include "worker/engine/runtime_messages.hpp"
#include "worker/engine/loop_worker_boot_config.hpp"
#include "worker/sandbox.hpp"
#include "worker/program_buffers.hpp"
#include "worker/topology/domain_identity.hpp"
#include "refuzz/proto_wire/ivshmem_protocol.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <sys/types.h>

namespace refuzz::worker {
class IExecBackend;
class IObservationBus;
} // namespace refuzz::worker

namespace refuzz::worker::topology {

inline constexpr uint32_t kDefaultDomainStartupTimeoutMs = 60'000;

enum class DomainStopIntent : uint8_t {
    kRecovery = 0,
    kPeriodicRecycle,
    kRequestedProcRebind,
    kStartupCleanup,
    kDaemonShutdown,
    kCancellation,
};

struct DomainStopPlan {
    DomainStopIntent intent = DomainStopIntent::kDaemonShutdown;
    bool graceful = true;
    // Only task-watchdog recovery may logically detach a loop that remains
    // alive after its ns-runner has been killed and reaped.
    bool allow_abandon = false;
    uint32_t graceful_timeout_ms = 2000;
    uint32_t kill_timeout_ms = 2000;
    uint32_t runner_timeout_ms = 1000;
    uint32_t reap_timeout_ms = 2000;
    // Zero lets the topology derive one deadline from the phase budgets.
    // DomainSupervisor sets this to its own phase deadline so every stop stage
    // consumes one shared absolute budget.
    uint64_t absolute_deadline_us = 0;
};

inline DomainStopPlan StartupCleanupStopPlan()
{
    DomainStopPlan plan{};
    plan.intent = DomainStopIntent::kStartupCleanup;
    plan.graceful = false;
    return plan;
}

enum class DomainStopResult : uint8_t {
    kClean = 0,
    kForced,
    kAbandoned,
    kFailed,
};

inline bool DomainStopPhysicallyReclaimed(DomainStopResult result)
{
    return result == DomainStopResult::kClean ||
           result == DomainStopResult::kForced;
}

inline bool DomainStopAllowsReplacement(DomainStopResult result)
{
    return result != DomainStopResult::kFailed;
}

enum class DomainStartKind : uint8_t {
    kReady = 0,
    kRejected,
    kExited,
    kStalled,
};

struct DomainStartResult {
    DomainStartKind kind = DomainStartKind::kRejected;
    uint32_t proc_id = 0;
    ::refuzz::worker::engine::LoopStartupStage stage =
        ::refuzz::worker::engine::LoopStartupStage::kUnknown;
    int32_t error_number = 0;
    int32_t exit_status = 0;

    bool IsReady() const { return kind == DomainStartKind::kReady; }
};

inline DomainStartResult MakeDomainStartReady(uint32_t proc_id)
{
    DomainStartResult result{};
    result.kind = DomainStartKind::kReady;
    result.proc_id = proc_id;
    result.stage = ::refuzz::worker::engine::LoopStartupStage::kReady;
    return result;
}

inline DomainStartResult MakeDomainStartRejected(
    uint32_t proc_id,
    ::refuzz::worker::engine::LoopStartupStage stage,
    int error_number)
{
    DomainStartResult result{};
    result.kind = DomainStartKind::kRejected;
    result.proc_id = proc_id;
    result.stage = stage;
    result.error_number = error_number;
    return result;
}

inline DomainStartResult MakeDomainStartExited(uint32_t proc_id,
                                                int exit_status,
                                                int error_number)
{
    DomainStartResult result{};
    result.kind = DomainStartKind::kExited;
    result.proc_id = proc_id;
    result.error_number = error_number;
    result.exit_status = exit_status;
    return result;
}

inline DomainStartResult MakeDomainStartStalled(uint32_t proc_id,
                                                 int error_number)
{
    DomainStartResult result{};
    result.kind = DomainStartKind::kStalled;
    result.proc_id = proc_id;
    result.error_number = error_number;
    return result;
}

// daemon 一次性 setup 参数。
struct TopologyConfig {
    SandboxMode sandbox_mode = SandboxMode::kNone;
    // Production invariant. Non-privileged topology tests may explicitly opt
    // out because they test process/pipe behavior, not mount isolation.
    bool allow_no_private_mount_namespace_for_tests = false;
    size_t transport_mapped_bytes = 0;
    uint32_t recycle_after = 600;     // 0 = unlimited; engine post-report maintenance uses this threshold
    DomainIdentity identity{0, kAnyProcId, 0};
    // Compatibility input for topology-focused tests. Production sets
    // identity explicitly; an unspecified identity.proc_id adopts worker_id.
    uint32_t worker_id = 0;
    uint32_t exec_timeout_ms = 5000;  // 单条 prog 强杀阈值,topology Collect 内用
    // Sandbox/KCOV/net namespace initialization has a separate, longer
    // budget than one program execution.
    uint32_t startup_timeout_ms = kDefaultDomainStartupTimeoutMs;
    // One attempt-wide monotonic deadline. When non-zero, every blocking
    // startup phase consumes the remaining budget instead of starting its own
    // timer. Standalone topology callers may leave it zero; Setup resolves the
    // duration above into one absolute deadline before spawning.
    uint64_t startup_deadline_us = 0;
    // A partially-created domain is stopped with the same mechanical chain as
    // an established domain. DomainSupervisor supplies its configured phase
    // budgets here; standalone topology users get the standard forced plan.
    DomainStopPlan startup_cleanup_plan = StartupCleanupStopPlan();
    // [LoopRuntime V3 mmap policy] 透传 transport 共享内存 base / size,
    // LoopRuntime 用来 DONTFORK control/header/step-ring,保留 data window
    // 给 program child 继承。stdio profile 传 nullptr/0。
    void* transport_shm_base = nullptr;
    size_t transport_shm_size = 0;
    ProgramBufferMapping program_mapping;
    int execution_backing_fd = -1;
    ::refuzz::worker::engine::LoopWorkerBootConfig loop_boot_config =
        ::refuzz::worker::engine::MakeLoopWorkerBootConfig();
    std::string executor_path;
};

// Dispatch 返回的句柄。当前单 child 模型只允许 1 条 in-flight,
// generation 帮 caller 检测 child respawn 边界。
struct DispatchHandle {
    uint64_t generation = 0;
};

// 一条 program 的拓扑层视图。跨 topology 边界只传长度、标量和 offset
// descriptor；buffer 地址由 execution domain 根据自己的 mapping base 解析。
struct ProgramRequest {
    uint32_t input_len = 0;
    uint32_t output_cap = 0;
    uint32_t flags = 0;
    uint64_t executor_id = 0;
    uint32_t dispatch_gen = 0;
    ProgramBufferDescriptor buffers;
};

enum class CollectKind : uint8_t {
    kDone,          // program finished/was classified; inspect result_kind
    kTimeout,       // daemon watchdog expired; supervisor decides recovery
    kChildAborted,  // child 退出/被信号杀 (crash_signal 字段从 wstatus 取)
    kCancelled,     // CancelPredicate 返 true
    kHarnessFail,   // topology 内部错误 (fork/pipe broken / IPC 协议失败)
};

struct CollectResult {
    CollectKind kind = CollectKind::kHarnessFail;
    uint32_t output_len = 0;
    int32_t status = 0;
    uint32_t flags = 0;
    ::refuzz::worker::engine::RuntimeResultKind result_kind =
        ::refuzz::worker::engine::RuntimeResultKind::kNoResult;
    uint32_t crash_signal = 0; // kChildAborted 时有意义
    ::refuzz::worker::engine::HarnessFatalReason fatal_reason =
        ::refuzz::worker::engine::HarnessFatalReason::kNone;
};

// 周期回调:topology Collect 内部 polling 时调,返 true => 停止等待并返
// kCancelled。是否停止/替换 domain 仍由 DomainSupervisor 决定。
using CancelPredicate = bool (*)(void* user);

// 三种实现枚举,工厂使用。
enum class TopologyKind : uint8_t {
    kReusableChild = 0,
    kRecycleChild = 1,
    kDoubleFork = 2,
    kExecDoubleFork = 3,
};

class ProcessTopology {
public:
    virtual ~ProcessTopology() = default;

    // daemon-side 一次性 setup。显式区分 child 拒绝、退出和无进展超时。
    // ReusableChild / RecycleChild: 启动 long-lived child + LoopRuntime (inline executor)
    // DoubleFork: unshare(NEWPID) + fork → loop child = PID 1 → LoopRuntime (fork executor)
    virtual DomainStartResult Setup(const TopologyConfig& cfg) = 0;

    // 派发一条 program。
    // 单 child 模型:Dispatch 前必须 Collect 上一条 (单 in-flight 约束)。
    virtual DispatchHandle Dispatch(const ProgramRequest& req) = 0;

    // 收 result。timeout_ms = 0 表示无超时。cancel 周期回调(可空)。
    // timeout / crash / cancel 时 topology 只观察并分类，不停止或重建 domain。
    // DomainSupervisor 在拿到分类后统一执行 Recover(reason)。
    virtual CollectResult Collect(DispatchHandle h, uint32_t timeout_ms,
                                  CancelPredicate cancel, void* cancel_user) = 0;

    // 当前 execution-domain child pid，供 supervisor 诊断与故障分类。
    virtual pid_t CurrentChildPid() const = 0;

    // 当前 child generation (respawn 计数)。
    virtual uint64_t CurrentChildGeneration() const = 0;

    // Non-blocking execution-domain liveness observation used at idle
    // maintenance boundaries.
    virtual bool ExecutionDomainExited() const = 0;

    // 机械执行 DomainSupervisor 给出的 stop escalation 计划。topology 不据此
    // 决定 daemon 是否退出，也不自行启动 replacement domain。
    virtual DomainStopResult Stop(const DomainStopPlan& plan) = 0;
};

// 工厂:根据 kind 实例化 topology。legacy fork topology 继承 backend/bus；
// exec topology 在新进程内重建组件。
std::unique_ptr<ProcessTopology> MakeTopology(TopologyKind kind,
                                              IExecBackend& backend,
                                              IObservationBus& bus);

} // namespace refuzz::worker::topology

// DoubleForkTopology 实现 — D12 ns-runner 实装。
//
// 跟 ReusableChildTopology::ForkChild 区别:
//   (a) fork 路径走 NsRunnerSupervisor::Spawn,自动插入 ns-runner 中间层
//       一次性 unshare(NEWPID),解 D11 setns 止血的根因
//   (b) loop_child 进 LoopRuntime 时用 ForkingProgramExecutor(每条 prog
//       fork program child)而非 InlineProgramExecutor
//
// IPC 协议跟 base 完全一致 → Dispatch/Collect/WaitChild/Stop
// 全 base 直接复用。base ctx_.pid 持 ns-runner pid;ns-runner 内部 waitpid
// propagate loop_child 退出码。

#include "worker/topology/double_fork_topology.hpp"

#include "worker/backend/exec_backend.hpp"
#include "worker/engine/loop_runtime.hpp"
#include "worker/engine/program_runtime.hpp"
#include "worker/log/log_macros.hpp"
#include "worker/observation/observation_bus.hpp"
#include "worker/topology/ns_runner.hpp"
#include "worker/topology/topology_probe.hpp"

#include <unistd.h>

#include <algorithm>
#include <cerrno>

#define LOG(fmt, ...) ::refuzz::worker::log::WorkerLog("[Worker] " fmt "\n", ##__VA_ARGS__)

namespace refuzz::worker::topology {

namespace eng = ::refuzz::worker::engine;

namespace {

// loop_child entry 闭包包。NsRunnerSupervisor 用 free function + void* 调度,
// 这个 struct 把 ForkChild 需要传给 LoopRuntimeRun 的 by-reference 字段打包。
struct LoopChildArgs {
    ::refuzz::worker::IExecBackend* backend;
    ::refuzz::worker::IObservationBus* bus;
    uint32_t worker_id;
    uint32_t proc_id;
    SandboxMode sandbox_mode;
    bool allow_no_private_mount_namespace_for_tests;
    size_t transport_mapped_bytes;
    void* transport_shm_base;
    size_t transport_shm_size;
    ProgramBufferMapping program_mapping;
    uint32_t exec_timeout_ms;
};

// 在新 PID NS 内 loop_child 入口(PID 1 in fallback host NS 也走这条)。
void DoubleForkLoopEntry(int ready_r, int done_w, void* user)
{
    auto* args = static_cast<LoopChildArgs*>(user);

    EmitTopologyProbeSelf("loop-entry", args->worker_id, 0, 0);

    eng::ForkingProgramExecutor executor(*args->backend, *args->bus,
                                         args->worker_id,
                                         args->proc_id,
                                         args->exec_timeout_ms);
    eng::LoopRuntimeRun(ready_r, done_w, args->worker_id, args->proc_id,
                        *args->backend, *args->bus,
                        args->sandbox_mode,
                        args->allow_no_private_mount_namespace_for_tests,
                        args->transport_mapped_bytes,
                        args->transport_shm_base,
                        args->transport_shm_size,
                        args->program_mapping,
                        -1,
                        executor);
    // [[noreturn]] — LoopRuntimeRun 永不返回。
}

} // namespace

DoubleForkTopology::DoubleForkTopology(
    ::refuzz::worker::IExecBackend& backend,
    ::refuzz::worker::IObservationBus& bus)
    : ReusableChildTopology(backend, bus)
{}

DomainStartResult DoubleForkTopology::Setup(const TopologyConfig& cfg)
{
    return ReusableChildTopology::Setup(cfg);
}

DomainStartResult DoubleForkTopology::ForkChild()
{
    // LoopChildArgs 在 daemon 栈上,fork 后 loop_child 拿到的是 fork-COW 副本,
    // entry 立即 deref 一次后就进 LoopRuntimeRun(永不返回),daemon 栈是否
    // 复用都无关。
    LoopChildArgs args{
        backend_,
        bus_,
        cfg_.identity.worker_id,
        cfg_.identity.proc_id,
        cfg_.sandbox_mode,
        cfg_.allow_no_private_mount_namespace_for_tests,
        cfg_.transport_mapped_bytes,
        cfg_.transport_shm_base,
        cfg_.transport_shm_size,
        cfg_.program_mapping,
        cfg_.exec_timeout_ms,
    };

    NsRunnerSupervisor sup;
    if (sup.Spawn(&DoubleForkLoopEntry, &args,
                  cfg_.startup_cleanup_plan,
                  cfg_.startup_deadline_us) != 0) {
        const int saved_errno = errno;
        DomainHandle partial = sup.Detach();
        if (partial.pid > 0) {
            static_cast<DomainHandle&>(ctx_) = partial;
            ++ctx_.generation;
        }
        LOG("DoubleFork: NsRunnerSupervisor::Spawn failed");
        errno = saved_errno;
        return saved_errno == ETIMEDOUT
            ? MakeDomainStartStalled(cfg_.identity.proc_id, saved_errno)
            : MakeDomainStartRejected(
                cfg_.identity.proc_id, eng::LoopStartupStage::kNamespace,
                saved_errno != 0 ? saved_errno : EPROTO);
    }

    // Detach:supervisor 退出后不 close fd / 不 kill pid;base ctx_ 接管。
    static_cast<DomainHandle&>(ctx_) = sup.Detach();
    ctx_.generation++;
    dispatch_failed_ = false;

    LOG("DoubleFork: ns_runner_pid=%d ns_pidfd=%d loop_pidfd=%d gen=%lu",
        ctx_.pid, ctx_.ns_runner_pidfd, ctx_.loop_pidfd, ctx_.generation);
    return MakeDomainStartReady(cfg_.identity.proc_id);
}

DomainStartResult ExecDoubleForkTopology::Setup(const TopologyConfig& cfg)
{
    return ReusableChildTopology::Setup(cfg);
}

DomainStartResult ExecDoubleForkTopology::ForkChild()
{
    auto boot = cfg_.loop_boot_config;
    boot.size = static_cast<uint16_t>(sizeof(boot));
    boot.worker_id = cfg_.identity.worker_id;
    boot.proc_id = cfg_.identity.proc_id;
    boot.proc_epoch = cfg_.identity.proc_epoch;
    boot.kcov_child_mode = static_cast<uint32_t>(
        eng::LoopKcovChildMode::kInheritedFromLoop);
    boot.buffer_source = static_cast<uint32_t>(cfg_.program_mapping.source);
    boot.window_resource_offset = cfg_.program_mapping.resource_offset;
    boot.window_size = cfg_.program_mapping.mapped_size;
    boot.input_resource_offset = cfg_.program_mapping.input_offset;
    boot.input_size = cfg_.program_mapping.input_size;
    boot.output_resource_offset = cfg_.program_mapping.output_offset;
    boot.output_size = cfg_.program_mapping.output_size;
    boot.result_resource_offset = cfg_.program_mapping.result_page_offset;
    boot.result_size = cfg_.program_mapping.result_page_size;
    if (cfg_.allow_no_private_mount_namespace_for_tests) {
        boot.flags |= eng::kLoopBootAllowNoPrivateMountNamespaceForTests;
    }

    ExecNsRunnerSpawnConfig spawn{};
    spawn.boot = boot;
    spawn.backing_fd = cfg_.execution_backing_fd;
    spawn.executor_path = cfg_.executor_path;
    spawn.startup_deadline_us = cfg_.startup_deadline_us;

    ExecNsRunnerSupervisor supervisor;
    const DomainStartResult start_result = supervisor.Spawn(spawn);
    if (!start_result.IsReady()) {
        DomainHandle partial = supervisor.Detach();
        if (partial.pid > 0) {
            static_cast<DomainHandle&>(ctx_) = partial;
            ++ctx_.generation;
        }
        errno = start_result.error_number;
        LOG("ExecDoubleFork: Spawn failed kind=%u stage=%u errno=%d",
            static_cast<unsigned>(start_result.kind),
            static_cast<unsigned>(start_result.stage),
            start_result.error_number);
        return start_result;
    }
    static_cast<DomainHandle&>(ctx_) = supervisor.Detach();
    ++ctx_.generation;
    dispatch_failed_ = false;
    return start_result;
}

} // namespace refuzz::worker::topology

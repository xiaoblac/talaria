// Brick 4a — snapshot worker loop. See snapshot_engine.hpp + the design doc.

#include "worker/engine/snapshot_engine.hpp"

#include "worker/backend/syz_exec_runner.hpp"          // PreallocateSyzExecScratch
#include "worker/engine/program_runtime.hpp"           // ProgramRuntimeInstallCrashHandlers
#include "worker/exec_mode.hpp"                         // ExecModeFromFlags
#include "worker/log/log_macros.hpp"
#include "worker/sandbox.hpp"                           // ApplySandbox, SandboxSizing, kSyzExecScratchBytes
#include "worker/sandbox/device_init/device_init.hpp"  // SetupCgroupsLoop, CheckpointNetNamespace
#include "worker/topology/domain_identity.hpp"

#include "refuzz/proto_wire/ivshmem_protocol.h"

#include <cerrno>
#include <chrono>
#include <csignal>
#include <unistd.h>

#define LOG(fmt, ...) ::refuzz::worker::log::WorkerLog("[Worker] " fmt "\n", ##__VA_ARGS__)

// Set by the SIGINT/SIGTERM handler in ivshmem_worker_main.cpp.
extern volatile sig_atomic_t g_running;

namespace refuzz::worker {

int RunSnapshotEngine(IWorkerTaskChannel& task_channel,
                      IExecutionDomainRegistry& domain_registry,
                      IExecBackend& backend,
                      IObservationBus& bus,
                      const EngineConfig& cfg)
{
    const topology::ProcIdLane proc_lane(
        cfg.worker_id, domain_registry.WorkerCount());
    if (!proc_lane.Valid()) {
        LOG("snapshot: invalid proc-id lane worker=%u workers=%u",
            cfg.worker_id, domain_registry.WorkerCount());
        return 1;
    }
    const PersistedProcState persisted = domain_registry.LoadProcState();
    const uint32_t proc_id = persisted.valid && proc_lane.Owns(persisted.proc_id)
        ? proc_lane.Next(persisted.proc_id)
        : proc_lane.Initial();
    const uint32_t proc_epoch = persisted.valid ? persisted.epoch + 1u : 0u;
    if (!domain_registry.PublishProcState(proc_id, proc_epoch)) {
        LOG("snapshot: failed to persist proc state proc=%u epoch=%u",
            proc_id, proc_epoch);
        return 1;
    }
    backend.ConfigureProcId(proc_id);
    bus.ConfigureProcId(proc_id);

    // ── One-time setup (mirrors LoopRuntimeRun's setup, minus the fork-specific
    //    bits — no MADV_DONTFORK / SUBREAPER / per-program workdir, since the
    //    snapshot worker never forks and loadvm resets per-program state). ──

    // Route glibc abort/__fortify_fail stderr to ttyS0 so the host ConsoleSensor
    // (and the Brick-4a VMI reader) see crash text.
    {
        const int log_fd = ::refuzz::worker::log::WorkerLogFd();
        if (log_fd >= 0 && log_fd != STDERR_FILENO) {
            (void)::dup2(log_fd, STDERR_FILENO);
        }
    }

    // Crash signal handlers (SIGSEGV/SIGABRT/...) → bus crash snapshot.
    engine::ProgramRuntimeInstallCrashHandlers(&bus);

    // KCOV open + KCOV_REMOTE_ENABLE + step-event ring. Done once; the fd/handle
    // persist across every restore (they live in the worker process, captured
    // in S0). ChildExecuteTask drives per-program KCOV Begin/collect in-process.
    if (!bus.InitAll()) {
        LOG("snapshot: observation_bus.InitAll degraded (a sink self-downgraded)");
    } else {
        LOG("snapshot: observation_bus.InitAll OK sinks=%zu", bus.SinkCount());
    }

    // syz exec scratch (16 MiB data window) must be touched before ApplySandbox
    // tightens RLIMIT_AS, else every program exec_errors.
    if (!PreallocateSyzExecScratch()) {
        LOG("snapshot: PreallocateSyzExecScratch failed errno=%d; exiting", errno);
        return 3;
    }

    // [TODO Brick4a parity] fd-table ABI: continuous mode runs
    // PrepareChildFdTableAbi (move reFuzz internal fds to a high reserved band so
    // the program's fuzz-visible fds start clean at 3). It takes pipe fds the
    // snapshot path doesn't have; a no-pipe variant is a follow-up. Deferred for
    // the first functional cut — most programs run; close(3)-style fd-parity is
    // the refinement.

    ::refuzz::worker::SandboxSizing sizing{};
    sizing.ivshmem_bytes  = cfg.transport_mapped_bytes;
    sizing.scratch_bytes  = ::refuzz::worker::kSyzExecScratchBytes;
    sizing.coverage_bytes = bus.TotalBufferBytes();
    sizing.proc_id = proc_id;
    // Top-level worker (no daemon watchdog parent; reparented to init via nohup).
    sizing.no_parent_watchdog = true;
    if (int sb_rc = ::refuzz::worker::ApplySandbox(cfg.sandbox_mode, sizing); sb_rc != 0) {
        LOG("snapshot: ApplySandbox(%s) failed rc=%d; exiting",
            ::refuzz::worker::SandboxModeName(cfg.sandbox_mode), sb_rc);
        return 2;
    }

    // cgroup hierarchy + netfilter-hook checkpoint. Once: loadvm restores S0
    // before each program, so a software reset would duplicate snapshot work.
    ::refuzz::worker::sandbox::device_init::SetupCgroupsLoop(
        static_cast<std::uint64_t>(proc_id));
    if (cfg.sandbox_mode != SandboxMode::kSetuid &&
        !::refuzz::worker::sandbox::device_init::CheckpointNetNamespace()) {
        const int checkpoint_errno = errno != 0 ? errno : EIO;
        LOG("snapshot: network namespace checkpoint failed errno=%d; exiting",
            checkpoint_errno);
        return 4;
    }

    // ── Ready. Publishing READY completes the host handshake; the first Submit
    //    then takes savevm S0 with this fully-warm worker parked below. ──
    task_channel.SetDomainReady(true);
    LOG("snapshot worker ready (warm, in-place) pid=%d — spin-waiting on TaskSlot",
        getpid());

    // ── Spin-wait + in-place execute. WaitTask(0) = non-blocking poll; the outer
    //    loop spins with NO sleep, so S0 lands on a clean poll instruction and
    //    loadvm resumes straight into reading the host-written TaskSlot (syz
    //    "restore = execute signal"). No fork, no per-program workdir. ──
    while (g_running != 0) {
        auto task = task_channel.WaitTask(std::chrono::milliseconds(0));
        if (!task) {
            continue;  // tight spin (host loadvm-gates submission; 1-in-flight)
        }

        if (task->target_proc_id != PROC_ID_ANY &&
            task->target_proc_id != proc_id) {
            TaskResult rejected{};
            rejected.executor_id = task->executor_id;
            rejected.dispatch_gen = task->dispatch_gen;
            rejected.status = -1;
            rejected.completion_status = COMP_STATUS_HARNESS_FATAL;
            rejected.error_code = ERR_HARNESS_FORK_SERVER_PROTOCOL;
            rejected.proc_id = proc_id;
            task_channel.ReportDone(rejected);
            continue;
        }

        task_channel.ResetOutputLen();
        ExecMode mode = ExecModeFromFlags(task->flags);
        uint32_t out_len = 0;
        ExecTaskFailure exec_failure = ExecTaskFailure::kNone;
        const int status = ChildExecuteTask(
            backend, bus,
            task->input_buf, task->input_len,
            task->output_buf, task->output_cap, &out_len,
            mode, cfg.worker_id, task->executor_id,
            task_flags_get_collect_comps(task->flags) != 0,
            &exec_failure);

        TaskResult result{};
        result.executor_id       = task->executor_id;
        result.dispatch_gen      = task->dispatch_gen;
        result.output_len        = out_len;
        result.status            = status;
        // ChildExecuteTask 失败 = worker 侧问题(wire 输入非法 / sink / backend),
        // 程序无罪 → 基础设施故障,两个 error_code 分归属。同 ProgramRuntimeRunInline。
        if (status == 0) {
            result.completion_status = static_cast<uint32_t>(COMP_STATUS_OK);
            result.error_code        = ERR_OK;
        } else {
            result.completion_status = static_cast<uint32_t>(COMP_STATUS_INFRA_FAULT);
            result.error_code = (exec_failure == ExecTaskFailure::kInvalidInput)
                ? ERR_INVALID_INPUT
                : ERR_EXECUTOR_ERROR;
        }
        result.proc_id = proc_id;
        task_channel.ReportDone(result);
    }

    LOG("snapshot worker loop exiting (g_running cleared)");
    return 0;
}

}  // namespace refuzz::worker

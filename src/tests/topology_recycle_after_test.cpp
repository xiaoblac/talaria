// Test: explicit post-report recycle rebuilds the reusable child.
//
// 背景 (P1 review finding-1):旧 ExecutionEngine::Run 末尾有
// `if (recycle_after > 0 && tasks_executed >= recycle_after) RespawnChild()`
// 检查。P1 把 child 生命周期搬到 topology 时漏掉了。stdio profile 默认
// `recycle_after=1`,必须每条 prog 后 respawn,否则 fd/mmap/signal/process
// state 跨 prog 泄漏(P1 第一次 oracle 跑出 20 个 fd_return expected
// divergence hits 就是这个 leak 的体现,baseline 只有 2)。
//
// 本 test:fork 真 child + Noop backend + 空 ObservationBus,Setup → Dispatch
// → Collect 一条 dummy program(4 字节 wire 头) → Stop + Setup,verify:
//   - generation 从 1 升到 2(Setup 后 +1, recycle 后又 +1)
//   - pid 改变
// 都成立才证明 recycle 不再发生在 Collect/ReportDone 前，而由显式 idle
// maintenance operation 触发。

#include "worker/backend/exec_backend.hpp"
#include "worker/observation/observation_bus.hpp"
#include "worker/topology/process_topology.hpp"
#include "worker/topology/reusable_child_topology.hpp"

#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <sys/syscall.h>
#include <unistd.h>

// ExecutionEngine::Run reads `extern volatile sig_atomic_t g_running` from a
// main file (ivshmem_worker_main / refuzz_wire_driver_stdio). worker_core is a
// static library that depends on this symbol — every binary that links
// worker_core must define it. Test binary defines it here.
volatile sig_atomic_t g_running = 1;

namespace {

refuzz::worker::topology::DomainStopPlan PeriodicStopPlan()
{
    refuzz::worker::topology::DomainStopPlan plan{};
    plan.intent =
        refuzz::worker::topology::DomainStopIntent::kPeriodicRecycle;
    plan.graceful = true;
    return plan;
}

int Shutdown(refuzz::worker::topology::ProcessTopology& topology)
{
    refuzz::worker::topology::DomainStopPlan plan{};
    plan.intent =
        refuzz::worker::topology::DomainStopIntent::kDaemonShutdown;
    return topology.Stop(plan) ==
            refuzz::worker::topology::DomainStopResult::kFailed
        ? -1 : 0;
}

class NoopBackend : public refuzz::worker::IExecBackend {
public:
    int Execute(const uint8_t* /*input*/, uint32_t /*input_len*/,
                uint8_t* output, uint32_t output_cap,
                uint32_t* output_len,
                refuzz::worker::ExecMode /*mode*/ = {}) override
    {
        // 写 16 字节占位(SyzExecResult v1 大小级);只是为了 PackAllFeedback
        // 有内容写,test 不解析。返 0 表示成功。
        const uint32_t want = std::min<uint32_t>(16u, output_cap);
        std::memset(output, 0, want);
        *output_len = want;
        return 0;
    }
    const char* Name() const override { return "noop-test-backend"; }
};

int OpenPidfd(pid_t pid)
{
#ifdef SYS_pidfd_open
    return static_cast<int>(::syscall(SYS_pidfd_open, pid, 0u));
#else
    (void)pid;
    return -1;
#endif
}

class StubbornChildTopology final
    : public refuzz::worker::topology::ReusableChildTopology {
public:
    using ReusableChildTopology::ReusableChildTopology;

    uint32_t fork_count() const { return fork_count_; }

protected:
    refuzz::worker::topology::DomainStartResult ForkChild() override
    {
        int ready_fds[2] = {-1, -1};
        int done_fds[2] = {-1, -1};
        if (::pipe(ready_fds) != 0) {
            return refuzz::worker::topology::MakeDomainStartRejected(
                cfg_.identity.proc_id,
                refuzz::worker::engine::LoopStartupStage::kUnknown,
                errno);
        }
        if (::pipe(done_fds) != 0) {
            const int saved_errno = errno;
            ::close(ready_fds[0]);
            ::close(ready_fds[1]);
            return refuzz::worker::topology::MakeDomainStartRejected(
                cfg_.identity.proc_id,
                refuzz::worker::engine::LoopStartupStage::kUnknown,
                saved_errno);
        }

        const pid_t pid = ::fork();
        if (pid < 0) {
            const int saved_errno = errno;
            ::close(ready_fds[0]);
            ::close(ready_fds[1]);
            ::close(done_fds[0]);
            ::close(done_fds[1]);
            return refuzz::worker::topology::MakeDomainStartRejected(
                cfg_.identity.proc_id,
                refuzz::worker::engine::LoopStartupStage::kUnknown,
                saved_errno);
        }
        if (pid == 0) {
            ::close(ready_fds[1]);
            ::close(done_fds[0]);
            for (;;) {
                ::pause();
            }
        }

        ::close(ready_fds[0]);
        ::close(done_fds[1]);
        ctx_.pid = pid;
        ctx_.loop_pidfd = OpenPidfd(pid);
        ctx_.ns_runner_pidfd = -1;
        ctx_.ready_pipe_w = ready_fds[1];
        ctx_.done_pipe_r = done_fds[0];
        ctx_.direct_child_reaped = false;
        ctx_.direct_child_status_known = false;
        ctx_.direct_child_status = 0;
        ++ctx_.generation;
        dispatch_failed_ = false;
        ++fork_count_;
        return refuzz::worker::topology::MakeDomainStartReady(
            cfg_.identity.proc_id);
    }

private:
    uint32_t fork_count_ = 0;
};

class CrashOnGracefulStopTopology final
    : public refuzz::worker::topology::ReusableChildTopology {
public:
    using ReusableChildTopology::ReusableChildTopology;

    uint32_t fork_count() const { return fork_count_; }

protected:
    refuzz::worker::topology::DomainStartResult ForkChild() override
    {
        int ready_fds[2] = {-1, -1};
        int done_fds[2] = {-1, -1};
        if (::pipe(ready_fds) != 0) {
            return refuzz::worker::topology::MakeDomainStartRejected(
                cfg_.identity.proc_id,
                refuzz::worker::engine::LoopStartupStage::kUnknown,
                errno);
        }
        if (::pipe(done_fds) != 0) {
            const int saved_errno = errno;
            ::close(ready_fds[0]);
            ::close(ready_fds[1]);
            return refuzz::worker::topology::MakeDomainStartRejected(
                cfg_.identity.proc_id,
                refuzz::worker::engine::LoopStartupStage::kUnknown,
                saved_errno);
        }

        const pid_t pid = ::fork();
        if (pid < 0) {
            const int saved_errno = errno;
            ::close(ready_fds[0]);
            ::close(ready_fds[1]);
            ::close(done_fds[0]);
            ::close(done_fds[1]);
            return refuzz::worker::topology::MakeDomainStartRejected(
                cfg_.identity.proc_id,
                refuzz::worker::engine::LoopStartupStage::kUnknown,
                saved_errno);
        }
        if (pid == 0) {
            ::close(ready_fds[1]);
            ::close(done_fds[0]);
            uint8_t byte = 0;
            ssize_t received;
            do {
                received = ::read(ready_fds[0], &byte, sizeof(byte));
            } while (received < 0 && errno == EINTR);
            if (received == 0) {
                ::raise(SIGTERM);
            }
            _exit(17);
        }

        ::close(ready_fds[0]);
        ::close(done_fds[1]);
        ctx_.pid = pid;
        ctx_.loop_pidfd = OpenPidfd(pid);
        ctx_.ns_runner_pidfd = -1;
        ctx_.ready_pipe_w = ready_fds[1];
        ctx_.done_pipe_r = done_fds[0];
        ctx_.direct_child_reaped = false;
        ctx_.direct_child_status_known = false;
        ctx_.direct_child_status = 0;
        ++ctx_.generation;
        dispatch_failed_ = false;
        ++fork_count_;
        return refuzz::worker::topology::MakeDomainStartReady(
            cfg_.identity.proc_id);
    }

private:
    uint32_t fork_count_ = 0;
};

class FailHealthyRespawnTopology final
    : public refuzz::worker::topology::ReusableChildTopology {
public:
    using ReusableChildTopology::ReusableChildTopology;

    uint32_t fork_attempts() const { return fork_attempts_; }

protected:
    refuzz::worker::topology::DomainStartResult ForkChild() override
    {
        ++fork_attempts_;
        if (fork_attempts_ == 2) {
            errno = ETIMEDOUT;
            return refuzz::worker::topology::MakeDomainStartStalled(
                cfg_.identity.proc_id, errno);
        }
        return ReusableChildTopology::ForkChild();
    }

private:
    uint32_t fork_attempts_ = 0;
};

} // namespace

int main()
{
    ::setenv("REFUZZ_DISABLE_STOP_FUSE_ABORT", "1", 1);
    using namespace refuzz::worker;

    NoopBackend backend;
    ObservationBus bus;  // 空 sink:InitAll 返 true,PackFeedback no-op

    topology::ReusableChildTopology topo(backend, bus);

    topology::TopologyConfig cfg{};
    cfg.sandbox_mode = SandboxMode::kNone;
    cfg.allow_no_private_mount_namespace_for_tests = true;
    cfg.transport_mapped_bytes = 0;
    cfg.recycle_after = 1;  // 关键:1 条 prog 后必须 respawn
    cfg.worker_id = 0;
    cfg.exec_timeout_ms = 10000;

    uint8_t input_buf[64];
    std::memset(input_buf, 0, sizeof(input_buf));
    uint8_t output_buf[1024];

    const uintptr_t mapping_begin = std::min(
        reinterpret_cast<uintptr_t>(input_buf),
        reinterpret_cast<uintptr_t>(output_buf));
    const uintptr_t mapping_end = std::max(
        reinterpret_cast<uintptr_t>(input_buf) + sizeof(input_buf),
        reinterpret_cast<uintptr_t>(output_buf) + sizeof(output_buf));
    cfg.program_mapping.source = ProgramBufferSource::kLinearSharedMemory;
    cfg.program_mapping.worker_id = 0;
    cfg.program_mapping.local_base = reinterpret_cast<uint8_t*>(mapping_begin);
    cfg.program_mapping.resource_offset = 0;
    cfg.program_mapping.mapped_size = mapping_end - mapping_begin;
    cfg.program_mapping.input_offset =
        reinterpret_cast<uintptr_t>(input_buf) - mapping_begin;
    cfg.program_mapping.input_size = sizeof(input_buf);
    cfg.program_mapping.output_offset =
        reinterpret_cast<uintptr_t>(output_buf) - mapping_begin;
    cfg.program_mapping.output_size = sizeof(output_buf);

    if (!topo.Setup(cfg).IsReady()) {
        std::fprintf(stderr, "FAIL: Setup with mapping returned non-zero\n");
        return 1;
    }
    const uint64_t gen_before = topo.CurrentChildGeneration();
    const pid_t pid_before = topo.CurrentChildPid();
    if (gen_before != 1) {
        std::fprintf(stderr, "FAIL: gen_before expected 1, got %llu\n",
                     static_cast<unsigned long long>(gen_before));
        (void)Shutdown(topo);
        return 1;
    }
    if (pid_before <= 0) {
        std::fprintf(stderr, "FAIL: pid_before invalid: %d\n", pid_before);
        (void)Shutdown(topo);
        return 1;
    }

    topology::ProgramRequest req{};
    req.input_len = sizeof(input_buf);
    req.output_cap = sizeof(output_buf);
    req.flags = 0;
    req.executor_id = 0;
    req.buffers.source = ProgramBufferSource::kLinearSharedMemory;
    req.buffers.worker_id = 0;
    req.buffers.input_offset = cfg.program_mapping.input_offset;
    req.buffers.output_offset = cfg.program_mapping.output_offset;
    req.buffers.result_page_offset = 0;

    const auto h = topo.Dispatch(req);
    const auto res = topo.Collect(h, /*timeout_ms=*/10000,
                                  /*cancel=*/nullptr, /*cancel_user=*/nullptr);

    if (res.kind != topology::CollectKind::kDone) {
        std::fprintf(stderr,
                     "FAIL: Collect.kind=%d (expected kDone=0). "
                     "crash_signal=%u\n",
                     static_cast<int>(res.kind), res.crash_signal);
        (void)Shutdown(topo);
        return 1;
    }

    if (topo.CurrentChildGeneration() != gen_before ||
        topo.CurrentChildPid() != pid_before) {
        std::fprintf(stderr,
                     "FAIL: Collect recycled before the post-report boundary\n");
        (void)Shutdown(topo);
        return 1;
    }
    if (topo.Stop(PeriodicStopPlan()) != topology::DomainStopResult::kClean) {
        std::fprintf(stderr, "FAIL: graceful periodic stop was not clean\n");
        (void)Shutdown(topo);
        return 1;
    }
    if (!topo.Setup(cfg).IsReady()) {
        std::fprintf(stderr, "FAIL: supervisor-style periodic restart failed\n");
        (void)Shutdown(topo);
        return 1;
    }

    const uint64_t gen_after = topo.CurrentChildGeneration();
    const pid_t pid_after = topo.CurrentChildPid();

    if (gen_after <= gen_before) {
        std::fprintf(stderr,
                     "FAIL: explicit recycle did not advance generation: "
                     "advance: before=%llu after=%llu\n",
                     static_cast<unsigned long long>(gen_before),
                     static_cast<unsigned long long>(gen_after));
        (void)Shutdown(topo);
        return 1;
    }
    if (pid_after == pid_before) {
        std::fprintf(stderr,
                     "FAIL: explicit recycle did not change pid: "
                     "change: before=%d after=%d\n",
                     pid_before, pid_after);
        (void)Shutdown(topo);
        return 1;
    }

    std::fprintf(stderr,
                 "PASS: explicit post-report recycle enforced. "
                 "generation %llu -> %llu, pid %d -> %d\n",
                 static_cast<unsigned long long>(gen_before),
                 static_cast<unsigned long long>(gen_after),
                 pid_before, pid_after);

    if (Shutdown(topo) != 0) {
        std::fprintf(stderr, "FAIL: graceful topology teardown failed\n");
        return 1;
    }

    StubbornChildTopology stubborn(backend, bus);
    if (!stubborn.Setup(cfg).IsReady()) {
        std::fprintf(stderr, "FAIL: stubborn Setup returned non-zero\n");
        return 1;
    }
    const uint64_t stubborn_generation = stubborn.CurrentChildGeneration();
    const auto forced_result = stubborn.Stop(PeriodicStopPlan());
    if (forced_result != topology::DomainStopResult::kForced) {
        std::fprintf(stderr,
                     "FAIL: forced recycle did not require proc rotation: %d\n",
                     static_cast<int>(forced_result));
        (void)Shutdown(stubborn);
        return 1;
    }
    if (stubborn.CurrentChildPid() != -1 ||
        stubborn.CurrentChildGeneration() != stubborn_generation ||
        stubborn.fork_count() != 1) {
        std::fprintf(stderr,
                     "FAIL: forced recycle rebuilt the untrusted proc domain\n");
        (void)Shutdown(stubborn);
        return 1;
    }
    if (Shutdown(stubborn) != 0) {
        std::fprintf(stderr, "FAIL: forced topology teardown failed\n");
        return 1;
    }

    std::fprintf(stderr,
                 "PASS: forced recycle stopped without reusing proc identity\n");

    FailHealthyRespawnTopology failed_respawn(backend, bus);
    if (!failed_respawn.Setup(cfg).IsReady()) {
        std::fprintf(stderr, "FAIL: failed-respawn Setup returned non-zero\n");
        return 1;
    }
    const uint64_t failed_respawn_generation =
        failed_respawn.CurrentChildGeneration();
    const auto failed_respawn_stop =
        failed_respawn.Stop(PeriodicStopPlan());
    if (failed_respawn_stop != topology::DomainStopResult::kClean ||
        failed_respawn.Setup(cfg).IsReady()) {
        std::fprintf(stderr,
                     "FAIL: supervisor-style recycle spawn failure was not surfaced\n");
        (void)Shutdown(failed_respawn);
        return 1;
    }
    if (failed_respawn.CurrentChildPid() != -1 ||
        failed_respawn.CurrentChildGeneration() != failed_respawn_generation ||
        failed_respawn.fork_attempts() != 2) {
        std::fprintf(stderr,
                     "FAIL: failed recycle spawn left inconsistent child state\n");
        (void)Shutdown(failed_respawn);
        return 1;
    }
    if (Shutdown(failed_respawn) != 0) {
        std::fprintf(stderr, "FAIL: failed-respawn teardown failed\n");
        return 1;
    }

    std::fprintf(stderr,
                 "PASS: recycle spawn failure requires proc rotation\n");

    CrashOnGracefulStopTopology crashing(backend, bus);
    if (!crashing.Setup(cfg).IsReady()) {
        std::fprintf(stderr, "FAIL: crashing Setup returned non-zero\n");
        return 1;
    }
    const uint64_t crashing_generation = crashing.CurrentChildGeneration();
    const auto crashing_result = crashing.Stop(PeriodicStopPlan());
    if (crashing_result != topology::DomainStopResult::kForced) {
        std::fprintf(stderr,
                     "FAIL: abnormal graceful exit retained proc identity: %d\n",
                     static_cast<int>(crashing_result));
        (void)Shutdown(crashing);
        return 1;
    }
    if (crashing.CurrentChildPid() != -1 ||
        crashing.CurrentChildGeneration() != crashing_generation ||
        crashing.fork_count() != 1) {
        std::fprintf(stderr,
                     "FAIL: abnormal graceful exit rebuilt untrusted proc domain\n");
        (void)Shutdown(crashing);
        return 1;
    }
    if (Shutdown(crashing) != 0) {
        std::fprintf(stderr, "FAIL: crashing topology teardown failed\n");
        return 1;
    }

    std::fprintf(stderr,
                 "PASS: abnormal graceful exit requires proc rotation\n");
    return 0;
}

// Test: DoubleForkTopology Setup + Dispatch + Collect + explicit Stop 跑通。
//
// 在 host 跑(non-root):unshare(CLONE_NEWPID) 通常会 EPERM 静默 fallback
// (DoubleFork::ForkChild 只 LOG 不 fail),所以这里 verify 的是接合点不 panic
// + ForkingProgramExecutor 跑通一条 dummy prog + child pid/generation 正常推进
// + supervisor-style Stop 干净。
//
// 真正的 NEWPID 隔离 verification 在 VM oracle (V9.1-V9.5) 里跑,因为 host
// 通常没 user-ns 权限 / 配置。

#include "worker/backend/exec_backend.hpp"
#include "worker/log/log_macros.hpp"
#include "worker/observation/observation_bus.hpp"
#include "worker/topology/double_fork_topology.hpp"
#include "worker/topology/process_topology.hpp"

#include <signal.h>
#include <unistd.h>

#include <algorithm>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

volatile sig_atomic_t g_running = 1;

namespace {

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
        const uint32_t want = std::min<uint32_t>(16u, output_cap);
        std::memset(output, 0, want);
        *output_len = want;
        return 0;
    }
    const char* Name() const override { return "noop-test-backend"; }
};

class SlowBackend final : public refuzz::worker::IExecBackend {
public:
    int Execute(const uint8_t*, uint32_t, uint8_t*, uint32_t,
                uint32_t* output_len,
                refuzz::worker::ExecMode = {}) override
    {
        ::usleep(2'000'000);
        *output_len = 0;
        return 0;
    }
    const char* Name() const override { return "slow-test-backend"; }
};

class InspectableDoubleForkTopology final
    : public refuzz::worker::topology::DoubleForkTopology {
public:
    using DoubleForkTopology::DoubleForkTopology;

    void SeedStaleDirectChildState()
    {
        ctx_.direct_child_reaped = true;
        ctx_.direct_child_status_known = true;
        ctx_.direct_child_status = 17 << 8;
    }

    bool DirectChildStateReset() const
    {
        return !ctx_.direct_child_reaped &&
               !ctx_.direct_child_status_known &&
               ctx_.direct_child_status == 0;
    }
};

} // namespace

int main()
{
    ::setenv("REFUZZ_DISABLE_STOP_FUSE_ABORT", "1", 1);
    using namespace refuzz::worker;

    ::setenv("REFUZZ_TOPOLOGY_PROBE", "1", 1);
    log::WorkerLogFdStorage() = STDERR_FILENO;
    log::EnableWorkerLog();

    NoopBackend backend;
    ObservationBus bus;

    InspectableDoubleForkTopology topo(backend, bus);
    topo.SeedStaleDirectChildState();

    topology::TopologyConfig cfg{};
    cfg.sandbox_mode = SandboxMode::kNone;
    cfg.allow_no_private_mount_namespace_for_tests = true;
    cfg.transport_mapped_bytes = 0;
    cfg.recycle_after = 0;  // DoubleFork 不靠 loop child 短命,recycle_after 关
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
        std::fprintf(stderr, "FAIL: Setup with mapping failed\n");
        return 1;
    }
    if (!topo.DirectChildStateReset()) {
        std::fprintf(stderr,
                     "FAIL: DoubleFork ForkChild retained stale reap state\n");
        (void)Shutdown(topo);
        return 1;
    }
    const pid_t pid_before = topo.CurrentChildPid();
    const uint64_t gen_before = topo.CurrentChildGeneration();
    if (pid_before <= 0 || gen_before != 1) {
        std::fprintf(stderr, "FAIL: bad pid=%d gen=%llu after Setup\n",
                     pid_before,
                     static_cast<unsigned long long>(gen_before));
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

    // 跑两条 prog,verify loop child 长期活(没 ENOMEM 死局)。
    for (int i = 0; i < 2; ++i) {
        const auto h = topo.Dispatch(req);
        const auto res = topo.Collect(h, /*timeout_ms=*/10000,
                                      nullptr, nullptr);
        if (res.kind != topology::CollectKind::kDone ||
            res.result_kind != engine::RuntimeResultKind::kNormal) {
            std::fprintf(stderr,
                         "FAIL: prog %d kind=%d result_kind=%u reason=%u "
                         "flags=0x%x crash_signal=%u\n",
                         i, static_cast<int>(res.kind),
                         static_cast<unsigned>(res.result_kind),
                         static_cast<unsigned>(res.fatal_reason), res.flags,
                         res.crash_signal);
            (void)Shutdown(topo);
            return 1;
        }
    }

    const pid_t pid_after = topo.CurrentChildPid();
    const uint64_t gen_after = topo.CurrentChildGeneration();

    // loop child 长期活:recycle_after=0 时,gen/pid 跑完 2 条 prog 不变。
    if (gen_after != gen_before) {
        std::fprintf(stderr,
                     "FAIL: loop child respawned mid-test (gen %llu→%llu)。"
                     "DoubleFork 设计是 loop child 长期活,只有 program child fork-per-prog\n",
                     static_cast<unsigned long long>(gen_before),
                     static_cast<unsigned long long>(gen_after));
        (void)Shutdown(topo);
        return 1;
    }
    if (pid_after != pid_before) {
        std::fprintf(stderr,
                     "FAIL: loop child pid changed (%d→%d) — 不该\n",
                     pid_before, pid_after);
        (void)Shutdown(topo);
        return 1;
    }

    std::fprintf(stderr,
                 "PASS: DoubleFork Setup + 2 prog + Stop 跑通。"
                 "loop child pid=%d gen=%llu(长期活,不随 prog 变)\n",
                 pid_before,
                 static_cast<unsigned long long>(gen_after));

    (void)Shutdown(topo);

    SlowBackend slow_backend;
    ObservationBus slow_bus;
    topology::DoubleForkTopology timeout_topo(slow_backend, slow_bus);
    if (!timeout_topo.Setup(cfg).IsReady()) {
        std::fprintf(stderr, "FAIL: timeout topology setup failed\n");
        return 1;
    }
    const uint64_t timeout_gen_before = timeout_topo.CurrentChildGeneration();
    const auto timeout_handle = timeout_topo.Dispatch(req);
    const auto timeout_result = timeout_topo.Collect(
        timeout_handle, /*daemon watchdog=*/100, nullptr, nullptr);
    if (timeout_result.kind != topology::CollectKind::kTimeout) {
        std::fprintf(stderr,
                     "FAIL: daemon watchdog kind=%d result_kind=%u reason=%u "
                     "flags=0x%x "
                     "expected kTimeout=%d\n",
                     static_cast<int>(timeout_result.kind),
                     static_cast<unsigned>(timeout_result.result_kind),
                     static_cast<unsigned>(timeout_result.fatal_reason),
                     timeout_result.flags,
                     static_cast<int>(topology::CollectKind::kTimeout));
        (void)Shutdown(timeout_topo);
        return 1;
    }
    if (timeout_result.fatal_reason !=
        engine::HarnessFatalReason::kDomainWatchdogTimeout) {
        std::fprintf(stderr,
                     "FAIL: daemon watchdog reason=%u expected domain timeout\n",
                     static_cast<unsigned>(timeout_result.fatal_reason));
        (void)Shutdown(timeout_topo);
        return 1;
    }
    if (timeout_topo.CurrentChildPid() <= 0 ||
        timeout_topo.CurrentChildGeneration() != timeout_gen_before) {
        std::fprintf(stderr,
                     "FAIL: Collect made a lifecycle decision before supervisor recovery\n");
        (void)Shutdown(timeout_topo);
        return 1;
    }
    topology::DomainStopPlan recovery_stop{};
    recovery_stop.intent = topology::DomainStopIntent::kRecovery;
    recovery_stop.graceful = false;
    if (timeout_topo.Stop(recovery_stop) ==
            topology::DomainStopResult::kFailed ||
        timeout_topo.CurrentChildPid() > 0 ||
        timeout_topo.CurrentChildGeneration() != timeout_gen_before) {
        std::fprintf(stderr,
                     "FAIL: supervisor-directed timeout stop failed\n");
        (void)Shutdown(timeout_topo);
        return 1;
    }
    cfg.identity = topology::DomainIdentity{0, 1, 1};
    const auto rotated_start = timeout_topo.Setup(cfg);
    if (!rotated_start.IsReady() ||
        rotated_start.proc_id != cfg.identity.proc_id ||
        timeout_topo.CurrentChildGeneration() <= timeout_gen_before ||
        timeout_topo.CurrentChildPid() <= 0) {
        std::fprintf(stderr,
                     "FAIL: engine-style rotated domain setup failed\n");
        (void)Shutdown(timeout_topo);
        return 1;
    }
    (void)Shutdown(timeout_topo);
    return 0;
}

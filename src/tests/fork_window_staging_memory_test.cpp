// [fix: production staging activation -- pure-memory verification]
//
// topology_exec_double_fork_test.cpp already exercises the exact production
// code path (ExecDoubleForkTopology is the literal class TopologyKind::
// kExecDoubleFork instantiates) and passes end to end, but asserting that
// staging specifically ACTIVATED via captured WorkerLog output turned out to
// be environment-fragile: this sandbox has a real /dev/ttyS0, so the loop-
// child's WorkerLog opens it directly (and moves the fd into a reserved
// band) regardless of what the test process's own stderr is redirected to --
// a CI box without that device, or with different permissions, would behave
// differently, silently passing or failing for the wrong reason.
//
// This test instead verifies the OBSERVABLE OUTCOME directly, via
// /proc/<pid>/maps of the (long-lived, parked) loop-child process. Nothing
// here depends on logging, serial devices, or timing races:
//
//   1. A MAP_SHARED anonymous mapping of exactly sizeof(WorkerDataWindowV3)
//      bytes is present -- the staging window loop_runtime.cpp allocates
//      when raw_fork_window_active computed true. Proves staging actually
//      engaged, not just that Setup() happened to succeed via the old,
//      unstaged fallback.
//   2. The original memfd-backed window mapping (config.program_mapping.
//      mapped_size bytes, MAP_SHARED) is STILL present in the loop-child's
//      OWN address space -- MADV_DONTFORK only excludes a range from a FORK
//      CHILD's address space, it does not unmap it from the process that
//      called madvise; the loop-child still needs it to read raw input and
//      transcribe output back for the host to see.
//
// Loop-child PID resolution: ExecDoubleForkTopology's public interface
// (CurrentChildPid()) surfaces the ns-runner process's PID. The loop child
// is a SECOND, separate fork inside the ns-runner (RunExecNsRunnerRole,
// after unshare(CLONE_NEWPID)), so it has a different PID as seen from this
// (host) PID namespace. /proc/<ns_runner_pid>/task/<ns_runner_pid>/children
// lists direct children in the CALLER's namespace regardless of what
// namespace the child itself later unshared into, so it resolves correctly.

#include "worker/coverage/coverage_collector.hpp"
#include "worker/engine/loop_worker_boot_config.hpp"
#include "worker/topology/double_fork_topology.hpp"
#include "worker/topology/ns_runner.hpp"

#include "refuzz/proto_wire/ivshmem_protocol.h"

#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <linux/memfd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <vector>

// program_runtime.cpp's LOG/SIGCHLD path reads g_running (same requirement
// as topology_exec_double_fork_test.cpp).
volatile sig_atomic_t g_running = 1;

#ifndef REFUZZ_EXECUTOR_TEST_PATH
#define REFUZZ_EXECUTOR_TEST_PATH "refuzz_executor"
#endif

namespace {

// Direct child PIDs of `pid`, resolved in the CALLER's PID namespace
// regardless of what namespace the child itself later unshared into.
std::vector<pid_t> DirectChildren(pid_t pid)
{
    std::vector<pid_t> out;
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/%d/task/%d/children", pid, pid);
    std::FILE* f = std::fopen(path, "r");
    if (f == nullptr) {
        return out;
    }
    int child = 0;
    while (std::fscanf(f, "%d", &child) == 1) {
        out.push_back(static_cast<pid_t>(child));
    }
    std::fclose(f);
    return out;
}

struct MapsEntry {
    uint64_t start = 0;
    uint64_t end = 0;
    bool shared = false;
    bool memfd_backed = false;
};

std::vector<MapsEntry> ReadMaps(pid_t pid)
{
    std::vector<MapsEntry> out;
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    std::FILE* f = std::fopen(path, "r");
    if (f == nullptr) {
        return out;
    }
    char line[512];
    while (std::fgets(line, sizeof(line), f) != nullptr) {
        unsigned long long start = 0, end = 0;
        char perms[8] = {};
        if (std::sscanf(line, "%llx-%llx %7s", &start, &end, perms) != 3) {
            continue;
        }
        MapsEntry e{};
        e.start = start;
        e.end = end;
        e.shared = std::strchr(perms, 's') != nullptr;
        e.memfd_backed = std::strstr(line, "/memfd:") != nullptr;
        out.push_back(e);
    }
    std::fclose(f);
    return out;
}

} // namespace

int main()
{
    ::setenv("REFUZZ_DISABLE_STOP_FUSE_ABORT", "1", 1);
    using namespace refuzz::worker;

    constexpr uint64_t kInputOffset = 0;
    constexpr uint64_t kInputSize = 4096;
    constexpr uint64_t kOutputOffset = kInputOffset + kInputSize;
    constexpr uint64_t kOutputSize = 4096;
    constexpr uint64_t kResultOffset = kOutputOffset + kOutputSize;
    constexpr uint64_t kMappingSize =
        kResultOffset + sizeof(ProgramResultPageV3);

    const int fd = static_cast<int>(::syscall(
        SYS_memfd_create, "refuzz-fork-window-staging-test", MFD_CLOEXEC));
    if (fd < 0 || ::ftruncate(fd, static_cast<off_t>(kMappingSize)) != 0) {
        std::perror("memfd");
        return 1;
    }

    topology::TopologyConfig config{};
    config.sandbox_mode = SandboxMode::kNone;
    config.allow_no_private_mount_namespace_for_tests = true;
    config.identity = topology::DomainIdentity{0, 0, 0};
    config.worker_id = 0;
    config.exec_timeout_ms = 5000;
    config.execution_backing_fd = fd;
    config.executor_path = REFUZZ_EXECUTOR_TEST_PATH;
    config.program_mapping.source = ProgramBufferSource::kLinearSharedMemory;
    config.program_mapping.worker_id = 0;
    config.program_mapping.resource_offset = 0;
    config.program_mapping.mapped_size = kMappingSize;
    config.program_mapping.input_offset = kInputOffset;
    config.program_mapping.input_size = kInputSize;
    config.program_mapping.output_offset = kOutputOffset;
    config.program_mapping.output_size = kOutputSize;
    config.program_mapping.result_page_offset = kResultOffset;
    config.program_mapping.result_page_size = sizeof(ProgramResultPageV3);

    config.loop_boot_config = engine::MakeLoopWorkerBootConfig();
    config.loop_boot_config.coverage_mode =
        static_cast<uint32_t>(CoverageMode::kNone);
    config.loop_boot_config.sandbox_mode =
        static_cast<uint32_t>(SandboxMode::kNone);
    config.loop_boot_config.thread_count = 1;
    config.loop_boot_config.exec_timeout_ms = config.exec_timeout_ms;
    config.loop_boot_config.per_call_timeout_ms = 500;
    config.loop_boot_config.kcov_entries = 1024;
    config.loop_boot_config.kcov_collector_count = 1;
    config.loop_boot_config.kcov_premap_count = 0;

    topology::ExecDoubleForkTopology topology;
    const auto start_result = topology.Setup(config);
    if (!start_result.IsReady()) {
        std::perror("exec topology setup");
        ::close(fd);
        return 1;
    }

    // The loop child only starts reading requests after finishing ALL of
    // LoopRuntimeRun's one-time startup, so staging (if it engages) has
    // already happened by the time Setup() reports ready -- no dispatch
    // needed, no timing race to account for.
    const pid_t ns_runner_pid = topology.CurrentChildPid();
    const std::vector<pid_t> children = DirectChildren(ns_runner_pid);
    if (children.empty()) {
        std::fprintf(stderr,
                     "FAIL: ns-runner pid=%d has no discoverable child "
                     "(expected the loop-child fork)\n",
                     ns_runner_pid);
        topology::DomainStopPlan plan{};
        plan.intent = topology::DomainStopIntent::kDaemonShutdown;
        topology.Stop(plan);
        ::close(fd);
        return 1;
    }
    const pid_t loop_pid = children.front();

    const std::vector<MapsEntry> maps = ReadMaps(loop_pid);
    if (maps.empty()) {
        std::fprintf(stderr,
                     "FAIL: could not read /proc/%d/maps for loop-child "
                     "(pid resolution or permission issue)\n",
                     loop_pid);
        topology::DomainStopPlan plan{};
        plan.intent = topology::DomainStopIntent::kDaemonShutdown;
        topology.Stop(plan);
        ::close(fd);
        return 1;
    }

    constexpr uint64_t kStagingSize = sizeof(WorkerDataWindowV3);
    bool saw_staging_window = false;
    bool saw_original_window = false;
    for (const MapsEntry& e : maps) {
        const uint64_t len = e.end - e.start;
        if (e.shared && !e.memfd_backed && len == kStagingSize) {
            saw_staging_window = true;
        }
        if (e.shared && e.memfd_backed && len == kMappingSize) {
            saw_original_window = true;
        }
    }

    bool ok = true;
    if (!saw_staging_window) {
        std::fprintf(stderr,
                     "FAIL: no MAP_SHARED anonymous mapping of size %llu "
                     "(sizeof(WorkerDataWindowV3)) found in loop-child "
                     "pid=%d -- fork_window_base/size did not activate "
                     "staging (see loop_runtime.cpp raw_fork_window_active)\n",
                     static_cast<unsigned long long>(kStagingSize), loop_pid);
        ok = false;
    }
    if (!saw_original_window) {
        std::fprintf(stderr,
                     "FAIL: the original memfd-backed window (size %llu) is "
                     "no longer mapped in the loop-child itself -- "
                     "MADV_DONTFORK should only exclude it from FORK "
                     "CHILDREN, not unmap it here; the loop-child needs it "
                     "to transcribe input/output\n",
                     static_cast<unsigned long long>(kMappingSize));
        ok = false;
    }

    topology::DomainStopPlan plan{};
    plan.intent = topology::DomainStopIntent::kDaemonShutdown;
    const bool teardown_ok =
        topology.Stop(plan) != topology::DomainStopResult::kFailed;
    ::close(fd);
    return ok && teardown_ok ? 0 : 1;
}

#include "worker/engine/loop_worker_boot_config.hpp"
#include "worker/coverage/coverage_collector.hpp"
#include "worker/log/log_macros.hpp"
#include "worker/topology/double_fork_topology.hpp"
#include "worker/topology/ns_runner.hpp"

#include "refuzz/program/syz/exec_wire_decode.hpp"
#include "refuzz/program/syz/generated/target_linux_amd64_call_table.gen.hpp"
#include "refuzz/proto_wire/ivshmem_protocol.h"

#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <linux/memfd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

volatile sig_atomic_t g_running = 1;

#ifndef REFUZZ_EXECUTOR_TEST_PATH
#define REFUZZ_EXECUTOR_TEST_PATH "refuzz_executor"
#endif

int Shutdown(refuzz::worker::topology::ProcessTopology& topology)
{
    refuzz::worker::topology::DomainStopPlan plan{};
    plan.intent =
        refuzz::worker::topology::DomainStopIntent::kDaemonShutdown;
    return topology.Stop(plan) ==
            refuzz::worker::topology::DomainStopResult::kFailed
        ? -1 : 0;
}

int main()
{
    ::setenv("REFUZZ_DISABLE_STOP_FUSE_ABORT", "1", 1);
    using namespace refuzz::worker;
    log::WorkerLogFdStorage() = STDERR_FILENO;
    log::EnableWorkerLog();

    constexpr uint64_t kInputOffset = 0;
    constexpr uint64_t kInputSize = 4096;
    constexpr uint64_t kOutputOffset = kInputOffset + kInputSize;
    constexpr uint64_t kOutputSize = 4096;
    constexpr uint64_t kResultOffset = kOutputOffset + kOutputSize;
    constexpr uint64_t kMappingSize = kResultOffset + sizeof(ProgramResultPageV3);

    const int fd = static_cast<int>(::syscall(SYS_memfd_create,
                                               "refuzz-exec-topology-test",
                                               MFD_CLOEXEC));
    if (fd < 0 || ::ftruncate(fd, static_cast<off_t>(kMappingSize)) != 0) {
        std::perror("memfd");
        return 1;
    }
    void* mapping = ::mmap(nullptr, kMappingSize,
                           PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mapping == MAP_FAILED) {
        std::perror("mmap");
        ::close(fd);
        return 1;
    }

    auto* base = static_cast<uint8_t*>(mapping);
    std::memset(base, 0, kMappingSize);

    {
        engine::LoopWorkerBootConfig invalid_boot =
            engine::MakeLoopWorkerBootConfig();
        invalid_boot.buffer_source = static_cast<uint32_t>(
            ProgramBufferSource::kLinearSharedMemory);
        invalid_boot.window_resource_offset = 0;
        invalid_boot.window_size = kMappingSize;
        invalid_boot.input_resource_offset = kMappingSize + 1;
        invalid_boot.input_size = 1;
        invalid_boot.output_resource_offset = kOutputOffset;
        invalid_boot.output_size = kOutputSize;

        topology::ExecNsRunnerSpawnConfig invalid_spawn{};
        invalid_spawn.boot = invalid_boot;
        invalid_spawn.backing_fd = fd;
        invalid_spawn.executor_path = REFUZZ_EXECUTOR_TEST_PATH;
        invalid_spawn.startup_deadline_us = now_us() + 5'000'000ULL;

        topology::ExecNsRunnerSupervisor invalid_supervisor;
        errno = 0;
        const topology::DomainStartResult invalid_result =
            invalid_supervisor.Spawn(invalid_spawn);
        const int invalid_errno = errno;
        const pid_t partial_pid = invalid_supervisor.NsRunnerPid();
        const auto post_failure_stop = invalid_supervisor.Stop();
        if (invalid_result.kind != topology::DomainStartKind::kRejected ||
            invalid_result.stage != engine::LoopStartupStage::kBootRead ||
            invalid_errno != EPROTO || partial_pid <= 0 ||
            invalid_supervisor.NsRunnerPid() != -1 ||
            post_failure_stop == topology::DomainStopResult::kFailed) {
            std::fprintf(stderr,
                         "invalid geometry startup kind=%u stage=%u errno=%d "
                         "partial_pid=%d pid=%d stop=%u\n",
                         static_cast<unsigned>(invalid_result.kind),
                         static_cast<unsigned>(invalid_result.stage),
                         invalid_errno, partial_pid,
                         invalid_supervisor.NsRunnerPid(),
                         static_cast<unsigned>(post_failure_stop));
            ::munmap(mapping, kMappingSize);
            ::close(fd);
            return 1;
        }
    }

    constexpr uint64_t kGetpidCallId = 538;
    static_assert(
        refuzz::program::syz::generated::
            kLinuxAmd64CallIdToNr[kGetpidCallId] == SYS_getpid);
    refuzz::program::syz::WireProgram wire_program{};
    wire_program.num_calls = 1;
    refuzz::program::syz::WireCall call{};
    call.call_id = kGetpidCallId;
    call.copyout_idx = ~uint64_t{0};
    wire_program.instrs.emplace_back(std::move(call));
    const auto program =
        refuzz::program::syz::encode_wire_program(wire_program);
    if (program.size() > kInputSize) {
        std::fprintf(stderr, "encoded empty program exceeds input window\n");
        ::munmap(mapping, kMappingSize);
        ::close(fd);
        return 1;
    }
    std::memcpy(base + kInputOffset, program.data(), program.size());

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
    config.program_mapping.local_base = base;
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
    config.loop_boot_config.flags |= engine::kLoopBootEnableWorkerLog;

    topology::ExecDoubleForkTopology topology;
    const auto start_result = topology.Setup(config);
    if (!start_result.IsReady()) {
        std::perror("exec topology setup");
        ::munmap(mapping, kMappingSize);
        ::close(fd);
        return 1;
    }

    topology::ProgramRequest request{};
    request.input_len = program.size();
    request.output_cap = kOutputSize;
    request.executor_id = 1;
    request.dispatch_gen = 1;
    request.buffers.source = ProgramBufferSource::kLinearSharedMemory;
    request.buffers.worker_id = 0;
    request.buffers.input_offset = kInputOffset;
    request.buffers.output_offset = kOutputOffset;
    request.buffers.result_page_offset = kResultOffset;

    const auto handle = topology.Dispatch(request);
    const auto result = topology.Collect(handle, 10000, nullptr, nullptr);
    const bool ok = result.kind == topology::CollectKind::kDone &&
                    result.result_kind == engine::RuntimeResultKind::kNormal &&
                    start_result.proc_id == config.identity.proc_id;
    if (!ok) {
        std::fprintf(stderr,
                     "FAIL: kind=%d result=%u fatal=%u signal=%u\n",
                     static_cast<int>(result.kind),
                     static_cast<unsigned>(result.result_kind),
                     static_cast<unsigned>(result.fatal_reason),
                     result.crash_signal);
    }

    const int teardown_result = Shutdown(topology);
    ::munmap(mapping, kMappingSize);
    ::close(fd);
    return ok && teardown_result == 0 ? 0 : 1;
}

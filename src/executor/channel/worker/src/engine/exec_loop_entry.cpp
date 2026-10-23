#include "worker/engine/exec_loop_entry.hpp"

#include "worker/backend/exec_backend.hpp"
#include "worker/engine/loop_runtime.hpp"
#include "worker/engine/program_runtime.hpp"
#include "worker/log/log_macros.hpp"
#include "worker/observation/observation_bus.hpp"
#include "worker/perf/worker_perf.hpp"
#include "worker/profile/kernel_syz_execution_domain.hpp"
#include "worker/sandbox.hpp"

#include "refuzz/proto_wire/ivshmem_protocol.h"

#include <cerrno>
#include <cstdint>
#include <limits>
#include <sys/mman.h>
#include <unistd.h>

namespace refuzz::worker::engine {
namespace {

struct MappedRange {
    void* mapping = nullptr;
    size_t mapping_size = 0;
    uint8_t* data = nullptr;
};

void WriteStartupFailure(int fd,
                         uint32_t proc_id,
                         LoopStartupStage stage,
                         int error_number)
{
    if (fd < 0) {
        return;
    }
    LoopStartupStatus status = MakeLoopStartupStatus();
    status.ready = 0;
    status.proc_id = proc_id;
    status.stage = stage;
    status.error_number = error_number;
    const uint8_t* data = reinterpret_cast<const uint8_t*>(&status);
    size_t offset = 0;
    while (offset < sizeof(status)) {
        const ssize_t written = ::write(fd, data + offset, sizeof(status) - offset);
        if (written > 0) {
            offset += static_cast<size_t>(written);
        } else if (written < 0 && errno == EINTR) {
            continue;
        } else {
            break;
        }
    }
}

MappedRange MapRange(int fd, uint64_t resource_offset, uint64_t size)
{
    MappedRange result{};
    if (fd < 0 || size == 0) {
        errno = EINVAL;
        return result;
    }
    const long page_size_value = ::sysconf(_SC_PAGESIZE);
    if (page_size_value <= 0) {
        errno = EINVAL;
        return result;
    }
    const uint64_t page_size = static_cast<uint64_t>(page_size_value);
    const uint64_t aligned_offset = resource_offset & ~(page_size - 1u);
    const uint64_t delta = resource_offset - aligned_offset;
    if (aligned_offset >
            static_cast<uint64_t>(std::numeric_limits<off_t>::max()) ||
        delta > SIZE_MAX || size > SIZE_MAX - delta) {
        errno = EOVERFLOW;
        return result;
    }
    result.mapping_size = static_cast<size_t>(delta + size);
    result.mapping = ::mmap(nullptr,
                            result.mapping_size,
                            PROT_READ | PROT_WRITE,
                            MAP_SHARED,
                            fd,
                            static_cast<off_t>(aligned_offset));
    if (result.mapping == MAP_FAILED) {
        result.mapping = nullptr;
        result.mapping_size = 0;
        return result;
    }
    result.data = static_cast<uint8_t*>(result.mapping) + delta;
    return result;
}

} // namespace

[[noreturn]] void RunExecLoop(const LoopWorkerBootConfig& config,
                              int backing_fd,
                              int ready_fd,
                              int done_fd,
                              int startup_ack_fd)
{
    if (!LoopWorkerBootGeometryValid(config, sizeof(ProgramResultPageV3))) {
        WriteStartupFailure(startup_ack_fd, config.proc_id,
                            LoopStartupStage::kBootRead, EPROTO);
        _exit(20);
    }

    if ((config.flags & kLoopBootEnableWorkerLog) != 0) {
        ::refuzz::worker::log::EnableWorkerLog();
    }
    ::refuzz::worker::log::WorkerLog(
        "[Worker] exec loop begin pid=%d worker=%u proc=%u epoch=%u "
        "backing_fd=%d ready_fd=%d done_fd=%d startup_fd=%d window_off=%llu "
        "window_size=%llu\n",
        static_cast<int>(::getpid()), config.worker_id, config.proc_id,
        config.proc_epoch, backing_fd, ready_fd, done_fd, startup_ack_fd,
        static_cast<unsigned long long>(config.window_resource_offset),
        static_cast<unsigned long long>(config.window_size));
    ::refuzz::worker::perf::Configure(
        (config.flags & kLoopBootEnableWorkerPerf) != 0,
        config.worker_perf_sample_rate,
        config.worker_perf_report_every);

    ::refuzz::worker::log::WorkerLog(
        "[Worker] exec loop stage=window-map begin proc=%u\n",
        config.proc_id);
    MappedRange window = MapRange(backing_fd,
                                  config.window_resource_offset,
                                  config.window_size);
    if (window.data == nullptr) {
        const int saved_errno = errno;
        WriteStartupFailure(startup_ack_fd, config.proc_id,
                            LoopStartupStage::kWindowMap, saved_errno);
        _exit(21);
    }
    ::refuzz::worker::log::WorkerLog(
        "[Worker] exec loop stage=window-map complete proc=%u mapped=%zu\n",
        config.proc_id, window.mapping_size);

    MappedRange step_ring{};
    StepEventRingHeader* step_header = nullptr;
    StepEventSlot* step_slots = nullptr;
    if ((config.flags & kLoopBootEnableStepEvents) != 0) {
        step_ring = MapRange(backing_fd,
                             config.step_ring_resource_offset,
                             config.step_ring_size);
        if (step_ring.data == nullptr ||
            config.step_ring_size < sizeof(StepEventRingHeader) ||
            config.step_ring_capacity >
                (config.step_ring_size - sizeof(StepEventRingHeader)) /
                    sizeof(StepEventSlot)) {
            const int saved_errno = errno != 0 ? errno : EPROTO;
            WriteStartupFailure(startup_ack_fd, config.proc_id,
                                LoopStartupStage::kWindowMap, saved_errno);
            _exit(22);
        }
        step_header = reinterpret_cast<StepEventRingHeader*>(step_ring.data);
        step_slots = reinterpret_cast<StepEventSlot*>(
            step_ring.data + sizeof(StepEventRingHeader));
    }
    ::close(backing_fd);

    ::refuzz::worker::log::WorkerLog(
        "[Worker] exec loop stage=component-build begin proc=%u\n",
        config.proc_id);
    auto domain = BuildKernelSyzExecutionDomain(config, step_header, step_slots);
    if (!domain) {
        WriteStartupFailure(startup_ack_fd, config.proc_id,
                            LoopStartupStage::kComponentBuild, EINVAL);
        _exit(23);
    }
    ::refuzz::worker::log::WorkerLog(
        "[Worker] exec loop stage=component-build complete proc=%u\n",
        config.proc_id);

    ProgramBufferMapping mapping{};
    mapping.source = static_cast<ProgramBufferSource>(config.buffer_source);
    mapping.worker_id = config.worker_id;
    mapping.local_base = window.data;
    mapping.resource_offset = config.window_resource_offset;
    mapping.mapped_size = config.window_size;
    mapping.input_offset = config.input_resource_offset;
    mapping.input_size = config.input_size;
    mapping.output_offset = config.output_resource_offset;
    mapping.output_size = config.output_size;
    mapping.result_page_offset = config.result_resource_offset;
    mapping.result_page_size = config.result_size;

    ForkingProgramExecutor executor(*domain.backend,
                                    *domain.bus,
                                    config.worker_id,
                                    config.proc_id,
                                    config.exec_timeout_ms);
    const auto sandbox_mode = static_cast<SandboxMode>(config.sandbox_mode);
    const bool allow_no_private_mount_namespace_for_tests =
        (config.flags & kLoopBootAllowNoPrivateMountNamespaceForTests) != 0;
    const size_t mapped_bytes = window.mapping_size + step_ring.mapping_size;
    ::refuzz::worker::log::WorkerLog(
        "[Worker] exec loop stage=loop-runtime enter proc=%u\n",
        config.proc_id);
    // [fix: production staging activation] window.mapping/window.mapping_size
    // is this worker's own data window (input+output+result page), already
    // mapped above from backing_fd = resource2_fd (the PCI BAR) — exactly the
    // range that used to be silently inherited by every program-child fork
    // because this call passed nullptr/0 here (only the legacy kDoubleFork
    // path populated transport_shm_base). Passing it as fork_window_base/size
    // makes LoopRuntimeRun MADV_DONTFORK this range and route program buffers
    // through anon-shared staging instead — see loop_runtime.hpp's parameter
    // comment.
    LoopRuntimeRun(ready_fd,
                   done_fd,
                   config.worker_id,
                   config.proc_id,
                   *domain.backend,
                   *domain.bus,
                   sandbox_mode,
                   allow_no_private_mount_namespace_for_tests,
                   mapped_bytes,
                   nullptr,
                   0,
                   mapping,
                   startup_ack_fd,
                   executor,
                   window.mapping,
                   window.mapping_size);
}

} // namespace refuzz::worker::engine

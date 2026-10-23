#include "refuzz/channel/internal/worker_start_sequence.hpp"

#include "refuzz/channel/control/control_plane.hpp"
#include "refuzz/channel/substrate/substrate_contract.hpp"

#include <chrono>
#include <string>

namespace refuzz::channel::internal {

namespace {

Error RollbackWorkers(runtime::ISubstrate& substrate,
                      uint32_t vm_index,
                      Error error)
{
    auto stopped = substrate.StopAllWorkers(vm_index);
    if (!stopped.ok()) {
        error.message += "; rollback StopAllWorkers failed: " +
                         stopped.error().message;
    }
    return error;
}

std::chrono::milliseconds Remaining(
    std::chrono::steady_clock::time_point deadline)
{
    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline) {
        return std::chrono::milliseconds{0};
    }
    return std::chrono::ceil<std::chrono::milliseconds>(deadline - now);
}

} // namespace

Result<void> StartWorkersAndWaitReady(
    runtime::ISubstrate& substrate,
    control::IControlPlane& control_plane,
    uint32_t vm_index,
    uint32_t worker_count,
    std::chrono::milliseconds timeout)
{
    if (worker_count == 0) {
        return Error{ErrorKind::kConfig,
                     "StartWorkersAndWaitReady: worker_count must be non-zero"};
    }
    if (timeout <= std::chrono::milliseconds{0}) {
        return Error{ErrorKind::kConfig,
                     "StartWorkersAndWaitReady: timeout must be positive"};
    }

    const auto deadline = std::chrono::steady_clock::now() + timeout;
    for (uint32_t worker_id = 0; worker_id < worker_count; ++worker_id) {
        auto started = substrate.StartWorker(vm_index, worker_id);
        if (!started.ok()) {
            return RollbackWorkers(
                substrate,
                vm_index,
                Error{started.error().kind,
                      "StartWorker failed at worker[" +
                          std::to_string(worker_id) + "]: " +
                          started.error().message});
        }

        const auto remaining = Remaining(deadline);
        if (remaining.count() == 0) {
            return RollbackWorkers(
                substrate,
                vm_index,
                Error{ErrorKind::kTimeout,
                      "worker startup deadline expired after worker[" +
                          std::to_string(worker_id) + "] started"});
        }

        auto ready = control_plane.WaitWorkerReady(worker_id, remaining);
        if (!ready.ok()) {
            return RollbackWorkers(
                substrate,
                vm_index,
                Error{ready.error().kind,
                      "WaitWorkerReady failed at worker[" +
                          std::to_string(worker_id) + "]: " +
                          ready.error().message});
        }
    }

    const auto remaining = Remaining(deadline);
    if (remaining.count() == 0) {
        return RollbackWorkers(
            substrate,
            vm_index,
            Error{ErrorKind::kTimeout,
                  "worker startup deadline expired before final readiness verification"});
    }
    auto all_ready = control_plane.WaitAllWorkersReady(remaining);
    if (!all_ready.ok()) {
        return RollbackWorkers(
            substrate,
            vm_index,
            Error{all_ready.error().kind,
                  "final WaitAllWorkersReady failed: " +
                      all_ready.error().message});
    }

    return Result<void>::Ok();
}

} // namespace refuzz::channel::internal

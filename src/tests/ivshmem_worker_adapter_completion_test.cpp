#include "worker/adapter/ivshmem_adapter.hpp"

#include "refuzz/proto_wire/error_codes.h"
#include "refuzz/proto_wire/ivshmem_protocol.h"

#include <signal.h>

#include <atomic>
#include <cstdint>
#include <cstdio>

volatile sig_atomic_t g_running = 1;

namespace refuzz::worker {

struct IvshmemWorkerAdapterTestAccess {
    static void Bind(IvshmemWorkerAdapter& adapter,
                     WorkerCtrl* ctrl,
                     TaskSlot* task,
                     CompletionSlot* completion)
    {
        adapter.ctrl_ = ctrl;
        adapter.task_ = task;
        adapter.completion_ = completion;
        adapter.domain_ready_.store(true, std::memory_order_release);
    }

    static CompletionStatus StatusFromTaskResult(const TaskResult& result)
    {
        return IvshmemWorkerAdapter::StatusFromTaskResult(result);
    }
};

} // namespace refuzz::worker

namespace {

#define CHECK(cond)                                                                \
    do {                                                                           \
        if (!(cond)) {                                                             \
            std::fprintf(stderr, "CHECK failed: %s (line %d)\n", #cond, __LINE__); \
            return 1;                                                              \
        }                                                                          \
    } while (0)

int TestBlockedCompletionPublicationIsFatal()
{
    WorkerCtrl ctrl{};
    TaskSlot task{};
    CompletionSlot completion{};
    __atomic_store_n(&ctrl.host_state,
                     static_cast<std::uint32_t>(HOST_REG_GRANTED),
                     __ATOMIC_RELEASE);
    __atomic_store_n(&ctrl.guest_state,
                     static_cast<std::uint32_t>(GUEST_REG_READY),
                     __ATOMIC_RELEASE);
    task.executor_id = 100;
    task.dispatch_gen = 7;
    task_slot_store_state_v3(&task, TASK_TAKEN);
    completion.executor_id = 99;
    completion.dispatch_gen = 6;
    completion.error_code = ERR_OK;
    completion_slot_store_state_v3(&completion, COMP_READY);

    refuzz::worker::IvshmemWorkerAdapter adapter({});
    refuzz::worker::IvshmemWorkerAdapterTestAccess::Bind(
        adapter, &ctrl, &task, &completion);

    refuzz::worker::TaskResult result{};
    result.executor_id = task.executor_id;
    result.dispatch_gen = task.dispatch_gen;
    result.completion_status = COMP_STATUS_HUNG;
    result.error_code = ERR_DOMAIN_WATCHDOG_TIMEOUT;

    g_running = 0;
    adapter.ReportDone(result);
    g_running = 1;

    CHECK(completion_slot_load_state_v3(&completion) ==
          static_cast<std::uint32_t>(COMP_READY));
    CHECK(completion.executor_id == 99);
    CHECK(completion.dispatch_gen == 6);
    CHECK(completion.error_code == ERR_OK);
    CHECK(task_slot_load_state_v3(&task) ==
          static_cast<std::uint32_t>(TASK_TAKEN));
    CHECK(task.executor_id == 100);
    CHECK(task.dispatch_gen == 7);
    CHECK(__atomic_load_n(&ctrl.error_latch, __ATOMIC_ACQUIRE) ==
          ERR_HARNESS_FORK_SERVER_PROTOCOL);
    CHECK(__atomic_load_n(&ctrl.guest_state, __ATOMIC_ACQUIRE) ==
          static_cast<std::uint32_t>(GUEST_REG_CLAIMED));
    CHECK(adapter.LifecycleState() ==
          refuzz::worker::AdapterLifecycleState::kFailed);
    CHECK(adapter.ExitCode() != 0);

    adapter.SetDomainReady(true);
    CHECK(__atomic_load_n(&ctrl.guest_state, __ATOMIC_ACQUIRE) ==
          static_cast<std::uint32_t>(GUEST_REG_CLAIMED));
    return 0;
}

int TestStatusFallbackMapsHarnessReasons()
{
    refuzz::worker::TaskResult r{};
    r.status = -1;

    // hang-evidence（daemon watchdog / reap 类）→ HUNG
    r.error_code = ERR_DOMAIN_WATCHDOG_TIMEOUT;
    CHECK(refuzz::worker::IvshmemWorkerAdapterTestAccess::StatusFromTaskResult(r) ==
          COMP_STATUS_HUNG);
    r.error_code = ERR_HARNESS_MAIN_REAP_FAILED;
    CHECK(refuzz::worker::IvshmemWorkerAdapterTestAccess::StatusFromTaskResult(r) ==
          COMP_STATUS_HUNG);
    r.error_code = ERR_HARNESS_STOPPED_REAP_TIMEOUT;
    CHECK(refuzz::worker::IvshmemWorkerAdapterTestAccess::StatusFromTaskResult(r) ==
          COMP_STATUS_HUNG);
    r.error_code = ERR_HARNESS_CLEANUP_FAILED;
    CHECK(refuzz::worker::IvshmemWorkerAdapterTestAccess::StatusFromTaskResult(r) ==
          COMP_STATUS_HUNG);

    // infra（outer fork / post-exit 协议错 / KCOV）→ HARNESS_FATAL
    r.error_code = ERR_HARNESS_OUTER_FORK_EAGAIN;
    CHECK(refuzz::worker::IvshmemWorkerAdapterTestAccess::StatusFromTaskResult(r) ==
          COMP_STATUS_HARNESS_FATAL);
    r.error_code = ERR_HARNESS_OUTER_FORK_FAILED;
    CHECK(refuzz::worker::IvshmemWorkerAdapterTestAccess::StatusFromTaskResult(r) ==
          COMP_STATUS_HARNESS_FATAL);
    r.error_code = ERR_HARNESS_FORK_SERVER_PROTOCOL;
    CHECK(refuzz::worker::IvshmemWorkerAdapterTestAccess::StatusFromTaskResult(r) ==
          COMP_STATUS_HARNESS_FATAL);
    r.error_code = ERR_HARNESS_KCOV_STATE_INVALID;
    CHECK(refuzz::worker::IvshmemWorkerAdapterTestAccess::StatusFromTaskResult(r) ==
          COMP_STATUS_HARNESS_FATAL);

    // 阶段相关的 14/15：无阶段信息不猜，保持 UNKNOWN 显形
    r.error_code = ERR_DOMAIN_REPLACEMENT_START_FAILED;
    CHECK(refuzz::worker::IvshmemWorkerAdapterTestAccess::StatusFromTaskResult(r) ==
          COMP_STATUS_UNKNOWN);
    r.error_code = ERR_DOMAIN_OWNERSHIP_UNRECLAIMED;
    CHECK(refuzz::worker::IvshmemWorkerAdapterTestAccess::StatusFromTaskResult(r) ==
          COMP_STATUS_UNKNOWN);

    return 0;
}

} // namespace

int main()
{
    if (TestBlockedCompletionPublicationIsFatal() != 0) {
        return 1;
    }
    if (TestStatusFallbackMapsHarnessReasons() != 0) {
        return 1;
    }
    return 0;
}

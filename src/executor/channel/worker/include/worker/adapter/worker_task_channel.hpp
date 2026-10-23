#pragma once

#include "worker/program_buffers.hpp"
#include "refuzz/proto_wire/ivshmem_protocol.h"

#include <chrono>
#include <cstdint>
#include <optional>

namespace refuzz::worker {

struct WorkerIO {
    const uint8_t* input_buf = nullptr;
    uint32_t input_len = 0;
    uint8_t* output_buf = nullptr;
    uint32_t output_cap = 0;
    uint32_t* crash_output_len = nullptr;
    ProgramResultPageV3* result_page = nullptr;
    uint64_t executor_id = 0;
    uint32_t dispatch_gen = 0;
    uint32_t timeout_ms = 0;
    uint32_t flags = 0;
    uint32_t target_proc_id = PROC_ID_ANY;
    bool cancel_requested = false;
    ProgramBufferDescriptor buffers;
};

struct TaskResult {
    uint64_t executor_id = 0;
    uint32_t dispatch_gen = 0;
    uint32_t output_len = 0;
    int32_t status = 0;
    uint32_t completion_status = 0;
    uint32_t error_code = 0;
    uint32_t crash_signal = 0;
    uint32_t proc_id = PROC_ID_ANY;
    bool cancel_observed = false;
};

enum class AdapterLifecycleState : uint8_t {
    kRunning = 0,
    kCleanShutdown,
    kFailed,
};

class IWorkerTaskChannel {
public:
    virtual ~IWorkerTaskChannel() = default;

    virtual std::optional<WorkerIO> WaitTask(
        std::chrono::milliseconds timeout) = 0;
    virtual void ReportDone(const TaskResult& result) = 0;
    virtual bool CancelRequested() const = 0;
    // Controls host sendability without affecting daemon heartbeat. READY
    // means the execution domain has completed startup and can accept work.
    virtual void SetDomainReady(bool /*ready*/) {}
    virtual void ResetOutputLen() = 0;
    virtual uint32_t GetCrashOutputLen() const = 0;
    virtual int ExitCode() const { return 0; }
    virtual AdapterLifecycleState LifecycleState() const {
        return AdapterLifecycleState::kRunning;
    }
};

} // namespace refuzz::worker

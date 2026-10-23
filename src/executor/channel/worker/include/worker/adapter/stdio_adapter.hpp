// Copyright 2026 reFuzz project author -------youngkk.
//
// StdioWorkerAdapter: local length-prefixed syz exec wire transport used by
// the Layer-3 paired VM oracle. The adapter owns protocol I/O and reports EOF
// or protocol failure; DomainSupervisor alone owns daemon/domain lifecycle.

#pragma once

#include "refuzz/proto_wire/ivshmem_protocol.h"
#include "worker/adapter/worker_adapter.hpp"

#include <cstddef>
#include <cstdint>
#include <string>

namespace refuzz::worker {

class StdioWorkerAdapter final : public IWorkerAdapter,
                                 public IWorkerTaskChannel,
                                 public IExecutionDomainRegistry,
                                 public IWorkerRegistrar {
public:
    struct Config {
        int input_fd = 0;
        int output_fd = 1;
        uint32_t worker_id = 0;
        uint32_t exec_timeout_ms = 5000;
        uint32_t max_input_size = 4u << 20;
        // Match upstream syzkaller stdio executor's anonymous output mapping:
        // execute_stdio_main() preallocates kMaxOutputCoverage = 6 MiB.
        uint32_t output_size = SYZKALLER_MAX_OUTPUT_COVERAGE;
    };

    StdioWorkerAdapter();
    explicit StdioWorkerAdapter(Config config);
    ~StdioWorkerAdapter() override;

    IWorkerTaskChannel& TaskChannel() override { return *this; }
    IExecutionDomainRegistry& DomainRegistry() override { return *this; }
    IWorkerRegistrar& Registrar() override { return *this; }

    int Init() override;
    int Handshake() override { return 0; }
    std::optional<WorkerIO> WaitTask(std::chrono::milliseconds timeout) override;
    void ReportDone(const TaskResult& result) override;
    bool CancelRequested() const override { return false; }
    void Cleanup() override;
    void ResetOutputLen() override;
    uint32_t GetCrashOutputLen() const override;
    size_t SandboxMappedBytes() const override { return shared_size_; }
    int ExitCode() const override { return exit_code_; }
    AdapterLifecycleState LifecycleState() const override;
    uint32_t WorkerId() const override { return config_.worker_id; }
    uint32_t WorkerCount() const override { return 1; }
    PersistedProcState LoadProcState() const override { return proc_state_; }
    bool PublishProcState(uint32_t proc_id, uint32_t epoch) override {
        proc_state_.proc_id = proc_id;
        proc_state_.epoch = epoch;
        proc_state_.valid = true;
        return true;
    }
    bool PublishDirtyProcMask(uint32_t dirty_proc_mask) override {
        proc_state_.dirty_proc_mask = dirty_proc_mask;
        return true;
    }
    bool PublishMaintenanceError(uint32_t error_code) override {
        maintenance_error_ = error_code;
        return true;
    }
    bool GetExecutionDomainTransport(
        ExecutionDomainTransport* out) const override;

private:
    struct SharedState;

    enum class ReadStatus : uint8_t {
        kOk = 0,
        kCleanEof,
        kTruncated,
        kError,
    };

    ReadStatus ReadExact(void* buf, std::size_t n);
    void EmitProtocolError(const std::string& msg);
    void EmitJsonLine(const std::string& line);
    std::string BuildResultJson(const TaskResult& result) const;
    uint8_t* InputBuffer();
    const uint8_t* InputBuffer() const;
    uint8_t* OutputBuffer();
    const uint8_t* OutputBuffer() const;

    Config config_;
    SharedState* shared_ = nullptr;
    size_t shared_size_ = 0;
    int shared_fd_ = -1;
    bool eof_ = false;
    int exit_code_ = 0;
    uint64_t next_executor_id_ = 1;
    uint64_t current_executor_id_ = 0;
    uint32_t current_dispatch_gen_ = 0;
    uint32_t current_n_calls_ = 0;
    PersistedProcState proc_state_{};
    uint32_t maintenance_error_ = 0;
};

} // namespace refuzz::worker

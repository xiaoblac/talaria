// IvshmemWorkerAdapter: ivshmem 传输适配层（V2）
// 封装共享内存 attach、注册握手、Task/Completion 收发、心跳与 doorbell 通知。
//
// [v2 R4] 继承链改为 IvshmemTransport (它再继承 IWorkerAdapter)。
//          ivshmem-specific step ring 方法通过 IvshmemTransport 接口暴露给
//          profile runner,
//          ROLLBACK 仅需把基类改回 IWorkerAdapter,删除 transport/ 子接口。

#pragma once

#include "worker/adapter/worker_adapter.hpp"
#include "worker/transport/ivshmem_transport.hpp"  // [v2 R4]
#include "refuzz/proto_wire/ivshmem_protocol.h"

#include <atomic>
#include <cstdint>

namespace refuzz::worker {

// class IvshmemWorkerAdapter : public IWorkerAdapter {
// [v2 inheritance — 当前版本: 透过 IvshmemTransport 子接口暴露 ivshmem-specific 方法]
class IvshmemWorkerAdapter : public IvshmemTransport,
                             public IWorkerTaskChannel,
                             public IExecutionDomainRegistry,
                             public IWorkerRegistrar {
public:
    struct Config {
        uint32_t worker_id = 0;
        uint32_t vm_id = 0;
        int peer_id = 1;
        int poll_ms = 1;
        bool enable_step_events = false;
    };

    explicit IvshmemWorkerAdapter(Config config);
    ~IvshmemWorkerAdapter() override;

    IWorkerTaskChannel& TaskChannel() override { return *this; }
    IExecutionDomainRegistry& DomainRegistry() override { return *this; }
    IWorkerRegistrar& Registrar() override { return *this; }

    int Init() override;
    int Handshake() override;
    std::optional<WorkerIO> WaitTask(std::chrono::milliseconds timeout) override;
    void ReportDone(const TaskResult& result) override;
    void Cleanup() override;

    // [v2 R4] 通过 IvshmemTransport 子接口实现 (typed),override 同名虚函数
    WorkerDataWindowV3* GetWorkerDataWindow() override;
    // IWorkerTaskChannel data-plane 方法，ExecutionEngine 只依赖该 facet。
    uint32_t GetCrashOutputLen() const override;
    void ResetOutputLen() override;
    size_t SandboxMappedBytes() const override { return bar2_size_ + bar0_size_; }
    void* TransportShmBase() const override { return shm_; }
    size_t TransportShmSize() const override { return bar2_size_; }
    bool GetExecutionDomainTransport(
        ExecutionDomainTransport* out) const override;
    bool InitialCorpusTriaged() const override {
        return hdr_ != nullptr && load_corpus_triaged_v3(hdr_) != 0;
    }

    int Register() override;
    bool NeedReregister();
    bool CancelRequested() const override;
    void SetDomainReady(bool ready) override;
    int ExitCode() const override {
        return transport_failed_.load(std::memory_order_acquire) ? 1 : 0;
    }
    AdapterLifecycleState LifecycleState() const override {
        return transport_failed_.load(std::memory_order_acquire)
            ? AdapterLifecycleState::kFailed
            : AdapterLifecycleState::kRunning;
    }
    void RingDoorbell();

    WorkerControlAreaV3* GetControlArea() const { return control_area_; }
    WorkerDataWindowV3* GetDataWindow() const { return data_window_; }
    TaskSlot* GetTaskSlot() const { return task_; }
    CompletionSlot* GetCompletionSlot() const { return completion_; }
    WorkerCtrl* GetCtrl() const { return ctrl_; }
    ShmHeader* GetHeader() const { return hdr_; }
    int DriverFd() const { return driver_fd_; }
    uint32_t WorkerId() const override { return config_.worker_id; }
    uint32_t WorkerCount() const override { return hdr_ != nullptr ? hdr_->n_workers : 0; }
    PersistedProcState LoadProcState() const override;
    bool PublishProcState(uint32_t proc_id, uint32_t epoch) override;
    bool PublishDirtyProcMask(uint32_t dirty_proc_mask) override;
    bool PublishMaintenanceError(uint32_t error_code) override;
    uint32_t RegEpoch() const { return reg_epoch_; }
    size_t SharedMemorySize() const { return bar2_size_; }
    // BAR0 持有 doorbell MSI-X 寄存器 mmap 区（几 KiB 量级）。
    // 单独暴露是为了让 ChildMain 组装 SandboxSizing 时能把 child VA 里
    // *所有* ivshmem 源的 mmap 统计进去（BAR2 + BAR0 + step_event_ring）。
    size_t SharedMemoryBar0Size() const { return bar0_size_; }

    void BumpExecSeq();

    // [v2 R4] step event ring 三个 getter 改为 IvshmemTransport 虚函数 override
    StepEventRingHeader* GetStepEventHeader() const override { return step_event_hdr_; }
    StepEventSlot* GetStepEventSlots() const override { return step_event_slots_; }
    uint32_t GetStepEventCapacity() const override { return step_event_capacity_; }

private:
    friend struct IvshmemWorkerAdapterTestAccess;

    // [心跳重定义] Start/Stop/HeartbeatLoop/WriteHeartbeatOnce 已删。host 判存活改读执行
    //   状态机的进度令牌(control_plane.hpp WorkerHeartbeatSample);删除理由见
    //   ivshmem_adapter.cpp 里 WriteStepEvent 上方那段注释。
    void WriteStepEvent(uint64_t executor_id, StepEventPhase phase, CompletionStatus status, uint32_t op_index);
    void MarkCancelObserved();
    static CompletionStatus StatusFromTaskResult(const TaskResult& result);

    Config config_;
    void* shm_ = nullptr;
    size_t bar2_size_ = 0;
    void* bar0_ = nullptr;
    size_t bar0_size_ = 0;
    int driver_fd_ = -1;
    int resource2_fd_ = -1;
    ShmHeader* hdr_ = nullptr;
    WorkerControlAreaV3* control_area_ = nullptr;
    WorkerDataWindowV3* data_window_ = nullptr;
    WorkerCtrl* ctrl_ = nullptr;
    TaskSlot* task_ = nullptr;
    CompletionSlot* completion_ = nullptr;
    StepEventRingHeader* step_event_hdr_ = nullptr;
    StepEventSlot* step_event_slots_ = nullptr;
    uint32_t step_event_capacity_ = 0;
    uint64_t exec_seq_ = 0;
    uint32_t reg_epoch_ = 0;
    uint64_t current_executor_id_ = 0;
    uint32_t current_dispatch_gen_ = 0;
    uint32_t current_timeout_ms_ = 0;
    uint32_t current_input_len_ = 0;
    bool current_cancel_requested_ = false;
    std::atomic<bool> domain_ready_{false};
    std::atomic<bool> transport_failed_{false};
};

} // namespace refuzz::worker

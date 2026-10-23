#pragma once

// ShmInfra — V3 共享内存所有权层
//
// 职责：
//   1. 拥有 host↔guest 共享内存 mmap（RAII）
//   2. Init() 写入 V3 显式 region 布局字段（ShmHeader + StepEventRingHeader）
//   3. 以 typed view 方式暴露 WorkerCtrl/TaskSlot/CompletionSlot/Input/Output
//   4. 不承载上层状态机语义（注册、调度、取消由上层组件实现）

#include "refuzz/channel/infra/ivshmem_backbone.hpp"
#include "refuzz/channel/result.hpp"
#include "refuzz/core/channel_contract.hpp"
#include "refuzz/proto_wire/ivshmem_protocol.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace refuzz::channel::infra {

struct InfraConfig {
    std::string shm_path;
    uint32_t n_workers = 1;

    // StepEventRing 容量（必须为 2 的幂）
    uint32_t step_event_ring_capacity = STEPEVENT_RING_DEFAULT_CAPACITY;
};

class ShmInfra;

struct WorkerView {
    WorkerCtrl* ctrl() const noexcept { return control_ != nullptr ? &control_->ctrl : nullptr; }
    TaskSlot* task_slot() const noexcept { return control_ != nullptr ? &control_->task : nullptr; }
    CompletionSlot* completion_slot() const noexcept {
        return control_ != nullptr ? &control_->completion : nullptr;
    }

    uint8_t* input_pool() const noexcept { return data_ != nullptr ? data_->input_pool : nullptr; }
    uint8_t* output_pool() const noexcept { return data_ != nullptr ? data_->output_pool : nullptr; }
    ProgramResultPageV3* result_page() const noexcept {
        return data_ != nullptr ? &data_->result_page : nullptr;
    }

    size_t input_pool_size() const noexcept { return MAX_INPUT_SIZE; }
    size_t output_pool_size() const noexcept { return MAX_OUTPUT_SIZE; }

    bool valid() const noexcept { return control_ != nullptr && data_ != nullptr; }

private:
    friend class ShmInfra;
    WorkerView(WorkerControlAreaV3* control, WorkerDataWindowV3* data) noexcept
        : control_(control), data_(data) {}

    WorkerControlAreaV3* control_ = nullptr;
    WorkerDataWindowV3* data_ = nullptr;
};

class ShmInfra {
public:
    explicit ShmInfra(InfraConfig config);
    ~ShmInfra();

    ShmInfra(const ShmInfra&) = delete;
    ShmInfra& operator=(const ShmInfra&) = delete;

    refuzz::channel::Result<void> Init();

    WorkerView worker(uint32_t worker_id) noexcept;

    size_t total_size() const noexcept;
    uint32_t n_workers() const noexcept;
    bool initialized() const noexcept;
    uint32_t MaxInput() const noexcept;
    uint32_t MaxOutput() const noexcept;
    uint32_t StepEventRingCapacity() const noexcept;

    // 注册门控/轮次（V2 Header）
    void WriteRegEpoch(uint32_t val) noexcept;
    uint32_t ReadRegEpoch() const noexcept;
    void WriteHostReady(uint32_t val) noexcept;
    uint32_t ReadHostReady() const noexcept;
    void WriteCorpusTriaged(uint32_t val) noexcept;
    uint32_t ReadCorpusTriaged() const noexcept;

    // [machine-check C4.6] Read worker-0's published per-VM env facts. Returns
    // false if not yet published (env_features_ready == 0); else copies into
    // *out. The ready flag is acquire-loaded so the struct is fully visible.
    bool ReadEnvFeatures(::EnvFeatures* out) const noexcept;

    // StepEventRing typed accessor
    StepEventRingHeader* StepEventHeader() noexcept;
    const StepEventRingHeader* StepEventHeader() const noexcept;
    StepEventSlot* StepEventSlots() noexcept;
    const StepEventSlot* StepEventSlots() const noexcept;

    // [v3 Phase 3] 返回 core-neutral StepEventRecord，内部完成 wire→record 转换
    std::vector<refuzz::core::channel_contract::StepEventRecord>
        SnapshotStepEventRing() const;

    // const 重载：供 transport const 方法调用，消除 const_cast
    WorkerView worker(uint32_t worker_id) const noexcept;

    // [v3 Phase 4.1] 共享 mmap 所有权：CP/DP/StepEventSource 可以持一份引用
    // 通过 shared_ptr 让最后一位 owner 析构时自动释放 mmap
    // 调用前必须 Init() 成功；否则返回 nullptr
    std::shared_ptr<IvshmemBackbone> Backbone() const noexcept { return backbone_; }

private:
    InfraConfig config_;
    std::shared_ptr<IvshmemBackbone> backbone_;  // 所有 shm 生命周期与 typed view 均委托此
    bool initialized_ = false;
};

} // namespace refuzz::channel::infra

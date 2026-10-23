#pragma once

// [v3 Phase 4.1] IvshmemBackbone — 共享内存所有权与 typed view 层
//
// 设计来源：docs/channel-redesign/v3/80_migration.md §5.1（Phase 4 核心）
//
// 职责：
//   1. 拥有 ivshmem 共享内存文件：unlink / open / ftruncate / mmap / munmap
//   2. 以 typed view 暴露 V3 布局：header / control / data / step event ring
//   3. 支持通过 shared_ptr 被多个 owner 共享（ShmInfra / 未来的
//      IvshmemControlPlane / IvshmemDataPlane / IvshmemStepEventSource），
//      最后一位 owner 析构时自动 munmap
//
// 非职责：
//   - 不写注册握手字段 / host_ready（ShmInfra::WriteInitFields 在 Create 时委托到本类）
//   - 不承载上层状态机语义（CP/DP 各自实现）
//   - 不知道 Worker/Transport/Channel 等高层组件
//
// 并发模型：
//   - Base() / 各 getter 返回裸指针，允许多线程并发访问；内存同步由调用方用
//     ACQUIRE/RELEASE helpers（proto_wire/ivshmem_protocol.h 提供）保证
//   - 本对象除构造/析构外无可变状态；线程安全
//
// 生命周期：
//   Create(config) → （多个 owner 共享 shared_ptr） → 最后一个 owner 释放 → munmap + close fd
//
// 兼容约束（Phase 4.1 过渡期）：
//   - ShmInfra 改为本类的 shared_ptr owner，对外 API 语义 / 签名 0 改变
//   - Backbone::Create 一次性完成 mmap + WriteInitFields（V2 header + step ring header）
//     这样外部只要拿到 shared_ptr 就是一个"可直接读写"的状态，无需二次 Init

#include "refuzz/channel/result.hpp"
#include "refuzz/proto_wire/ivshmem_protocol.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace refuzz::channel::infra {

struct BackboneConfig {
    std::string shm_path;
    uint32_t    n_workers                  = 1;
    uint32_t    step_event_ring_capacity   = STEPEVENT_RING_DEFAULT_CAPACITY;
};

class IvshmemBackbone {
public:
    // 工厂：完成 unlink/open/ftruncate/mmap + WriteInitFields，返回可读写 shared 实例
    // 失败时返回 Error（kInfra）；成功时返回 shared_ptr，所有 owner 共享同一 mmap
    //
    // 注：返回 shared_ptr<IvshmemBackbone> 而非 unique_ptr —— 是 Phase 4 的核心约束，
    // 让 CP/DP/StepEventSource 各自持一份引用，mmap 生命周期由 RAII 自动管理
    static refuzz::channel::Result<std::shared_ptr<IvshmemBackbone>>
        Create(BackboneConfig config);

    ~IvshmemBackbone();

    IvshmemBackbone(const IvshmemBackbone&)            = delete;
    IvshmemBackbone& operator=(const IvshmemBackbone&) = delete;
    IvshmemBackbone(IvshmemBackbone&&)                 = delete;
    IvshmemBackbone& operator=(IvshmemBackbone&&)      = delete;

    // ── 原始 base ── 仅供内部 typed getter；外部用 typed view 接口
    void*       Base()       noexcept { return mapping_base_; }
    const void* Base() const noexcept { return mapping_base_; }

    size_t      MappedSize()  const noexcept { return mapping_size_; }
    uint32_t    NWorkers()    const noexcept { return config_.n_workers; }
    uint32_t    StepEventRingCapacity() const noexcept { return config_.step_event_ring_capacity; }
    const std::string& ShmPath() const noexcept { return config_.shm_path; }

    // ── V3 header typed getter ──
    ShmHeader*       Header()       noexcept;
    const ShmHeader* Header() const noexcept;

    // ── Worker control/data typed getter ──
    // worker_id 越界时返回 nullptr；ShmInfra::worker() 的 WorkerView 基础
    WorkerControlAreaV3*       WorkerControl(uint32_t worker_id)       noexcept;
    const WorkerControlAreaV3* WorkerControl(uint32_t worker_id) const noexcept;
    WorkerDataWindowV3*        WorkerData(uint32_t worker_id)          noexcept;
    const WorkerDataWindowV3*  WorkerData(uint32_t worker_id) const    noexcept;

    // ── Step event ring typed getter ──
    StepEventRingHeader*       StepEventHeader()       noexcept;
    const StepEventRingHeader* StepEventHeader() const noexcept;
    StepEventSlot*             StepEventSlots()       noexcept;
    const StepEventSlot*       StepEventSlots() const noexcept;

private:
    IvshmemBackbone() = default;

    // 内部：构造后调用，填 V3 header + step ring header magic / capacity / 归零
    void WriteInitFields() noexcept;

    BackboneConfig config_;

    int    mapping_fd_   = -1;
    void*  mapping_base_ = nullptr;   // mmap'd address
    size_t mapping_size_ = 0;
};

} // namespace refuzz::channel::infra

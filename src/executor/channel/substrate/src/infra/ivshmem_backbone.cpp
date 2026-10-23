// [v3 Phase 4.1] IvshmemBackbone 实现
//
// 职责：拥有 ivshmem mmap 的生命周期，暴露 V3 typed getter；
// 允许多 owner 共享（shared_ptr）。从 ShmInfra::Init/WriteInitFields 搬出。

#include "refuzz/channel/infra/ivshmem_backbone.hpp"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cassert>
#include <cerrno>
#include <cstring>
#include <string>
#include <utility>

namespace refuzz::channel::infra {

namespace {

// 与历史 ShmInfra::Init 对齐的 size 计算：按 page 对齐后再向上取 2 的幂
// （plain 模式下 QEMU ivshmem size= 必须是 MB 级 power-of-2；doorbell PCI BAR 也要求 power-of-2）
size_t RoundUpLayout(size_t layout_size) noexcept
{
    const size_t page_rounded = ((layout_size + PAGE_SIZE - 1) / PAGE_SIZE) * PAGE_SIZE;
    size_t pow2 = 1;
    while (pow2 < page_rounded) pow2 <<= 1;
    return pow2;
}

} // namespace

refuzz::channel::Result<std::shared_ptr<IvshmemBackbone>>
IvshmemBackbone::Create(BackboneConfig config)
{
    if (config.n_workers == 0 || config.n_workers > MAX_WORKERS) {
        return refuzz::channel::Error{
            refuzz::channel::ErrorKind::kInfra,
            "IvshmemBackbone::Create() invalid n_workers"
        };
    }
    if (config.shm_path.empty()) {
        return refuzz::channel::Error{
            refuzz::channel::ErrorKind::kInfra,
            "IvshmemBackbone::Create() shm_path is empty"
        };
    }
    if (!is_power_of_two_u32(config.step_event_ring_capacity)) {
        return refuzz::channel::Error{
            refuzz::channel::ErrorKind::kInfra,
            "IvshmemBackbone::Create() step_event_ring_capacity must be power-of-two"
        };
    }

    const size_t layout_size = get_total_shm_size_v3(config.n_workers,
                                                     config.step_event_ring_capacity);
    const size_t total_size  = RoundUpLayout(layout_size);

    if (unlink(config.shm_path.c_str()) < 0) {
        const int err = errno;
        if (err != ENOENT) {
            return refuzz::channel::Error{
                refuzz::channel::ErrorKind::kInfra,
                std::string("IvshmemBackbone::Create() unlink failed: ") + std::strerror(err)
            };
        }
    }

    const int fd = open(config.shm_path.c_str(), O_CREAT | O_RDWR, 0660);
    if (fd < 0) {
        const int err = errno;
        return refuzz::channel::Error{
            refuzz::channel::ErrorKind::kInfra,
            std::string("IvshmemBackbone::Create() open failed: ") + std::strerror(err)
        };
    }

    if (ftruncate(fd, static_cast<off_t>(total_size)) < 0) {
        const int err = errno;
        ::close(fd);
        unlink(config.shm_path.c_str());
        return refuzz::channel::Error{
            refuzz::channel::ErrorKind::kInfra,
            std::string("IvshmemBackbone::Create() ftruncate failed: ") + std::strerror(err)
        };
    }

    void* const base = mmap(nullptr,
                            total_size,
                            PROT_READ | PROT_WRITE,
                            MAP_SHARED,
                            fd,
                            0);
    if (base == MAP_FAILED) {
        const int err = errno;
        ::close(fd);
        unlink(config.shm_path.c_str());
        return refuzz::channel::Error{
            refuzz::channel::ErrorKind::kInfra,
            std::string("IvshmemBackbone::Create() mmap failed: ") + std::strerror(err)
        };
    }

    // 归零 + 写初始 header 字段
    std::memset(base, 0, total_size);

    // 私有构造 + make_shared 两段式：此处用 new + shared_ptr{} 保证能访问 private ctor
    std::shared_ptr<IvshmemBackbone> self(new IvshmemBackbone());
    self->config_       = std::move(config);
    self->mapping_fd_   = fd;
    self->mapping_base_ = base;
    self->mapping_size_ = total_size;
    self->WriteInitFields();

    return refuzz::channel::Result<std::shared_ptr<IvshmemBackbone>>::Ok(std::move(self));
}

IvshmemBackbone::~IvshmemBackbone()
{
    if (mapping_base_ != nullptr && mapping_base_ != MAP_FAILED) {
        munmap(mapping_base_, mapping_size_);
        mapping_base_ = nullptr;
    }
    if (mapping_fd_ >= 0) {
        ::close(mapping_fd_);
        mapping_fd_ = -1;
    }
    // 注：不 unlink shm 文件 —— 与历史 ShmInfra::~ShmInfra 行为一致（由 Runtime 路径负责清理）
}

void IvshmemBackbone::WriteInitFields() noexcept
{
    assert(mapping_base_ != nullptr && mapping_base_ != MAP_FAILED);

    auto* hdr = get_shm_header_v3(mapping_base_);
    hdr->magic                    = IVSHMEM_MAGIC;
    hdr->version                  = PROTOCOL_VERSION;
    hdr->n_workers                = config_.n_workers;
    hdr->worker_area_size         = 0;
    hdr->step_event_ring_capacity = config_.step_event_ring_capacity;
    hdr->reg_epoch                = 0;
    store_host_ready_v3(hdr, 0);
    store_corpus_triaged_v3(hdr, 0);

    hdr->control_region_offset = get_control_region_offset_v3();
    hdr->control_region_size = get_control_region_size_v3(config_.n_workers);
    hdr->data_region_offset = get_data_region_offset_v3(config_.n_workers);
    hdr->data_region_size = get_data_region_size_v3(config_.n_workers);
    hdr->step_ring_offset = get_step_event_ring_offset_v3(config_.n_workers);
    hdr->step_ring_size = get_step_event_ring_size_v3(config_.step_event_ring_capacity);
    hdr->per_worker_control_stride =
        static_cast<uint32_t>(get_worker_control_stride_v3());
    hdr->per_worker_data_stride =
        static_cast<uint32_t>(get_worker_data_stride_v3());
    hdr->data_input_offset = static_cast<uint32_t>(
        offsetof(WorkerDataWindowV3, input_pool));
    hdr->data_input_size = MAX_INPUT_SIZE;
    hdr->data_output_offset = static_cast<uint32_t>(
        offsetof(WorkerDataWindowV3, output_pool));
    hdr->data_output_size = MAX_OUTPUT_SIZE;
    hdr->data_result_offset = static_cast<uint32_t>(
        offsetof(WorkerDataWindowV3, result_page));
    hdr->data_result_size = static_cast<uint32_t>(sizeof(ProgramResultPageV3));

    auto* ring_hdr    = get_step_event_ring_header_v3(mapping_base_);
    ring_hdr->magic   = STEPEVENT_RING_MAGIC;
    ring_hdr->capacity = config_.step_event_ring_capacity;
    __atomic_store_n(&ring_hdr->head, 0ULL, __ATOMIC_RELEASE);
    __atomic_store_n(&ring_hdr->tail, 0ULL, __ATOMIC_RELEASE);
}

ShmHeader* IvshmemBackbone::Header() noexcept
{
    assert(mapping_base_ != nullptr);
    return get_shm_header_v3(mapping_base_);
}

const ShmHeader* IvshmemBackbone::Header() const noexcept
{
    assert(mapping_base_ != nullptr);
    return get_shm_header_v3_const(mapping_base_);
}

WorkerControlAreaV3* IvshmemBackbone::WorkerControl(uint32_t worker_id) noexcept
{
    assert(mapping_base_ != nullptr);
    if (worker_id >= config_.n_workers) return nullptr;
    return get_worker_control_area_v3(mapping_base_, worker_id);
}

const WorkerControlAreaV3* IvshmemBackbone::WorkerControl(uint32_t worker_id) const noexcept
{
    assert(mapping_base_ != nullptr);
    if (worker_id >= config_.n_workers) return nullptr;
    return get_worker_control_area_v3_const(mapping_base_, worker_id);
}

WorkerDataWindowV3* IvshmemBackbone::WorkerData(uint32_t worker_id) noexcept
{
    assert(mapping_base_ != nullptr);
    if (worker_id >= config_.n_workers) return nullptr;
    return get_worker_data_window_v3(mapping_base_, worker_id);
}

const WorkerDataWindowV3* IvshmemBackbone::WorkerData(uint32_t worker_id) const noexcept
{
    assert(mapping_base_ != nullptr);
    if (worker_id >= config_.n_workers) return nullptr;
    return get_worker_data_window_v3_const(mapping_base_, worker_id);
}

StepEventRingHeader* IvshmemBackbone::StepEventHeader() noexcept
{
    assert(mapping_base_ != nullptr);
    return get_step_event_ring_header_v3(mapping_base_);
}

const StepEventRingHeader* IvshmemBackbone::StepEventHeader() const noexcept
{
    assert(mapping_base_ != nullptr);
    return get_step_event_ring_header_v3_const(mapping_base_);
}

StepEventSlot* IvshmemBackbone::StepEventSlots() noexcept
{
    assert(mapping_base_ != nullptr);
    return get_step_event_slots_v3(mapping_base_);
}

const StepEventSlot* IvshmemBackbone::StepEventSlots() const noexcept
{
    assert(mapping_base_ != nullptr);
    return get_step_event_slots_v3_const(mapping_base_);
}

} // namespace refuzz::channel::infra

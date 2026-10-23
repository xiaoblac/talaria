// [v3 Phase 4.1] ShmInfra 薄化：内部持 shared_ptr<IvshmemBackbone>
//
// 改造策略：
//   - 对外所有 API 签名 / 语义 / 返回值完全不变
//   - mmap / ftruncate / munmap / 写 V2 header 全部搬进 IvshmemBackbone
//   - ShmInfra 只做 BackboneConfig 适配 + 结果委托
//
// 这样未来 Phase 4.2 CP/DP 可以通过 ShmInfra::Backbone() 拿 shared_ptr
// 各自持一份引用，mmap 生命周期由 RAII 自动保证。

#include "refuzz/channel/infra/shm_infra.hpp"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <utility>

namespace refuzz::channel::infra {

ShmInfra::ShmInfra(InfraConfig config)
    : config_(std::move(config))
{
}

ShmInfra::~ShmInfra() = default;

refuzz::channel::Result<void> ShmInfra::Init()
{
    if (initialized_) {
        return refuzz::channel::Error{
            refuzz::channel::ErrorKind::kInfra,
            "ShmInfra::Init() called on already-initialized instance"
        };
    }

    BackboneConfig bb_cfg;
    bb_cfg.shm_path                 = config_.shm_path;
    bb_cfg.n_workers                = config_.n_workers;
    bb_cfg.step_event_ring_capacity = config_.step_event_ring_capacity;

    auto r = IvshmemBackbone::Create(std::move(bb_cfg));
    if (!r.ok()) {
        return refuzz::channel::Error{r.error().kind, r.error().message};
    }
    backbone_    = std::move(r.value());
    initialized_ = true;
    return refuzz::channel::Result<void>::Ok();
}

WorkerView ShmInfra::worker(uint32_t worker_id) noexcept
{
    assert(initialized_);
    assert(backbone_);
    WorkerControlAreaV3* control = backbone_->WorkerControl(worker_id);
    WorkerDataWindowV3* data = backbone_->WorkerData(worker_id);
    return WorkerView{control, data};
}

WorkerView ShmInfra::worker(uint32_t worker_id) const noexcept
{
    return const_cast<ShmInfra*>(this)->worker(worker_id);
}

size_t ShmInfra::total_size() const noexcept
{
    return backbone_ ? backbone_->MappedSize() : 0;
}

uint32_t ShmInfra::n_workers() const noexcept
{
    return config_.n_workers;
}

bool ShmInfra::initialized() const noexcept
{
    return initialized_;
}

uint32_t ShmInfra::MaxInput() const noexcept
{
    return MAX_INPUT_SIZE;
}

uint32_t ShmInfra::MaxOutput() const noexcept
{
    return MAX_OUTPUT_SIZE;
}

uint32_t ShmInfra::StepEventRingCapacity() const noexcept
{
    return config_.step_event_ring_capacity;
}

void ShmInfra::WriteRegEpoch(uint32_t val) noexcept
{
    assert(initialized_);
    backbone_->Header()->reg_epoch = val;
}

uint32_t ShmInfra::ReadRegEpoch() const noexcept
{
    assert(initialized_);
    return backbone_->Header()->reg_epoch;
}

void ShmInfra::WriteHostReady(uint32_t val) noexcept
{
    assert(initialized_);
    store_host_ready_v3(backbone_->Header(), val);
}

uint32_t ShmInfra::ReadHostReady() const noexcept
{
    assert(initialized_);
    return load_host_ready_v3(backbone_->Header());
}

void ShmInfra::WriteCorpusTriaged(uint32_t val) noexcept
{
    assert(initialized_);
    store_corpus_triaged_v3(backbone_->Header(), val != 0 ? 1u : 0u);
}

uint32_t ShmInfra::ReadCorpusTriaged() const noexcept
{
    assert(initialized_);
    return load_corpus_triaged_v3(backbone_->Header());
}

bool ShmInfra::ReadEnvFeatures(::EnvFeatures* out) const noexcept
{
    assert(initialized_);
    if (out == nullptr) {
        return false;
    }
    const ShmHeader* hdr = backbone_->Header();
    if (load_env_features_ready_v3(hdr) == 0u) {
        return false;  // worker-0 hasn't published yet
    }
    *out = hdr->env_features;  // acquire on the flag makes the struct visible
    return true;
}

StepEventRingHeader* ShmInfra::StepEventHeader() noexcept
{
    assert(initialized_);
    return backbone_->StepEventHeader();
}

const StepEventRingHeader* ShmInfra::StepEventHeader() const noexcept
{
    assert(initialized_);
    return backbone_->StepEventHeader();
}

StepEventSlot* ShmInfra::StepEventSlots() noexcept
{
    assert(initialized_);
    return backbone_->StepEventSlots();
}

const StepEventSlot* ShmInfra::StepEventSlots() const noexcept
{
    assert(initialized_);
    return backbone_->StepEventSlots();
}

std::vector<refuzz::core::channel_contract::StepEventRecord>
ShmInfra::SnapshotStepEventRing() const
{
    namespace cc = refuzz::core::channel_contract;
    std::vector<cc::StepEventRecord> out;
    assert(initialized_);

    const StepEventRingHeader* hdr = StepEventHeader();
    const uint32_t capacity = hdr->capacity;
    if (capacity == 0 || !is_power_of_two_u32(capacity)) {
        return out;
    }

    const uint64_t head = step_event_head_load_v3(hdr);
    const uint64_t begin = (head > capacity) ? (head - capacity) : 0;
    const StepEventSlot* slots = StepEventSlots();

    out.reserve(static_cast<size_t>(head - begin));
    for (uint64_t pos = begin; pos < head; ++pos) {
        const StepEventSlot* slot = &slots[static_cast<uint32_t>(pos & (capacity - 1U))];
        const uint64_t seq1 = step_event_seq_load_v3(slot);
        if (seq1 != pos + 1) {
            continue;
        }

        StepEventSlot snapshot = *slot;
        const uint64_t seq2 = step_event_seq_load_v3(slot);
        if (seq2 != pos + 1) {
            continue;
        }

        cc::StepEventRecord rec;
        rec.worker_id   = snapshot.worker_id;
        rec.actor_id    = snapshot.actor_id;
        rec.executor_id = snapshot.executor_id;
        rec.op_index    = snapshot.op_index;
        rec.phase       = snapshot.phase;
        rec.status      = snapshot.status;
        rec.reserved0   = snapshot.reserved0;
        rec.seq         = seq2;
        rec.ts_us       = snapshot.ts_us;
        std::memcpy(rec.payload.data(), snapshot.reserved,
                    std::min(sizeof(snapshot.reserved), rec.payload.size()));
        out.push_back(rec);
    }
    return out;
}

} // namespace refuzz::channel::infra

// step_event_writer 实现
// 全局变量仅在 child 进程内使用 (fork 后独立地址空间)。

#include "worker/observation/step_event_writer.hpp"
#include "refuzz/proto_wire/ivshmem_protocol.h"

namespace refuzz::worker {
namespace {

StepEventRingHeader* g_step_hdr = nullptr;
StepEventSlot* g_step_slots = nullptr;
uint32_t g_step_capacity = 0;
uint32_t g_step_worker_id = 0;
uint64_t g_step_executor_id = 0;

} // namespace

void SetStepEventWriter(StepEventRingHeader* hdr, StepEventSlot* slots,
                        uint32_t capacity, uint32_t worker_id)
{
    g_step_hdr = hdr;
    g_step_slots = slots;
    g_step_capacity = capacity;
    g_step_worker_id = worker_id;
}

void SetStepEventExecutorId(uint64_t executor_id)
{
    g_step_executor_id = executor_id;
}

void WriteStepEventForCall(uint32_t op_index,
                           StepEventPhase phase, CompletionStatus status)
{
    if (g_step_hdr == nullptr || g_step_slots == nullptr || g_step_capacity == 0) {
        return;
    }
    // capacity must be power of 2
    if ((g_step_capacity & (g_step_capacity - 1)) != 0) {
        return;
    }

    const uint64_t pos = step_event_head_fetch_add_v3(g_step_hdr, 1);
    StepEventSlot* slot = &g_step_slots[pos & (g_step_capacity - 1U)];

    // Write slot: zero seq first (signals "in-progress"), fill fields, fence, then set seq
    step_event_seq_store_v3(slot, 0ULL);
    slot->worker_id   = g_step_worker_id;
    slot->actor_id    = g_step_worker_id;
    slot->executor_id = g_step_executor_id;
    slot->op_index    = op_index;
    slot->phase       = static_cast<uint32_t>(phase);
    slot->status      = static_cast<uint32_t>(status);
    slot->ts_us       = now_us();
    __atomic_thread_fence(__ATOMIC_RELEASE);
    step_event_seq_store_v3(slot, pos + 1ULL);
}

} // namespace refuzz::worker

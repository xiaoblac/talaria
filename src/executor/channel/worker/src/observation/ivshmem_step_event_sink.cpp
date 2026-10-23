// Copyright 2026 reFuzz project author -------youngkk.
//
// IvshmemStepEventSink 实现：在 Init() 阶段调 SetStepEventWriter 设置
// 全局指针；kTaskStart 时更新 executor_id；其它事件由 step_event_writer
// 全局函数在 driver 内部直接写 ring (R2 暂未把 per-call 走总线)。
//
// R2 引入。

#include "worker/observation/ivshmem_step_event_sink.hpp"

#include "worker/observation/step_event_writer.hpp"

namespace refuzz::worker {

IvshmemStepEventSink::IvshmemStepEventSink(StepEventRingHeader* hdr,
                                           StepEventSlot* slots,
                                           uint32_t capacity,
                                           uint32_t worker_id)
    : hdr_(hdr)
    , slots_(slots)
    , capacity_(capacity)
    , worker_id_(worker_id)
{}

bool IvshmemStepEventSink::Init()
{
    // SetStepEventWriter 接 nullptr 即禁用,无副作用——可以无脑调。
    SetStepEventWriter(hdr_, slots_, capacity_, worker_id_);
    return true;
}

void IvshmemStepEventSink::OnEvent(ObservationEvent ev, const ObservationContext& ctx)
{
    switch (ev) {
    case ObservationEvent::kTaskStart:
        SetStepEventExecutorId(ctx.executor_id);
        break;
    case ObservationEvent::kActionBefore:
    case ObservationEvent::kActionAfter:
        // R2: per-call 事件由 driver 内部 (syz_exec_runner) 直接调
        //     WriteStepEventForCall 走 child 进程全局 ring 指针。
        //     这里不重复写入。
        break;
    case ObservationEvent::kSessionEnd:
        // step events 通过 ring 实时写入,会话结束没有额外动作。
        break;
    }
}

} // namespace refuzz::worker

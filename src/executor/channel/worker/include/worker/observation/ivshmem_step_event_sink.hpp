// Copyright 2026 reFuzz project author -------youngkk.
//
// IvshmemStepEventSink: 把 step_event ring 包装成 IObservationSink。
//
// R2 引入：替换 ChildMain 里"main 透传 step_event_hdr/slots/capacity 给
// engine config + child" 的硬编码,统一为"sink 持有 ring 指针,事件总线
// 驱动"。
//
// 注意：per-call (kActionBefore/After) 写入仍然走 step_event_writer.cpp
// 的全局函数 WriteStepEventForCall——因为这个函数被 worker thread 在
// threaded 模式下并发调用,其内部已用 atomic fetch_add + memory fence
// 保证线程安全。Sink 只在 Init() 阶段把 ring 指针塞给那个全局；
// kTaskStart 事件用来更新 g_step_executor_id。
//
// R3 会把 step_event_hdr/slots/capacity 从 EngineConfig 删掉,
// 改由 main 直接构造此 sink (通过 IvshmemTransport 拿到 ring)；
// R2 阶段先保留 EngineConfig 字段不动,只新增 sink 这条平行路径。

#pragma once

#include "refuzz/proto_wire/ivshmem_protocol.h"
#include "worker/observation/observation_bus.hpp"

#include <cstdint>

namespace refuzz::worker {

class IvshmemStepEventSink final : public IObservationSink {
public:
    IvshmemStepEventSink(StepEventRingHeader* hdr,
                         StepEventSlot* slots,
                         uint32_t capacity,
                         uint32_t worker_id);

    // child 内 fork 后调用：把 ring 指针塞进 step_event_writer 的 (child 进程内)
    // 全局变量,让 WriteStepEventForCall 后续按位置写。
    bool Init() override;

    void OnEvent(ObservationEvent ev, const ObservationContext& ctx) override;

    // step events 是 streaming 写入 ring 的,task 结束时不 pack 任何额外帧。
    void PackFeedback(uint8_t* /*out*/, uint32_t /*out_cap*/,
                      uint32_t* /*inout_len*/) override {}

    uint32_t SnapshotForCrash(uint8_t* /*out*/, uint32_t /*out_cap*/) const override {
        return 0;
    }

    size_t BufferBytes() const override { return 0; }

    const char* Name() const override { return "ivshmem_step_event"; }

private:
    StepEventRingHeader* hdr_ = nullptr;
    StepEventSlot* slots_ = nullptr;
    uint32_t capacity_ = 0;
    uint32_t worker_id_ = 0;
};

} // namespace refuzz::worker

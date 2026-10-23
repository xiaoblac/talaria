// Copyright 2026 reFuzz project author -------youngkk.
//
// IvshmemTransport: ivshmem transport 的"具体协议层"接口,
// 在通用 IWorkerAdapter composition root 之上
// 暴露 ivshmem 独有的访问点 (共享内存 area / step ring 指针)。
//
// R4 引入：把这些 ivshmem-specific 方法从 IWorkerAdapter 撤出,使
// IWorkerAdapter 真正成为 transport-agnostic 接口。
// profile runner 通过 AsIvshmem() 拿到这一层；engine/supervisor 不依赖它。
//
// profile runner 在 adapter.Init() 后读取一次 ivshmem-specific view。

#pragma once

#include "refuzz/proto_wire/ivshmem_protocol.h"
#include "worker/adapter/worker_adapter.hpp"

#include <cstdint>

namespace refuzz::worker {

class IvshmemTransport : public IWorkerAdapter {
public:
    ~IvshmemTransport() override = default;

    // [no-rtti devirt 2026-05-22] 让 caller 通过 base IWorkerAdapter 接口
    // 拿 IvshmemTransport* 不走 dynamic_cast (RTTI 关掉以省 binary).
    IvshmemTransport* AsIvshmem() override { return this; }

    // V3 worker data window。program child 只继承这块 data window,不继承
    // control/step-ring region。
    virtual WorkerDataWindowV3* GetWorkerDataWindow() = 0;

    // step event ring 指针 (R3 起由 IvshmemStepEventSink 持有,
    // main 在构造 sink 时通过此接口取一次)。
    virtual StepEventRingHeader* GetStepEventHeader() const = 0;
    virtual StepEventSlot* GetStepEventSlots() const = 0;
    virtual uint32_t GetStepEventCapacity() const = 0;
};

} // namespace refuzz::worker

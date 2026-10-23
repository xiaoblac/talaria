#pragma once

// [v3 Phase 1.B / Phase 3] IStepEventSource — worker step event 环形缓冲快照抽象
//
// 设计来源：docs/channel-redesign/v3/40_evidence.md §2.2
// 职责：
//   - Snapshot()：返回当前所有 worker 的 step-event ring 快照；按 seq/ts 升序
//   - IsAvailable()：false → 当前场景无 step ring（如 ssh dmesg）；Sensor 不调 Snapshot
//
// 约束：Snapshot() 必须是 thread-safe 的只读操作（ivshmem 实现用 seq-counter 做无锁读）
//
// [Phase 3 改动]
// StepEventRecord 定义已上移到 core/channel_contract.hpp，
// 本文件 using 引入，保持 evidence::StepEventRecord 这个书写形式不变，
// 同时避免"channel 内外双定义"造成的结构漂移。

#include "refuzz/core/channel_contract.hpp"

#include <vector>

namespace refuzz::channel::evidence {

// core-neutral StepEventRecord 的 alias；用法完全一致
using StepEventRecord = refuzz::core::channel_contract::StepEventRecord;

class IStepEventSource {
public:
    virtual ~IStepEventSource() = default;

    virtual std::vector<StepEventRecord> Snapshot() const = 0;
    virtual bool                         IsAvailable() const = 0;
};

} // namespace refuzz::channel::evidence

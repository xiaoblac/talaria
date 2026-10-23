// step_event_writer: 全局 StepEvent 写入接口
// child 进程 fork 后调用 SetStepEventWriter 设置 ring 指针,
// 执行后端通过 WriteStepEventForCall 在每个 syscall 前后写入事件。
// 线程安全: ring 使用 atomic fetch_add, 多线程可并发写入。

#pragma once

#include "refuzz/proto_wire/ivshmem_protocol.h"
#include <cstdint>

namespace refuzz::worker {

// 初始化 child 进程内的全局 step event writer。
// fork 后由 ChildMain 调用一次。传入 nullptr 表示禁用写入。
void SetStepEventWriter(StepEventRingHeader* hdr, StepEventSlot* slots,
                        uint32_t capacity, uint32_t worker_id);

// 设置当前 task 的 executor_id (每次 ChildMain 收到 ReadyMsg 后调用)。
// 这样 WriteStepEventForCall 不需要每次传入 executor_id。
void SetStepEventExecutorId(uint64_t executor_id);

// 写入一个 syscall 级别的 step event。
// 使用最近一次 SetStepEventExecutorId 设置的 executor_id。
// 如果 writer 未初始化, 静默跳过。
void WriteStepEventForCall(uint32_t op_index, StepEventPhase phase,
                           CompletionStatus status = COMP_STATUS_OK);

} // namespace refuzz::worker

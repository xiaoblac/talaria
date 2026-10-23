#pragma once

// refuzz::core::channel_contract — request dispatch lifecycle event
//
// 中立的"派发生命周期"合同,与 channel_contract.hpp 的 result/routing 合同
// (Completion / Abnormal / Fault)**正交**:
//
//   pull/window 生命周期(本文件):
//     JobScheduler submit request
//       -> channeldispatcher Channel::Submit
//       -> kAccepted(或 host fail-closed kRejected)
//       -> RequestLifecycleEvent{executor_id, phase}
//       -> FuzzerLoop drain -> JobScheduler::MarkAccepted(executor_id)
//       -> 释放 request-window credit -> scheduler 可继续 pull
//
//   result/routing 生命周期(channel_contract.hpp 的 ChannelEvent):
//     request -> Completion/Abnormal/Fault -> event_queue -> TryClaim / catch-all
//
// 拆成两条线的目的:继续 pull 只等 **accepted**(执行侧已接管),既不像等
// completion 那样过度保守,也不像看 task_queue 被 pop 那样过度激进。executor 只发
// 这个中立事件、不认识 job;JobScheduler 只认 executor_id、不认识 channel —— 无跨模块耦合。
//
// 独立于 channel_contract.hpp 单列一个轻头文件:包含它的编译单元(executor submit
// 线程 / control loop / lifecycle 队列)不必因此重编所有 include channel_contract.hpp 的地方。

#include <cstdint>

namespace refuzz::core::channel_contract {

// 一次派发到达"执行侧已接管窗口"的收尾方式。两者都释放同一个 request-window credit;
// 区分仅供 metric / 日志。绝大多数是 kAccepted;kRejected 只在 host 侧 fail-closed
// (如 MaterializeExecWire 失败,任务从未 Submit 到 channel)时发,保证窗口不泄漏。
enum class RequestLifecyclePhase : uint8_t {
    kAccepted = 0,   // Channel::Submit 返回 kAccepted —— 执行侧已接管该 executor_id
    kRejected = 1,   // host 侧 fail-closed,任务未提交给 channel —— 释放窗口以防泄漏
};

inline const char* RequestLifecyclePhaseName(RequestLifecyclePhase phase)
{
    switch (phase) {
    case RequestLifecyclePhase::kAccepted: return "accepted";
    case RequestLifecyclePhase::kRejected: return "rejected";
    }
    return "unknown";
}

struct RequestLifecycleEvent {
    // 调度器为该 request 分配的 executor_id(与 ChannelDispatchRequest.executor_id /
    // HostFuzzTask.executor_id 同一空间,单调唯一,可 demux)。
    uint64_t executor_id = 0;
    RequestLifecyclePhase phase = RequestLifecyclePhase::kAccepted;
    // accept 时 channel 的 generation(诊断用;kRejected 恒 0)。
    uint32_t generation = 0;
};

} // namespace refuzz::core::channel_contract

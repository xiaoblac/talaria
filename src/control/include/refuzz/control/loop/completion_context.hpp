#pragma once
// [Step 6 stage 清场] ConsumerCtx + event 提取 helper —— 从退役的 stage/stage_context.hpp
// + stage/stage_chain.hpp 迁出。这些是 **loop 的 completion 处理上下文/工具**,jobs-only 下
// 由 FuzzerLoop::{ProcessEventFeedback, ProcessCatchAllCompletion} 消费,与 stage framework
// 无关(ConsumerCtx 自包含,不引用 StageDeps/StageChain)。

#include "refuzz/core/channel_contract.hpp"     // ChannelEvent / CompletionContext
#include "refuzz/feedback/feedback_engine.hpp"  // EngineOutput

#include <cstdint>
#include <optional>

namespace refuzz::control {

// 本 tick 要消费的 event + 它的 feedback 判定。feedback.Process(event) 有状态(coverage
// store 每调一次 MergeCoverage)→ 每 event 只 Process 一次:FuzzerLoop::ProcessEventFeedback
// 在处理前调一次、填 feedback_output。event_consumed 现无 setter(consumer_chain 已删),恒 false。
struct ConsumerCtx {
    refuzz::core::channel_contract::ChannelEvent     event;
    std::optional<refuzz::fuzzer::EngineOutput>      feedback_output = std::nullopt;
    bool                                             event_consumed = false;
    bool                                             stop_chain = false;
};

// ChannelEvent → executor_id。Completion / AbnormalCompletion 在 .ctx.executor_id;
// Fault 没有关联 data-plane executor,返回 0 作为 sentinel。
inline std::uint64_t ExecutorIdOf(
    const refuzz::core::channel_contract::ChannelEvent& ev) noexcept
{
    if (auto* c = ev.AsCompletion()) return c->ctx.executor_id;
    if (auto* a = ev.AsAbnormal())   return a->ctx.executor_id;
    return 0;
}

// 数据平面事件的 CompletionContext(seed_id / program_payload / artifact)。Completion /
// AbnormalCompletion 携带;Fault 无 → nullptr。catch-all 在 Process(event) 后取 ctx 编排 admit。
inline const refuzz::core::channel_contract::CompletionContext*
CompletionCtxOf(const refuzz::core::channel_contract::ChannelEvent& ev) noexcept
{
    if (auto* c = ev.AsCompletion()) return &c->ctx;
    if (auto* a = ev.AsAbnormal())   return &a->ctx;
    return nullptr;
}

} // namespace refuzz::control

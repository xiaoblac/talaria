// Copyright 2026 reFuzz project author -------youngkk.

#include "refuzz/feedback/engine/composite_feedback_engine.hpp"

#include "refuzz/feedback/observation/kernel_observation.hpp"  // [exec-accounting] executed_calls

#include <algorithm>
#include <utility>

namespace refuzz::fuzzer {

CompositeFeedbackEngine::CompositeFeedbackEngine(std::string name)
    : name_(std::move(name))
{}

void CompositeFeedbackEngine::AddSignal(std::unique_ptr<ISignal> signal)
{
    if (!signal) {
        return;
    }
    signals_.push_back(std::move(signal));
}

void CompositeFeedbackEngine::SetAggregator(std::unique_ptr<IFeedbackAggregator> aggregator)
{
    aggregator_ = std::move(aggregator);
    aggregator_id_ = aggregator_ ? aggregator_->Id() : std::string{};
}

EngineOutput CompositeFeedbackEngine::Process(const refuzz::core::channel_contract::ChannelEvent& event)
{
    EngineOutput out;
    if (!aggregator_) {
        return out;
    }

    // 1. 采样：每个信号独立处理事件
    contribs_buf_.clear();
    contribs_buf_.reserve(signals_.size());
    for (auto& sig : signals_) {
        contribs_buf_.push_back(sig->Sample(event));
    }

    // 2. 聚合：产出 verdict(=CompositeScore)。crash_payload 镜像到 EngineOutput.crash_dispatch。
    out.verdict        = aggregator_->Aggregate(event, contribs_buf_);
    out.crash_dispatch = out.verdict.crash_payload;

    // [v2 batch 3 PR-W2] 合并各 signal 的 transient observation 进 EngineOutput。
    // 顺序:按 signal 在 signals_ 中的注册顺序依次 MergeFrom;同 type_index key
    // **后写覆盖前写**(即后注册的 signal 同类型 observation 覆盖前注册)。后续 stage
    // / control loop 自决消费(verdict 重构后 actuation 全在 loop)。
    for (const auto& contrib : contribs_buf_) {
        if (!contrib.observation.Empty()) {
            out.observation.MergeFrom(contrib.observation);
        }
    }

    // [exec-accounting 重构] executed_calls = 合并后 observation 里真正执行过的 call
    // 数。signal 在 decode worker output 时已逐 call 解出 executed flag
    // (kCallFlagExecuted);这里只是把它数出来作为一等输出 —— **零重解** SyzExecResult。
    // 控制环据此写 fuzzer.calls.executed,而不再让某个 stage 重新 decode。无 per-call
    // observation 的 family(留空)自然得 0。
    if (const auto* kco = out.observation.Get<KernelExecutionObservation>()) {
        std::uint64_t executed = 0;
        for (const auto& call : kco->per_call) {
            if (call.executed) {
                ++executed;
            }
        }
        out.executed_calls = executed;
    }

    // Phase F / F3: triage and minimization need an idempotent snapshot of the
    // event's raw signal hashes. Do not gate this on score.interesting: coverage
    // signals update global feedback state during sampling, so a second
    // evaluation of the same event would otherwise erase the stable signal.
    std::vector<std::uint64_t> merged;
    for (const auto& c : contribs_buf_) {
        if (!c.hashes.empty()) {
            merged.insert(merged.end(), c.hashes.begin(), c.hashes.end());
        }
    }
    if (!merged.empty()) {
        std::sort(merged.begin(), merged.end());
        merged.erase(std::unique(merged.begin(), merged.end()), merged.end());
    }
    out.new_signal_hashes = std::move(merged);

    std::vector<std::uint64_t> novel;
    for (const auto& c : contribs_buf_) {
        if (!c.novel_hashes.empty()) {
            novel.insert(novel.end(), c.novel_hashes.begin(), c.novel_hashes.end());
        }
    }
    if (!novel.empty()) {
        std::sort(novel.begin(), novel.end());
        novel.erase(std::unique(novel.begin(), novel.end()), novel.end());
    }
    out.novel_signal_hashes = std::move(novel);

    return out;
}

} // namespace refuzz::fuzzer

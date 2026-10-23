// Copyright 2026 reFuzz project author -------youngkk.
//
// IFeedbackAggregator — 把 N 个 SignalContribution 合并为一个 CompositeScore。
//
// Aggregator 是新设计中**唯一**理解"哪种信号该如何参与最终决策"的地方。
// 同一组信号在不同 aggregator 下可以表现完全不同的策略
// （coverage_guided / blackbox / weighted_or / ...）。

#pragma once

#include "refuzz/core/channel_contract.hpp"
#include "refuzz/fuzzer/feedback_verdict.hpp"   // SeedDisposition + Verdict(=CompositeScore)
#include "refuzz/feedback/signal/signal.hpp"
#include "refuzz/proto_domain/combined_crash_event.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <string>

namespace refuzz::fuzzer {

// [verdict 下沉 — PR1] CompositeScore 结构已搬到 core/fuzzer/feedback_verdict.hpp
// 并改名 Verdict。此处留 alias 让 aggregator/dispatcher 现有代码不动即可编译;
// PR2 删除别名,全量改用 Verdict。
using CompositeScore = Verdict;

class IFeedbackAggregator {
public:
    virtual ~IFeedbackAggregator() = default;

    virtual std::string Id() const = 0;

    // 输入：本次事件 + 所有信号贡献（顺序与 engine 注册顺序一致）。
    virtual CompositeScore Aggregate(const refuzz::core::channel_contract::ChannelEvent& event,
                                     std::span<const SignalContribution> contribs) = 0;
};

} // namespace refuzz::fuzzer

// Copyright 2026 reFuzz project author -------youngkk.
//
// BlackboxAggregator — 忽略覆盖类信号的黑盒聚合策略。
//
// 与旧 NullFeedbackEngine 的判定语义严格等价：
//   1. 完全忽略 kCoverage / kComparison 信号
//   2. 任一 kFault 信号 fired → is_crash + 透传 crash_payload
//   3. exec_code == kOk → 不标 interesting（dispatcher 决定是否盲目 admit）
//   4. exec_code == kTimeout / kExecError → 标记但不入库

#pragma once

#include "refuzz/feedback/aggregator/feedback_aggregator.hpp"

namespace refuzz::fuzzer {

class BlackboxAggregator final : public IFeedbackAggregator {
public:
    std::string Id() const override { return "blackbox"; }

    CompositeScore Aggregate(const refuzz::core::channel_contract::ChannelEvent& event,
                             std::span<const SignalContribution> contribs) override;
};

} // namespace refuzz::fuzzer

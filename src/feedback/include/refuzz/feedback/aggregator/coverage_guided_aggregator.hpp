// Copyright 2026 reFuzz project author -------youngkk.
//
// CoverageGuidedAggregator — 标准覆盖引导聚合策略。
//
// 与旧 KcovFeedbackEngine 的判定语义严格等价：
//   1. 任一 kCoverage / kComparison 信号 magnitude>0 → interesting + Promote
//   2. 任一 kFault / kSanitizer 信号 fired → is_crash + 透传 crash_payload
//   3. exec_code == kTimeout / kExecError → Demote, 不入库
//   4. malformed coverage / empty coverage → 标记但不 admit

#pragma once

#include "refuzz/feedback/aggregator/feedback_aggregator.hpp"

namespace refuzz::fuzzer {

class CoverageGuidedAggregator final : public IFeedbackAggregator {
public:
    std::string Id() const override { return "coverage_guided"; }

    CompositeScore Aggregate(const refuzz::core::channel_contract::ChannelEvent& event,
                             std::span<const SignalContribution> contribs) override;
};

} // namespace refuzz::fuzzer

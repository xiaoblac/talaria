// Copyright 2026 reFuzz project author -------youngkk.
//
// WeightedOrAggregator — 按 signal_id → weight 表加权累加 magnitude，
// 总分超阈值 → interesting。
//
// 用于多信号联合判定的可调实验场景（例如 cov×权重 + cmp×权重 综合采纳）。

#pragma once

#include "refuzz/feedback/aggregator/feedback_aggregator.hpp"

#include <string>
#include <unordered_map>

namespace refuzz::fuzzer {

class WeightedOrAggregator final : public IFeedbackAggregator {
public:
    WeightedOrAggregator(std::unordered_map<std::string, double> weights,
                         double interesting_threshold);

    std::string Id() const override { return "weighted_or"; }

    CompositeScore Aggregate(const refuzz::core::channel_contract::ChannelEvent& event,
                             std::span<const SignalContribution> contribs) override;

private:
    std::unordered_map<std::string, double> weights_;
    double threshold_ = 0.0;
};

} // namespace refuzz::fuzzer

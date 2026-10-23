// Copyright 2026 reFuzz project author -------youngkk.
//
// AggregatorCatalog — IFeedbackAggregator 工厂注册表。

#pragma once

#include "refuzz/catalog/typed_catalog.hpp"
#include "refuzz/feedback/aggregator/feedback_aggregator.hpp"

#include <string>
#include <unordered_map>

namespace refuzz::fuzzer {

struct AggregatorTraits {
    using Product = IFeedbackAggregator;

    struct BuildContext {
        // 多数 aggregator 无依赖；weighted_or 需要权重表
        std::unordered_map<std::string, double> signal_weights;
        double interesting_threshold = 0.0;
    };
};

using AggregatorCatalog = refuzz::catalog::TypedCatalog<AggregatorTraits>;

void RegisterBuiltinAggregators(AggregatorCatalog& catalog);

} // namespace refuzz::fuzzer

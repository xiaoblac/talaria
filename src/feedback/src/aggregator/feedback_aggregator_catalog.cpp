// Copyright 2026 reFuzz project author -------youngkk.

#include "refuzz/feedback/aggregator/feedback_aggregator_catalog.hpp"

#include "refuzz/feedback/aggregator/blackbox_aggregator.hpp"
#include "refuzz/feedback/aggregator/coverage_guided_aggregator.hpp"
#include "refuzz/feedback/aggregator/weighted_or_aggregator.hpp"

namespace refuzz::fuzzer {

namespace {

using Entry = AggregatorCatalog::Entry;

Entry MakeCoverageGuidedEntry()
{
    Entry entry;
    entry.meta = {"coverage_guided", "Coverage Guided Aggregator",
                  "Accept by cov_gain > 0; crash/timeout/exec_error passthrough."};
    entry.build = [](const AggregatorTraits::BuildContext&)
        -> core::Result<std::unique_ptr<IFeedbackAggregator>> {
        return std::make_unique<CoverageGuidedAggregator>();
    };
    return entry;
}

Entry MakeBlackboxEntry()
{
    Entry entry;
    entry.meta = {"blackbox", "Blackbox Aggregator",
                  "Ignore coverage signals; only propagate crash/exec classification."};
    entry.build = [](const AggregatorTraits::BuildContext&)
        -> core::Result<std::unique_ptr<IFeedbackAggregator>> {
        return std::make_unique<BlackboxAggregator>();
    };
    return entry;
}

Entry MakeWeightedOrEntry()
{
    Entry entry;
    entry.meta = {"weighted_or", "Weighted-OR Aggregator",
                  "Sum weighted magnitudes across signals; admit when sum > threshold."};
    entry.build = [](const AggregatorTraits::BuildContext& ctx)
        -> core::Result<std::unique_ptr<IFeedbackAggregator>> {
        return std::make_unique<WeightedOrAggregator>(ctx.signal_weights,
                                                      ctx.interesting_threshold);
    };
    return entry;
}

} // namespace

void RegisterBuiltinAggregators(AggregatorCatalog& catalog)
{
    catalog.Register(MakeCoverageGuidedEntry());
    catalog.Register(MakeBlackboxEntry());
    catalog.Register(MakeWeightedOrEntry());
}

} // namespace refuzz::fuzzer

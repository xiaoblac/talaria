// Copyright 2026 reFuzz project author -------youngkk.
//
// SignalCatalog — feedback signal 工厂注册表。
//
// 由 Assembler 构造并填充；CompositeFeedbackEngine 装配阶段按 id 取信号实例。

#pragma once

#include "refuzz/catalog/typed_catalog.hpp"
// [v1 — REMOVED in PR-K-0; ICoverageSink no longer referenced]
// #include "refuzz/core/coverage.hpp"
#include "refuzz/feedback/feedback_codec.hpp"
#include "refuzz/feedback/signal/signal.hpp"

namespace refuzz::fuzzer {

class IFeedbackStore;
class IPriorityCalculator;  // [v2 batch 3 PR-Y]
class ISaturationFilter;    // [v2 batch 3 G5]

struct SignalTraits {
    using Product = ISignal;

    struct BuildContext {
        IFeedbackStore*             feedback_store  = nullptr;  // 覆盖类信号去重 (kcov_pc)
        // [v1 coverage_sink — ROLLBACK: uncomment]
        // core::ICoverageSink*        coverage_sink   = nullptr;  // 覆盖外溢
        // [v2 PR-K-0 — sink removed per Rule A; see kcov-coverage-curve.md §4.2]
        // [v2 Epic 5 PR-5-B] cmp dedupe truth-store — separate HashFeedbackStore
        // instance from `feedback_store` per Epic 5 plan §3 D-9 / Q3 decision.
        // Orchestrator constructs both; nullptr is allowed for non-cmp engines
        // (KcovCmpSignal::Sample then degrades to fired=false).
        IFeedbackStore*             cmp_feedback_store = nullptr;
        CoverageNormalizationConfig coverage_config{};
        // [v2 batch 3 PR-Y] PriorityCalculator — KcovCoverageSignal 必需(catalog
        // 的 MakeKcovCoverageEntry 在 nullptr 时 fail-loud);其它 signal(eg.
        // KcovCmpSignal、ExecResultSignal、FaultSignal)忽略此字段(MakeKcovCmpEntry
        // 等不校验)。
        IPriorityCalculator*        priority_calculator = nullptr;
        // [v2 batch 3 G5] SaturationFilter — 同 PR-Y pattern。KcovCoverageSignal
        // 必需(catalog nullptr fail-loud);其它 signal 忽略。
        ISaturationFilter*          saturation_filter   = nullptr;
    };
};

using SignalCatalog = refuzz::catalog::TypedCatalog<SignalTraits>;

// 内置信号注册（exec_result / fault / kcov_coverage / kcov_cmp）。
void RegisterBuiltinSignals(SignalCatalog& catalog);

} // namespace refuzz::fuzzer

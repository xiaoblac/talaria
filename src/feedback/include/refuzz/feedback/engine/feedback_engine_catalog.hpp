// Copyright 2026 reFuzz project author -------youngkk.
//
// FeedbackEngineCatalog + FeedbackEngineSpec — engine 命名组合的注册表。
//
// Engine 在新设计中只是"信号集合 + aggregator + dispatcher"的声明性组合。
// 命名 engine（如 "kernel_kcov" / "null"）在此 catalog 注册；
// 临时 ad-hoc engine 由前端构造 FeedbackEngineSpec 直接喂给 BuildFromSpec。

#pragma once

#include "refuzz/catalog/typed_catalog.hpp"
// [v1 — REMOVED in PR-K-0; ICoverageSink no longer referenced]
// #include "refuzz/core/coverage.hpp"
#include "refuzz/feedback/aggregator/feedback_aggregator_catalog.hpp"
#include "refuzz/feedback/feedback_codec.hpp"
#include "refuzz/feedback/feedback_engine.hpp"
#include "refuzz/feedback/signal/feedback_signal_catalog.hpp"

#include <memory>
#include <string>
#include <vector>

namespace refuzz::fuzzer {

class IFeedbackStore;
class IPriorityCalculator;  // [v2 batch 3 PR-Y]
class ISaturationFilter;    // [v2 batch 3 G5]

// FeedbackEngineSpec — 描述一个 engine 由哪些子组件组合而成。
struct FeedbackEngineSpec {
    std::string                 engine_id;          // 命名 engine 的唯一 id
    std::vector<std::string>    signal_ids;         // 顺序敏感（决定 contribs 顺序）
    std::string                 aggregator_id;
    // [verdict 重构] dispatcher_id 已删除:准入行为现由 corpus admit-mode 决定,
    // 与 engine 选择解耦(见 CorpusManager::AdmitMode)。
    AggregatorTraits::BuildContext aggregator_ctx;  // weighted_or 等用得上
};

struct FeedbackEngineTraits {
    using Product = IFeedbackEngine;

    // Engine 构造上下文。不包含 FeedbackEngineSpec —— 命名 engine 的 spec
    // 由 catalog entry 的 build lambda 闭包捕获 (见 MakeSpecEntry);
    // ad-hoc 模式由调用方直接调用 BuildFromSpec(ctx, external_spec),
    // 不经 catalog 入口。两条路径合并在 BuildFromSpec 里实现。
    struct BuildContext {
        // [verdict 重构] 两个子 catalog 必须就位(dispatcher catalog 已删)
        const SignalCatalog*     signals      = nullptr;
        const AggregatorCatalog* aggregators  = nullptr;

        // 信号构造时的横切依赖
        IFeedbackStore*             feedback_store  = nullptr;
        // [v1 coverage_sink — ROLLBACK: uncomment]
        // core::ICoverageSink*        coverage_sink   = nullptr;
        // [v2 PR-K-0 — sink removed per Rule A; see kcov-coverage-curve.md §4.2]
        // [v2 Epic 5 PR-5-B] cmp dedupe truth-store — separate HashFeedbackStore
        // instance from `feedback_store` per Epic 5 plan §3 D-9 / Q3 decision.
        // Forwarded into SignalTraits::BuildContext::cmp_feedback_store.
        IFeedbackStore*             cmp_feedback_store = nullptr;
        CoverageNormalizationConfig coverage_config{};
        // [v2 batch 3 PR-Y] PriorityCalculator — KcovCoverageSignal 必需(catalog
        // 在 nullptr 时 fail-loud);其它 signal(eg. KcovCmpSignal)忽略此字段。
        // Assembler 装 FeedbackEngine 时填 bundle.priority_calculator.get()。
        IPriorityCalculator*        priority_calculator = nullptr;
        // [v2 batch 3 G5] SaturationFilter — 同 PR-Y pattern;Assembler 填
        // bundle.saturation_filter.get()。
        ISaturationFilter*          saturation_filter   = nullptr;
    };
};

using FeedbackEngineCatalog = refuzz::catalog::TypedCatalog<FeedbackEngineTraits>;

// 公共组装函数：按 spec 从三个子 catalog 拼装一个 CompositeFeedbackEngine。
// 两条装配路径都经过它：
//   1. 命名 engine: catalog entry 的 build lambda 调用 BuildFromSpec(ctx, fixed_spec)
//   2. Ad-hoc engine: Assembler 根据 ResolvedPlan::ad_hoc_feedback_spec
//      直接调用 BuildFromSpec(ctx, *spec)
// 失败原因(信号/聚合/分发未注册等)以 ComponentError 形式返回。
core::Result<std::unique_ptr<IFeedbackEngine>>
BuildFromSpec(const FeedbackEngineTraits::BuildContext& ctx,
              const FeedbackEngineSpec& spec);

// 内置 engine 注册（kernel_kcov / null / kernel_kcov_cmp）。
void RegisterBuiltinFeedbackEngines(FeedbackEngineCatalog& catalog);

} // namespace refuzz::fuzzer

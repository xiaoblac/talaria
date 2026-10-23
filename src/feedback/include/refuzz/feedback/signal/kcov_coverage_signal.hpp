// Copyright 2026 reFuzz project author -------youngkk.
//
// KcovCoverageSignal — kcov PC trace 覆盖类信号。
//
// 旧 CoverageFeedbackCodec + CoverageObserver + CoverageEvaluator 的合并产物。
// 内部持有 CoverageFeedbackCodec 做解码，引用外部 IFeedbackStore 做去重。
//
// [v2 PR-K-0 — ICoverageSink/sink 入参已移除] 见
// docs/plans/kcov-coverage-curve.md §4.2 (Rule A: telemetry 不再持有
// 覆盖 hash truth-store)。HashFeedbackStore 是聚合 hash 的唯一来源,
// 持久化由 orchestrator Stop 时的 SaveToFile 负责。

#pragma once

#include "refuzz/feedback/feedback_codec.hpp"
#include "refuzz/feedback/signal/signal.hpp"

// [v1 — REMOVED in PR-K-0; ICoverageSink no longer referenced]
// ROLLBACK: uncomment include + restore sink parameter + sink_ member.
// #include "refuzz/core/coverage.hpp"

namespace refuzz::fuzzer {

struct KernelExecutionObservation;
class IFeedbackStore;
class IPriorityCalculator;  // [v2 batch 3 PR-Y]
class ISaturationFilter;    // [v2 batch 3 G5]

} // namespace refuzz::fuzzer

namespace refuzz::program::syz {
class Prog;
} // namespace refuzz::program::syz

namespace refuzz::fuzzer {

class KcovCoverageSignal final : public ISignal {
public:
    // [v1 KcovCoverageSignal ctor without priority_calculator — ROLLBACK:
    //  uncomment v1 + remove v2;catalog MakeKcovCoverageEntry 同步还原]
    // KcovCoverageSignal(IFeedbackStore& store,
    //                    CoverageNormalizationConfig config = {});
    //
    // [v1 PR-Y ctor (no saturation_filter) — ROLLBACK: uncomment + 移除下面 v2 G5;
    //  catalog MakeKcovCoverageEntry 同步还原]
    // KcovCoverageSignal(IFeedbackStore& store,
    //                    const IPriorityCalculator& priority_calculator,
    //                    CoverageNormalizationConfig config = {});
    //
    // [v2 batch 3 G5] +ISaturationFilter& 参数(non-null contract,catalog
    // MakeKcovCoverageEntry 已 fail-loud nullptr)。Sample 内部按 plan §3.G5
    // pipeline:Extract → build observation → saturation gate → byte-equal
    // (no drop) 或 filtered union(部分/全 drop)→ store.MergeCoverage。
    KcovCoverageSignal(IFeedbackStore& store,
                       const IPriorityCalculator& priority_calculator,
                       ISaturationFilter& saturation_filter,
                       CoverageNormalizationConfig config = {});

    std::string Id() const override   { return "kcov_coverage"; }
    SignalKind  Kind() const override { return SignalKind::kCoverage; }

    SignalContribution Sample(const refuzz::core::channel_contract::ChannelEvent& event) override;

private:
    IFeedbackStore&            store_;
    // [v2 batch 3 PR-Y] PriorityCalculator(non-null,catalog 已 fail-loud)。
    const IPriorityCalculator& priority_calculator_;
    // [v2 batch 3 G5] SaturationFilter(non-null,catalog 已 fail-loud)。
    // 注意:filter 是 stateful(per-syscall counter),Sample 调 Filter() 修改
    // 内部 state — 因此**不能**是 const&。
    ISaturationFilter&         saturation_filter_;
    // [v1 sink_ member — ROLLBACK: uncomment]
    // core::ICoverageSink*   sink_ = nullptr;
    CoverageFeedbackCodec      codec_;

    // PC mode and edge mode both use the full IFeedbackStore as the host-side
    // max-signal truth store. cover_edges changes the signal unit fed to the
    // store (per-call edge hashes instead of raw PCs), not the store semantics.
};

} // namespace refuzz::fuzzer

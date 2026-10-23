// Copyright 2026 reFuzz project author -------youngkk.

#include "refuzz/feedback/engine/feedback_engine_catalog.hpp"

#include "refuzz/feedback/engine/composite_feedback_engine.hpp"

#include <utility>

namespace refuzz::fuzzer {

namespace {

using FeedbackEntry = FeedbackEngineCatalog::Entry;

// 构造 SignalCatalog::BuildContext。
SignalTraits::BuildContext MakeSignalCtx(const FeedbackEngineTraits::BuildContext& ctx)
{
    SignalTraits::BuildContext out;
    out.feedback_store  = ctx.feedback_store;
    // [v1 sink propagation — ROLLBACK: uncomment]
    // out.coverage_sink   = ctx.coverage_sink;
    // [v2 PR-K-0 — sink dropped from BuildContext]
    // [v2 Epic 5 PR-5-B] forward cmp_feedback_store so KcovCmpSignal sees
    // its own dedupe instance.
    out.cmp_feedback_store = ctx.cmp_feedback_store;
    out.coverage_config = ctx.coverage_config;
    // [v2 batch 3 PR-Y] forward priority_calculator so KcovCoverageSignal can
    // get the SyzkallerPriorityCalculator instance from AssembledBundle.
    out.priority_calculator = ctx.priority_calculator;
    // [v2 batch 3 G5] forward saturation_filter so KcovCoverageSignal can
    // get the KernelCoverageSaturationFilter instance from AssembledBundle.
    out.saturation_filter   = ctx.saturation_filter;
    return out;
}

FeedbackEntry MakeSpecEntry(const FeedbackEngineSpec& fixed_spec,
                            const std::string& display_name,
                            const std::string& description)
{
    FeedbackEntry entry;
    entry.meta = {fixed_spec.engine_id, display_name, description};
    entry.build = [fixed_spec](const FeedbackEngineTraits::BuildContext& ctx)
        -> core::Result<std::unique_ptr<IFeedbackEngine>> {
        return BuildFromSpec(ctx, fixed_spec);
    };
    return entry;
}

} // namespace

core::Result<std::unique_ptr<IFeedbackEngine>>
BuildFromSpec(const FeedbackEngineTraits::BuildContext& ctx,
              const FeedbackEngineSpec& spec)
{
    if (ctx.signals == nullptr || ctx.aggregators == nullptr) {
        return std::unexpected(core::ComponentError::Config(
            "feedback_engine",
            "signals / aggregators catalog must both be provided"));
    }
    if (spec.signal_ids.empty()) {
        return std::unexpected(core::ComponentError::Config(
            spec.engine_id.empty() ? "feedback_engine" : spec.engine_id,
            "spec.signal_ids must not be empty"));
    }

    auto engine = std::make_unique<CompositeFeedbackEngine>(
        spec.engine_id.empty() ? std::string{"unnamed"} : spec.engine_id);

    const auto sig_ctx = MakeSignalCtx(ctx);
    for (const auto& sig_id : spec.signal_ids) {
        auto r = ctx.signals->Build(sig_id, sig_ctx);
        if (!r.has_value()) {
            return std::unexpected(r.error());
        }
        engine->AddSignal(std::move(*r));
    }

    {
        auto r = ctx.aggregators->Build(spec.aggregator_id, spec.aggregator_ctx);
        if (!r.has_value()) {
            return std::unexpected(r.error());
        }
        engine->SetAggregator(std::move(*r));
    }

    // [verdict 重构] 不再装配 dispatcher;engine 只产 verdict,actuation 归 control loop。
    return std::unique_ptr<IFeedbackEngine>(std::move(engine));
}

void RegisterBuiltinFeedbackEngines(FeedbackEngineCatalog& catalog)
{
    // kernel_kcov : exec_result + fault + kcov_coverage, coverage_guided + corpus_admit
    {
        FeedbackEngineSpec spec;
        spec.engine_id     = "kernel_kcov";
        spec.signal_ids    = {"exec_result", "fault", "kcov_coverage"};
        spec.aggregator_id = "coverage_guided";
        catalog.Register(MakeSpecEntry(
            spec, "Kernel KCOV Engine",
            "exec_result + fault + kcov_coverage, coverage-guided admit."));
    }

    // xiuos_kcov : XiUOS UART backend — coverage (256B path bitmap) + the
    // per-program invariant oracle (heap/state corruption + leak), coverage-
    // guided admit. Mirrors kernel_kcov with XiUOS-native signals; the oracle's
    // crash_payload flows the same aggregator → crash_dispatch path.
    // [轴B wedge harvest 2026-05-29] "fault" 必须在列:它的 FaultSignal 把 ABNORMAL
    // completion(kTimeout=worker wedge / kExecError / kWorkerSignaled)经
    // BuildCombinedFromAbnormal 转成 crash_payload → crash_pipeline → exec_timeout
    // bucket。缺它则 XiUOS 的 CHECK-spin wedge(如 CA_INIT(0,0))永远不落 finding
    // (oracle 只管 COMPLETION,管不到没回结果的 wedge)。kernel_kcov 一直有 fault。
    {
        FeedbackEngineSpec spec;
        spec.engine_id     = "xiuos_kcov";
        // [State coverage 2026-05-29] xiuos_state_coverage = second coverage dimension
        // (joint-hash of peak live-object-count features) to escape PC-coverage
        // saturation (interesting froze at 69 / corpus stopped growing in the 9h run).
        // A program is interesting on (new PC) OR (new state) → admit + promote.
        // [State coverage §8.1] xiuos_call_transition = call-graph edge coverage
        // (ordering dimension) added alongside state-coverage; MVP count-features
        // re-saturated, edges give a ~|API|^2 gradient. interesting on new PC OR
        // new state-config OR new call-edge.
        spec.signal_ids    = {"exec_result", "fault", "xiuos_coverage",
                              "xiuos_state_coverage", "xiuos_call_transition",
                              "xiuos_oracle"};
        spec.aggregator_id = "coverage_guided";
        catalog.Register(MakeSpecEntry(
            spec, "XiUOS KCOV+Oracle Engine",
            "exec_result + fault + xiuos_coverage + xiuos_state_coverage + "
            "xiuos_call_transition + xiuos_oracle, coverage-guided admit."));
    }

    // null : exec_result + fault, blackbox + corpus_admit_all
    {
        FeedbackEngineSpec spec;
        spec.engine_id     = "null";
        spec.signal_ids    = {"exec_result", "fault"};
        spec.aggregator_id = "blackbox";
        catalog.Register(MakeSpecEntry(
            spec, "Null (Blackbox) Engine",
            "No coverage; admit any non-abnormal seed; scheduler neutral."));
    }

    // kernel_kcov_cmp : exec_result + fault + kcov_coverage + kcov_cmp,
    //                   coverage_guided + corpus_admit
    {
        FeedbackEngineSpec spec;
        spec.engine_id     = "kernel_kcov_cmp";
        spec.signal_ids    = {"exec_result", "fault", "kcov_coverage", "kcov_cmp"};
        spec.aggregator_id = "coverage_guided";
        catalog.Register(MakeSpecEntry(
            spec, "Kernel KCOV+CMP Engine",
            "Coverage + comparison signals with coverage-guided admit."));
    }
}

} // namespace refuzz::fuzzer

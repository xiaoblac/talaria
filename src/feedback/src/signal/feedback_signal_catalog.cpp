// Copyright 2026 reFuzz project author -------youngkk.

#include "refuzz/feedback/signal/feedback_signal_catalog.hpp"

#include "refuzz/feedback/signal/exec_result_signal.hpp"
#include "refuzz/feedback/signal/fault_signal.hpp"
#include "refuzz/feedback/signal/kcov_cmp_signal.hpp"
#include "refuzz/feedback/signal/kcov_coverage_signal.hpp"
#include "refuzz/feedback/signal/xiuos_coverage_signal.hpp"
#include "refuzz/feedback/signal/xiuos_state_coverage_signal.hpp"
#include "refuzz/feedback/signal/xiuos_call_transition_signal.hpp"
#include "refuzz/feedback/signal/xiuos_oracle_signal.hpp"

namespace refuzz::fuzzer {

namespace {

using SignalEntry = SignalCatalog::Entry;

SignalEntry MakeExecResultEntry()
{
    SignalEntry entry;
    entry.meta = {"exec_result", "Exec Result Signal",
                  "Map ChannelEvent type to proto::ResultCode + exec flags."};
    entry.build = [](const SignalTraits::BuildContext&)
        -> core::Result<std::unique_ptr<ISignal>> {
        return std::make_unique<ExecResultSignal>();
    };
    return entry;
}

SignalEntry MakeFaultEntry()
{
    SignalEntry entry;
    entry.meta = {"fault", "Fault Signal",
                  "Build CombinedCrashEvent from Fault / AbnormalCompletion events."};
    entry.build = [](const SignalTraits::BuildContext&)
        -> core::Result<std::unique_ptr<ISignal>> {
        return std::make_unique<FaultSignal>();
    };
    return entry;
}

SignalEntry MakeKcovCoverageEntry()
{
    SignalEntry entry;
    // [v1 meta string — ROLLBACK: uncomment]
    // entry.meta = {"kcov_coverage", "KCOV Coverage Signal",
    //               "Decode kcov_trace_pc output, merge into feedback store, optional sink."};
    // [v2 PR-K-0 — sink path removed]
    entry.meta = {"kcov_coverage", "KCOV Coverage Signal",
                  "Decode kcov_trace_pc output, merge into feedback store."};
    entry.build = [](const SignalTraits::BuildContext& ctx)
        -> core::Result<std::unique_ptr<ISignal>> {
        if (ctx.feedback_store == nullptr) {
            return std::unexpected(core::ComponentError::Config(
                "kcov_coverage", "feedback_store is required"));
        }
        // [v2 batch 3 PR-Y B3] priority_calculator 必需 — Assembler PR-W1 fail-loud
        // 已确保 bundle 装配阶段 priority_calculator 不可能为空,但 catalog 直接被
        // 误用(不经 Assembler)时仍要 fail-loud 而非 silent degrade。
        if (ctx.priority_calculator == nullptr) {
            return std::unexpected(core::ComponentError::Config(
                "kcov_coverage", "priority_calculator is required (PR-Y)"));
        }
        // [v2 batch 3 G5] saturation_filter 必需 — 同 PR-Y B3 模板 fail-loud。
        if (ctx.saturation_filter == nullptr) {
            return std::unexpected(core::ComponentError::Config(
                "kcov_coverage", "saturation_filter is required (G5)"));
        }

        // [v2 batch 3 G5] +saturation_filter 参数(non-null contract,catalog 已 fail-loud)。
        return std::make_unique<KcovCoverageSignal>(*ctx.feedback_store,
                                                    *ctx.priority_calculator,
                                                    *ctx.saturation_filter,
                                                    ctx.coverage_config);
    };
    return entry;
}

SignalEntry MakeKcovCmpEntry()
{
    SignalEntry entry;

    // [v2 Epic 5 PR-5-B — real path]
    entry.meta = {"kcov_cmp", "KCOV Comparison Signal",
                  "Decode kcov_trace_cmp records, dedupe via cmp HashFeedbackStore."};
    entry.build = [](const SignalTraits::BuildContext& ctx)
        -> core::Result<std::unique_ptr<ISignal>> {
        // [v2 Epic 5 PR-5-B] use cmp-specific store (Q3 decision: separate
        // HashFeedbackStore instance). nullptr is tolerated — KcovCmpSignal
        // degrades to fired=false / magnitude=0.
        return std::make_unique<KcovCmpSignal>(ctx.cmp_feedback_store);
    };
    return entry;
}

SignalEntry MakeXiuosCoverageEntry()
{
    SignalEntry entry;
    entry.meta = {"xiuos_coverage", "XiUOS Coverage Signal",
                  "AFL log2-bucketize + global OR over the worker's 256B path "
                  "bitmap (XiUOS UART backend)."};
    entry.build = [](const SignalTraits::BuildContext&)
        -> core::Result<std::unique_ptr<ISignal>> {
        return std::make_unique<XiuosCoverageSignal>();
    };
    return entry;
}

SignalEntry MakeXiuosStateCoverageEntry()
{
    SignalEntry entry;
    entry.meta = {"xiuos_state_coverage", "XiUOS State/Interaction Coverage Signal",
                  "Second coverage dimension: joint-hash the worker's per-program "
                  "peak live-object-count features (RESULT v2 state region); a new "
                  "joint state → interesting. Escapes PC-coverage saturation."};
    entry.build = [](const SignalTraits::BuildContext&)
        -> core::Result<std::unique_ptr<ISignal>> {
        return std::make_unique<XiuosStateCoverageSignal>();
    };
    return entry;
}

SignalEntry MakeXiuosCallTransitionEntry()
{
    SignalEntry entry;
    entry.meta = {"xiuos_call_transition", "XiUOS Call-Transition Coverage Signal",
                  "Call-graph edge coverage over the program's API sequence "
                  "(new prev->cur bigram → interesting). ~|API|^2 ordering space; "
                  "host-side decode of program_payload, no worker change."};
    entry.build = [](const SignalTraits::BuildContext&)
        -> core::Result<std::unique_ptr<ISignal>> {
        return std::make_unique<XiuosCallTransitionSignal>();
    };
    return entry;
}

SignalEntry MakeXiuosOracleEntry()
{
    SignalEntry entry;
    entry.meta = {"xiuos_oracle", "XiUOS Per-Program Oracle Signal",
                  "Map the worker's per-program invariant verdict "
                  "(Completion vendor_status / vendor_flags) to a crash_payload "
                  "finding: heap/state corruption (hard) + leak (soft lead)."};
    entry.build = [](const SignalTraits::BuildContext&)
        -> core::Result<std::unique_ptr<ISignal>> {
        return std::make_unique<XiuosOracleSignal>();
    };
    return entry;
}

} // namespace

void RegisterBuiltinSignals(SignalCatalog& catalog)
{
    catalog.Register(MakeExecResultEntry());
    catalog.Register(MakeFaultEntry());
    catalog.Register(MakeKcovCoverageEntry());
    catalog.Register(MakeKcovCmpEntry());
    catalog.Register(MakeXiuosCoverageEntry());
    catalog.Register(MakeXiuosStateCoverageEntry());
    catalog.Register(MakeXiuosCallTransitionEntry());
    catalog.Register(MakeXiuosOracleEntry());
}

} // namespace refuzz::fuzzer

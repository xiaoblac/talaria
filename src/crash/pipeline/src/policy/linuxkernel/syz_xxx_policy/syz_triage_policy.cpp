#include "refuzz/crash/pipeline/policy/linuxkernel/syz_xxx_policy/syz_triage_policy.hpp"

#include <variant>

namespace refuzz::crash {

CrashPipelinePlan AllUniqueTriagePolicy::BuildPlan(
    const refuzz::proto::CombinedCrashEvent& /* event */) const
{
    return FullPipelinePlan();
}

CrashPipelinePlan HighSeverityTriagePolicy::BuildPlan(
    const refuzz::proto::CombinedCrashEvent& /* event */) const
{
    auto plan = FullPipelinePlan();
    auto& enqueue = std::get<EnqueueParams>(plan.back().params);
    enqueue.allowed_types = {
        refuzz::channel::CrashType::kKasan,
        refuzz::channel::CrashType::kPanic,
        refuzz::channel::CrashType::kBug,
    };
    enqueue.fallback_reason = ReproEligibility::kNotKernelCrash;
    return plan;
}

CrashPipelinePlan QuotaZeroTriagePolicy::BuildPlan(
    const refuzz::proto::CombinedCrashEvent& /* event */) const
{
    return NoEnqueuePipelinePlan();
}

CrashPipelinePlan ActionableFindingsTriagePolicy::BuildPlan(
    const refuzz::proto::CombinedCrashEvent& /* event */) const
{
    auto plan = FullPipelinePlan();
    auto& enqueue = std::get<EnqueueParams>(plan.back().params);
    // Replay-reproducible kinds: a genuine trap/death (the worker stops
    // returning RESULT) and a wedge (timeout-0 IPC blocks forever). These match
    // the XiUOS repro engine's CountsAsRepro = run.crashed || run.timed_out.
    enqueue.eligible_kinds = {
        CrashKind::kKernelCrash,
        CrashKind::kWorkerDead,
        CrashKind::kExecutionTimeout,
    };
    return plan;
}

} // namespace refuzz::crash

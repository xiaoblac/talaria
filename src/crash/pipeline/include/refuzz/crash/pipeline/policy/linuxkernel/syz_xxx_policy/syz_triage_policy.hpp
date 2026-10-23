#pragma once

#include "refuzz/crash/pipeline/core/policy.hpp"
#include "refuzz/channel/health/health_types.hpp"
#include "refuzz/crash/infra/crash_context.hpp"
#include "refuzz/proto_domain/combined_crash_event.hpp"

#include <cstdint>
#include <variant>
#include <vector>

namespace refuzz::crash {

enum class CrashPipelineOp : uint8_t {
    kBuildContext = 0,
    kParseAndClassify,
    kDedup,
    kPersist,
    kReport,
    kEnqueue,
};

struct BuildContextParams {};
struct ParseAndClassifyParams {};
struct DedupParams {};
struct PersistParams {};
struct ReportParams {};

enum class ReproEligibility : uint8_t {
    kEnqueue = 0,
    kNotKernelCrash,
    kDuplicate,
    kEmptyProgramLog,
    kSuppressed,
};

inline const char* ReproEligibilityName(ReproEligibility eligibility)
{
    switch (eligibility) {
    case ReproEligibility::kEnqueue:
        return "enqueue";
    case ReproEligibility::kNotKernelCrash:
        return "not_kernel_crash";
    case ReproEligibility::kDuplicate:
        return "duplicate";
    case ReproEligibility::kEmptyProgramLog:
        return "empty_program_log";
    case ReproEligibility::kSuppressed:
        return "suppressed";
    }
    return "unknown";
}

struct EnqueueParams {
    ReproEligibility fallback_reason = ReproEligibility::kEnqueue;
    bool require_kernel_crash = true;
    bool reject_duplicates = true;
    bool require_program_log = true;
    bool reject_suppressed = true;
    std::vector<refuzz::channel::CrashType> allowed_types;
    // Crash-kind eligibility (orthogonal to allowed_types, which gates on the
    // console CrashType). When non-empty it REPLACES the require_kernel_crash
    // check: an incident is enqueued only if its crash_kind ∈ eligible_kinds.
    // Empty → legacy require_kernel_crash behaviour ({kKernelCrash}). Targets
    // whose primary findings are wedges/worker-deaths (XiUOS) set this so those
    // reproducible incidents reach the repro queue.
    std::vector<CrashKind> eligible_kinds;
};

using CrashPipelineParams = std::variant<
    BuildContextParams,
    ParseAndClassifyParams,
    DedupParams,
    PersistParams,
    ReportParams,
    EnqueueParams>;

struct CrashPipelineNode {
    CrashPipelineOp op;
    CrashPipelineParams params;
};

using CrashPipelinePlan = std::vector<CrashPipelineNode>;

class ISyzTriagePolicy : public IPolicy {
public:
    ~ISyzTriagePolicy() override = default;
    virtual CrashPipelinePlan BuildPlan(const refuzz::proto::CombinedCrashEvent& event) const = 0;
    virtual void OnActivated() {}
};

class AllUniqueTriagePolicy final : public ISyzTriagePolicy {
public:
    CrashPipelinePlan BuildPlan(const refuzz::proto::CombinedCrashEvent& event) const override;
};

class HighSeverityTriagePolicy final : public ISyzTriagePolicy {
public:
    CrashPipelinePlan BuildPlan(const refuzz::proto::CombinedCrashEvent& event) const override;
};

class QuotaZeroTriagePolicy final : public ISyzTriagePolicy {
public:
    CrashPipelinePlan BuildPlan(const refuzz::proto::CombinedCrashEvent& event) const override;
};

// Enqueue every actionable, replay-reproducible finding — genuine crashes
// (kKernelCrash/kWorkerDead) AND wedges (kExecutionTimeout) — not just kernel
// panics. Targets whose dominant findings are wedges/worker-deaths (e.g. the
// XiUOS app-surface worker, whose timeout-0 IPC ops wedge deterministically)
// select this so those incidents reach the repro pipeline.
class ActionableFindingsTriagePolicy final : public ISyzTriagePolicy {
public:
    CrashPipelinePlan BuildPlan(const refuzz::proto::CombinedCrashEvent& event) const override;
};

inline CrashPipelinePlan FullPipelinePlan()
{
    return {
        {CrashPipelineOp::kBuildContext, BuildContextParams{}},
        {CrashPipelineOp::kParseAndClassify, ParseAndClassifyParams{}},
        {CrashPipelineOp::kDedup, DedupParams{}},
        {CrashPipelineOp::kPersist, PersistParams{}},
        {CrashPipelineOp::kReport, ReportParams{}},
        {CrashPipelineOp::kEnqueue, EnqueueParams{}},
    };
}

inline CrashPipelinePlan NoEnqueuePipelinePlan()
{
    return {
        {CrashPipelineOp::kBuildContext, BuildContextParams{}},
        {CrashPipelineOp::kParseAndClassify, ParseAndClassifyParams{}},
        {CrashPipelineOp::kDedup, DedupParams{}},
        {CrashPipelineOp::kPersist, PersistParams{}},
        {CrashPipelineOp::kReport, ReportParams{}},
    };
}

} // namespace refuzz::crash

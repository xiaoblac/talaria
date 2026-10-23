// [XiUOS leak 一等公民化 Phase 1]
//
// XiUOS-owned crash-pipeline ops. See header for the rationale: XiUOS is a
// first-class family with its OWN classification/routing op, registered through
// the same CrashPipelineRegistry/ICrashPipelineOp interface as syz — no silos,
// no `if(target==xiuos)` in the syz ops.

#include "refuzz/crash/pipeline/ops/xiuos/xiuos_pipeline_ops.hpp"

#include "refuzz/crash/pipeline/ops/linuxkernel/syz_ops/syz_pipeline_ops.hpp"

#include <chrono>
#include <string>
#include <utility>

namespace refuzz::crash {
namespace {

// Target-agnostic mappers (local to keep XiuosBuildContextOp self-contained).
CrashContext::ProgramEntry ToProgramEntry(const refuzz::proto::FrozenProgramEntry& entry)
{
    CrashContext::ProgramEntry program;
    program.executor_id = entry.executor_id;
    program.seed_id = entry.seed_id;
    program.origin_seed_id = entry.origin_seed_id;
    program.payload = entry.program_payload;
    program.submit_ts_us = entry.submit_ts_us;
    program.has_completed_result = entry.completion.has_value();
    if (entry.completion.has_value()) {
        program.worker_id = entry.completion->worker_id;
        program.output = entry.completion->output;
        program.start_ts_us = entry.completion->start_ts_us;
        program.finish_ts_us = entry.completion->finish_ts_us;
        program.result_code = entry.completion->result_code;
        program.infra_error = entry.completion->infra_error;
        program.crash_signal = entry.completion->crash_signal;
        program.leak_bytes = entry.completion->leak_bytes;
        // [XiUOS leak 一等公民化 Phase 5] resource-residue carrier (parallel to leak_bytes).
        program.resource_residue = entry.completion->resource_residue;
        program.coverage_hashes = entry.completion->coverage_hashes;
    }
    return program;
}

// XiuosBuildContextOp — the ONE XiUOS-specific op. Routes a XiUOS finding by
// XiUOS semantics:
//   * ResultCode::kResourceLeak  → CrashKind::kResourceLeak + leak title +
//     leak_bytes carrier (this is the headline of Phase 1).
//   * everything else            → the same routing the syz BuildContextOp uses
//     (fault reasons → kKernelCrash/kWorkerDead/kVmDead/...; kTimeout →
//     kExecutionTimeout; kExecError → kExecError) so XiUOS wedges/errors still
//     bucket correctly.
//
// It registers under CrashPipelineOp::kBuildContext (same op-kind contract as
// syz) but lives in the XiUOS engine's own registry — the manager builds one
// registry per engine, so the XiUOS slot resolves to this implementation.
class XiuosBuildContextOp final : public ICrashPipelineOp {
public:
    CrashPipelineOp Kind() const override
    {
        return CrashPipelineOp::kBuildContext;
    }

    void Execute(const refuzz::proto::CombinedCrashEvent& event,
                 CrashContext& ctx,
                 const CrashPipelineParams& params) override
    {
        (void)std::get<BuildContextParams>(params);

        CrashContext next;
        next.incident_id = event.incident_id;
        next.created_at = std::chrono::system_clock::now();
        // XiUOS UART worker has no sanitizer build; leave default kNone.

        for (const auto& entry : event.history) {
            next.program_log.push_back(ToProgramEntry(entry));
        }

        if (event.crash_program.has_value()) {
            next.program_log.push_back(ToProgramEntry(*event.crash_program));
            next.crash_program_index = static_cast<int32_t>(next.program_log.size() - 1);
            next.crash_signal = next.program_log.back().crash_signal;
            next.leak_bytes = next.program_log.back().leak_bytes;
            next.resource_residue = next.program_log.back().resource_residue;
        }

        if (event.fault_event.has_value()) {
            // XiUOS findings flow on the completion path (XiuosOracleSignal builds
            // a CombinedCrashEvent from a clean Completion). A fault_event means a
            // genuine infra fault on the XiUOS channel (worker dead / vm dead /
            // trap) — route it the same target-agnostic way syz does so XiUOS
            // wedges/aborts still bucket correctly.
            const auto& fault = *event.fault_event;
            next.console_log = fault.crash_console;
            next.raw_title = fault.crash_title;
            next.channel_id = fault.channel_id;
            next.slot_id = fault.slot_id;
            next.generation = fault.generation;
            next.fault_reason = fault.reason;
            next.fault_source = fault.source;
            next.fault_origin = fault.origin;

            if (!event.crash_program.has_value() && !fault.program_payload.empty()) {
                CrashContext::ProgramEntry pe;
                pe.executor_id = fault.executor_id;
                pe.payload = fault.program_payload;
                pe.submit_ts_us = fault.submit_ts_us;
                next.program_log.push_back(std::move(pe));
                next.crash_program_index = static_cast<int32_t>(next.program_log.size() - 1);
            }

            switch (fault.reason) {
            case refuzz::proto::FaultReason::kKernelCrash:
                next.crash_kind = CrashKind::kKernelCrash;
                break;
            case refuzz::proto::FaultReason::kNoOutput:
                next.crash_kind = CrashKind::kNoOutput;
                break;
            case refuzz::proto::FaultReason::kWorkerHeartbeatLost:
                next.crash_kind = CrashKind::kWorkerDead;
                break;
            case refuzz::proto::FaultReason::kVmDead:
                next.crash_kind = CrashKind::kVmDead;
                break;
            case refuzz::proto::FaultReason::kInflightStale:
                next.crash_kind = CrashKind::kExecutionTimeout;
                break;
            case refuzz::proto::FaultReason::kSubmitFailed:
                next.crash_kind = CrashKind::kExecError;
                break;
            case refuzz::proto::FaultReason::kGenerationReset:
                next.crash_kind = CrashKind::kUnknownIncident;
                break;
            case refuzz::proto::FaultReason::kAbnormalExit:
                next.crash_kind = CrashKind::kUnknownIncident;
                break;
            case refuzz::proto::FaultReason::kUnknown:
                next.crash_kind = CrashKind::kUnknownIncident;
                break;
            }
        } else if (event.crash_program.has_value() &&
                   event.crash_program->completion.has_value()) {
            const auto& result = *event.crash_program->completion;

            // [Contract oracle §3.1] semantic contract violation. crash_signal =
            // the wrong (non-EOK) return; resource_residue = (api_id<<8|call_index).
            // Decode into a human title; routes to its OWN contract_violation/ bucket.
            if (result.result_code == refuzz::proto::ResultCode::kContractViolation) {
                next.crash_kind = CrashKind::kContractViolation;
                next.crash_signal = result.crash_signal;
                const std::uint32_t enc  = result.resource_residue;
                const std::uint32_t api  = (enc >> 8) & 0xffu;
                const std::uint32_t call = enc & 0xffu;
                next.title = "contract violation: api=" + std::to_string(api) +
                             " call=" + std::to_string(call) + " ret=" +
                             std::to_string(static_cast<std::int32_t>(result.crash_signal));
            } else
            // [Priority-inversion detector] crash_signal = mutex slot;
            // resource_residue = (holder_prio<<8 | waiter_prio). Own bucket.
            if (result.result_code == refuzz::proto::ResultCode::kPriorityInversion) {
                next.crash_kind = CrashKind::kPriorityInversion;
                next.crash_signal = result.crash_signal;
                const std::uint32_t enc    = result.resource_residue;
                const std::uint32_t holder = (enc >> 8) & 0xffu;
                const std::uint32_t waiter = enc & 0xffu;
                next.title = "priority inversion: mutex=" +
                             std::to_string(result.crash_signal) + " holder=" +
                             std::to_string(holder) + " waiter=" + std::to_string(waiter);
            } else
            // [Stack-overflow detector] crash_signal = used bytes;
            // resource_residue = (task_slot<<16 | depth). task_slot 0xff = worker.
            if (result.result_code == refuzz::proto::ResultCode::kStackOverflow) {
                next.crash_kind = CrashKind::kStackOverflow;
                next.crash_signal = result.crash_signal;
                const std::uint32_t enc   = result.resource_residue;
                const std::uint32_t tslot = (enc >> 16) & 0xffffu;
                const std::uint32_t depth = enc & 0xffffu;
                const std::string who = (tslot == 0xffu) ? "worker" : std::to_string(tslot);
                next.title = "stack overflow: task=" + who + " used=" +
                             std::to_string(result.crash_signal) + "/" + std::to_string(depth);
            } else
            // [XiUOS leak 一等公民化 Phase 1] the headline route: a clean
            // completion that left a resource leak → its OWN kind + leak title +
            // magnitude. This is the only branch that distinguishes XiUOS from
            // the borrowed syz routing.
            if (result.result_code == refuzz::proto::ResultCode::kResourceLeak) {
                next.crash_kind = CrashKind::kResourceLeak;
                next.leak_bytes = result.leak_bytes;
                next.resource_residue = result.resource_residue;
                // crash_signal must be 0 for a leak — never conflate the
                // magnitude with a worker signal.
                next.crash_signal = 0;
                // [XiUOS leak 一等公民化 Phase 5] resource residue dominates the title
                // (it pinpoints the leaked kernel object class); a program may carry
                // both heap delta + residue, but the residue is the sharper label.
                if (result.resource_residue > 0) {
                    const std::uint32_t residue = result.resource_residue;
                    const std::uint32_t waitq  = residue & 0xffu;
                    const std::uint32_t victim = (residue >> 8) & 0xffu;
                    const std::uint32_t delay  = (residue >> 16) & 0xffu;
                    next.title = "resource leak: waitq=" + std::to_string(waitq) +
                                 " victim=" + std::to_string(victim) +
                                 " delay=" + std::to_string(delay);
                } else {
                    next.title =
                        "heap leak, " + std::to_string(result.leak_bytes) + " bytes";
                }
            } else if (result.result_code == refuzz::proto::ResultCode::kTimeout ||
                       result.infra_error == refuzz::proto::InfraError::kTimeout) {
                next.crash_kind = CrashKind::kExecutionTimeout;
            } else if (result.result_code == refuzz::proto::ResultCode::kExecError ||
                       result.infra_error == refuzz::proto::InfraError::kExecutorError ||
                       result.infra_error == refuzz::proto::InfraError::kInvalidInput ||
                       result.infra_error == refuzz::proto::InfraError::kOutputTooLarge) {
                next.crash_kind = CrashKind::kExecError;
            } else if (result.infra_error == refuzz::proto::InfraError::kWorkerCrashed) {
                // [Phase 2] Real trap / worker crash: a kWorkerSignaled/kWorkerCrashed
                // abnormal maps to BOTH result_code=kCrashed AND infra_error=
                // kWorkerCrashed (fault_signal MapAbnormalToResultCode). Must be
                // checked BEFORE the bare-kCrashed branch below — else traps (the
                // degenerate-arg crashers) get misrouted into state_violation.
                next.crash_kind = CrashKind::kKernelCrash;
            } else if (result.result_code == refuzz::proto::ResultCode::kCrashed) {
                // [Phase 2] XiUOS state-violation: the oracle's kCrashed with
                // infra_error=kNone — the worker's per-call heap/state integrity check
                // caught silent corruption (invariant code in crash_signal). A real
                // bug, distinct from a trap → own state_violation/ bucket.
                next.crash_kind = CrashKind::kStateViolation;
                next.title = "state violation: invariant " +
                             std::to_string(next.crash_signal);
            }

            // [#12 state_violation dedup] Dedup the SEMANTIC findings by their
            // root-cause title (invariant N / leak shape / api·call·ret / mutex·prios),
            // NOT by program payload. A non-empty parsed_report.title flips the
            // agnostic DedupOp's fold_payload OFF, so the dedup hash keys on the title
            // (via DedupDescription) instead of folding the payload — the 12870
            // payload-variants of one Class-B invariant collapse to ONE finding per
            // invariant (and leaks per shape, contract per api·ret, …). NOT applied to
            // kKernelCrash / kExecutionTimeout / kExecError (generic titles → they MUST
            // stay per-payload so distinct traps/inputs don't wrongly merge).
            switch (next.crash_kind) {
            case CrashKind::kResourceLeak:
            case CrashKind::kStateViolation:
            case CrashKind::kContractViolation:
            case CrashKind::kPriorityInversion:
            case CrashKind::kStackOverflow: {
                if (!next.title.empty()) {
                    ParsedCrashReport pr;
                    pr.title = next.title;
                    next.parsed_report = std::move(pr);
                }
                break;
            }
            default:
                break;
            }

            if (event.console_snapshot.has_value() && !event.console_snapshot->empty()) {
                next.console_log = *event.console_snapshot;
            }

            next.fault_reason = refuzz::proto::FaultReason::kAbnormalExit;
            next.fault_source = refuzz::proto::FaultSource::kAbnormalCompletion;
            next.fault_origin = refuzz::proto::FaultOrigin::kAbnormalCompletion;
        }

        // artifact-first universal contract — propagate, never decode.
        next.origin_artifact = event.crash_origin_artifact;

        ctx = std::move(next);
    }
};

// XiuosTitleOp — fills a fallback title for the non-leak XiUOS kinds so the
// reused PersistOp/ReportOp emit a meaningful title even though XiUOS has no
// serial-console parser. Runs in the kParseAndClassify slot (the syz
// KernelReportParser there is a no-op for XiUOS — it has no kernel console). The
// leak title is already set by XiuosBuildContextOp and is left untouched.
class XiuosTitleOp final : public ICrashPipelineOp {
public:
    CrashPipelineOp Kind() const override
    {
        return CrashPipelineOp::kParseAndClassify;
    }

    void Execute(const refuzz::proto::CombinedCrashEvent&,
                 CrashContext& ctx,
                 const CrashPipelineParams& params) override
    {
        (void)std::get<ParseAndClassifyParams>(params);
        if (!ctx.title.empty()) {
            return;  // leak title (or any prior title) wins.
        }
        switch (ctx.crash_kind) {
        case CrashKind::kResourceLeak:
            ctx.title = "heap leak";
            break;
        case CrashKind::kStateViolation:
            ctx.title = "xiuos state violation";
            break;
        case CrashKind::kContractViolation:
            ctx.title = "xiuos contract violation";
            break;
        case CrashKind::kPriorityInversion:
            ctx.title = "xiuos priority inversion";
            break;
        case CrashKind::kStackOverflow:
            ctx.title = "xiuos stack overflow";
            break;
        case CrashKind::kKernelCrash:
            ctx.title = "xiuos kernel crash";
            break;
        case CrashKind::kExecutionTimeout:
            ctx.title = "xiuos wedge (execution timeout)";
            break;
        case CrashKind::kExecError:
            ctx.title = "xiuos execution error";
            break;
        case CrashKind::kVmDead:
            ctx.title = "xiuos worker vm dead";
            break;
        case CrashKind::kWorkerDead:
            ctx.title = "xiuos worker dead";
            break;
        case CrashKind::kUnknownIncident:
            ctx.title = "xiuos unknown incident";
            break;
        case CrashKind::kNoOutput:
            ctx.title = "no output from test machine";
            break;
        }
    }
};

}  // namespace

void RegisterXiuosCrashPipelineOps(CrashPipelineRegistry& registry,
                                   DiagnosticStore* diagnostic_store,
                                   IReproQueue* repro_queue)
{
    // XiUOS-owned classification/routing.
    registry.Register(std::make_unique<XiuosBuildContextOp>());
    registry.Register(std::make_unique<XiuosTitleOp>());
    // Reuse the genuinely target-agnostic ops (single definition in syz_ops).
    registry.Register(MakeDedupOp(diagnostic_store));
    registry.Register(MakePersistOp(diagnostic_store));
    registry.Register(MakeReportOp());
    registry.Register(MakeEnqueueOp(repro_queue));
}

namespace testing {

std::unique_ptr<ICrashPipelineOp> MakeXiuosBuildContextOpForTest()
{
    return std::make_unique<XiuosBuildContextOp>();
}

}  // namespace testing

}  // namespace refuzz::crash

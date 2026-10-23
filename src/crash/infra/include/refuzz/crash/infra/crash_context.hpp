#pragma once

#include "refuzz/channel/health/health_types.hpp"
#include "refuzz/channel/worker/mode.hpp"
#include "refuzz/crash/components/symbolizer/kernel_report_parser.hpp"
#include "refuzz/program/artifact.hpp"
#include "refuzz/proto_domain/fault_event.hpp"
#include "refuzz/proto_domain/types.hpp"

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace refuzz::crash {

enum class CrashKind : uint8_t {
    kUnknownIncident = 0,
    kKernelCrash = 1,
    kWorkerDead = 2,
    kVmDead = 3,
    kExecutionTimeout = 4,
    kExecError = 5,
    // [XiUOS leak 一等公民化 Phase 1] resource leak (heap/resource residue) — own
    // diagnostics bucket `resource_leak/`. See docs/plans/xiuos-leak-componentization.md.
    kResourceLeak = 6,
    // [XiUOS leak 一等公民化 Phase 2] state violation: the worker's per-call heap/state
    // integrity check caught silent corruption (a real bug) — distinct from a real
    // trap/kernel crash. Own bucket `state_violation/`.
    kStateViolation = 7,
    // [Contract oracle §3.1] semantic contract violation: a must-succeed op on a
    // verified-valid precondition returned non-EOK. Own bucket `contract_violation/`.
    kContractViolation = 8,
    // [Priority-inversion detector] priority-inheritance invariant violated — own
    // bucket `priority_inversion/`.
    kPriorityInversion = 9,
    // [Stack-overflow detector] task stack high-water near/at its depth — own bucket
    // `stack_overflow/`.
    kStackOverflow = 10,
    // Full retained-classification window expired without a kernel report.
    kNoOutput = 11,
};

inline const char* CrashKindName(CrashKind kind)
{
    switch (kind) {
    case CrashKind::kUnknownIncident:
        return "unknown_incident";
    case CrashKind::kKernelCrash:
        return "kernel_crash";
    case CrashKind::kWorkerDead:
        return "worker_dead";
    case CrashKind::kVmDead:
        return "vm_dead";
    case CrashKind::kExecutionTimeout:
        return "exec_timeout";
    case CrashKind::kExecError:
        return "exec_error";
    case CrashKind::kResourceLeak:
        return "resource_leak";
    case CrashKind::kStateViolation:
        return "state_violation";
    case CrashKind::kContractViolation:
        return "contract_violation";
    case CrashKind::kPriorityInversion:
        return "priority_inversion";
    case CrashKind::kStackOverflow:
        return "stack_overflow";
    case CrashKind::kNoOutput:
        return "no_output";
    }
    return "unknown_incident";
}

struct CrashContext {
    std::string console_log;

    struct ProgramEntry {
        uint64_t executor_id = 0;
        uint64_t seed_id = 0;
        uint64_t origin_seed_id = 0;
        bool has_completed_result = false;
        uint32_t worker_id = 0;
        std::vector<uint8_t> payload;
        std::vector<uint8_t> output;
        uint64_t submit_ts_us = 0;
        uint64_t start_ts_us = 0;
        uint64_t finish_ts_us = 0;
        refuzz::proto::ResultCode result_code = refuzz::proto::ResultCode::kOk;
        refuzz::proto::InfraError infra_error = refuzz::proto::InfraError::kNone;
        uint32_t crash_signal = 0;
        // [XiUOS leak 一等公民化 Phase 1] leak magnitude carried from
        // FrozenExecutionSummary::leak_bytes (NOT crash_signal).
        uint32_t leak_bytes = 0;
        // [XiUOS leak 一等公民化 Phase 5] resource residue (waitq|victim<<8|delay<<16)
        // carried from FrozenExecutionSummary::resource_residue. Parallel to leak_bytes.
        uint32_t resource_residue = 0;
        std::vector<uint64_t> coverage_hashes;
        // [async-crash-reproduction Phase 1] typed view for this entry, carried
        // from FrozenProgramEntry::artifact. StageExtract sets
        // ReproResult::selected_artifact from it so a history/bisect/concat
        // extract can be minimized. Null when unavailable.
        std::shared_ptr<const ::refuzz::program::ProgramArtifact> artifact;
    };
    std::vector<ProgramEntry> program_log;

    int32_t crash_program_index = -1;

    std::string title;
    std::string raw_title;
    std::string target = "linux/amd64";
    std::string origin;
    refuzz::channel::CrashType type = refuzz::channel::CrashType::kUnknown;
    std::string guilty_frame;
    bool corrupted = false;
    bool suppressed = false;

    uint64_t incident_id = 0;
    uint32_t channel_id = 0;
    uint32_t slot_id = 0;
    uint32_t generation = 0;
    uint32_t crash_signal = 0;
    // [XiUOS leak 一等公民化 Phase 1] leak magnitude for kResourceLeak findings.
    // XiuosBuildContextOp hoists this from the crash program's leak_bytes; it
    // serializes as `leak_bytes` in meta.json. Stays 0 for non-leak incidents.
    uint32_t leak_bytes = 0;
    // [XiUOS leak 一等公民化 Phase 5] resource residue (waitq|victim<<8|delay<<16) for
    // kResourceLeak findings. XiuosBuildContextOp hoists this from the crash program's
    // resource_residue; serializes as `resource_residue` in meta.json. 0 for non-leak.
    uint32_t resource_residue = 0;
    uint64_t crash_hash = 0;
    bool is_duplicate = false;
    std::chrono::system_clock::time_point created_at{};
    // [v1 fault_reason/source 默认值是 kWorkerHeartbeatLost/kHealthMonitor
    //   — ROLLBACK: revert below to v1 values]
    // refuzz::proto::FaultReason fault_reason = refuzz::proto::FaultReason::kWorkerHeartbeatLost;
    // refuzz::proto::FaultSource fault_source = refuzz::proto::FaultSource::kHealthMonitor;
    // [v2 PR-D 默认值改 kAbnormalExit/kAbnormalCompletion — ROLLBACK: revert above]
    // refuzz::proto::FaultReason fault_reason = refuzz::proto::FaultReason::kAbnormalExit;
    // refuzz::proto::FaultSource fault_source = refuzz::proto::FaultSource::kAbnormalCompletion;
    // [v2 PR-E 默认值改 kUnknown — 当前版本]
    // PR-D 把默认值改成 abnormal-shaped 解决了"心跳丢失误标"问题,但本质上还是
    // "default 当真值"——若未来某条路径漏填,就会被伪装成合法的 abnormal incident。
    // 改成 kUnknown 后,任何漏填路径都直接在 meta.json 暴露成 "unknown",可立即定位。
    // BuildContextOp 两个分支都已显式赋值(第一分支走 fault.reason 映射,第二分支
    // 显式写 kAbnormalExit/kAbnormalCompletion),不依赖默认值。
    refuzz::proto::FaultReason fault_reason = refuzz::proto::FaultReason::kUnknown;
    refuzz::proto::FaultSource fault_source = refuzz::proto::FaultSource::kUnknown;
    // §3.11-A — origin of the underlying sensor signal. ParseAndClassifyOp
    // gates the kWorkerDead → kKernelCrash evidence-coercion on
    // origin == kSerialPattern (see Bug #1 in crash-pipeline review).
    refuzz::proto::FaultOrigin fault_origin = refuzz::proto::FaultOrigin::kUnknown;

    CrashKind crash_kind = CrashKind::kUnknownIncident;
    std::vector<std::string> alt_titles;
    std::vector<std::string> pseudo_trace;
    std::vector<std::string> unsupported_features;
    std::optional<ParsedCrashReport> parsed_report;
    refuzz::channel::worker::WorkerSanitizerMode sanitizer_mode =
        refuzz::channel::worker::WorkerSanitizerMode::kNone;

    // §3.11-A / post-V1-retirement: authoritative program artifact for
    // the program that triggered this crash. BuildContextOp propagates
    // this from CombinedCrashEvent::crash_origin_artifact, which is
    // filled from CompletionContext::artifact on the abnormal/completion
    // path. It must not be reconstructed from program_payload or exec-wire
    // bytes; those bytes are only the executor submission representation.
    //
    // May be null when:
    //   - crash had no associated program (pure infra fault)
    //   - the event came from a path that does not yet propagate artifacts
    //     (for example the current Fault scene path)
    //   - a legacy/payload-only test setup injected no artifact
    std::shared_ptr<const ::refuzz::program::ProgramArtifact> origin_artifact;
};

} // namespace refuzz::crash

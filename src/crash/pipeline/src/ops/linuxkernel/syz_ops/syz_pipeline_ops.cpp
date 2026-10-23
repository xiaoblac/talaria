#include "refuzz/crash/pipeline/ops/linuxkernel/syz_ops/syz_pipeline_ops.hpp"

#include "refuzz/crash/infra/diagnostic_artifact.hpp"
#include "refuzz/logging/host_logger.hpp"
#include "refuzz/program/artifact_materializer.hpp"
#include "refuzz/program/syz/target.hpp"

#include <algorithm>
#include <chrono>
#include <memory>
#include <string>
#include <utility>

namespace refuzz::crash {
namespace {

// A parsed kernel report already has syzkaller's canonical identity encoded in
// its title. Raw frames and the local fault detector are observations about the
// incident, not additional parts of that identity. Infrastructure findings do
// not have a parsed report, so they keep the reason discriminator and let the
// caller fold payload bytes into the hash.
std::string DedupDescription(const CrashContext& ctx)
{
    if (ctx.parsed_report.has_value() &&
        !ctx.parsed_report->title.empty()) {
        return ctx.parsed_report->title;
    }

    std::string out;
    out.reserve(96);

    if (!ctx.title.empty()) {
        out.append(ctx.title);
    } else if (ctx.crash_signal != 0) {
        out.append("signal-");
        out.append(std::to_string(ctx.crash_signal));
    } else {
        out.append(CrashKindName(ctx.crash_kind));
    }

    out.append("|reason=");
    out.append(std::to_string(static_cast<int>(ctx.fault_reason)));
    return out;
}

const CrashContext::ProgramEntry* CrashProgramEntry(const CrashContext& ctx)
{
    if (ctx.crash_program_index < 0 ||
        ctx.crash_program_index >= static_cast<int32_t>(ctx.program_log.size())) {
        return nullptr;
    }
    return &ctx.program_log[ctx.crash_program_index];
}

CrashContext::ProgramEntry ToProgramEntry(const refuzz::proto::FrozenProgramEntry& entry)
{
    CrashContext::ProgramEntry program;
    program.executor_id = entry.executor_id;
    program.seed_id = entry.seed_id;
    program.origin_seed_id = entry.origin_seed_id;
    program.payload = entry.program_payload;
    program.submit_ts_us = entry.submit_ts_us;
    // [async-crash-reproduction Phase 1] carry the typed view so StageExtract can
    // set selected_artifact for a history/bisect/concat extract.
    program.artifact = entry.artifact;
    program.has_completed_result = entry.completion.has_value();
    if (entry.completion.has_value()) {
        program.worker_id = entry.completion->worker_id;
        program.output = entry.completion->output;
        program.start_ts_us = entry.completion->start_ts_us;
        program.finish_ts_us = entry.completion->finish_ts_us;
        program.result_code = entry.completion->result_code;
        program.infra_error = entry.completion->infra_error;
        program.crash_signal = entry.completion->crash_signal;
        // [XiUOS leak 一等公民化 Phase 1] propagate the dedicated leak carrier.
        program.leak_bytes = entry.completion->leak_bytes;
        // [XiUOS leak 一等公民化 Phase 5] target-agnostic resource-residue carrier
        // (parallel to leak_bytes; classification stays in xiuos ops).
        program.resource_residue = entry.completion->resource_residue;
        program.coverage_hashes = entry.completion->coverage_hashes;
    }
    return program;
}

class BuildContextOp final : public ICrashPipelineOp {
public:
    explicit BuildContextOp(refuzz::channel::worker::WorkerSanitizerMode sanitizer_mode)
        : sanitizer_mode_(sanitizer_mode)
    {}

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
        next.sanitizer_mode = sanitizer_mode_;

        for (const auto& entry : event.history) {
            next.program_log.push_back(ToProgramEntry(entry));
        }

        if (event.crash_program.has_value()) {
            next.program_log.push_back(ToProgramEntry(*event.crash_program));
            next.crash_program_index = static_cast<int32_t>(next.program_log.size() - 1);
            next.crash_signal = next.program_log.back().crash_signal;
        }

        if (event.fault_event.has_value()) {
            const auto& fault = *event.fault_event;
            next.console_log = fault.crash_console;
            next.raw_title = fault.crash_title;
            next.channel_id = fault.channel_id;
            next.slot_id = fault.slot_id;
            next.generation = fault.generation;
            next.fault_reason = fault.reason;
            next.fault_source = fault.source;
            // §3.11-A — origin 透传：用于 ParseAndClassifyOp 的 coercion gate。
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
            // [v2 PR-D abnormal path 不应走这条 fault 分支 — 当前版本]
            // kAbnormalExit 仅在 BuildContextOp 第二分支(else if crash_program/completion)
            // 显式赋值给 next.fault_reason,不会出现在 fault_event.reason 上(channel
            // 端 EmitFaultEvent 仅在真实 fault sensor 触发时调用)。这里作 defensive
            // fallback,出现的话归为 kUnknownIncident,避免 crash pipeline 错升级。
            case refuzz::proto::FaultReason::kAbnormalExit:
                next.crash_kind = CrashKind::kUnknownIncident;
                break;
            // [v2 PR-E kUnknown defensive case — 当前版本]
            // 默认占位值。如果 BuildCombinedFromFault 漏填 reason,会落到这里,
            // 显式归为 kUnknownIncident,避免 -Werror -Wswitch 失败。
            case refuzz::proto::FaultReason::kUnknown:
                next.crash_kind = CrashKind::kUnknownIncident;
                break;
            }
        } else if (event.crash_program.has_value() && event.crash_program->completion.has_value()) {
            // [v1 crash_signal!=0 → kWorkerDead — ROLLBACK: uncomment below, remove v2]
            // const auto& result = *event.crash_program->completion;
            // if (result.result_code == refuzz::proto::ResultCode::kTimeout ||
            //     result.infra_error == refuzz::proto::InfraError::kTimeout) {
            //     next.crash_kind = CrashKind::kExecutionTimeout;
            // } else if (result.result_code == refuzz::proto::ResultCode::kExecError ||
            //            result.infra_error == refuzz::proto::InfraError::kExecutorError ||
            //            result.infra_error == refuzz::proto::InfraError::kInvalidInput ||
            //            result.infra_error == refuzz::proto::InfraError::kOutputTooLarge) {
            //     next.crash_kind = CrashKind::kExecError;
            // } else if (result.infra_error == refuzz::proto::InfraError::kWorkerCrashed ||
            //            result.crash_signal != 0) {
            //     next.crash_kind = CrashKind::kWorkerDead;
            // }
            // [v2 去掉 crash_signal!=0 fallback — 当前版本]
            // 上游 channel.cpp 已把 program 行为致 child 退出/被信号归类为 kChildAborted →
            // MapAbnormalToResultCode/InfraError 把它压成 kExecError/kExecutorError，
            // 这里第二个分支会先命中，不再误升级到 kWorkerDead。
            // 去掉 `crash_signal != 0` 的 fallback —— 真正的 daemon-side worker dead 由
            // infra_error == kWorkerCrashed 表达，crash_signal 数值本身只是诊断信息。
            const auto& result = *event.crash_program->completion;
            if (result.result_code == refuzz::proto::ResultCode::kTimeout ||
                result.infra_error == refuzz::proto::InfraError::kTimeout) {
                next.crash_kind = CrashKind::kExecutionTimeout;
            } else if (result.result_code == refuzz::proto::ResultCode::kExecError ||
                       result.infra_error == refuzz::proto::InfraError::kExecutorError ||
                       result.infra_error == refuzz::proto::InfraError::kInvalidInput ||
                       result.infra_error == refuzz::proto::InfraError::kOutputTooLarge) {
                next.crash_kind = CrashKind::kExecError;
            } else if (result.infra_error == refuzz::proto::InfraError::kWorkerCrashed) {
                next.crash_kind = CrashKind::kWorkerDead;
            }

            // [v2 PR-B abnormal path console snapshot — 当前版本]
            // 第一分支(fault path)从 fault_event.crash_console 读 console_log,
            // 这里第二分支(abnormal path)无 fault_event,改从 combined.console_snapshot
            // 读。Channel/feedback 已在 EmitAbnormalCompletion 与 BuildCombinedFromAbnormal
            // 把 ConsoleRingBuffer 最近若干行写到这个 universal slot。
            // 修复 abnormal 落盘时 [console] block / serial_log_tail 全丢的问题。
            if (event.console_snapshot.has_value() && !event.console_snapshot->empty()) {
                next.console_log = *event.console_snapshot;
            }

            // [v2 PR-D abnormal path 显式写 fault_reason/source/origin — 当前版本]
            // 旧版本第二分支不写这三个字段,保留 CrashContext 默认值
            // (kWorkerHeartbeatLost/kHealthMonitor/kUnknown) → DiagnosticStore::BuildMetaJson
            // 把它们当真值印出来,误导用户以为是 health sensor 测的心跳丢失。
            // 现在显式标 kAbnormalExit / kAbnormalCompletion / kAbnormalCompletion,
            // 同时让 ParseAndClassifyOp evidence-coercion gate(只认 origin==kSerialPattern)
            // 自然不命中,符合"abnormal path 已独立分类,不需要二次升级"的语义。
            next.fault_reason = refuzz::proto::FaultReason::kAbnormalExit;
            next.fault_source = refuzz::proto::FaultSource::kAbnormalCompletion;
            next.fault_origin = refuzz::proto::FaultOrigin::kAbnormalCompletion;
        }

        // post-V1-retirement artifact-first universal contract — D-1 + B-4:
        //   原行为：MakeArtifactFromCanonicalPayload(program_log[idx].payload)
        //   尝试把 exec-wire bytes 反向解码回 typed Prog。该路径在 L2 之后
        //   就已不工作（exec-wire ≠ canonical .syz text），且违反"artifact 是
        //   单向 lower 出口、不可反推"的 cornerstone 不变式（多目标场景下
        //   raw-bytes / RPC / VM-snapshot 根本没法 round-trip）。
        //   修复：origin_artifact 必须从 CombinedCrashEvent.crash_origin_artifact
        //   预先填好（feedback::BuildCombinedFromAbnormal 注入 ctx.artifact）。
        //   BuildContextOp 只负责 propagate，不再 decode。
        //   Fault path 暂不带 artifact（channeldispatcher 不做 fault→artifact
        //   配对）；下游 repro_manager.StageMinimize 已 fail-closed。
        //   详见 docs/syzkaller-parity-review/post_v1_retirement_followups.md。
        next.origin_artifact = event.crash_origin_artifact;

        ctx = std::move(next);
    }

private:
    refuzz::channel::worker::WorkerSanitizerMode sanitizer_mode_;
};

class ParseAndClassifyOp final : public ICrashPipelineOp {
public:
    ParseAndClassifyOp(KernelReportParser* parser, Addr2lineSymbolizer* symbolizer)
        : parser_(parser)
        , symbolizer_(symbolizer)
    {}

    CrashPipelineOp Kind() const override
    {
        return CrashPipelineOp::kParseAndClassify;
    }

    void Execute(const refuzz::proto::CombinedCrashEvent&,
                 CrashContext& ctx,
                 const CrashPipelineParams& params) override
    {
        (void)std::get<ParseAndClassifyParams>(params);

        if (!ctx.console_log.empty()) {
            auto parsed = parser_->Parse(ctx.console_log);
            if (parsed.has_value()) {
                ctx.parsed_report = std::move(parsed);
                if (!ctx.parsed_report->title.empty()) {
                    ctx.title = ctx.parsed_report->title;
                    ctx.raw_title = ctx.parsed_report->raw_title;
                }
                ctx.alt_titles = ctx.parsed_report->alt_titles;
                ctx.type = ctx.parsed_report->type;
                ctx.guilty_frame = ctx.parsed_report->guilty_function;
                ctx.corrupted = ctx.parsed_report->corrupted;

                if (symbolizer_ != nullptr && !ctx.parsed_report->frames.empty()) {
                    symbolizer_->SymbolizeReport(*ctx.parsed_report);
                }
                // §3.11-A — Bug #1 修复：evidence-coercion 必须 gate 在
                // origin == kSerialPattern。HeartbeatSensor / VmAlive /
                // health-internal 触发的事件即便 console 里有残留 panic
                // 文本，也不能改写 crash_kind ——那段 console 不是这个
                // incident 的真实证据，是同 channel 上其它 incident 的回响。
                if (ctx.crash_kind == CrashKind::kWorkerDead &&
                    ctx.parsed_report->type != refuzz::channel::CrashType::kUnknown &&
                    ctx.fault_origin == refuzz::proto::FaultOrigin::kSerialPattern) {
                    ctx.crash_kind = CrashKind::kKernelCrash;
                }
                return;
            }
        }

        if (!ctx.raw_title.empty()) {
            ctx.title = KernelReportParser::NormalizeTitle(ctx.raw_title);
            // §3.11-A — 同上 origin gate。
            if (ctx.crash_kind == CrashKind::kWorkerDead &&
                ctx.fault_origin == refuzz::proto::FaultOrigin::kSerialPattern) {
                ctx.crash_kind = CrashKind::kKernelCrash;
            }
            return;
        }

        switch (ctx.crash_kind) {
        case CrashKind::kKernelCrash:
            ctx.title = "unknown kernel crash";
            break;
        case CrashKind::kVmDead:
            ctx.title = "vm dead (no console output)";
            // [#4 fail-closed] 无 console 证据的存活死亡 = 不是内核 bug,只是"VM/worker
            // 不响应了"。证据缺失≠hang。标 suppressed → 记录类 op(Dedup/Persist/Report)
            // 不入 bug 账本,改喂 worker_stall_unexplained 遥测。有 console 证据的情形早已
            // 在上面 with-title 路径 coerce 成 kKernelCrash,根本不到这个 fallback。
            // recovery 走 channel fault(kWorkerHeartbeatLost)另一条路,不受此影响。
            ctx.suppressed = true;
            break;
        case CrashKind::kWorkerDead:
            ctx.title = "worker dead (no crash pattern)";
            ctx.suppressed = true;  // [#4 fail-closed] 心跳 stall 只是 daemon 不 tick,非 hang
            break;
        case CrashKind::kExecutionTimeout:
            ctx.title = "execution timeout";
            break;
        case CrashKind::kExecError:
            ctx.title = "execution error";
            break;
        case CrashKind::kNoOutput:
            ctx.title = "no output from test machine";
            break;
        case CrashKind::kUnknownIncident:
            ctx.title = "unknown incident";
            break;
        case CrashKind::kResourceLeak:
            // XiUOS resource leaks are classified by the XiUOS pipeline ops, not
            // here; this generic fallback title only keeps the switch exhaustive.
            ctx.title = "resource leak";
            break;
        case CrashKind::kStateViolation:
            // XiUOS state violations classified by XiUOS ops; generic fallback only.
            ctx.title = "state violation";
            break;
        case CrashKind::kContractViolation:
            // XiUOS contract violations classified by XiUOS ops; generic fallback only.
            ctx.title = "contract violation";
            break;
        case CrashKind::kPriorityInversion:
            // XiUOS priority inversions classified by XiUOS ops; generic fallback only.
            ctx.title = "priority inversion";
            break;
        case CrashKind::kStackOverflow:
            // XiUOS stack overflows classified by XiUOS ops; generic fallback only.
            ctx.title = "stack overflow";
            break;
        }
    }

private:
    KernelReportParser* parser_;
    Addr2lineSymbolizer* symbolizer_;
};

class DedupOp final : public ICrashPipelineOp {
public:
    explicit DedupOp(DiagnosticStore* diagnostic_store)
        : diagnostic_store_(diagnostic_store)
    {}

    CrashPipelineOp Kind() const override
    {
        return CrashPipelineOp::kDedup;
    }

    void Execute(const refuzz::proto::CombinedCrashEvent&,
                 CrashContext& ctx,
                 const CrashPipelineParams& params) override
    {
        (void)std::get<DedupParams>(params);
        if (diagnostic_store_ == nullptr) {
            return;
        }
        // [#4 fail-closed] suppressed = 无 console 证据的存活死亡(worker/vm),不是内核
        // bug → 不进 DiagnosticStore dedup/账本(不占 bug 计数)。
        if (ctx.suppressed) {
            return;
        }

        // Kernel reports with a parsed title identify the same bug independent
        // of the triggering program. Infrastructure faults have only a fixed
        // fallback title, so retain the payload to keep those incidents split.
        const std::string description = DedupDescription(ctx);
        const auto* entry = CrashProgramEntry(ctx);
        const bool has_real_title = ctx.parsed_report.has_value()
                                 && !ctx.parsed_report->title.empty();
        const bool fold_payload = !has_real_title;
        ctx.crash_hash = HashDiagnosticArtifact(
            ctx.crash_kind,
            description,
            (fold_payload && entry != nullptr) ? entry->payload : std::vector<uint8_t>{},
            (fold_payload && entry != nullptr) ? entry->output : std::vector<uint8_t>{});
        ctx.is_duplicate = diagnostic_store_->IsDuplicate(ctx.crash_kind, ctx.crash_hash);
    }

private:
    DiagnosticStore* diagnostic_store_;
};

class PersistOp final : public ICrashPipelineOp {
public:
    explicit PersistOp(DiagnosticStore* diagnostic_store)
        : diagnostic_store_(diagnostic_store)
    {}

    CrashPipelineOp Kind() const override
    {
        return CrashPipelineOp::kPersist;
    }

    void Execute(const refuzz::proto::CombinedCrashEvent&,
                 CrashContext& ctx,
                 const CrashPipelineParams& params) override
    {
        (void)std::get<PersistParams>(params);
        if (diagnostic_store_ == nullptr) {
            return;
        }
        // [#4 fail-closed] suppressed → 不落 crash artifact(不是内核 bug)。
        if (ctx.suppressed) {
            return;
        }

        DiagnosticArtifact artifact;
        artifact.kind = ctx.crash_kind;
        artifact.description = DedupDescription(ctx);
        artifact.fragment.title = ctx.title;
        artifact.fragment.console_output = ctx.console_log;
        // [v2 PR-E serial_log_tail 同步落盘 — 当前版本]
        // DiagnosticStore::SaveArtifact 仅在 artifact.serial_log_tail 非空时写
        // serial_log_tail.txt 文件。此前 PersistOp 不填这一字段, [console] block
        // 进 report0 但独立的 serial_log_tail.txt 永远不出现。这里把 ctx.console_log
        // 同步写一份让两个落盘出口语义一致。
        // 用同一份 raw text(console_output 与 serial_log_tail 内容相同),让 grep / tail
        // 工具的常规消费习惯都能命中。
        artifact.serial_log_tail = ctx.console_log;
        artifact.fragment.type = ctx.type;
        artifact.target = ctx.target;
        artifact.origin = ctx.origin;
        artifact.pseudo_trace = ctx.pseudo_trace;
        artifact.unsupported_features = ctx.unsupported_features;
        artifact.timestamp = ctx.created_at;
        artifact.metadata.fault_incident_id = ctx.incident_id;
        artifact.metadata.channel_id = ctx.channel_id;
        artifact.metadata.slot_id = ctx.slot_id;
        artifact.metadata.generation = ctx.generation;
        artifact.metadata.crash_signal = ctx.crash_signal;
        // [XiUOS leak 一等公民化 Phase 1] carry the leak magnitude through to the
        // persisted metadata (serializes as `leak_bytes` in meta.json).
        artifact.metadata.leak_bytes = ctx.leak_bytes;
        // [XiUOS leak 一等公民化 Phase 5] same for resource residue.
        artifact.metadata.resource_residue = ctx.resource_residue;
        artifact.metadata.fault_reason = ctx.fault_reason;
        artifact.metadata.fault_source = ctx.fault_source;
        // [v2 PR-D fault_origin 透传到 metadata — 当前版本]
        artifact.metadata.fault_origin = ctx.fault_origin;
        artifact.metadata.sanitizer_mode = ctx.sanitizer_mode;

        const auto* entry = CrashProgramEntry(ctx);
        if (entry != nullptr) {
            artifact.program_payload = entry->payload;
            artifact.output_payload = entry->output;
            artifact.coverage_hashes = entry->coverage_hashes;
            artifact.metadata.executor_id = entry->executor_id;
            artifact.metadata.seed_id = entry->seed_id;
            artifact.metadata.has_completed_result = entry->has_completed_result;
            artifact.metadata.worker_id = entry->worker_id;
            artifact.metadata.result_code = entry->result_code;
            artifact.metadata.infra_error = entry->infra_error;
            artifact.metadata.start_ts_us = entry->start_ts_us;
            artifact.metadata.finish_ts_us = entry->finish_ts_us;
            artifact.metadata.crash_signal = entry->crash_signal != 0
                ? entry->crash_signal
                : artifact.metadata.crash_signal;
            // [XiUOS leak 一等公民化 Phase 1] same entry-precedence for leak_bytes.
            artifact.metadata.leak_bytes = entry->leak_bytes != 0
                ? entry->leak_bytes
                : artifact.metadata.leak_bytes;
            // [XiUOS leak 一等公民化 Phase 5] same entry-precedence for resource_residue.
            artifact.metadata.resource_residue = entry->resource_residue != 0
                ? entry->resource_residue
                : artifact.metadata.resource_residue;
        }

        // [crash-execution-history-ring] persist the recent execution history:
        // every program_log entry except the crash entry (which stays in
        // program_payload -> prog0.bin), in order. For a kernel-crash this carries
        // the Layer-2 ring history harvested by Channel; for other faults it is the
        // in-flight snapshot. Empty when only the crash program is present.
        for (int32_t i = 0; i < static_cast<int32_t>(ctx.program_log.size()); ++i) {
            if (i == ctx.crash_program_index) continue;
            artifact.history_payloads.push_back(ctx.program_log[i].payload);
        }

        // §3.11-B — fallback hash when DedupOp didn't run (no diagnostic_store).
        // Mirror the conditional fold from DedupOp::Execute.
        // Mirror DedupOp: only a parsed kernel title is stable enough to
        // collapse payloads; infrastructure fallback titles keep payload data.
        const bool persist_has_real_title = ctx.parsed_report.has_value()
                                         && !ctx.parsed_report->title.empty();
        const bool persist_fold_payload = !persist_has_real_title;
        artifact.artifact_hash = ctx.crash_hash != 0
            ? ctx.crash_hash
            : HashDiagnosticArtifact(
                artifact.kind,
                artifact.description,
                persist_fold_payload ? artifact.program_payload : std::vector<uint8_t>{},
                persist_fold_payload ? artifact.output_payload : std::vector<uint8_t>{});

        if (ctx.parsed_report.has_value()) {
            std::string sym_text;
            for (size_t i = 0; i < ctx.parsed_report->frames.size(); ++i) {
                const auto& frame = ctx.parsed_report->frames[i];
                sym_text += "#" + std::to_string(i) + " " + frame.function;
                if (!frame.file.empty()) {
                    sym_text += " " + frame.file + ":" + std::to_string(frame.line);
                }
                sym_text += "\n";
            }
            artifact.symbolized_report = std::move(sym_text);
        }

        diagnostic_store_->SaveArtifact(artifact);
    }

private:
    DiagnosticStore* diagnostic_store_;
};

class ReportOp final : public ICrashPipelineOp {
public:
    CrashPipelineOp Kind() const override
    {
        return CrashPipelineOp::kReport;
    }

    void Execute(const refuzz::proto::CombinedCrashEvent&,
                 CrashContext& ctx,
                 const CrashPipelineParams& params) override
    {
        (void)std::get<ReportParams>(params);
        // [#4 fail-closed] suppressed = 无 console 证据的存活死亡:不当 bug 报,改一条
        // 健康/遥测事件(worker_stall_unexplained)。计数看它的出现率;率飙 = 测量/基础
        // 设施问题信号(如 DIAGNOSING 窗口太短伪造 stall),不是发现的 bug。
        if (ctx.suppressed) {
            refuzz::logging::HostLogger::Instance().Log(
                "CrashPipeline",
                "worker_stall_unexplained",
                {refuzz::logging::Field("incident_id", ctx.incident_id),
                 refuzz::logging::Field("channel_id", ctx.channel_id),
                 refuzz::logging::Field("crash_kind", CrashKindName(ctx.crash_kind)),
                 refuzz::logging::Field("title", ctx.title.empty() ? std::string("-") : ctx.title)});
            return;
        }
        refuzz::logging::HostLogger::Instance().Log(
            "CrashPipeline",
            "crash_classify",
            {refuzz::logging::Field("incident_id", ctx.incident_id),
             refuzz::logging::Field("channel_id", ctx.channel_id),
             refuzz::logging::Field("title", ctx.title.empty() ? std::string("-") : ctx.title),
             refuzz::logging::Field("type", static_cast<int>(ctx.type)),
             refuzz::logging::Field("crash_kind", CrashKindName(ctx.crash_kind)),
             refuzz::logging::Field("corrupted", ctx.corrupted),
             refuzz::logging::Field("duplicate", ctx.is_duplicate),
             refuzz::logging::Field("programs", ctx.program_log.size()),
             refuzz::logging::Field("crash_idx", ctx.crash_program_index),
             refuzz::logging::Field("signal", ctx.crash_signal)});
    }
};

class EnqueueOp final : public ICrashPipelineOp {
public:
    explicit EnqueueOp(IReproQueue* repro_queue)
        : repro_queue_(repro_queue)
    {}

    CrashPipelineOp Kind() const override
    {
        return CrashPipelineOp::kEnqueue;
    }

    void Execute(const refuzz::proto::CombinedCrashEvent&,
                 CrashContext& ctx,
                 const CrashPipelineParams& params) override
    {
        const auto& enqueue = std::get<EnqueueParams>(params);

        // Crash-kind gate: eligible_kinds (when set) replaces the Linux-centric
        // require_kernel_crash so wedge/worker-dead targets can repro their
        // findings. A program_log entry with a non-empty payload is what the
        // extract stage actually replays, so "has a program" means "has at least
        // one non-empty payload", not merely a non-empty log vector.
        const bool kind_ok =
            !enqueue.eligible_kinds.empty()
                ? (std::find(enqueue.eligible_kinds.begin(),
                             enqueue.eligible_kinds.end(),
                             ctx.crash_kind) != enqueue.eligible_kinds.end())
                : (!enqueue.require_kernel_crash ||
                   ctx.crash_kind == CrashKind::kKernelCrash);
        const bool has_program = std::any_of(
            ctx.program_log.begin(), ctx.program_log.end(),
            [](const CrashContext::ProgramEntry& e) { return !e.payload.empty(); });

        ReproEligibility eligibility = ReproEligibility::kEnqueue;
        if (!kind_ok) {
            eligibility = ReproEligibility::kNotKernelCrash;
        } else if (enqueue.reject_duplicates && ctx.is_duplicate) {
            eligibility = ReproEligibility::kDuplicate;
        } else if (enqueue.require_program_log && !has_program) {
            eligibility = ReproEligibility::kEmptyProgramLog;
        } else if (enqueue.reject_suppressed && ctx.suppressed) {
            eligibility = ReproEligibility::kSuppressed;
        } else if (!enqueue.allowed_types.empty()) {
            bool allowed = false;
            for (const auto type : enqueue.allowed_types) {
                if (type == ctx.type) {
                    allowed = true;
                    break;
                }
            }
            if (!allowed) {
                eligibility = enqueue.fallback_reason;
            }
        }

        if (repro_queue_ == nullptr) {
            refuzz::logging::HostLogger::Instance().Log(
                "CrashPipeline",
                "crash_enqueue",
                {refuzz::logging::Field("incident_id", ctx.incident_id),
                 refuzz::logging::Field("title", ctx.title.empty() ? std::string("-") : ctx.title),
                 refuzz::logging::Field("crash_kind", CrashKindName(ctx.crash_kind)),
                 refuzz::logging::Field("result", "drop"),
                 refuzz::logging::Field("reason", "no_repro_queue"),
                 refuzz::logging::Field("pending", 0),
                 refuzz::logging::Field("capacity", 0)});
            return;
        }

        const auto before = repro_queue_->Snapshot();
        bool pushed = false;
        if (eligibility == ReproEligibility::kEnqueue) {
            pushed = repro_queue_->Push(ctx);
        }
        const auto after = repro_queue_->Snapshot();

        std::string result = "drop";
        std::string reason = ReproEligibilityName(eligibility);
        if (eligibility == ReproEligibility::kEnqueue) {
            if (pushed) {
                result = "enqueue";
                reason = "enqueued";
            } else {
                reason = "queue_full";
            }
        }

        refuzz::logging::HostLogger::Instance().Log(
            "CrashPipeline",
            "crash_enqueue",
            {refuzz::logging::Field("incident_id", ctx.incident_id),
             refuzz::logging::Field("title", ctx.title.empty() ? std::string("-") : ctx.title),
             refuzz::logging::Field("crash_kind", CrashKindName(ctx.crash_kind)),
             refuzz::logging::Field("result", result),
             refuzz::logging::Field("reason", reason),
             refuzz::logging::Field("pending", after.pending),
             refuzz::logging::Field("capacity", after.capacity),
             refuzz::logging::Field("dropped", after.dropped),
             refuzz::logging::Field("pending_before", before.pending)});
    }

private:
    IReproQueue* repro_queue_;
};

} // namespace

void RegisterKernelCrashPipelineOps(CrashPipelineRegistry& registry,
                                    KernelReportParser* parser,
                                    Addr2lineSymbolizer* symbolizer,
                                    refuzz::channel::worker::WorkerSanitizerMode sanitizer_mode,
                                    DiagnosticStore* diagnostic_store,
                                    IReproQueue* repro_queue)
{
    registry.Register(std::make_unique<BuildContextOp>(sanitizer_mode));
    registry.Register(std::make_unique<ParseAndClassifyOp>(parser, symbolizer));
    registry.Register(std::make_unique<DedupOp>(diagnostic_store));
    registry.Register(std::make_unique<PersistOp>(diagnostic_store));
    registry.Register(std::make_unique<ReportOp>());
    registry.Register(std::make_unique<EnqueueOp>(repro_queue));
}

// [XiUOS leak 一等公民化 Phase 1] target-agnostic op factories — single
// definition reused by other families' Register*CrashPipelineOps.
std::unique_ptr<ICrashPipelineOp> MakeDedupOp(DiagnosticStore* diagnostic_store)
{
    return std::make_unique<DedupOp>(diagnostic_store);
}

std::unique_ptr<ICrashPipelineOp> MakePersistOp(DiagnosticStore* diagnostic_store)
{
    return std::make_unique<PersistOp>(diagnostic_store);
}

std::unique_ptr<ICrashPipelineOp> MakeReportOp()
{
    return std::make_unique<ReportOp>();
}

std::unique_ptr<ICrashPipelineOp> MakeEnqueueOp(IReproQueue* repro_queue)
{
    return std::make_unique<EnqueueOp>(repro_queue);
}

// §3.11-A / §3.11-C — test-friendly factories.
namespace testing {

std::unique_ptr<ICrashPipelineOp>
MakeBuildContextOpForTest(refuzz::channel::worker::WorkerSanitizerMode sanitizer_mode) {
    return std::make_unique<BuildContextOp>(sanitizer_mode);
}

std::unique_ptr<ICrashPipelineOp>
MakeParseAndClassifyOpForTest(KernelReportParser* parser,
                              Addr2lineSymbolizer* symbolizer) {
    return std::make_unique<ParseAndClassifyOp>(parser, symbolizer);
}

std::string ComputeDedupDescriptionForTest(const CrashContext& ctx) {
    return DedupDescription(ctx);
}

} // namespace testing

} // namespace refuzz::crash

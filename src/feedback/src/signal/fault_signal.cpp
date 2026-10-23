// Copyright 2026 reFuzz project author -------youngkk.
//
// FaultSignal — 旧 FaultObserver + FeedbackPipeline::BuildCombinedFromFault /
// BuildCombinedFromAbnormal 的合并实现。

#include "refuzz/feedback/signal/fault_signal.hpp"

#include "refuzz/proto_domain/fault_event.hpp"
#include "refuzz/proto_domain/frozen_program_entry.hpp"

#include <chrono>

namespace refuzz::fuzzer {

namespace {

uint64_t NowUs()
{
    const auto now = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(now).count());
}

proto::FaultReason MapFaultReason(refuzz::core::channel_contract::FaultKind kind)
{
    switch (kind) {
    case refuzz::core::channel_contract::FaultKind::kKernelCrash:
        return proto::FaultReason::kKernelCrash;
    case refuzz::core::channel_contract::FaultKind::kNoOutput:
        return proto::FaultReason::kNoOutput;
    case refuzz::core::channel_contract::FaultKind::kVmDead:
        return proto::FaultReason::kVmDead;
    case refuzz::core::channel_contract::FaultKind::kWorkerDead:
        return proto::FaultReason::kWorkerHeartbeatLost;
    case refuzz::core::channel_contract::FaultKind::kHealthInternal:
        // health_internal 不走 fuzzer fault 路径(不发 AbnormalCompletion)→ 不可达;
        // 若真到这里,用 kUnknown 暴露,不伪装成某个具体 fault。
        return proto::FaultReason::kUnknown;
    }
    return proto::FaultReason::kUnknown;
}

// [v2 +kChildAborted — 当前版本]
// kChildAborted 不应映射到 kCrashed/kWorkerCrashed，否则 FaultSignal::Sample 会
// 走 c.fired = true + BuildCombinedFromAbnormal → 进 crash pipeline → 错升级为 worker_dead。
// 把它当作 execution-level abnormal：result_code=kExecError, infra_error=kExecutorError。
proto::ResultCode MapAbnormalToResultCode(refuzz::core::channel_contract::AbnormalKind kind)
{
    // NOTE: 这是 AbnormalKind→ResultCode 的**第 2 份**拷贝(另两份在
    // exec_result_signal.cpp / control minimize_admit.cpp::ExecStatusOf)。三份必须
    // 保持一致 —— 见 task「AbnormalKind→ResultCode 3 份重写,应收敛成单一权威」。
    switch (kind) {
    case refuzz::core::channel_contract::AbnormalKind::kHang:
        return proto::ResultCode::kTimeout;
    case refuzz::core::channel_contract::AbnormalKind::kWorkerCrashed:
    case refuzz::core::channel_contract::AbnormalKind::kWorkerSignaled:
        return proto::ResultCode::kCrashed;
    case refuzz::core::channel_contract::AbnormalKind::kNoResult:
    case refuzz::core::channel_contract::AbnormalKind::kCancelled:
    case refuzz::core::channel_contract::AbnormalKind::kChildAborted:
    case refuzz::core::channel_contract::AbnormalKind::kHarnessRecovered:
    case refuzz::core::channel_contract::AbnormalKind::kHarnessFatal:
    case refuzz::core::channel_contract::AbnormalKind::kInfraFault:
    case refuzz::core::channel_contract::AbnormalKind::kUnknown:
        return proto::ResultCode::kExecError;
    }
    return proto::ResultCode::kExecError;
}

proto::InfraError MapAbnormalToInfraError(refuzz::core::channel_contract::AbnormalKind kind)
{
    switch (kind) {
    case refuzz::core::channel_contract::AbnormalKind::kHang:
        return proto::InfraError::kTimeout;
    case refuzz::core::channel_contract::AbnormalKind::kWorkerCrashed:
    case refuzz::core::channel_contract::AbnormalKind::kWorkerSignaled:
        return proto::InfraError::kWorkerCrashed;
    case refuzz::core::channel_contract::AbnormalKind::kInfraFault:
        // ERR_INVALID_INPUT / ERR_EXECUTOR_ERROR 都归 executor 层错误
        return proto::InfraError::kExecutorError;
    case refuzz::core::channel_contract::AbnormalKind::kNoResult:
    case refuzz::core::channel_contract::AbnormalKind::kCancelled:
    case refuzz::core::channel_contract::AbnormalKind::kChildAborted:
    case refuzz::core::channel_contract::AbnormalKind::kHarnessRecovered:
    case refuzz::core::channel_contract::AbnormalKind::kHarnessFatal:
    case refuzz::core::channel_contract::AbnormalKind::kUnknown:
        return proto::InfraError::kExecutorError;
    }
    return proto::InfraError::kExecutorError;
}

struct FrozenPrograms {
    std::optional<proto::FrozenProgramEntry> crash_program;
    std::vector<proto::FrozenProgramEntry>   history;
};

FrozenPrograms BuildFrozenPrograms(const refuzz::core::channel_contract::CrashScene& scene)
{
    FrozenPrograms out;
    if (scene.candidate_window.empty()) {
        return out;
    }
    const size_t crash_index = scene.candidate_window.size() - 1;
    for (size_t i = 0; i < scene.candidate_window.size(); ++i) {
        const auto& task = scene.candidate_window[i];
        proto::FrozenProgramEntry entry;
        entry.executor_id     = task.executor_id;
        entry.seed_id         = task.seed_id;
        entry.origin_seed_id  = task.origin_seed_id;
        entry.program_payload = task.payload;
        // [async-crash-reproduction Phase 1] carry the typed view so a
        // history/bisect/concat extract can be minimized downstream.
        entry.artifact        = task.artifact;
        if (i == crash_index) {
            out.crash_program = std::move(entry);
        } else {
            out.history.push_back(std::move(entry));
        }
    }
    return out;
}

proto::CombinedCrashEvent BuildCombinedFromFault(const refuzz::core::channel_contract::ChannelEvent& event)
{
    proto::CombinedCrashEvent combined;
    const auto* fault = event.AsFault();
    if (fault == nullptr) {
        return combined;
    }

    combined.incident_id = fault->incident_id != 0
        ? fault->incident_id
        : (event.event_id != 0 ? event.event_id : static_cast<uint64_t>(event.channel_id));

    auto programs = BuildFrozenPrograms(fault->scene);
    combined.crash_program = std::move(programs.crash_program);
    combined.history       = std::move(programs.history);

    // [v2 Epic 6 D-7 §3.10 fix — propagate artifact populated by
    //  channeldispatcher::AttachArtifactToEvent's Fault branch.
    //  Mirror BuildCombinedFromAbnormal:210 — same crash_origin_artifact
    //  slot, just sourced from the last candidate_window entry's
    //  ChannelTaskSnapshot.artifact instead of CompletionContext.artifact.
    //  Empty / missing-inflight stays nullptr (legacy fail-close parity).]
    if (!fault->scene.candidate_window.empty()) {
        combined.crash_origin_artifact =
            fault->scene.candidate_window.back().artifact;
    }

    if (combined.incident_id != 0) {
        proto::FaultEvent fe;
        fe.incident_id   = combined.incident_id;
        fe.channel_id    = event.channel_id;
        fe.slot_id       = 0;
        fe.generation    = fault->channel_ctx.generation;
        fe.reason        = MapFaultReason(fault->kind);
        fe.source        = proto::FaultSource::kChannelInternal;
        // §3.11-A — origin 透传：cc::FaultOrigin 与 proto::FaultOrigin
        // 数值同步（见 channel_contract.hpp + fault_event.hpp 注释），
        // 直接 static_cast 即可，下游 CrashContext.fault_origin 用来
        // gate evidence-coercion。
        fe.origin        = static_cast<proto::FaultOrigin>(fault->origin);
        fe.created_ts_us = NowUs();
        fe.crash_title   = fault->scene.console.title;
        fe.crash_console = fault->scene.console.console_output;
        if (combined.crash_program.has_value()) {
            fe.executor_id     = combined.crash_program->executor_id;
            fe.submit_ts_us    = combined.crash_program->submit_ts_us;
            fe.program_payload = combined.crash_program->program_payload;
        }
        combined.fault_event = std::move(fe);
    }

    // [v2 PR-B fault path 也填 combined.console_snapshot — 当前版本]
    // 跟 abnormal path 对称: BuildContextOp 第二分支吃 combined.console_snapshot,
    // 第一分支(fault path)目前只读 fault_event.crash_console。这里多写一份让
    // 两个分支都可统一从 combined.console_snapshot 读(便于将来 BuildContextOp 简化)。
    // 空字符串不写,避免覆盖 abnormal path 已写好的 snapshot。
    if (fault != nullptr && !fault->scene.console.console_output.empty()) {
        combined.console_snapshot = fault->scene.console.console_output;
    }
    return combined;
}

proto::CombinedCrashEvent BuildCombinedFromAbnormal(const refuzz::core::channel_contract::ChannelEvent& event)
{
    proto::CombinedCrashEvent combined;
    const auto* abnormal = event.AsAbnormal();
    if (abnormal == nullptr) {
        return combined;
    }
    const auto& ctx = abnormal->ctx;
    combined.incident_id = event.event_id != 0 ? event.event_id : ctx.executor_id;

    proto::FrozenProgramEntry crash_program;
    crash_program.executor_id     = ctx.executor_id;
    crash_program.seed_id         = ctx.seed_id;
    crash_program.origin_seed_id  = ctx.origin_seed_id;
    crash_program.program_payload = ctx.program_payload;
    crash_program.submit_ts_us    = ctx.submit_ts_us;

    proto::FrozenExecutionSummary summary;
    summary.worker_id    = ctx.worker_id;
    summary.result_code  = MapAbnormalToResultCode(abnormal->kind);
    summary.infra_error  = MapAbnormalToInfraError(abnormal->kind);
    summary.start_ts_us  = ctx.submit_ts_us;
    summary.finish_ts_us = NowUs();
    summary.crash_signal = abnormal->diagnostics.crash_signal;
    summary.output       = abnormal->output;
    crash_program.completion = std::move(summary);

    combined.crash_program = std::move(crash_program);
    // post-V1-retirement artifact-first universal contract:
    //   ctx.artifact 是 V2 typed authority；channeldispatcher 在 ForwardEvents
    //   注入 CompletionContext。直填 CombinedCrashEvent.crash_origin_artifact
    //   让 BuildContextOp 把它挂到 CrashContext.origin_artifact，repro/minimize
    //   不再走 reverse-decode（D-1）。
    combined.crash_origin_artifact = ctx.artifact;

    // [v2 PR-B abnormal console snapshot — 当前版本]
    // Channel 在 abnormal 触发时已从 ConsoleRingBuffer 取了最近若干行 console
    // 文本(EmitAbnormalCompletion / worker 上报 abnormal 两条路径都注入)。
    // 这里直接透传到 combined.console_snapshot,BuildContextOp 第二分支据此
    // 灌 ctx.console_log,落盘 report0 才有 [console] block。
    // 空 string 不写入 optional,避免下游误判"有 console 但是空字符串"。
    if (!abnormal->console_snapshot.empty()) {
        combined.console_snapshot = abnormal->console_snapshot;
    }
    return combined;
}

// [方案 A] program-child 自身 crash 现在走 **Completion**(覆盖有效,对齐 syz
// reply_execute(0)),诊断由 Completion::crash_diagnostic 旁路携带。这个 builder 从
// Completion 建 crash_payload —— 与 BuildCombinedFromAbnormal 等价,只是字段源换成
// Completion(ctx + crash_diagnostic + output),让 crash 记录照常落盘。
proto::CombinedCrashEvent BuildCombinedFromChildAbortCompletion(
    const refuzz::core::channel_contract::ChannelEvent& event)
{
    proto::CombinedCrashEvent combined;
    const auto* comp = event.AsCompletion();
    if (comp == nullptr || !comp->crash_diagnostic.has_value()) {
        return combined;
    }
    const auto& ctx = comp->ctx;
    combined.incident_id = event.event_id != 0 ? event.event_id : ctx.executor_id;

    proto::FrozenProgramEntry crash_program;
    crash_program.executor_id     = ctx.executor_id;
    crash_program.seed_id         = ctx.seed_id;
    crash_program.origin_seed_id  = ctx.origin_seed_id;
    crash_program.program_payload = ctx.program_payload;
    crash_program.submit_ts_us    = ctx.submit_ts_us;

    proto::FrozenExecutionSummary summary;
    summary.worker_id    = ctx.worker_id;
    // child-abort = program 行为致 child 退出,worker 健在 → 不升级为 kCrashed/worker_dead
    // (与旧 abnormal kChildAborted 的映射一致:kExecError / kExecutorError)。
    summary.result_code  = proto::ResultCode::kExecError;
    summary.infra_error  = proto::InfraError::kExecutorError;
    summary.start_ts_us  = ctx.submit_ts_us;
    summary.finish_ts_us = NowUs();
    summary.crash_signal = comp->crash_diagnostic->crash_signal;
    summary.output       = comp->output;
    crash_program.completion = std::move(summary);

    combined.crash_program = std::move(crash_program);
    combined.crash_origin_artifact = ctx.artifact;
    return combined;
}

uint32_t FaultKindToFlag(refuzz::core::channel_contract::FaultKind kind)
{
    switch (kind) {
    case refuzz::core::channel_contract::FaultKind::kKernelCrash:
        return kSignalFlagFaultKernelCrash;
    case refuzz::core::channel_contract::FaultKind::kNoOutput:
        return kSignalFlagFaultNoOutput;
    case refuzz::core::channel_contract::FaultKind::kVmDead:
        return kSignalFlagFaultVmDead;
    case refuzz::core::channel_contract::FaultKind::kWorkerDead:
        return kSignalFlagFaultWorkerHeartbeatLost;
    case refuzz::core::channel_contract::FaultKind::kHealthInternal:
        return 0;  // 无对应 fault-signal flag(不走 fuzzer fault 路径)
    }
    return 0;
}

} // namespace

SignalContribution FaultSignal::Sample(const refuzz::core::channel_contract::ChannelEvent& event)
{
    SignalContribution c;
    c.id   = Id();
    c.kind = Kind();

    if (event.IsFault()) {
        c.fired       = true;
        c.exec_flags  = kSignalFlagFaultObserved;
        const auto* fault = event.AsFault();
        if (fault != nullptr) {
            c.exec_flags |= FaultKindToFlag(fault->kind);
            // [v1 仅 kKernelCrash 注入 crash_payload — ROLLBACK: uncomment below, remove v2]
            // if (fault->kind == refuzz::core::channel_contract::FaultKind::kKernelCrash) {
            //     c.exec_code = proto::ResultCode::kCrashed;
            //     c.crash_payload = BuildCombinedFromFault(event);
            // } else {
            //     c.exec_code = proto::ResultCode::kExecError;
            // }
            // [v2 PR-C 所有 fault kind 都注入 crash_payload — 当前版本]
            // 旧版本只对 kKernelCrash fault 构造 crash_payload,kVmDead / kWorkerDead
            // fault 完全不进 crash pipeline,导致 HeartbeatSensor 真实判 worker_dead
            // / ConsoleSensor 真实判 vm_dead 的 incident 永远不会落盘到 diagnostics/
            // 对应 bucket。只有 abnormal completion path 走通,落盘 bucket 严重失真。
            // 现在所有 fault kind 都 BuildCombinedFromFault,exec_code 仍按 kind 分:
            //   kKernelCrash → kCrashed (语义上 program 行为致 kernel crash)
            //   其它(kVmDead/kWorkerDead) → kExecError (infra-fault,不归 program 错)
            // 下游 BuildContextOp 第一分支 / DedupOp / PersistOp 据 fault.kind 落到
            // 对应 CrashKind bucket。
            c.crash_payload = BuildCombinedFromFault(event);
            if (fault->kind == refuzz::core::channel_contract::FaultKind::kKernelCrash ||
                fault->kind == refuzz::core::channel_contract::FaultKind::kNoOutput) {
                c.exec_code = proto::ResultCode::kCrashed;
            } else {
                c.exec_code = proto::ResultCode::kExecError;
            }
        }
    } else if (event.IsAbnormal()) {
        const auto* abnormal = event.AsAbnormal();
        if (abnormal != nullptr) {
            c.exec_code = MapAbnormalToResultCode(abnormal->kind);
            // [v1 仅 kCrashed 注入 crash_payload — ROLLBACK: revert to gated]
            // if (c.exec_code == proto::ResultCode::kCrashed) {
            //     c.fired = true;
            //     c.crash_payload = BuildCombinedFromAbnormal(event);
            // }
            // [v2 PR-E 所有 diagnostic-worthy abnormal 都构造 crash_payload — 当前版本]
            // 旧版本只在 kCrashed (即 kWorkerSignaled abnormal) 时注入 crash_payload,
            // PR-A 把 child abort 改为 kChildAborted → kExecError 后,这类事件再也不
            // 进 crash pipeline。timeout 同理 → exec_timeout bucket 永远空。
            // 修复:让 kTimeout / kExecError / kChildAborted / kWorkerSignaled / kWorkerCrashed
            // 都走 BuildCombinedFromAbnormal,跳过 kCancelled (host 主动取消,不是 incident)。
            // BuildContextOp 第二分支据 result.result_code 分流到 exec_timeout / exec_error /
            // worker_dead bucket。is_crash 由 aggregator 仅看 exec_code == kCrashed 决定,
            // 不会因为多了 crash_payload 而错升级。
            if (abnormal->kind != refuzz::core::channel_contract::AbnormalKind::kCancelled) {
                c.fired = true;
                c.crash_payload = BuildCombinedFromAbnormal(event);
            }
        }
    } else if (event.IsCompletion()) {
        // [方案 A] program-child 自身 crash 现在是 Completion(覆盖走 KcovCoverageSignal
        // 正常消费),但它**也**是一个 crash 事实 —— 若带 crash_diagnostic,在此建
        // crash_payload 落盘,与旧 abnormal kChildAborted 路径等价。exec_code 保持
        // kExecError(program 行为致 child 退出,不是内核 crash);aggregator 只看
        // exec_code==kCrashed 定 is_crash,故不会把这次 completion 误升级成 crash 而
        // 污染 corpus admit。其余普通 Completion(无 crash_diagnostic)不 fire。
        const auto* comp = event.AsCompletion();
        if (comp != nullptr && comp->crash_diagnostic.has_value()) {
            c.fired = true;
            c.exec_code = proto::ResultCode::kExecError;
            c.crash_payload = BuildCombinedFromChildAbortCompletion(event);
        }
    }

    return c;
}

} // namespace refuzz::fuzzer

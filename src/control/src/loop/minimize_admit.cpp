// minimize admit / demux 实现(loop-home)。见 loop/minimize_admit.hpp。

#include "refuzz/control/loop/minimize_admit.hpp"

#include "refuzz/control/loop/elaboration_dispatch.hpp"  // DispatchElaboration
#include "refuzz/corpus/inbox.hpp"
#include "refuzz/feedback/observation/kernel_observation.hpp"
#include "refuzz/fuzzer/metrics/fuzzer_metrics.hpp"
#include "refuzz/mutator/mutator_engine.hpp"             // AnalyzeStateAltitude seam
#include "refuzz/program/artifact.hpp"
#include "refuzz/program/seed_metadata.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/proto_domain/types.hpp"

#include <cstdint>
#include <utility>
#include <vector>

namespace refuzz::control {

namespace {

using PerCallCandidate = refuzz::fuzzer::TriagePerCallCandidateMetadata::Candidate;

// PRE-minimize state altitude → shadow 元数据(shadow off 时零开销)。
void StampPreMinAltitude(
    JobDeps& deps, refuzz::fuzzer::Seed& dst,
    const std::shared_ptr<const refuzz::program::ProgramArtifact>& art)
{
    if (!deps.seed_value_shadow_enabled) {
        return;
    }
    if (!art || !art->valid() || !deps.mutator_handle.HasValue()) {
        return;
    }
    if (auto alt = deps.mutator_handle.Get().AnalyzeStateAltitude(*art)) {
        refuzz::fuzzer::SeedPreMinAltitudeMetadata m;
        m.resource_producers   = alt->resource_producers;
        m.resource_consumers   = alt->resource_consumers;
        m.distinct_kinds       = alt->distinct_kinds;
        m.max_dependency_depth = alt->max_dependency_depth;
        dst.metadata.Set(m);
    }
}

refuzz::proto::ResultCode ExecStatusOf(
    const refuzz::core::channel_contract::ChannelEvent& event)
{
    namespace cc = refuzz::core::channel_contract;
    if (event.IsCompletion()) {
        return refuzz::proto::ResultCode::kOk;
    }
    if (const auto* abnormal = event.AsAbnormal(); abnormal != nullptr) {
        // NOTE: AbnormalKind→ResultCode 的**第 3 份**拷贝(另两份在
        // feedback/signal/{fault,exec_result}_signal.cpp)。见 task「应收敛成单一权威」。
        switch (abnormal->kind) {
        case cc::AbnormalKind::kHang:
            return refuzz::proto::ResultCode::kTimeout;
        case cc::AbnormalKind::kWorkerCrashed:
        case cc::AbnormalKind::kWorkerSignaled:
            return refuzz::proto::ResultCode::kCrashed;
        case cc::AbnormalKind::kNoResult:
        case cc::AbnormalKind::kCancelled:
        case cc::AbnormalKind::kChildAborted:
        case cc::AbnormalKind::kHarnessRecovered:
        case cc::AbnormalKind::kHarnessFatal:
        case cc::AbnormalKind::kInfraFault:
        case cc::AbnormalKind::kUnknown:
            return refuzz::proto::ResultCode::kExecError;
        }
    }
    if (const auto* fault = event.AsFault(); fault != nullptr) {
        return (fault->kind == cc::FaultKind::kKernelCrash ||
                fault->kind == cc::FaultKind::kNoOutput)
            ? refuzz::proto::ResultCode::kCrashed
            : refuzz::proto::ResultCode::kExecError;
    }
    return refuzz::proto::ResultCode::kExecError;
}

// Stamp CorpusCoverageMetadata from the candidate alone — no verdict/artifact
// needed, since it's just the pre-minimize deflake stable cover/signal (same
// for the per-call and Extra cases; minimize never changes what gets stamped
// here, see the "cover storage is aligned with syz" note on ComputeCallCoverUnion).
void StampCorpusCoverageMetadata(refuzz::fuzzer::Seed& final_seed,
                                 const PerCallCandidate& candidate)
{
    refuzz::fuzzer::CorpusCoverageMetadata cc;
    cc.cover_hashes = candidate.cover_hashes;
    cc.signal_cover_hashes = candidate.stable_signal_hashes;
    cc.signal_hashes_are_edges = candidate.signal_hashes_are_edges;
    cc.signal_cover_prios = candidate.signal_cover_prios;
    if (!cc.cover_hashes.empty() || !cc.signal_cover_hashes.empty()) {
        final_seed.metadata.Set(std::move(cc));
    }
}

void StampPerCallCandidateMetadata(refuzz::fuzzer::Seed& final_seed,
                                   const refuzz::fuzzer::Seed& original_seed,
                                   const PerCallCandidate& candidate,
                                   const MinimizeDriver::StepVerdict* verdict,
                                   JobDeps& deps)
{
    // [Extra/-1 — syz Info.Extra as job.calls[-1]] there is no guilty CALL to
    //   remap/verify against the minimized program (prog.CallName(-1) =
    //   ExtraCallName, not indexable into final_prog->calls()). Stamp
    //   guilty_call_index=-1 directly from the candidate (already correct —
    //   Extra minimize never touches call indices) and skip the remap checks
    //   below, which only make sense for a real per-call target. Corpus cover
    //   accounting (the part that actually feeds Corpus PC/Edge total) doesn't
    //   depend on any of that, so it's stamped unconditionally either way.
    if (candidate.call_index < 0) {
        refuzz::fuzzer::TriageStableSignalMetadata stable_meta;
        stable_meta.hashes = candidate.stable_signal_hashes;
        stable_meta.guilty_call_index = -1;
        stable_meta.guilty_call_hashes = candidate.new_stable_signal_hashes;
        stable_meta.guilty_errno_value = candidate.errno_value;
        stable_meta.guilty_syscall_id = candidate.syscall_id;
        stable_meta.guilty_call_hashes_are_edges = candidate.signal_hashes_are_edges;
        if (const auto* pcm =
                original_seed.metadata.Get<refuzz::fuzzer::TriagePerCallCandidateMetadata>();
            pcm != nullptr && pcm->exec_status.has_value()) {
            stable_meta.exec_status = *pcm->exec_status;
        }
        final_seed.metadata.Set(std::move(stable_meta));
        StampCorpusCoverageMetadata(final_seed, candidate);
        return;
    }

    if (verdict == nullptr) {
        deps.logger.Log(
            "control.minimize",
            "minimize_remapped_guilty_no_verdict",
            {refuzz::logging::Field("seed_id", final_seed.seed_id),
             refuzz::logging::Field("original_call_index", candidate.call_index)});
        return;
    }
    const int remapped_call_index = verdict->remapped_guilty_call_index;
    if (remapped_call_index < 0) {
        deps.logger.Log(
            "control.minimize",
            "minimize_remapped_guilty_missing",
            {refuzz::logging::Field("seed_id", final_seed.seed_id),
             refuzz::logging::Field("original_call_index", candidate.call_index)});
        return;
    }
    if (final_seed.artifact == nullptr || !final_seed.artifact->valid()) {
        deps.logger.Log(
            "control.minimize",
            "minimize_remapped_guilty_no_artifact",
            {refuzz::logging::Field("seed_id", final_seed.seed_id),
             refuzz::logging::Field("original_call_index", candidate.call_index),
             refuzz::logging::Field("remapped_call_index", remapped_call_index)});
        return;
    }
    auto final_prog = final_seed.artifact->As<refuzz::program::syz::Prog>();
    if (final_prog == nullptr ||
        remapped_call_index >= static_cast<int>(final_prog->calls().size())) {
        deps.logger.Log(
            "control.minimize",
            "minimize_remapped_guilty_invalid",
            {refuzz::logging::Field("seed_id", final_seed.seed_id),
             refuzz::logging::Field("original_call_index", candidate.call_index),
             refuzz::logging::Field("remapped_call_index", remapped_call_index),
             refuzz::logging::Field(
                 "final_call_count",
                 static_cast<std::uint64_t>(
                     final_prog != nullptr ? final_prog->calls().size() : 0))});
        return;
    }

    refuzz::fuzzer::TriageStableSignalMetadata stable_meta;
    stable_meta.hashes = candidate.stable_signal_hashes;
    stable_meta.guilty_call_index = remapped_call_index;
    stable_meta.guilty_call_hashes = candidate.new_stable_signal_hashes;
    stable_meta.guilty_errno_value = candidate.errno_value;
    stable_meta.guilty_syscall_id = candidate.syscall_id;
    stable_meta.guilty_call_hashes_are_edges = candidate.signal_hashes_are_edges;
    if (const auto* pcm =
            original_seed.metadata.Get<refuzz::fuzzer::TriagePerCallCandidateMetadata>();
        pcm != nullptr && pcm->exec_status.has_value()) {
        stable_meta.exec_status = *pcm->exec_status;
    }
    final_seed.metadata.Set(std::move(stable_meta));
    StampCorpusCoverageMetadata(final_seed, candidate);
}

refuzz::fuzzer::Seed BuildAdmittedSeed(
    JobDeps&                            deps,
    const refuzz::fuzzer::Seed&         original_seed,
    MinimizeDriver::StepVerdict*        verdict,
    const PerCallCandidate*             finished_candidate)
{
    refuzz::fuzzer::Seed final_seed;
    final_seed.seed_id  = deps.next_seed_id++;
    final_seed.payload  = (verdict != nullptr && verdict->final_payload.has_value())
                        ? std::move(*verdict->final_payload)
                        : original_seed.payload;
    final_seed.artifact = (verdict != nullptr && verdict->final_artifact != nullptr)
                        ? verdict->final_artifact
                        : original_seed.artifact;
    final_seed.priority = original_seed.priority;
    {
        refuzz::fuzzer::SeedSourceMetadata src_meta{
            refuzz::fuzzer::SeedSource::kMutation, /*attempt=*/0};
        if (const auto* orig =
                original_seed.metadata.Get<refuzz::fuzzer::SeedSourceMetadata>()) {
            src_meta.source = orig->source;
        }
        final_seed.metadata.Set(src_meta);
    }
    final_seed.metadata.Set(refuzz::fuzzer::SeedAdmissionStateMetadata{});
    if (const auto* lin =
            original_seed.metadata.Get<refuzz::fuzzer::SeedLineageMetadata>()) {
        final_seed.metadata.Set(*lin);
    }
    if (const auto* sb =
            original_seed.metadata.Get<refuzz::fuzzer::SeedStabilityMetadata>()) {
        final_seed.metadata.Set(*sb);
    }
    StampPreMinAltitude(deps, final_seed, original_seed.artifact);

    if (finished_candidate != nullptr) {
        StampPerCallCandidateMetadata(
            final_seed, original_seed, *finished_candidate, verdict, deps);
    } else {
        const auto* orig_cc = original_seed.metadata
                .Get<refuzz::fuzzer::CorpusCoverageMetadata>();
        refuzz::fuzzer::CorpusCoverageMetadata cc;
        if (orig_cc != nullptr && !orig_cc->cover_hashes.empty()) {
            cc.cover_hashes = orig_cc->cover_hashes;
        } else if (verdict != nullptr) {
            cc.cover_hashes = std::move(verdict->final_cover);
        }
        if (orig_cc != nullptr) {
            cc.signal_cover_hashes = orig_cc->signal_cover_hashes;
            cc.signal_hashes_are_edges = orig_cc->signal_hashes_are_edges;
            cc.signal_cover_prios  = orig_cc->signal_cover_prios;
        }
        if (!cc.cover_hashes.empty() || !cc.signal_cover_hashes.empty()) {
            final_seed.metadata.Set(std::move(cc));
        }
    }
    return final_seed;
}

void PushAdmittedSeed(JobDeps& deps,
                      refuzz::fuzzer::Seed final_seed,
                      bool dispatch_elaboration,
                      std::uint64_t origin_executor_id)
{
    const std::uint64_t final_seed_id = final_seed.seed_id;
    refuzz::fuzzer::Seed followup_seed = final_seed;
    deps.corpus_inbox.TryPush(std::move(final_seed));
    if (dispatch_elaboration) {
        DispatchElaboration(deps, followup_seed, final_seed_id, origin_executor_id);
    }
}

} // namespace

void AdmitMinimizedSeed(
    JobDeps&                            deps,
    const refuzz::fuzzer::Seed&         original_seed,
    MinimizeDriver::StepVerdict&        verdict,
    const refuzz::fuzzer::TriagePerCallCandidateMetadata::Candidate* finished_candidate,
    std::uint64_t                       origin_executor_id)
{
    auto final_seed = BuildAdmittedSeed(
        deps, original_seed, &verdict, finished_candidate);
    PushAdmittedSeed(deps, std::move(final_seed),
                     /*dispatch_elaboration=*/true, origin_executor_id);
    if (deps.metrics.minimize_completed) {
        deps.metrics.minimize_completed->Inc();
    }
}

void AdmitStableSeed(
    JobDeps&                    deps,
    const refuzz::fuzzer::Seed& stable_seed,
    bool                        dispatch_elaboration,
    std::uint64_t               origin_executor_id)
{
    auto final_seed = BuildAdmittedSeed(
        deps, stable_seed, /*verdict=*/nullptr, /*finished_candidate=*/nullptr);
    PushAdmittedSeed(deps, std::move(final_seed),
                     dispatch_elaboration, origin_executor_id);
}

job::ExecResult ProjectExecResult(
    const refuzz::core::channel_contract::ChannelEvent& event,
    const refuzz::fuzzer::EngineOutput*                 out)
{
    job::ExecResult r;
    r.exec_status = static_cast<int>(ExecStatusOf(event));
    r.abnormal = event.IsAbnormal();
    if (const auto* ab = event.AsAbnormal(); ab != nullptr) {
        namespace cc = refuzz::core::channel_contract;
        switch (ab->kind) {
        case cc::AbnormalKind::kHang:
        case cc::AbnormalKind::kWorkerCrashed:
        case cc::AbnormalKind::kWorkerSignaled:
        case cc::AbnormalKind::kCancelled:
        case cc::AbnormalKind::kHarnessRecovered:
        case cc::AbnormalKind::kHarnessFatal:
            r.hard_stop = true;   // 没有任何有效结果可能 → 继续对这条(乃至同 worker 的)请求无意义
            break;
        case cc::AbnormalKind::kInfraFault:
        case cc::AbnormalKind::kUnknown:
            // 基础设施/配置错(ERR_INVALID_INPUT 是确定性的:重试必然同样失败)、
            // 协议错位 → 继续无意义,hard_stop。这修掉了旧 kExecError 一律
            // hard_stop=false 对"配置错会被无限重试"的隐患。
            r.hard_stop = true;
            break;
        case cc::AbnormalKind::kNoResult:
            // worker 健在,只是这次没产出 → 不整条中止,交给各 job 的空-replay 容忍。
            r.hard_stop = false;
            break;
        case cc::AbnormalKind::kChildAborted:
            // 程序自己 crash,worker 健在。注:kChildAborted 现在走 Completion 侧
            //（channel 把它归为 data-bearing),正常到不了本 Abnormal 分支;保留兜底。
            r.hard_stop = false;
            break;
        }
    }
    if (const auto* p = event.AsCompletion(); p != nullptr) {
        r.output = p->output;
    } else if (const auto* p = event.AsAbnormal(); p != nullptr) {
        r.output = p->output;
    }
    if (out != nullptr) {
        r.signal_hashes = out->new_signal_hashes;
        if (const auto* kco =
                out->observation.Get<refuzz::fuzzer::KernelExecutionObservation>()) {
            r.per_call.reserve(kco->per_call.size());
            for (const auto& call : kco->per_call) {
                r.per_call.push_back(job::CallSignal{
                    .coverage_hashes     = call.coverage_hashes,
                    .edge_hashes         = call.edge_hashes,
                    .novel_signal_hashes = call.novel_signal_hashes,  // [per-call novelty]
                    .errno_value         = call.errno_value,
                    .syscall_id          = call.syscall_id,
                    .fault_injected      = call.fault_injected,
                    .signal_priority     = call.signal_priority,
                });
            }
            r.extra_cover = kco->extra_cover;
            r.extra_signal_hashes = kco->extra_signal_hashes;
            r.extra_signal_hashes_are_edges = kco->extra_signal_hashes_are_edges;
            r.extra_novel_signal_hashes = kco->extra_novel_signal_hashes;  // [per-call novelty]
        }
    }
    return r;
}

} // namespace refuzz::control

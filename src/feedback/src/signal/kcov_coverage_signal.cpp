// Copyright 2026 reFuzz project author -------youngkk.

#include "refuzz/feedback/signal/kcov_coverage_signal.hpp"

#include "refuzz/feedback/coverage_semantics.hpp"             // [v2 G5] NormalizeCoverageEntries(per-call slice)
#include "refuzz/feedback/decode/syz_exec_result_decode.hpp"  // [v2 PR-Y/G5] decode SyzExecResult head + strict tail
#include "refuzz/feedback/observation/kernel_observation.hpp" // [v2 G5] KernelExecutionObservation
#include "refuzz/feedback/priority_calculator.hpp"            // [v2 PR-Y]
#include "refuzz/feedback/saturation_filter.hpp"              // [v2 G5]
#include "refuzz/feedback/signal_attributes.hpp"              // [v2 PR-Y]
#include "refuzz/fuzzer/interfaces.hpp"
#include "refuzz/logging/host_logger.hpp"
#include "refuzz/program/artifact.hpp"                        // [v2 PR-Y] ProgramArtifact + As<>()
#include "refuzz/program/syz/any.hpp"                         // [v2 PR-Y] call_contains_any
#include "refuzz/program/syz/prog.hpp"                        // [v2 PR-Y] syz::Prog / Call
#include "refuzz/program/syz/target.hpp"                      // [v2 PR-Y] linux_amd64()
#include "worker/backend/syz_exec_runner.hpp"                 // [v2 G5] SyzExecResult sizeof for tail compute

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace refuzz::fuzzer {

namespace {

void SortUniqueU64(std::vector<std::uint64_t>& values)
{
    std::sort(values.begin(), values.end());
    values.erase(std::unique(values.begin(), values.end()), values.end());
}

std::vector<std::uint64_t> ExtractOrderedKcovPacket(
    const std::vector<std::uint8_t>& payload)
{
    const std::size_t header_size = sizeof(refuzz::proto::WorkerFeedbackHeader);
    if (payload.size() < header_size) {
        return {};
    }

    refuzz::proto::WorkerFeedbackHeader hdr{};
    std::memcpy(&hdr, payload.data() + (payload.size() - header_size), header_size);
    if (hdr.magic != refuzz::proto::kWorkerFeedbackMagic ||
        hdr.version != refuzz::proto::kWorkerFeedbackVersion ||
        static_cast<refuzz::proto::FeedbackKind>(hdr.kind) !=
            refuzz::proto::FeedbackKind::kCoverageKcov) {
        return {};
    }

    const std::size_t cov_bytes =
        static_cast<std::size_t>(hdr.entry_count) * sizeof(std::uint64_t);
    if (payload.size() < header_size + cov_bytes) {
        return {};
    }

    const std::size_t cov_begin = payload.size() - header_size - cov_bytes;
    std::vector<std::uint64_t> raw(hdr.entry_count);
    if (cov_bytes > 0) {
        std::memcpy(raw.data(), payload.data() + cov_begin, cov_bytes);
    }
    return raw;
}

const char* CodecStatusName(ParseFeedbackStatus status)
{
    switch (status) {
    case ParseFeedbackStatus::kNoFeedback: return "no_feedback";
    case ParseFeedbackStatus::kOk: return "ok";
    case ParseFeedbackStatus::kMalformed: return "malformed";
    }
    return "unknown";
}

const char* EventKindName(
    refuzz::core::channel_contract::ChannelEvent::Kind kind)
{
    using Kind = refuzz::core::channel_contract::ChannelEvent::Kind;
    switch (kind) {
    case Kind::kCompletion: return "completion";
    case Kind::kAbnormal: return "abnormal";
    case Kind::kFault: return "fault";
    }
    return "unknown";
}

std::uint64_t ExecutorIdOf(
    const refuzz::core::channel_contract::ChannelEvent& event)
{
    if (const auto* c = event.AsCompletion(); c != nullptr) {
        return c->ctx.executor_id;
    }
    if (const auto* a = event.AsAbnormal(); a != nullptr) {
        return a->ctx.executor_id;
    }
    return 0;
}

} // namespace

// [v2 batch 3 G5] +ISaturationFilter& 参数。
KcovCoverageSignal::KcovCoverageSignal(IFeedbackStore& store,
                                       const IPriorityCalculator& priority_calculator,
                                       ISaturationFilter& saturation_filter,
                                       CoverageNormalizationConfig config)
    : store_(store)
    , priority_calculator_(priority_calculator)
    , saturation_filter_(saturation_filter)
    , codec_(config)
{}

SignalContribution KcovCoverageSignal::Sample(const refuzz::core::channel_contract::ChannelEvent& event)
{
    SignalContribution c;
    c.id   = Id();
    c.kind = Kind();

    // [v2 batch 3 PR-Y B2] 同时拿 ctx.artifact 给 SignalAttributes 反查用 —
    // Completion + Abnormal 两路径都支持(fault_signal.cpp:217 已有 abnormal
    // ctx.artifact 模板)。Sample 内本来就两路径都接 payload,artifact 跟 payload
    // 同源同时拿。
    std::vector<uint8_t> payload;
    std::shared_ptr<const refuzz::program::ProgramArtifact> artifact;
    // [align syz] from_abnormal:本次是**真正**的异常终止(task hang / worker 死 /
    // infra 故障等,event 落 Abnormal 侧)。这类执行的覆盖不并入全局 maxSignal、
    // 不 fire、不产 hashes(见下方 guard),只留 observation 供 crash 分析。
    //
    // 注意:program-child **自身 crash**(SIGSEGV/SIGABRT)现在是 **Completion**
    // (CompletionKind::kChildAborted) —— 用户态测试进程崩溃 ≠ 内核崩溃,crash 前
    // 已提交到 KCOV 的覆盖有效,对齐 syzkaller reply_execute(0) 当 Success 消费覆盖。
    // 所以它走下面 IsCompletion 分支、from_abnormal=false,覆盖正常计入;crash 事实
    // 由 Completion::crash_diagnostic 旁路交给 FaultSignal 落盘,两不误。
    bool from_abnormal = false;
    if (event.IsCompletion()) {
        const auto* p = event.AsCompletion();
        if (p != nullptr) {
            payload  = p->output;
            artifact = p->ctx.artifact;
        }
    } else if (event.IsAbnormal()) {
        from_abnormal = true;
        const auto* p = event.AsAbnormal();
        if (p != nullptr) {
            payload  = p->output;
            artifact = p->ctx.artifact;
        }
    } else {
        // Fault 事件无 output, 不参与 coverage 评估
        return c;
    }

    if (payload.empty()) {
        c.decoded.exec_status = proto::ResultCode::kOk;
        c.decoded.flags      |= proto::kFeedbackFlagEmptyCoverage;
        // [v2 batch 3 G5 P1 fix] **non-malformed 路径必须 set observation**
        // (plan §3.G5 修正 #4 / Observation policy 表)。empty payload 等价
        // kNoFeedback + 没 prog 上下文 — 写 empty KernelExecutionObservation,
        // consumer 自决 size==0 vs missing。
        c.observation.Set(KernelExecutionObservation{});
        return c;
    }

    // 反查 ctx.artifact → syz::Prog。priority 不再按整程序 OR 计算,而是在
    // per-call MergeCoverage 时按当前 syscall 计算,对齐 syzkaller signalPrio(call)。
    // artifact 为 null / cast 失败 / decode 失败不会构造 per-call admit 信息;若后续
    // 存在 coverage signal 却没有 per-call observation,下面 coverage_without_per_call
    // 会 log + malformed return。
    std::shared_ptr<const refuzz::program::syz::Prog> prog_view =
        artifact ? artifact->As<refuzz::program::syz::Prog>() : nullptr;
    const refuzz::program::syz::Prog* prog = prog_view.get();
    const refuzz::program::syz::Target* target = nullptr;
    if (prog != nullptr) {
        target = prog->target();
        if (target == nullptr) {
            target = &::refuzz::program::syz::Target::linux_amd64();
        }
    }

    // [v2 batch 3 G5] codec.Extract:剥尾部 KCOV packet → c.decoded.cov_hashes(normalized)。
    // 副作用:
    //   - kOk         → payload 缩到 residual = [SyzExecResult × n][uint64 × tail]
    //   - kNoFeedback → payload **未动**(magic/version 不对 / 非 KCOV 区段)
    //   - kMalformed  → payload 状态 unspecified
    const auto extra_cover_ordered_raw = ExtractOrderedKcovPacket(payload);
    const auto codec_status = codec_.Extract(&payload, &c.decoded);
    if (codec_status == ParseFeedbackStatus::kMalformed) {
        c.malformed = true;
        c.decoded.flags |= proto::kFeedbackFlagMalformedCoverage;
        return c;  // malformed:**不**写 observation(payload 不可信)
    }

    // [remote-kcov] Snapshot the program-level EXTRA / remote cover BEFORE the
    // per-call slices get folded into c.decoded.cov_hashes below. After Extract,
    // c.decoded.cov_hashes holds exactly the peeled task-end kCoverageKcov packet
    // = the async (khubd / softirq / kthread) coverage, as raw KCOV PC (Extract →
    // NormalizeCoverageEntries keeps raw PC, NOT edges, in both PC and edge mode).
    // Empty on the kNoFeedback path (worker emitted no task-end packet). This is
    // the reFuzz analog of syzkaller's Info.Extra.Cover; it is carried on the
    // observation (extra_cover) so the corpus COVER can union it in, while staying
    // out of per_call so per-syscall attribution remains exact.
    std::vector<std::uint64_t> extra_cover_raw = c.decoded.cov_hashes;
    std::vector<std::uint64_t> extra_signal_hashes;
    if (codec_.config().cover_edges &&
        CoverageEntriesPassSignalFilter(extra_cover_ordered_raw, codec_.config())) {
        extra_signal_hashes = ComputeEdgeSignal(extra_cover_ordered_raw);
        SortUniqueU64(extra_signal_hashes);
    } else {
        extra_signal_hashes = extra_cover_raw;
    }
    std::vector<std::uint64_t> program_pc_union = extra_cover_raw;
    std::vector<std::uint64_t> program_edge_union;
    if (codec_.config().cover_edges) {
        program_edge_union = extra_signal_hashes;
    }

    bool per_call_decode_attempted = false;
    bool per_call_decode_succeeded = false;

    // [v2 batch 3 G5 + PR-X step 5 wire-up] 所有 non-malformed 路径**都 build
    // KernelExecutionObservation** 写进 c.observation,即便 fired=false。
    // 详 plan §3.G5 修正 #4 (Observation policy 总结表)。
    {
        const std::size_t n_calls = prog ? prog->calls().size() : 0;
        KernelExecutionObservation kco;
        if (prog != nullptr && n_calls > 0) {
            const std::size_t head_bytes = n_calls * sizeof(refuzz::worker::SyzExecResult);
            if (codec_status == ParseFeedbackStatus::kOk) {
                per_call_decode_attempted = true;
                // residual 干净(packet 已剥)→ strict mode decode 安全。
                const std::size_t expected_tail = (payload.size() >= head_bytes)
                    ? (payload.size() - head_bytes) / sizeof(std::uint64_t)
                    : 0;
                auto dec = ::refuzz::feedback::decode::DecodeSyzExecResultsWithCoverage(
                    std::span<const std::uint8_t>(payload.data(), payload.size()),
                    n_calls,
                    expected_tail);
                if (!dec.results.empty()) {
                    per_call_decode_succeeded = true;
                    kco.per_call.reserve(n_calls);
                    // [remote-kcov S2] codec.Extract set c.decoded.cov_hashes to
                    // the peeled kCoverageKcov packet. In PC mode that packet is
                    // the program-level EXTRA (remote/softirq/kthread) cover —
                    // ADDITIVE to the per-call synchronous cover in the tail, NOT
                    // a superset of it (mirrors syzkaller info.Extra.Cover). So
                    // we must union the per-call slices INTO cov_hashes rather
                    // than leaving it as extra-only — else MergeCoverage below
                    // would lose all synchronous syscall coverage. (Legacy
                    // task-end full-coverage packets remain a superset of the
                    // per-call slices, so this union is a no-op for them.)
                    for (std::size_t i = 0; i < n_calls; ++i) {
                        const auto& r = dec.results[i];
                        // raw per-call slice → normalized(同 codec config)。
                        std::vector<std::uint64_t> raw_slice;
                        const std::size_t end = static_cast<std::size_t>(r.cover_offset) +
                                                static_cast<std::size_t>(r.cover_count);
                        if (r.cover_count > 0 && end <= dec.coverage_tail.size()) {
                            raw_slice.assign(
                                dec.coverage_tail.begin() + r.cover_offset,
                                dec.coverage_tail.begin() + end);
                        }
                        // [P2] admission unit = edge signal, derived from the
                        // ORDERED raw_slice BEFORE NormalizeCoverageEntries sorts
                        // it. observation/corpus_pc keep raw PC (norm_slice) below.
                        std::vector<std::uint64_t> adm_slice;
                        if (codec_.config().cover_edges &&
                            CoverageEntriesPassSignalFilter(raw_slice, codec_.config())) {
                            adm_slice = ComputeEdgeSignal(raw_slice);
                        }
                        auto norm_slice = NormalizeCoverageEntries(std::move(raw_slice),
                                                                    codec_.config());
                        std::uint32_t syscall_id = 0;
                        const auto& call_uniq = prog->calls()[i];
                        if (call_uniq && call_uniq->meta() != nullptr) {
                            syscall_id = static_cast<std::uint32_t>(call_uniq->meta()->id());
                        }
                        program_pc_union.insert(program_pc_union.end(),
                                                norm_slice.begin(), norm_slice.end());
                        program_edge_union.insert(program_edge_union.end(),
                                                  adm_slice.begin(), adm_slice.end());
                        const bool executed =
                            (r.flags & ::refuzz::worker::kCallFlagExecuted) != 0;
                        // [job-loop Step 4a] sibling flag bit — zero re-decode, r.flags
                        // already in hand. Feeds per_call[i].fault_injected for the
                        // fault-inject job's dependent-loop continue/break decision.
                        const bool fault_injected =
                            (r.flags & ::refuzz::worker::kCallFlagFaultInjected) != 0;
                        kco.per_call.push_back({
                            std::move(norm_slice),
                            r.err,
                            syscall_id,
                            executed,
                            fault_injected,
                            std::move(adm_slice),  // [PR3] per-call EDGE signal (cover_edges)
                        });
                    }
                }
                // dec.results 空 → strict decode 失败(eg. corrupted cover_offset/count
                // 越界);保 kco.per_call empty。若本次仍有 coverage signal,下面会
                // 记录 coverage_without_per_call 并 fail-loud。
            } else {  // kNoFeedback — PC mode (per-syscall coverage in tail)
                per_call_decode_attempted = true;
                // [当前补丁] PC mode worker 不再 emit task-end kCoverageKcov packet
                // (kcov_sink.cpp:161-167 注释直说 "PC coverage is owned by
                // KernelWireDriver's per-call SyzExecResult tail");per-syscall
                // coverage 通过 SyzExecResult.cover_offset/count 切片 + uint64
                // coverage_tail 落到 payload。这里做 WithCoverage decode,跟 kOk
                // 分支同样 normalize 后填 kco.per_call[i].coverage_hashes,保持
                // syzkaller per-syscall 语义。
                //
                // program-level cov_hashes 是这些 per-call slices 的 normalized
                // union,只为 store_.MergeCoverage 统计 new_cov_total —— **采集
                // 粒度仍是 per-syscall**,union 只是 accounting 副产品。
                const std::size_t expected_tail =
                    (payload.size() >= head_bytes)
                        ? (payload.size() - head_bytes) / sizeof(std::uint64_t)
                        : 0;
                auto dec = ::refuzz::feedback::decode::DecodeSyzExecResultsWithCoverage(
                    std::span<const std::uint8_t>(payload.data(), payload.size()),
                    n_calls,
                    expected_tail);
                if (!dec.results.empty()) {
                    per_call_decode_succeeded = true;
                    kco.per_call.reserve(n_calls);
                    for (std::size_t i = 0; i < n_calls; ++i) {
                        const auto& r = dec.results[i];
                        std::vector<std::uint64_t> raw_slice;
                        const std::size_t end =
                            static_cast<std::size_t>(r.cover_offset) +
                            static_cast<std::size_t>(r.cover_count);
                        if (r.cover_count > 0 && end <= dec.coverage_tail.size()) {
                            raw_slice.assign(
                                dec.coverage_tail.begin() + r.cover_offset,
                                dec.coverage_tail.begin() + end);
                        }
                        // [P2] admission unit = edge signal from ORDERED raw_slice
                        // (pre-sort); observation/corpus_pc keep raw PC below.
                        std::vector<std::uint64_t> adm_slice;
                        if (codec_.config().cover_edges &&
                            CoverageEntriesPassSignalFilter(raw_slice, codec_.config())) {
                            adm_slice = ComputeEdgeSignal(raw_slice);
                        }
                        auto norm_slice = NormalizeCoverageEntries(
                            std::move(raw_slice), codec_.config());
                        std::uint32_t syscall_id = 0;
                        const auto& call_uniq = prog->calls()[i];
                        if (call_uniq && call_uniq->meta() != nullptr) {
                            syscall_id = static_cast<std::uint32_t>(
                                call_uniq->meta()->id());
                        }
                        program_pc_union.insert(program_pc_union.end(),
                                                norm_slice.begin(), norm_slice.end());
                        program_edge_union.insert(program_edge_union.end(),
                                                  adm_slice.begin(), adm_slice.end());
                        const bool executed =
                            (r.flags & ::refuzz::worker::kCallFlagExecuted) != 0;
                        // [job-loop Step 4a] sibling flag bit — zero re-decode, r.flags
                        // already in hand. Feeds per_call[i].fault_injected for the
                        // fault-inject job's dependent-loop continue/break decision.
                        const bool fault_injected =
                            (r.flags & ::refuzz::worker::kCallFlagFaultInjected) != 0;
                        kco.per_call.push_back({
                            std::move(norm_slice),
                            r.err,
                            syscall_id,
                            executed,
                            fault_injected,
                            std::move(adm_slice),  // [PR3] per-call EDGE signal (cover_edges)
                        });
                    }
                }
                // dec.results 空(truncated payload / 严重 corrupted)→ kco.per_call
                // empty。若本次仍有 coverage signal,下面会记录
                // coverage_without_per_call 并 fail-loud。
            }
        }

        SortUniqueU64(program_pc_union);
        SortUniqueU64(program_edge_union);
        kco.program_raw_pcs = program_pc_union;
        kco.program_edge_hashes = program_edge_union;

        // [remote-kcov] attach the program-level EXTRA/remote cover (raw PC),
        // distinct from per_call. corpus_verify/triage union it into the corpus
        // COVER; per-call attribution never sees it.
        kco.extra_cover = std::move(extra_cover_raw);
        kco.extra_signal_hashes = std::move(extra_signal_hashes);
        kco.extra_signal_hashes_are_edges = codec_.config().cover_edges;

        // **永远 set,即便 empty**。artifact null / n_calls==0 / decode 失败时
        // kco.per_call 留 empty;若同时存在 coverage signal,下面记录诊断并返回
        // malformed,避免隐藏 per-call 链路错误。
        c.observation.Set(std::move(kco));
    }

    c.decoded.cov_hashes = codec_.config().cover_edges
        ? std::move(program_edge_union) : std::move(program_pc_union);

    if (c.decoded.cov_hashes.empty()) {
        // 没有覆盖数据(codec malformed / payload truncated / dec.results empty
        // / 无 per-call tail bytes):observation 已 set,fired 仍 false。**不**跑
        // saturation/store。
        //
        // 注意 kNoFeedback 不再单独 early-return —— PC mode 走 kNoFeedback 是正
        // 常路径(worker 不发 task-end packet),只要 kNoFeedback 分支成功
        // decode 出 per-call tail 并 union 进 cov_hashes,就应该跟 kOk 一样跑
        // saturation + MergeCoverage。
        return c;
    }

    auto* kco = c.observation.Get<KernelExecutionObservation>();
    if (kco == nullptr || kco->per_call.empty()) {
        refuzz::logging::HostLogger::Instance().Log(
            "feedback.kcov",
            "coverage_without_per_call",
            {refuzz::logging::Field("executor_id", ExecutorIdOf(event)),
             refuzz::logging::Field("event_kind", EventKindName(event.kind)),
             refuzz::logging::Field("codec_status", CodecStatusName(codec_status)),
             refuzz::logging::Field("has_artifact", artifact != nullptr),
             refuzz::logging::Field("has_syz_prog", prog != nullptr),
             refuzz::logging::Field("n_calls", static_cast<std::uint64_t>(
                 prog != nullptr ? prog->calls().size() : 0)),
             refuzz::logging::Field("per_call_decode_attempted", per_call_decode_attempted),
             refuzz::logging::Field("per_call_decode_succeeded", per_call_decode_succeeded),
             refuzz::logging::Field("signal_hashes", c.decoded.cov_hashes.size()),
             refuzz::logging::Field("extra_cover", kco != nullptr ? kco->extra_cover.size() : 0),
             refuzz::logging::Field("extra_signal", kco != nullptr ? kco->extra_signal_hashes.size() : 0),
             refuzz::logging::Field("payload_bytes_after_extract", payload.size())});
        c.malformed = true;
        c.decoded.flags |= proto::kFeedbackFlagMalformedCoverage;
        return c;
    }

    // [align syz — 异常执行的覆盖不进 maxSignal] 对齐 syzkaller:Hanged 主动 dontTriage
    // (fuzzer.go:153)、Crashed 的 Result 不带 Info(runner.go:589)→ 异常终止的覆盖
    // **既不 addRawMaxSignal、也不进 corpus**(只供 crash 分析)。此前 reFuzz 对 abnormal
    // 仍 MergeCoverage,会把异常运行的 PC "预先认领"进全局 maxSignal,压低之后**正常**
    // 种子覆盖同样 PC 时的 new-cov gain → 漏 admit;deflake 也不应把异常运行的覆盖算进
    // stable signal。故 abnormal 在此**提前返回**:observation 已建好(per-call cover 留给
    // crash pipeline),但 c.fired=false、c.hashes 空、不调 MergeCoverage —— 异常运行对
    // 覆盖信号完全 inert(在 corpus_verify/triage 里贡献空 hashes,自然打破 stability)。
    // partial(kPartial)是 IsCompletion 非 abnormal,覆盖照常计入,不受影响。
    if (from_abnormal) {
        return c;
    }

    // [v2 batch 3 G5] saturation gate — 在 max-signal merge 之前。
    // 返值语义(plan Arch A'):
    //   nullopt        → no drop,caller 用原 program-level c.decoded.cov_hashes
    //                    (byte-equal 严格保;baseline ctest 自然不破)
    //   decision.hashes non-empty → 部分 drop;caller 用 filtered(sort+unique
    //                               accepted union),并用 keep_calls 精确决定
    //                               哪些 per-call signal 参与 admission
    //   decision.hashes empty     → 全 drop;c.fired=false return(避免 coverage_empty
    //                               误记 + interesting=true 虚假信号;详 plan D3)
    std::optional<SaturationDecision> saturation_decision;
    if (codec_.config().cover_edges) {
        // [P2/P6] admission on edge signal. The saturation filter (P6) counts
        // raw-PC slice sizes against the per-call observation (which stays raw PC
        // for triage/corpus_pc) — it cannot gate the edge admission union, and its
        // per-syscall 10000-hash drop must not discard genuinely-new coverage from
        // the corpus-admission path. Feed cov_hashes (edges) straight to MergeCoverage.
        c.hashes = c.decoded.cov_hashes;
    } else {
        saturation_decision = saturation_filter_.Filter(
            c.observation,
            std::span<const std::uint64_t>(c.decoded.cov_hashes.data(),
                                           c.decoded.cov_hashes.size()));
        if (saturation_decision.has_value()) {
            if (saturation_decision->hashes.empty()) {
                // 全 drop — observation 已 set,fired 仍 false return。
                return c;
            }
            c.hashes = saturation_decision->hashes;
        } else {
            // no drop — byte-equal preserve(plan Arch A' 关键)
            c.hashes = c.decoded.cov_hashes;
        }
    }

    c.fired = true;

    // [per-call novelty — syz triageProgCall/addRawMaxSignal parity]
    // Do NOT merge c.hashes as one program-level union and then reverse-assign
    // novelty to calls. That hides attribution bugs and can make every stable
    // call that touched a shared edge look like a new-signal candidate. Instead,
    // consume the max-signal store in syscall order, exactly like syzkaller's
    // processResult/deflake path calls triageProgCall per call. The call whose
    // signal grows/upgrades the store owns that novel signal.
    std::size_t gain = 0;
    c.novel_hashes.clear();

    auto append_novel = [&](const std::vector<std::uint64_t>& values) {
        c.novel_hashes.insert(c.novel_hashes.end(), values.begin(), values.end());
    };

    auto call_prio = [&](std::size_t i, const KernelCallObservation& call)
        -> std::uint8_t {
        SignalAttributes attrs;
        attrs.execution_succeeded = call.executed && call.errno_value == 0;
        attrs.involves_special_input = false;
        if (prog != nullptr && target != nullptr && i < prog->calls().size()) {
            const auto& call_ptr = prog->calls()[i];
            if (call_ptr != nullptr) {
                attrs.involves_special_input =
                    ::refuzz::program::syz::call_contains_any(*target, *call_ptr);
            }
        }
        return priority_calculator_.Calculate(attrs);
    };

    auto merge_signal = [&](const std::vector<std::uint64_t>& signal,
                            std::uint8_t prio,
                            std::vector<std::uint64_t>* novel) {
        if (novel != nullptr) {
            novel->clear();
        }
        if (signal.empty()) {
            return;
        }
        std::vector<std::uint64_t> local_novel;
        gain += store_.MergeCoverage(signal, prio, &local_novel);
        if (novel != nullptr) {
            *novel = local_novel;
        }
        append_novel(local_novel);
    };

    for (std::size_t i = 0; i < kco->per_call.size(); ++i) {
        auto& call = kco->per_call[i];
        const std::uint8_t priority = call_prio(i, call);
        call.signal_priority = priority;
        if (!codec_.config().cover_edges && saturation_decision.has_value() &&
            (i >= saturation_decision->keep_calls.size() ||
             !saturation_decision->keep_calls[i])) {
            call.novel_signal_hashes.clear();
            continue;
        }
        if (codec_.config().cover_edges) {
            merge_signal(call.edge_hashes, priority, &call.novel_signal_hashes);
        } else {
            merge_signal(call.coverage_hashes, priority, &call.novel_signal_hashes);
        }
        SortUniqueU64(call.novel_signal_hashes);
    }
    // Extra/remote coverage is the syzkaller Info.Extra analog (call=-1).
    // It has its own admission-unit signal: edges in cover_edges mode, raw PCs
    // otherwise. When PC-mode saturation returned a filtered per-call union,
    // keep the old drop semantics and do not re-add Extra.
    if (codec_.config().cover_edges || !saturation_decision.has_value()) {
        merge_signal(kco->extra_signal_hashes, /*prio=*/0, &kco->extra_novel_signal_hashes);
        SortUniqueU64(kco->extra_novel_signal_hashes);
    }

    SortUniqueU64(c.novel_hashes);
    c.magnitude   = static_cast<uint64_t>(gain);
    c.interesting = (gain > 0);
    return c;
}

} // namespace refuzz::fuzzer

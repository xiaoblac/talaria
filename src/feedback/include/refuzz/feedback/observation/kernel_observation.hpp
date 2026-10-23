// Copyright 2026 reFuzz project author -------youngkk.
//
// KernelExecutionObservation —— kernel family 的 transient per-event observation。
//
// 装本次 event 的 per-call 信息(coverage hashes / errno / syscall_id),通过
// `SignalContribution.observation` → `EngineOutput.observation` 流转给 dispatcher
// / 后续 stage(G5 saturation / PR-Y prio 都消费这里)。
//
// **transient**:不持久化到 disk(PR-X 默认不 materialize 进 Seed.metadata)。
// 持久化决策(identity copy → SeedMetadataSerdeRegistry)留独立 PR;详
// docs/admit-pipeline-alignment/300_batch3_kernel_profile_stages.md §3.PR-X 修正 4。
//
// 跟 program/seed_metadata.hpp 区分:
//   - program/ = IR(intent — Call/Prog/Arg etc.)
//   - feedback/observation/ = observation(actuality — coverage / errno / 等)
// 此 header 住 feedback/observation/ 是 P8 原则的体现(observation 不进 program/)。

#pragma once

#include <cstdint>
#include <vector>

namespace refuzz::fuzzer {

// 单 call 的 KCOV PC slice + 执行 errno + 反查到的 syscall 类型 id。
// host 端 KcovCoverageSignal::Sample 在 decode worker output 时构造一份。
struct KernelCallObservation {
    std::vector<std::uint64_t> coverage_hashes;  // 该 call 的 KCOV PC entries(可空)
    std::int32_t               errno_value = 0;  // SyzExecResult.err
    std::uint32_t              syscall_id  = 0;  // SyscallMeta::id (host 反查 ProgramArtifact)
    // [2026-05-13 P1 fix-2] 该 slot 是否 driver 真 Dispatch 过(=kCallFlagExecuted)。
    // false → empty_call slot,可能来自 Forking executor partial fallback 后半段未
    // 执行的 syscall;errno_value/coverage_hashes 都是 zero-init 的占位,**不应**
    // 当真 success 参与 prio / saturation 统计。下游消费者要区分时,先看 executed。
    bool                       executed    = false;
    // [job-loop Step 4a] 该 call 是否命中 fault injection(=kCallFlagFaultInjected)。
    // executed 的姊妹位(同一份 SyzExecResult.flags,同一处 decode,零重解):bit 0 =
    // Executed,bit 3 = FaultInjected。fault-inject job 读 per_call[call_index].fault_injected
    // 判"内核是否还在这个注入点触发过 fault"→ 决定依赖循环 continue/break(等价旧
    // FaultInjectionConsumer 的 `decoded[call_index].flags & kCallFlagFaultInjected`)。
    bool                       fault_injected = false;
    // [PR3 per-element edge prio] 该 call 的 EDGE signal(cover_edges 模式下 = adm_slice
    // = pc^mix(prev));空 = PC mode 或无边。triage/verify 用它把"每条边由哪个 call 命中"
    // 关联起来,从而给每条边算 syz-style 优先级(errno==0 的成功 call → 高优先),供
    // 边-一致 corpus 最小化按"每边最优拥有者"裁剪(port syz signal.Minimize 的 per-element prio)。
    std::vector<std::uint64_t> edge_hashes{};
    // [per-call novelty attribution — syz triageProgCall parity] the subset of this
    // call's signal (edge_hashes in cover_edges mode, else coverage_hashes) that was
    // brand-new / prio-upgraded in the global max-signal store on THIS exec — i.e. the
    // signal THIS call first-owned. Computed by KcovCoverageSignal::Sample doing a
    // per-call MergeCoverage in call order (each edge claimed by the first owning call),
    // mirroring syz's per-call addRawMaxSignal. Empty for calls that added nothing new
    // (or on stable re-exec replays where the store already holds the signal). This is
    // the per-call `newSignal` reFuzz previously collapsed into a program-level union.
    std::vector<std::uint64_t> novel_signal_hashes{};
    // Exact priority used when this call's signal was merged into max-signal.
    // Deflake/minimize must preserve it instead of reducing signal to hash presence.
    std::uint8_t signal_priority = 0;
};

// 全 program 的 per-call observation;`per_call.size()` 跟 ProgramArtifact.calls()
// 顺序对齐(`per_call[i]` 对应第 i 次 dispatch 的 syscall)。
struct KernelExecutionObservation {
    std::vector<KernelCallObservation> per_call;
    // Full per-program measurement sets, already deduplicated by feedback.
    // Control and telemetry consume these directly and must not re-sort/re-dedup.
    std::vector<std::uint64_t> program_raw_pcs;
    std::vector<std::uint64_t> program_edge_hashes;
    // [remote-kcov] Program-level EXTRA / remote cover — async coverage produced
    // in kernel worker threads (kcov_remote: USB khubd enumeration + driver bind,
    // softirq RX, RCU/kthread) that is NOT attributable to any single syscall.
    // Mirrors syzkaller `Info.Extra` (call index -1). Kept OUT of `per_call` on
    // purpose: per-call minimize/prio/saturation stay exact (they never see an
    // unattributable PC), while the corpus COVER (corpus_pc) unions it in as a
    // program-level quantity. Raw KCOV PC (normalized), same basis as
    // per_call[i].coverage_hashes. Empty when the worker emitted no task-end
    // remote packet (no async coverage / PC-mode-only program).
    std::vector<std::uint64_t> extra_cover;
    // Admission-unit signal for EXTRA/remote. In raw-PC mode this is the normalized
    // extra_cover; in edge mode it is the syzkaller-style edge signal computed from
    // the ordered raw Extra PCs. This keeps corpus COVER (raw PC) separate from
    // max-signal/admission (edge or PC), matching per_call.coverage_hashes vs
    // per_call.edge_hashes.
    std::vector<std::uint64_t> extra_signal_hashes;
    bool extra_signal_hashes_are_edges = false;
    // [per-call novelty] EXTRA/remote (syz Info.Extra, call index -1) novel signal on
    // THIS exec — the program-level analog of per_call[i].novel_signal_hashes for the
    // unattributable async coverage. Feeds the deflake chased-call map's
    // call_index=-1 entry.
    std::vector<std::uint64_t> extra_novel_signal_hashes;
};

}  // namespace refuzz::fuzzer

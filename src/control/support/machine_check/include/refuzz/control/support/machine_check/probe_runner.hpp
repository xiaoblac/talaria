// Copyright 2026 reFuzz project author -------youngkk.
//
// [machine-check C4.2b] Trial-exec runner primitives — the host-side pieces
// that ride reFuzz's STANDARD data plane (NOT a bespoke channel driver):
//
//     HostFuzzTask ─push─> InMemoryTaskQueue ─> Executor (channeldispatcher)
//        ▲ artifact-first                              │ submits + lowers exec-wire
//        │                                             ▼
//     BuildProbeTask                            ChannelEvent (Completion)
//                                                      │ pop, match by executor_id
//                                                      ▼
//                                            DecodeProbeCompletion ─> per-call errno
//
// This module supplies only the two pure, VM-free primitives:
//   * BuildProbeTask     — wrap a probe program in the standard HostFuzzTask
//                          carrier (artifact-first, exactly like the mutator
//                          engine: BuildProbeProgram → assign_sizes_prog →
//                          MakeArtifactFromTypedProg). The Executor service
//                          lowers it to exec-wire from the artifact; we never
//                          touch IChannel here.
//   * DecodeProbeCompletion — read the per-call errno block at the head of a
//                          completion's output buffer.
//
// The actual push-to-task_queue / pop-from-event_queue drive loop is the
// machine-check orchestration phase in the control/ loop (C4.6), which is the
// only place that owns the queues + Executor. ENOSYS interpretation (errno ⇒
// unsupported) is C4.3. See docs/plans/machine-check.md.

#pragma once

#include "refuzz/program/syz/prog.hpp"        // Prog (pre-built probe batch)
#include "refuzz/program/syz/target.hpp"      // Target, SyscallMeta
#include "refuzz/queue/host_fuzz_task.hpp"    // HostFuzzTask

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace refuzz::control::support::machine_check {

namespace syz = ::refuzz::program::syz;

// Per-call trial result decoded from a probe program's completion. Raw signal
// only — interpretation (ENOSYS/EAFNOSUPPORT ⇒ unsupported) is C4.3, not here.
struct ProbeCallResult {
    const syz::SyscallMeta* meta     = nullptr;  // i-th non-null meta of the batch
    bool                    executed = false;    // kCallFlagExecuted set?
    int                     err      = 0;        // SyzExecResult.err (errno)
    std::int64_t            ret      = 0;        // SyzExecResult.ret
};

// Build a standard data-plane task carrying a probe program: one default-arg
// call per non-null meta, order-preserving (null metas skipped — see
// BuildProbeProgram). Artifact-first like the mutator engine; the Executor
// lowers it to exec-wire from the artifact. The caller pushes the returned task
// onto the InMemoryTaskQueue. `executor_id` MUST be nonzero (InMemoryTaskQueue
// rejects 0) and unique per in-flight task so the completion can be matched on
// the event queue. `calls.size()` should be <= kProbeMaxCalls (split larger
// sets across tasks).
refuzz::queue::HostFuzzTask BuildProbeTask(
    const syz::Target&                          target,
    const std::vector<const syz::SyscallMeta*>& calls,
    std::uint64_t                               executor_id,
    std::uint32_t                               timeout_ms);

// Decode the per-call errno block at the head of a completion's output buffer
// (channel_contract::Completion.output), aligned to `calls` — pass the SAME
// list given to BuildProbeTask: result[i] ↔ the i-th non-null meta. Returns one
// entry per non-null meta. A short/empty output buffer (abnormal, early death)
// yields executed=false for every entry — the caller (C4.3) treats that as
// "unknown", not "unsupported".
std::vector<ProbeCallResult> DecodeProbeCompletion(
    std::span<const std::uint8_t>               output,
    const std::vector<const syz::SyscallMeta*>& calls);

// Carry a PRE-BUILT probe program (its calls constructed by the support checks,
// e.g. a synthetic socket(af,Vals[0],proto) or openat("/dev/vhci")) as a
// standard HostFuzzTask. Same lowering as the meta-based BuildProbeTask
// (assign_sizes_prog → artifact); the Executor lowers it to exec-wire. Used by
// the machine-check, which gathers ProbeSpecs from the registry rather than
// building bare calls itself.
refuzz::queue::HostFuzzTask BuildProbeTaskFromProg(
    syz::Prog     prog,
    std::uint64_t executor_id,
    std::uint32_t timeout_ms);

// Decode the per-call errno block for a batch of `n_calls`, position-aligned:
// result[i] ↔ the i-th call of the program. The caller maps each position to its
// ProbeSpec tag. Short/empty output ⇒ executed=false for every entry.
std::vector<ProbeCallResult> DecodeProbeCompletion(
    std::span<const std::uint8_t> output,
    std::size_t                   n_calls);

} // namespace refuzz::control::support::machine_check

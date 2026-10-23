// Copyright 2026 reFuzz project author -------youngkk.

#include "refuzz/control/support/machine_check/probe_runner.hpp"

#include "refuzz/control/support/machine_check/probe_program.hpp"  // BuildProbeProgram
#include "refuzz/program/syz/artifact_materializer.hpp"            // MakeArtifactFromTypedProg
#include "refuzz/program/syz/size.hpp"                             // assign_sizes_prog
#include "refuzz/feedback/decode/syz_exec_result_decode.hpp"       // DecodeSyzExecResults, kCallFlag*

#include <memory>
#include <utility>

namespace refuzz::control::support::machine_check {

refuzz::queue::HostFuzzTask BuildProbeTask(
    const syz::Target&                          target,
    const std::vector<const syz::SyscallMeta*>& calls,
    std::uint64_t                               executor_id,
    std::uint32_t                               timeout_ms) {
    // Same lowering route as SyzV2MutatorEngine: build the typed prog, run the
    // size pass, then wrap as the typed authority. The Executor's materializer
    // (LowerToExecWire → serialize_for_exec) turns this into wire bytes at the
    // channel-dispatch boundary; we never hand-encode here.
    syz::Prog prog = BuildProbeProgram(target, calls);
    return BuildProbeTaskFromProg(std::move(prog), executor_id, timeout_ms);
}

refuzz::queue::HostFuzzTask BuildProbeTaskFromProg(
    syz::Prog     prog,
    std::uint64_t executor_id,
    std::uint32_t timeout_ms) {
    syz::assign_sizes_prog(prog);
    auto sp = std::make_shared<const syz::Prog>(std::move(prog));

    refuzz::queue::HostFuzzTask task;
    task.executor_id     = executor_id;
    task.artifact        = syz::MakeArtifactFromTypedProg(std::move(sp));
    task.opts.timeout_ms = timeout_ms;
    return task;
}

std::vector<ProbeCallResult> DecodeProbeCompletion(
    std::span<const std::uint8_t> output,
    std::size_t                   n_calls) {
    std::vector<ProbeCallResult> out(
        n_calls,
        ProbeCallResult{/*meta=*/nullptr, /*executed=*/false, /*err=*/0, /*ret=*/0});

    // Head-only decode (we want errno, not coverage). A short / empty output
    // leaves every entry executed=false ("unknown", not "unsupported").
    //
    // Trust the errno only for a FINISHED call (kCallFlagFinished), not merely an
    // Executed one. A probe call still in-flight at the worker end-drain — a
    // present-but-BLOCKING/terminating bare call (pause/rt_sigsuspend/exit/
    // clone…) — is written by finish_unfinished_tid as Executed-but-NOT-Finished
    // with a SENTINEL err=ENOSYS ("ran, no result"), NOT "syscall absent". syz's
    // machine-check KEEPS these (verified against its syz-manager.log: pause/exit/
    // clone are NOT in syz's disabled set — the syscalls exist, they just block).
    // Requiring Finished ⇒ a blocked lone call is "no evidence ⇒ keep", matching
    // syz; a real ENOSYS returns instantly so it is always Finished (still
    // disabled). Determinism comes from one-call-per-program probes
    // (kProbeMaxCalls=1): a lone blocked call always lands the same way and never
    // masks others, so the verdict no longer flips with thread scheduling — the
    // earlier flakiness was the 40-wide batching, not this flag choice.
    const std::vector<refuzz::worker::SyzExecResult> decoded =
        refuzz::feedback::decode::DecodeSyzExecResults(output, n_calls);
    for (std::size_t i = 0; i < decoded.size() && i < out.size(); ++i) {
        out[i].executed =
            (decoded[i].flags & refuzz::worker::kCallFlagFinished) != 0;
        out[i].err = decoded[i].err;
        out[i].ret = static_cast<std::int64_t>(decoded[i].ret);
    }
    return out;
}

std::vector<ProbeCallResult> DecodeProbeCompletion(
    std::span<const std::uint8_t>               output,
    const std::vector<const syz::SyscallMeta*>& calls) {
    // Mirror BuildProbeProgram's null-skip so result[i] ↔ the i-th non-null meta.
    std::vector<const syz::SyscallMeta*> non_null;
    non_null.reserve(calls.size());
    for (const syz::SyscallMeta* m : calls) {
        if (m != nullptr) non_null.push_back(m);
    }
    std::vector<ProbeCallResult> out =
        DecodeProbeCompletion(output, non_null.size());
    for (std::size_t i = 0; i < non_null.size() && i < out.size(); ++i) {
        out[i].meta = non_null[i];
    }
    return out;
}

} // namespace refuzz::control::support::machine_check

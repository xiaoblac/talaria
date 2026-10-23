// Copyright 2026 reFuzz project author -------youngkk.
//
// XiuosOracleSignal — see header. Maps a XiUOS RESULT completion's per-program
// oracle verdict (vendor_status / vendor_flags) onto a CombinedCrashEvent
// finding, mirroring FaultSignal's BuildCombinedFromAbnormal but sourced from a
// normal Completion (the worker answered cleanly; the verdict rides the vendor
// fields rather than an abnormal/fault).

#include "refuzz/feedback/signal/xiuos_oracle_signal.hpp"

#include "refuzz/proto_domain/combined_crash_event.hpp"
#include "refuzz/proto_domain/frozen_program_entry.hpp"
#include "refuzz/proto_wire/xiuos_uart_protocol.h"

#include <chrono>

namespace refuzz::fuzzer {

namespace {

uint64_t NowUs() {
    const auto now = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(now).count());
}

// Build a CombinedCrashEvent describing the program responsible for a
// per-program-oracle verdict. `result_code` separates a hard corruption
// (kCrashed) from a soft leak lead (kResourceLeak).
//
// [XiUOS leak 一等公民化 Phase 1/5] Carrier routing for a kResourceLeak:
//   - `leak_bytes` (heap delta, from vendor_flags) rides the dedicated leak_bytes
//     field (NOT crash_signal — that conflated a leak with a worker signal).
//   - `resource_residue` (waitq|victim<<8|delay<<16, from vendor_resource_residue)
//     rides the parallel resource_residue field. A program can leak BOTH → carry
//     both. crash_signal stays 0 for leaks.
// For a non-leak verdict (state-violation → kCrashed) `leak_bytes` carries the
// worker's invariant code into crash_signal instead, and resource_residue is 0.
refuzz::proto::CombinedCrashEvent BuildFromContext(
        const refuzz::core::channel_contract::ChannelEvent& event,
        const refuzz::core::channel_contract::CompletionContext& ctx,
        refuzz::proto::ResultCode result_code,
        std::uint32_t leak_bytes,
        std::uint32_t resource_residue) {
    refuzz::proto::CombinedCrashEvent combined;
    combined.incident_id =
        event.event_id != 0 ? event.event_id : ctx.executor_id;

    refuzz::proto::FrozenProgramEntry entry;
    entry.executor_id     = ctx.executor_id;
    entry.seed_id         = ctx.seed_id;
    entry.origin_seed_id  = ctx.origin_seed_id;
    entry.program_payload = ctx.program_payload;
    entry.submit_ts_us    = ctx.submit_ts_us;

    refuzz::proto::FrozenExecutionSummary summary;
    summary.worker_id    = ctx.worker_id;
    summary.result_code  = result_code;
    summary.infra_error  = refuzz::proto::InfraError::kNone;
    summary.start_ts_us  = ctx.submit_ts_us;
    summary.finish_ts_us = NowUs();
    if (result_code == refuzz::proto::ResultCode::kResourceLeak) {
        summary.leak_bytes       = leak_bytes;
        summary.resource_residue = resource_residue;
        summary.crash_signal     = 0;
    } else if (result_code == refuzz::proto::ResultCode::kContractViolation ||
               result_code == refuzz::proto::ResultCode::kPriorityInversion ||
               result_code == refuzz::proto::ResultCode::kStackOverflow) {
        // Same carrier shape for both soft semantic findings:
        //   contract:  crash_signal = wrong return,  resource_residue = (api<<8|call)
        //   prio-inv:  crash_signal = mutex slot,     resource_residue = (holder<<8|waiter)
        // XiuosBuildContextOp decodes per result_code.
        summary.crash_signal     = leak_bytes;
        summary.resource_residue = resource_residue;
    } else {
        // Non-leak verdict (state-violation): leak_bytes carries the invariant code.
        summary.crash_signal = leak_bytes;
    }
    entry.completion     = std::move(summary);

    combined.crash_program = std::move(entry);
    // artifact-first universal contract: the typed authority for repro/minimize.
    combined.crash_origin_artifact = ctx.artifact;
    return combined;
}

}  // namespace

SignalContribution XiuosOracleSignal::Sample(
        const refuzz::core::channel_contract::ChannelEvent& event) {
    SignalContribution c;
    c.id   = Id();
    c.kind = Kind();

    // ── Completion path (worker answered cleanly) ──
    if (event.IsCompletion()) {
        const auto* comp = event.AsCompletion();
        if (comp == nullptr) {
            return c;
        }

        // [Contract oracle §3.1] semantic contract violation: a must-succeed op on
        // a verified-valid precondition returned non-EOK. Own terminal, checked
        // FIRST so it takes precedence over a coincidental leak on the same program.
        // vendor_aux = the wrong return; vendor_resource_residue = (api<<8|call).
        if (comp->vendor_status == XIUOS_STATUS_CONTRACT_VIOLATION) {
            c.fired       = true;
            c.kind        = SignalKind::kSanitizer;
            c.exec_code   = refuzz::proto::ResultCode::kContractViolation;
            c.crash_payload = BuildFromContext(
                event, comp->ctx, refuzz::proto::ResultCode::kContractViolation,
                static_cast<std::uint32_t>(comp->vendor_aux),
                comp->vendor_resource_residue);
            return c;
        }

        // [Stack-overflow detector] a task stack high-water near/at its depth.
        // vendor_aux = used bytes; vendor_resource_residue = (task_slot<<16 | depth).
        if (comp->vendor_status == XIUOS_STATUS_STACK_OVERFLOW) {
            c.fired       = true;
            c.kind        = SignalKind::kSanitizer;
            c.exec_code   = refuzz::proto::ResultCode::kStackOverflow;
            c.crash_payload = BuildFromContext(
                event, comp->ctx, refuzz::proto::ResultCode::kStackOverflow,
                static_cast<std::uint32_t>(comp->vendor_aux),
                comp->vendor_resource_residue);
            return c;
        }

        // [Priority-inversion detector] a held mutex has a blocked waiter more
        // urgent than the holder — checked before leak (own terminal). vendor_aux =
        // mutex slot; vendor_resource_residue = (holder_prio<<8 | waiter_prio).
        if (comp->vendor_status == XIUOS_STATUS_PRIORITY_INVERSION) {
            c.fired       = true;
            c.kind        = SignalKind::kSanitizer;
            c.exec_code   = refuzz::proto::ResultCode::kPriorityInversion;
            c.crash_payload = BuildFromContext(
                event, comp->ctx, refuzz::proto::ResultCode::kPriorityInversion,
                static_cast<std::uint32_t>(comp->vendor_aux),
                comp->vendor_resource_residue);
            return c;
        }

        // Hard finding: the worker's per-call heap/state check caught silent
        // corruption and skipped its (unsafe) cleanup. Memory-safety class →
        // kCrashed so the aggregator marks is_crash; aux carries the invariant code.
        if (comp->vendor_status == XIUOS_STATUS_STATE_VIOLATION) {
            c.fired       = true;
            c.kind        = SignalKind::kSanitizer;
            c.exec_code   = refuzz::proto::ResultCode::kCrashed;
            c.crash_payload = BuildFromContext(
                event, comp->ctx, refuzz::proto::ResultCode::kCrashed,
                static_cast<std::uint32_t>(comp->vendor_aux), /*resource_residue=*/0);
            return c;
        }

        // Soft lead: a nonzero per-program leak. Resource class, NOT a crash.
        //
        // [XiUOS leak 一等公民化 Phase 1/5] Two parallel leak carriers:
        //   - vendor_flags            → heap delta (net bytes not reclaimed)
        //   - vendor_resource_residue → resource residue (waitq/victim/delay nodes
        //     auto-measured by the worker after the program's own cleanup, Phase 5)
        // Fire on OR; a program can leak both → carry both. exec_code is
        // kResourceLeak → routes through the XiUOS crash components into the OWN
        // resource_leak/ bucket.
        if (comp->vendor_flags > 0 || comp->vendor_resource_residue > 0) {
            c.fired       = true;
            c.kind        = SignalKind::kResource;
            c.magnitude   = comp->vendor_flags != 0 ? comp->vendor_flags
                                                    : comp->vendor_resource_residue;
            c.exec_code   = refuzz::proto::ResultCode::kResourceLeak;
            c.crash_payload = BuildFromContext(
                event, comp->ctx, refuzz::proto::ResultCode::kResourceLeak,
                comp->vendor_flags, comp->vendor_resource_residue);
            return c;
        }
        return c;
    }

    // ── Abnormal path (worker answered, but the last call also returned an errno) ──
    // [XiUOS leak 一等公民化 Phase 4] A leaky program whose last call errors arrives
    // as an AbnormalCompletion (error_code != 0 → not a success completion), and the
    // leak delta now rides abnormal.vendor_flags (channel Phase 4 propagation). Fire
    // the SAME resource-leak finding. The leak is the dominant signal: xiuos_oracle is
    // last in the engine's signal_ids, so this crash_payload overwrites FaultSignal's
    // exec_error one in the aggregator (last-writer-wins) → the program buckets as
    // resource_leak, not exec_error. SCOPE: leak only; state-violation migration is Phase 2.
    if (event.IsAbnormal()) {
        const auto* abn = event.AsAbnormal();
        if (abn == nullptr) {
            return c;
        }
        // [XiUOS leak 一等公民化 Phase 4/5] Fire on OR of the two leak carriers,
        // same as the completion branch (heap delta OR resource residue); carry both.
        if (abn->vendor_flags > 0 || abn->vendor_resource_residue > 0) {
            c.fired       = true;
            c.kind        = SignalKind::kResource;
            c.magnitude   = abn->vendor_flags != 0 ? abn->vendor_flags
                                                   : abn->vendor_resource_residue;
            c.exec_code   = refuzz::proto::ResultCode::kResourceLeak;
            c.crash_payload = BuildFromContext(
                event, abn->ctx, refuzz::proto::ResultCode::kResourceLeak,
                abn->vendor_flags, abn->vendor_resource_residue);
        }
        return c;
    }

    return c;
}

}  // namespace refuzz::fuzzer

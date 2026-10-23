// Copyright 2026 reFuzz project author -------youngkk.
//
// IExtraKcovControl (remote-kcov S1): the per-program control seam for the
// "extra" remote KCOV buffer (KCOV_REMOTE_ENABLE / COMMON handle).
//
// Why a seam: the extra buffer's resources live in KcovSink (observation/),
// but the per-program reset/collect must be driven from loop_runtime's program
// loop (engine/). loop_runtime only holds an IObservationBus&; rather than
// teach engine/ about the concrete KcovSink type, the bus exposes
// FindExtraKcovControl() which scans its sinks for whoever implements this
// tiny interface. KcovSink implements it; everything else returns nullptr.
//
// Methods are no-ops / 0 when the extra buffer is disabled (serial mode, no
// coverage, or KCOV_REMOTE_ENABLE failed) so callers need no extra gating.

#pragma once

#include <cstdint>

namespace refuzz::worker {

class IExtraKcovControl {
public:
    virtual ~IExtraKcovControl() = default;

    // Clear the extra remote KCOV write cursor at a program boundary
    // (call BEFORE the program executes / forks the program-child). The
    // program-side collect+emit is owned by KcovSink::PackFeedback (S2).
    virtual void ResetExtraProgram() = 0;

    // [remote-kcov R2] Mark whether the program about to execute contains a
    // call that produces ASYNC remote coverage (syz `remote_cover` attribute:
    // USB enumeration via khubd hub_event, net-RX injection, etc.). Set this
    // per-program BEFORE the program executes, alongside ResetExtraProgram().
    //
    // Why: the async kernel work usually runs AFTER the triggering syscall
    // returns, so PackFeedback's first remote-buffer drain sees nothing and —
    // with the legacy "first drain non-empty" gate — skips the settle/re-drain
    // loop, dropping the coverage. When this flag is set, PackFeedback runs the
    // settle loop unconditionally so khubd/softirq/RCU coverage is captured.
    //
    // The per-program default is false (ResetExtraProgram clears it), so an
    // implementation that never calls this keeps the legacy dynamic-gate
    // behavior — no regression. Optional seam: default no-op for any
    // implementer that does not track the attribute.
    virtual void SetProgramUsesRemoteCover(bool /*uses*/) {}
};

} // namespace refuzz::worker

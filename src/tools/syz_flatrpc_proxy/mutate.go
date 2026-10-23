package main

// V2 production-exec paired oracle / COV-B.1: wire-level mutation that forces
// `ExecFlag.CollectCover` on every HostMessage→ExecRequest before forwarding
// it to the runner. Triggered by config `ForceCollectCover` (env
// `REFUZZ_FORCE_COLLECT_COVER=1`).
//
// Rationale (plan §13.5 COV-B): syz-manager only sets CollectCover for a
// narrow slice of triage/signal jobs, so a vanilla capture yields ~0.4%
// kcov-bearing samples — far too few to calibrate plan §13.1 coverage gate
// thresholds. Forcing CollectCover gives us thousand-class samples per 30 min
// session at the cost of breaking byte-equal capture for ExecRequest frames.
//
// Audit trail: every mutated frame's decoded_summary record carries
// `original_exec_flags` alongside `exec_flags`, so the trace remains self-
// describing — downstream tools can see which bits we forced and reproduce
// the original wire if needed.
//
// Non-ExecRequest frames are NEVER touched. ExecRequests that already have
// CollectCover set are left byte-equal too (cheap path).

import (
	flatbuffers "github.com/google/flatbuffers/go"

	"github.com/google/syzkaller/pkg/flatrpc"
)

// mutateForceCollectCover examines one HostMessage body. Behavior:
//
//   - parseOK=false  : not parseable as HostMessage (caller should forward
//                      the original bytes unchanged and skip mutation)
//   - parseOK=true, mutated=false:
//       frame parsed but no mutation needed — either not an ExecRequest, or
//       all required bits already set. origExecFlags is meaningful when
//       it's an ExecRequest (caller may still want to record it for audit).
//       isExecRequest disambiguates.
//   - parseOK=true, mutated=true :
//       newBody is the re-serialized flatbuffer (no size prefix; caller adds
//       a fresh one). origExecFlags is the pre-mutation ExecFlags value
//       (EnvFlags pre-mutation is not surfaced — it's strictly session
//       setup, not equivalence dimension).
//
// Three-bit force-mutation rationale (2026-05-19 B.6 real capture):
//
//   1. ExecOpts.ExecFlags |= CollectCover  (bit 1) — request kcov PCs
//   2. ExecOpts.ExecFlags |= CollectSignal (bit 0) — upstream executor.cc
//      sets flag_collect_cover = flag_collect_signal && CollectCover, so
//      Cover without Signal at the per-call level is silently dropped
//   3. ExecOpts.EnvFlags  |= ExecEnvSignal  (bit 1) — upstream executor.cc
//      sets flag_coverage = (env_flags & ExecEnv::Signal); flag_coverage
//      is a SESSION-level gate over all per-call cover collection. Fresh-
//      exec jobs come with EnvFlags=0x10 (SandboxNone only) which would
//      otherwise leave cover collection process-disabled
//
// First B.6 capture missed step 2; second missed step 3 — both produced
// 0% cover on the 648 originally-0x0 fresh-exec requests because each
// downstream gate fired before the cover write path.
func mutateForceCollectCover(body []byte) (newBody []byte, origExecFlags uint64, isExecRequest, mutated, parseOK bool) {
	defer func() {
		// flatrpc.Parse can panic on a malformed/truncated tail. Soft-fail.
		if r := recover(); r != nil {
			parseOK = false
			mutated = false
			newBody = nil
		}
	}()
	msg, err := flatrpc.Parse[*flatrpc.HostMessageRaw](body)
	if err != nil || msg == nil || msg.Msg == nil {
		return nil, 0, false, false, false
	}
	parseOK = true
	req, ok := msg.Msg.Value.(*flatrpc.ExecRequest)
	if !ok {
		return nil, 0, false, false, true
	}
	isExecRequest = true
	if req.ExecOpts == nil {
		// No ExecOpts on this request — nothing to flip. Treat as no-op.
		return nil, 0, true, false, true
	}
	origExecFlags = uint64(req.ExecOpts.ExecFlags)
	origEnvFlags := uint64(req.ExecOpts.EnvFlags)

	const needExecBits = flatrpc.ExecFlagCollectSignal | flatrpc.ExecFlagCollectCover
	const needEnvBits = flatrpc.ExecEnvSignal
	execNeed := (origExecFlags & uint64(needExecBits)) != uint64(needExecBits)
	envNeed := (origEnvFlags & uint64(needEnvBits)) != uint64(needEnvBits)
	if !execNeed && !envNeed {
		// All three bits already on — no rewrite needed.
		return nil, origExecFlags, true, false, true
	}
	if execNeed {
		req.ExecOpts.ExecFlags |= needExecBits
	}
	if envNeed {
		req.ExecOpts.EnvFlags |= needEnvBits
	}

	builder := flatbuffers.NewBuilder(len(body) + 32)
	off := msg.Pack(builder)
	builder.FinishSizePrefixed(off)
	full := builder.FinishedBytes()
	if len(full) < 4 {
		return nil, origExecFlags, true, false, true
	}
	// FinishedBytes returns [u32 size_prefix | body...]. Strip the prefix —
	// the caller (forwardFrames) writes its own prefix matching the new size.
	body2 := make([]byte, len(full)-4)
	copy(body2, full[4:])
	return body2, origExecFlags, true, true, true
}

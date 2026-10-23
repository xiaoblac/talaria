#pragma once
// Triage deflake analysis — pure, side-effect-free functions extracted from
// triage_stage.cpp (Phase 3 Step 3.2) so BOTH the legacy triage consumer stage
// AND the job-model core-path job (job-loop redesign Step 3, see
// docs/job-loop-redesign/040_step3_triage_migration.md) compute stability on one
// shared implementation. The behavior follows syzkaller
// pkg/fuzzer/job.go:228-347: discovery seeds signals[0], then priority-aware
// k-of-n voting drives normal and boot-corpus stop conditions.
//
// Input is a vector<RunObservation> = the discovery sample followed by the N
// deflake re-exec results of one program (per-call raw KCOV hashes + edge signal
// + errno + syscall id). These
// functions never touch StageDeps / task queue / registry / metrics — that I/O
// orchestration stays in triage_stage.cpp (legacy consumer) and, in Step 3, in
// the core-path job. The observation types live here (not nested in
// TriageJobState) so the job can produce them from JobContext exec results
// without pulling in the whole stage machinery; TriageJobState aliases them.

#include "refuzz/control/stage/stable_cover.hpp"  // UnstableCoverStats (shared cover basis)
#include "refuzz/program/seed.hpp"                 // [Step 3 Slice C2] Seed (metadata stamping)
#include "refuzz/program/seed_metadata.hpp"        // TriagePerCallCandidateMetadata::Candidate
#include "refuzz/proto_domain/types.hpp"           // proto::ResultCode

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace refuzz::control::deflake {

// One syscall's execution facts within a single deflake run.
struct CallObservation {
    std::vector<std::uint64_t> coverage_hashes;
    std::int32_t               errno_value = 0;
    std::uint32_t              syscall_id = 0;
    // [PR3 per-element edge prio] this call's EDGE signal (cover_edges mode);
    // used to attribute a per-edge success priority to the seed's stable edges.
    std::vector<std::uint64_t> edge_hashes;
    std::uint8_t signal_priority = 0;
};

// One execution sample of the whole program (discovery or deflake replay).
struct RunObservation {
    std::vector<CallObservation> per_call;
    refuzz::proto::ResultCode exec_status = refuzz::proto::ResultCode::kOk;
    // [remote-kcov] program-level EXTRA/remote cover for this run (async
    // khubd/softirq/kthread PCs, unattributable to a syscall). Mirrors syz
    // Info.Extra; unioned into the corpus COVER (not per-call voted).
    std::vector<std::uint64_t> extra_cover;
    // Admission-unit signal for EXTRA/remote. Edge signal in cover_edges mode,
    // raw PC otherwise; kept separate from extra_cover's corpus-cover raw PCs.
    std::vector<std::uint64_t> extra_signal_hashes;
    bool extra_signal_hashes_are_edges = false;
    // Discovery participates in signal voting but, like syzkaller's initial
    // triageProgCall sample, does not contribute to triageCall.cover.
    bool contributes_cover = true;
};

// [per-call novelty — syz job.calls[call]] a call being "chased": the per-call
// newSignal accumulated from the discovery exec + every deflake re-exec (per-call
// MergeCoverage novelty in KcovCoverageSignal). Mirrors syz triageJob.calls, whose
// entries come from per-call addRawMaxSignal deltas. call_index=-1 = Extra/program-
// level. new_signal_hashes are in the ADMISSION unit (edges in cover_edges mode) and
// MUST be sorted+unique (candidate logic does sorted-set intersection). errno/
// syscall_id/is_edges carry the discovery-observed shape.
struct ChasedCall {
    int                          call_index = -1;
    std::vector<std::uint64_t>   new_signal_hashes;
    // Parallel to new_signal_hashes. Missing entries mean priority 0.
    std::vector<std::uint8_t>    new_signal_prios;
    std::optional<std::int32_t>  errno_value;
    std::optional<std::uint32_t> syscall_id;
    bool                         signal_hashes_are_edges = false;
    // Calls first discovered during deflake must not receive votes from older runs.
    std::size_t                  first_run_index = 0;
};

// The single "guilty" call chosen to carry the seed's stable signal — the call
// whose stable (k-of-n) signal ∩ program-stable intersection is largest.
struct SelectedStableCall {
    int call_index = -1;
    std::vector<std::uint64_t> hashes;
    std::int32_t errno_value = 0;
    std::uint32_t syscall_id = 0;
    bool hashes_are_edges = false;
};

// Pick the guilty call: among shape-consistent calls, the one whose k-of-n
// stable signal intersected with `program_stable` is largest. nullopt if none
// qualifies (empty runs / empty program_stable / no non-empty intersection).
std::optional<SelectedStableCall> SelectStableCall(
    const std::vector<RunObservation>& runs,
    const std::vector<std::uint64_t>& program_stable);

// Per-call candidates: for EACH chased call (syz job.calls), its k-of-n stable
// signal intersected with THAT call's accumulated newSignal
// (chased.new_signal_hashes). Non-empty ⇒ candidate — the syz handleCall filter
// (`newStableSignal.Empty() → skip`). NOT a scan of all stable calls against a
// program-level novel union (which over-attributed shared edges to every call).
// `program_stable` is the already-computed program-level admission gate; an
// empty set drops the program, while per-call attribution remains in its own
// signal domain. `min_votes` is the k in k-of-n (<=0 → n-of-n).
std::vector<refuzz::fuzzer::TriagePerCallCandidateMetadata::Candidate>
ComputeNewStableCallCandidates(
    const std::vector<RunObservation>& runs,
    const std::vector<std::uint64_t>& program_stable,
    const std::vector<ChasedCall>&    chased_calls,
    int min_votes);

// syzkaller stopDeflake parity for fuzzing programs. The caller enforces the
// initial sample floor; this function stops when every chased call has some new
// stable signal, max_runs is reached, or missing calls can no longer reach
// min_votes.
// This is intentionally per-call; a non-empty program-level stable intersection
// is not sufficient to stop.
bool ShouldStopFuzzDeflake(
    const std::vector<RunObservation>& runs,
    const std::vector<ChasedCall>&     chased_calls,
    int                                min_votes,
    int                                max_runs);

bool ShouldStopCorpusDeflake(
    const std::vector<RunObservation>& runs,
    const std::vector<ChasedCall>&     chased_calls,
    int                                min_votes,
    int                                min_runs,
    int                                max_runs,
    int                                total_runs,
    bool                               no_new_signal);

// Full stable cover (raw per-call KCOV, k=1 union across runs = syz inp.Cover).
std::vector<std::uint64_t> ComputeFullStableCover(
    const std::vector<RunObservation>& runs);

// Cross-run coverage variance (race-proximity signal, seed-value signal B):
// PCs covered in some-but-not-all runs vs the union footprint.
refuzz::control::UnstableCoverStats ComputeUnstableStats(
    const std::vector<RunObservation>& runs);

// The exec status shared by ALL runs, or nullopt if they disagree (used to gate
// stable admission on a consistent completion/crash/fault outcome).
std::optional<refuzz::proto::ResultCode> SelectStableExecStatus(
    const std::vector<RunObservation>& runs);

// [Step 3 Slice C2] Outcome of stamping a stable seed: whether it should proceed
// to minimize (admit), the metric unit count, and — for the fused core-path job —
// the per-call candidate list to minimize. Empty candidates now mean "drop and
// log at the runtime caller"; there is no whole-program fallback.
enum class StableSeedDropReason : std::uint8_t {
    kNone = 0,
    kNoChasedCalls,
    kNoPerCallCandidate,
};

struct StableSeedDecision {
    bool        admit          = false;   // stamped + should enqueue/run minimize
    std::size_t admitted_units = 0;       // triage_admit_stable increment
    StableSeedDropReason drop_reason = StableSeedDropReason::kNone;
    std::vector<refuzz::fuzzer::TriagePerCallCandidateMetadata::Candidate>
        per_call_candidates;
};

// Stamp per-call triage metadata on a STABLE seed and report the decision. Pure
// w.r.t. the world: mutates only `seed`; does NOT touch pending map / dispatcher
// / metrics / oracle / logging — the caller owns that I/O. Precondition: caller
// has already decided the program is stable (intersection non-empty, exec status
// consistent). No `chased_calls` means the per-call attribution chain is broken,
// so the caller must log and drop rather than falling back to a program-level
// guilty-call guess.
StableSeedDecision DecideAndStampStableSeed(
    refuzz::fuzzer::Seed&                seed,
    const std::vector<RunObservation>&  runs,
    const std::vector<std::uint64_t>&   intersection,
    refuzz::proto::ResultCode           stable_exec_status,
    int                                 min_votes,
    bool                                seed_value_shadow_enabled,
    // [per-call novelty] syz job.calls — per-call accumulated newSignal. Empty
    //   is a runtime wiring/decode anomaly and returns kNoChasedCalls.
    const std::vector<ChasedCall>&      chased_calls);

}  // namespace refuzz::control::deflake

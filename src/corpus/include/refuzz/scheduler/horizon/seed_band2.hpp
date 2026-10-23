// Copyright 2026 reFuzz project author -------youngkk.
//
// SeedBand2 — the band-② code-mass forward-value CANDIDATE (the kill-shot signal),
// SHADOW ONLY. future/future_cht (band-①: resource + transition horizons) anti-
// correlate with realized yield; the §5.3 offline kill-shot found that "uncovered
// handler code mass the seed's calls reach, per call" is the first forward signal
// that SUPPLEMENTS backward (resid_per_call ~ cluster-yield = +0.37, +0.34 beyond
// mab_ghat). It fills the band-② blindness resource/ChoiceTable have.
//
// It is a CANDIDATE, not truth. Known caveats it is exposed to validate, NOT to act on:
//   - most of its strength is shallow single-call detonators on TOTAL yield; the deep
//     long-horizon E[mass] term (downstream, beyond call-count) is only ~+0.06;
//   - code mass != triggerable mass — a reached handler's uncovered blocks may be gated
//     behind state the seed cannot construct (the reachability/value-flow gate, deferred);
//   - rewarding it could bias the corpus toward shallow big handlers vs deep multi-step
//     paths, and coverage-yield != bug-yield.
// → shadow-only; validate against downstream/long-horizon/bug oracles before it ever
//   drives selection. See docs/plans/structural-horizon-seed-value.md / research-axes-map.md §8.
#pragma once

#include <cstdint>
#include <string>
#include <unordered_set>
#include <vector>

namespace refuzz::program {
class ProgramArtifact;
}

namespace refuzz::fuzzer {

class SeedBand2 {
public:
    // Load the static function->block-count map (function_block_map.tsv:
    // "<hex_start>\t<block_count>\t<name>" — the trace-pc block universe per function).
    // Returns false if unreadable / empty; the component then stays inert (Score -> 0).
    bool LoadFunctionMap(const std::string& tsv_path);
    bool ready() const { return !func_starts_.empty(); }
    std::size_t function_count() const { return func_starts_.size(); }

    // band-②(seed) = Σ over the DISTINCT functions the seed's cover reaches of
    // max(0, block_count(F) - covered_blocks(F)) / ncalls — uncovered handler mass the
    // seed borders, per call (de-confounds single-call detonators from multi-call webs).
    // Scored against the CURRENT live covered set, THEN the seed's own PCs are folded in
    // (score-then-fold → the mask decays as the kernel gets covered, like the resource
    // novelty mask). cover_pcs = raw KCOV PCs (CorpusCoverageMetadata.cover_hashes; needs
    // raw_pc=true, else the PCs are hashed and FuncOf is meaningless). Empty / not-ready /
    // ncalls<=0 → 0. Observation only — drives nothing.
    double OnSeedAdmitted(const std::vector<std::uint64_t>& cover_pcs, int ncalls);

    // Convenience: extract ncalls from a syz artifact and forward. Non-syz → ncalls=0.
    double OnSeedAdmitted(const std::vector<std::uint64_t>& cover_pcs,
                          const refuzz::program::ProgramArtifact& artifact);

private:
    int FuncOf(std::uint64_t pc) const;  // binary search; -1 below range

    std::vector<std::uint64_t>        func_starts_;     // sorted ascending
    std::vector<std::int32_t>         func_blocks_;     // parallel: total trace-pc blocks
    std::vector<std::int32_t>         covered_in_func_; // live: distinct covered PCs per function
    std::unordered_set<std::uint64_t> seen_pc_;         // global covered-PC set (dedup the fold)
};

} // namespace refuzz::fuzzer

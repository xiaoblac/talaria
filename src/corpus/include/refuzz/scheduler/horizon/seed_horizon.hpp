// Copyright 2026 reFuzz project author -------youngkk.
//
// SeedHorizon — the live, in-engine future(seed) signal (docs/plans/
// structural-horizon-seed-value.md). Owns the de-flattened resource-precondition
// model + a LIVE novelty mask: which (produce-T → consumer-syscall) handoffs the
// corpus has realized. On each admitted seed it (1) scores future(seed) against
// the frontier the seed bordered (the mask as of the last refresh), (2) folds the
// seed's own realized handoffs into the mask, and (3) refreshes nmass on a cadence
// (cost control — ComputeMass is not per-exec). Observation only: the caller
// stamps the returned value into SeedHorizonMetadata; nothing here drives
// selection. The mask is what makes future DECAY (vs static centrality).
#pragma once

#include "refuzz/scheduler/horizon/seed_horizon_model.hpp"

#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

namespace refuzz::program {
class ProgramArtifact;
}
namespace refuzz::program::syz {
class Target;
struct SeedResourceFrontier;
}

namespace refuzz::fuzzer {

struct SeedHorizonConfig {
    double gamma = 0.5;  // horizon discount
    int    depth = 1;    // Katz truncation (hops past the leaf)
};

class SeedHorizon {
public:
    using Config = SeedHorizonConfig;

    // Build the model from the syz Target.
    explicit SeedHorizon(const refuzz::program::syz::Target& target,
                         SeedHorizonConfig cfg = {});
    // Inject a pre-Finalized model (tests).
    explicit SeedHorizon(SeedHorizonModel model, SeedHorizonConfig cfg = {});

    // future(seed) for its produced types, scored against the frontier the seed
    // bordered: nmass is brought up to date with ALL prior seeds' folds first (no
    // stale-mask lag), then scored pre-fold, then this seed's handoffs are folded.
    // ComputeMass runs at most once per admit (when the mask changed), never per-exec.
    double OnSeedAdmitted(const refuzz::program::syz::SeedResourceFrontier& fr);

    // Same, extracting the frontier from the seed's artifact (the syz IR walk is
    // encapsulated here so callers stay IR-agnostic). Non-syz artifact → 0.
    double OnSeedAdmitted(const refuzz::program::ProgramArtifact& artifact);

    // Score produced types against the current nmass without touching the mask.
    double Score(const std::vector<std::string>& produced_types) const;

    // Force an nmass refresh against the current mask.
    void Recompute();

    const SeedHorizonModel& model() const { return model_; }

    // [future_cht / Psyzkaller] inject the static call-transition successor table:
    // call_succ[id] = top-K (successor syscall id, normalized prior) for that call,
    // from the ChoiceTable (assembler-built, keeps corpus decoupled from mutator).
    // Empty = transition stratum off → TransitionValue returns 0.
    void SetCallSucc(std::vector<std::vector<std::pair<int, double>>> table)
    {
        call_succ_ = std::move(table);
    }

    // Novelty-masked transition horizon for a seed, then folds the seed's own calls
    // into the live "exercised" mask (score-then-fold, like OnSeedAdmitted). Non-syz
    // artifact / no table → 0. The mask decays the signal as calls get exercised
    // (call-granularity → coarse; may saturate mid-campaign — measured in shadow).
    double TransitionValue(const refuzz::program::ProgramArtifact& artifact);

private:
    void FoldEdges(const refuzz::program::syz::SeedResourceFrontier& fr);

    SeedHorizonModel                     model_;
    std::vector<std::unordered_set<int>> fired_;  // res id → realized consumer syscall ids
    SeedHorizonConfig                    cfg_;

    // [future_cht] static call-transition table + live exercised-call mask.
    std::vector<std::vector<std::pair<int, double>>> call_succ_;       // id → top-K (succ, prior)
    std::unordered_set<int>                          exercised_calls_; // calls seen in admitted seeds
};

} // namespace refuzz::fuzzer

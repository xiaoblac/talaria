// Copyright 2026 reFuzz project author -------youngkk.
//
// SeedHorizon impl — see seed_horizon.hpp.

#include "refuzz/scheduler/horizon/seed_horizon.hpp"

#include "refuzz/program/artifact.hpp"             // ProgramArtifact::As<Prog>
#include "refuzz/program/syz/prog.hpp"             // syz::Prog
#include "refuzz/program/syz/state_altitude.hpp"   // SeedResourceFrontier + AnalyzeResourceFrontier
#include "refuzz/program/syz/target.hpp"           // SyscallMeta::id() (Call::meta())

#include <utility>
#include <vector>

namespace refuzz::fuzzer {

SeedHorizon::SeedHorizon(const refuzz::program::syz::Target& target, SeedHorizonConfig cfg)
    : cfg_(cfg)
{
    model_.BuildFromTarget(target);
    fired_.assign(model_.num_resources(), {});
    Recompute();  // initial all-novel baseline (empty corpus)
}

SeedHorizon::SeedHorizon(SeedHorizonModel model, SeedHorizonConfig cfg)
    : model_(std::move(model)), cfg_(cfg)
{
    fired_.assign(model_.num_resources(), {});
    Recompute();
}

void SeedHorizon::Recompute()
{
    // realized(W, s): has any seed fed a W-compatible resource into consumer s?
    // fired_ is keyed on the consumer-wanted type W (FoldEdges inserts the edge's
    // wanted-type), so this matches the (W, call) key ComputeMass queries.
    auto realized = [this](int w, int s) {
        return w >= 0 && w < static_cast<int>(fired_.size()) &&
               fired_[w].count(s) > 0;
    };
    model_.ComputeMass(realized, cfg_.gamma, cfg_.depth);
}

void SeedHorizon::FoldEdges(const refuzz::program::syz::SeedResourceFrontier& fr)
{
    // edge.first is the CONSUMER-WANTED type W; fired_ is keyed on W to match the
    // (W, call) mask key in ComputeMass.
    for (const auto& [wanted, consumer] : fr.realized_edges) {
        const int w = model_.ResId(wanted);
        const int s = model_.SyscallId(consumer);
        if (w >= 0 && s >= 0 && w < static_cast<int>(fired_.size())) {
            fired_[w].insert(s);
        }
    }
}

double SeedHorizon::Score(const std::vector<std::string>& produced_types) const
{
    std::vector<int> ids;
    ids.reserve(produced_types.size());
    for (const auto& n : produced_types) {
        const int id = model_.ResId(n);
        if (id >= 0) {
            ids.push_back(id);
        }
    }
    return model_.Future(ids);
}

double SeedHorizon::OnSeedAdmitted(const refuzz::program::syz::SeedResourceFrontier& fr)
{
    // nmass currently reflects all PRIOR seeds' folds (recomputed at the end of the
    // previous admit / the ctor), so the pre-fold score is the frontier this seed
    // actually bordered — no stale-mask lag. Then fold this seed and recompute so
    // nmass stays current. ComputeMass runs once per admit, never per-exec.
    const double future = Score(fr.produced);
    FoldEdges(fr);
    Recompute();
    return future;
}

double SeedHorizon::OnSeedAdmitted(const refuzz::program::ProgramArtifact& artifact)
{
    auto prog = artifact.As<refuzz::program::syz::Prog>();
    if (!prog) {
        return 0.0;  // non-syz seed: no resource frontier
    }
    return OnSeedAdmitted(refuzz::program::syz::AnalyzeResourceFrontier(*prog));
}

double SeedHorizon::TransitionValue(const refuzz::program::ProgramArtifact& artifact)
{
    if (call_succ_.empty()) {
        return 0.0;  // transition stratum off (no ChoiceTable injected)
    }
    auto prog = artifact.As<refuzz::program::syz::Prog>();
    if (!prog) {
        return 0.0;  // non-syz seed: no syscall sequence
    }

    // The seed's call ids (index space of call_succ_ = SyscallMeta::id()).
    std::vector<int> ids;
    ids.reserve(prog->calls().size());
    for (const auto& c : prog->calls()) {
        const auto* m = c->meta();
        if (m != nullptr) {
            ids.push_back(static_cast<int>(m->id()));
        }
    }

    // Score: Σ over the seed's calls of the static transition prior toward
    // successors NOT yet exercised by any admitted seed (the live novelty mask).
    // Scored PRE-fold so a seed does not mask its own contribution.
    double score = 0.0;
    for (int id : ids) {
        if (id < 0 || id >= static_cast<int>(call_succ_.size())) {
            continue;
        }
        for (const auto& [succ, prior] : call_succ_[id]) {
            if (exercised_calls_.count(succ) == 0) {
                score += prior;
            }
        }
    }

    // Fold: this seed's calls are now exercised → their inbound transitions decay.
    for (int id : ids) {
        exercised_calls_.insert(id);
    }
    return score;
}

} // namespace refuzz::fuzzer

// Signal C — state-space altitude computation over the syz IR
// (docs/plans/seed-value-signals.md §2.3).
//
// Walks a syz Prog's ResultArg producer/consumer graph and fills the neutral
// program::StateAltitude POD. This is a syz-owned analysis (it reads the typed
// IR directly); generic control/corpus code reaches it only through the
// IMutatorEngine::AnalyzeStateAltitude seam, which returns the neutral POD.
#pragma once

#include "refuzz/program/state_altitude.hpp"

#include <string>
#include <utility>
#include <vector>

namespace refuzz::program::syz {

class Prog;

// Pure, deterministic. Producers = resource-typed call returns; consumers =
// ResultArgs anywhere in the args that reference a producer (res() != null);
// depth = longest producer→consumer chain over the call dependency graph.
::refuzz::program::StateAltitude ComputeStateAltitude(const Prog& prog);

// Resource frontier of a program (for the SeedHorizon signal): the resource
// TYPES it produces, and the REALIZED handoff edges. Each edge is keyed on the
// CONSUMER'S WANTED type W (the type the consuming arg declares), NOT the
// producer's type — so feeding a subtype into a generic slot realizes the
// generic (W, consumer) handoff. `produced` feeds future(seed)'s produced-type
// set; `realized_edges` feed the live novelty mask (matching the (W, call) key in
// SeedHorizonModel). Names are syz resource-type / syscall names.
struct SeedResourceFrontier {
    std::vector<std::string>                         produced;
    std::vector<std::pair<std::string, std::string>> realized_edges;  // (wanted-type W, consumer)
};

SeedResourceFrontier AnalyzeResourceFrontier(const Prog& prog);

} // namespace refuzz::program::syz

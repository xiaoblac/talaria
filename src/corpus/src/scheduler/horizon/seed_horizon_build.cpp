// Copyright 2026 reFuzz project author -------youngkk.
//
// SeedHorizonModel::BuildFromTarget — the only Target-aware TU. Fills the
// (otherwise target-agnostic) model from the finalized syz Target: every
// resource with its kind-chain, every syscall with the resource types it
// produces / consumes (input ∪ uses). Mirrors refuzz_seed_horizon_dump.

#include "refuzz/scheduler/horizon/seed_horizon_model.hpp"

#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/type.hpp"

#include <string>
#include <vector>

namespace refuzz::fuzzer {

void SeedHorizonModel::BuildFromTarget(const refuzz::program::syz::Target& target)
{
    for (const auto& d : target.resource_arena().descs()) {
        if (d) {
            AddResource(d->name(), d->kind());
        }
    }
    for (const auto& sc : target.syscalls()) {
        std::vector<std::string> produces, consumes;
        for (const auto* r : sc->creates_resources()) {
            if (r) produces.push_back(r->name());
        }
        // consumes = input_resources ONLY. uses_resources() in this target is
        // (created ∪ consumed), so adding it would miscount every PRODUCER of T as
        // a consumer of T (inflating consumer_count + polluting the frontier).
        // input_resources is the complete consumed set (kIn/kInOut, non-optional).
        // Optional-arg consumption is out of model scope (its realized handoffs are
        // folded but harmlessly unread, since those consumers aren't in the index).
        for (const auto* r : sc->input_resources()) {
            if (r) consumes.push_back(r->name());
        }
        AddSyscall(sc->name(), produces, consumes);
    }
    Finalize();
}

} // namespace refuzz::fuzzer

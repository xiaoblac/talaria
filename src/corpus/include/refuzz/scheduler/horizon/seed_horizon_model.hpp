// Copyright 2026 reFuzz project author -------youngkk.
//
// SeedHorizonModel — the de-flattened resource-precondition horizon that the
// in-engine SeedHorizon signal scores future(seed) on (docs/plans/
// structural-horizon-seed-value.md: SpecHorizon-RD-CORE resource-frontier term).
//
// Nodes = resource TYPES. A producer of type T (kind-chain K_T = broad..specific)
// can satisfy a consumer wanting any W in K_T. Two de-flatteners turn the flat
// resource graph into the rarity-discounted horizon — the corrections that
// separate this from the prior flat Layer-A (89 distinct / 270-way fd tie):
//   * inverse-producer  : producing T is worth nmass(T) = mass(T)/producer_count(T)
//   * hub-discount       : a consumer reached via kind W is weighted 1/consumer_count(W),
//                          so the generic `fd` hub (consumer_count ~1300) is killed
//                          while a specific leaf (consumer_count ~few) is kept —
//                          this is what removes hub-inheritance.
//
//   mass(T)  = Σ_{W∈K_T} (1/cc(W)) · #{novel consumers of W}        (leaf, masked)
//              + γ · Σ_{W∈K_T} (1/cc(W)) Σ_{S consumes W} Σ_{T'∈produces(S)} nmass(T')
//   nmass(T) = mass(T) / producer_count(T)
//   future(seed) = Σ_{T produced by the seed} nmass(T)
//
// `novel` is the coverage-novelty mask r: a (produce-T, consumer-S) handoff that
// no live seed has realized yet. The Katz recursion structure is STATIC; only the
// leaf is masked (the SR factorization V = (I−γP)⁻¹ r). Pure, target-agnostic
// (its own interned tables); BuildFromTarget (seed_horizon_build.cpp) is the thin
// adapter that fills it from the syz Target. ComputeMass runs once per mask-state
// (offline / on-admit, never per-exec); Future is then a cheap per-seed sum.
#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

namespace refuzz::program::syz {
class Target;
}

namespace refuzz::fuzzer {

class SeedHorizonModel {
public:
    // ---- construction from the syz Target (impl in seed_horizon_build.cpp, the
    //      only Target-aware TU) — Add* every resource + syscall, then Finalize. ----
    void BuildFromTarget(const refuzz::program::syz::Target& target);

    // ---- construction (by name; adapter + tests share this path) ----
    // A resource type with its kind-chain (broad → specific; the leaf is usually
    // the type's own name). Chain entries that are themselves resource types
    // create the sub-kind lattice; unknown entries are ignored at Finalize.
    void AddResource(const std::string& name, const std::vector<std::string>& kind_chain);
    // A syscall with the resource types it produces / consumes (consume = input ∪
    // uses). Names resolve to ids at Finalize; unknown names are ignored.
    void AddSyscall(const std::string& name,
                    const std::vector<std::string>& produces,
                    const std::vector<std::string>& consumes);
    // Intern names, resolve chains/produces/consumes, derive producer/consumer
    // counts and the consumers index. Call once after all Add*.
    void Finalize();

    // ---- queries ----
    int num_resources() const { return static_cast<int>(res_.size()); }
    int num_syscalls()  const { return static_cast<int>(call_.size()); }
    // -1 if unknown.
    int ResId(const std::string& name) const;
    // -1 if unknown. Syscall name → id (the consumers-index / mask basis).
    int SyscallId(const std::string& name) const;
    int producer_count(int res) const { return res_[res].producer_count; }
    int consumer_count(int res) const { return res_[res].consumer_count; }

    // ---- scoring ----
    // Recompute nmass[] for all resource types under a novelty mask. realized(W,
    // call) == true ⟺ some seed has fed a resource of (a subtype of) the consumer-
    // wanted type W into `call` — i.e. the (W, call) handoff is realized/covered →
    // excluded from the novel leaf. The key is the CONSUMER-WANTED type W (the kind
    // being summed), NOT the producing/scored type, so a subtype handoff decays the
    // generic frontier coherently. γ∈[0,1), depth = Katz truncation (0 = leaf only).
    void ComputeMass(const std::function<bool(int /*res*/, int /*call*/)>& realized,
                     double gamma, int depth);

    // future(seed) = Σ_{T produced by the seed} nmass[T].
    double Future(const std::vector<int>& produced_res) const;

    // inspection / test
    double nmass(int res) const { return nmass_[res]; }
    const std::vector<int>& consumers_of(int res) const { return consumers_of_[res]; }

private:
    struct Res {
        std::string              name;
        std::vector<std::string> kind_names;          // raw, pre-Finalize
        std::vector<int>         kind;                 // resolved chain (res ids)
        int                      producer_count = 0;
        int                      consumer_count = 0;
    };
    struct Call {
        std::string              name;
        std::vector<std::string> produces_names, consumes_names;  // raw
        std::vector<int>         produces, consumes;              // resolved
    };

    std::vector<Res>                     res_;
    std::vector<Call>                    call_;
    std::unordered_map<std::string, int> res_id_;
    std::unordered_map<std::string, int> call_id_;  // syscall name → id
    std::vector<std::vector<int>>        consumers_of_;  // res id → consuming call ids
    std::vector<double>                  nmass_;         // per res, last ComputeMass
    bool                                 finalized_ = false;
};

} // namespace refuzz::fuzzer

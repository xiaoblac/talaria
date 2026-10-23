// Copyright 2026 reFuzz project author -------youngkk.
//
// SeedLineageYieldStore — per-base-seed VALUE-REALIZED downstream-yield accumulator.
//
// The offline oracle substrate for the structural-horizon seed-future-value work
// (docs/plans/structural-horizon-seed-value.md §5.1). For each ROOT base corpus
// seed it accumulates the distinct coverage units (KCOV signal hashes / PCs)
// first unlocked by that seed's mutation LINEAGE, bucketed by lineage DEPTH so
// the near-term P(new) (depth 1 = a direct mutation of the root) is separable
// from the value-realized E[mass] (depth >= 2 = a mutation of a descendant). A
// coverage unit is credited to exactly ONE root — whichever lineage covered it
// first (first-toucher / submodular attribution).
//
// PURE accumulation. The store knows nothing about Seed or the lineage tree: the
// caller (FuzzerLoop, which owns the corpus + the SeedLineageMetadata
// parent-pointers) resolves origin_seed_id -> (root, depth) and feeds the
// executed cover of the outcome; the store's own seen-set decides which units
// are new and which root first-touched them. Observation only — it never affects
// selection. Owned by FuzzerLoop, constructed only when the seed-value shadow
// observation is enabled and a logs dir exists; dumped to a JSONL sidecar at
// shutdown. Mirrors HashFeedbackStore's placement & lifecycle.
#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace refuzz::fuzzer {

class SeedLineageYieldStore {
public:
    // Optional RAII dump: if `dump_path` is non-empty the table is written to it
    // (DumpToFile) when the store is destroyed — mirrors SeedValueShadowSink's
    // flush-on-dtor, so the owner needs no explicit shutdown call. Empty = in-
    // memory only (tests). A SIGKILL skips the dtor → no dump (acceptable).
    explicit SeedLineageYieldStore(std::string dump_path = {});
    ~SeedLineageYieldStore();

    // Per-root realized yield, bucketed by lineage depth (depths are shallow, so
    // an ordered map is both small and gives MaxDepth() for free).
    struct RootYield {
        // new coverage units credited at each lineage depth. depth is 1-based:
        // 1 = a direct mutation of the root base seed; >= 2 = a mutation of a
        // descendant (the "more than one step downstream" value signal).
        std::map<std::uint32_t, std::uint64_t> by_depth;

        std::uint64_t Direct() const;       // depth == 1  (near-term P(new))
        std::uint64_t Downstream() const;   // depth >= 2  (value-realized E[mass])
        std::uint64_t Total() const;
        std::uint32_t MaxDepth() const;     // 0 when empty
    };

    // Credit `root_seed_id` with the units in `executed_cover` it is the first
    // lineage to cover, attributed at lineage `depth` (>= 1). Already-credited
    // units are skipped (first-toucher). `executed_cover` need not be unique or
    // sorted. Returns the number of units newly credited.
    std::size_t Attribute(std::uint64_t root_seed_id,
                          std::uint32_t depth,
                          const std::vector<std::uint64_t>& executed_cover);

    // Per-root readout (a zero-valued RootYield if the root has no credited yield).
    RootYield Get(std::uint64_t root_seed_id) const;

    std::size_t RootCount() const { return by_root_.size(); }
    std::size_t CreditedUnits() const { return credited_.size(); }

    // One JSONL row per root seed — the offline value-realized oracle:
    //   {"root":<id>,"direct":d,"downstream":n,"total":t,"max_depth":m,
    //    "by_depth":{"1":..,"2":..}}
    bool DumpToFile(const std::string& path) const;

    // Periodic mid-run flush to the RAII dump_path_ (full rewrite). No-op if the
    // store was constructed in-memory (empty path). Lets the caller make the
    // value-realized oracle observable during a campaign and survive a SIGKILL,
    // instead of only dumping in the dtor.
    bool Flush() const;

private:
    std::string                                  dump_path_;  // RAII dump target ("" = none)
    std::unordered_set<std::uint64_t>            credited_;  // first-toucher guard
    std::unordered_map<std::uint64_t, RootYield> by_root_;   // root seed -> yield
};

} // namespace refuzz::fuzzer

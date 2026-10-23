// Copyright 2026 reFuzz project author -------youngkk.
//
// StaticBeliefGraph — in-engine read-out of the belief prior, with graded recovery-confidence AND
// REGION-PRECISE live calibration. graph_M.tsv is produced OFFLINE by scripts/seed_horizon/substrate (the 8-mechanism
// federation; each edge = an unlock hypothesis "A establishes P on S → gated slice R owned by B" carrying
// a Beta(α,β) prior + leverage). This is the C++ consumer.
//
// An edge A→B's live weight = ρ(A→B) · base · headroom(B):
//   ρ(A→B)     — EDGE CONFIDENCE; Beta(α,β); α+β = recovery concentration (strong recovery resists).
//   base       — STATIC LEVERAGE: weight/ρ_load = rarity·blindness·mass·cred (constant).
//   headroom(B)— TARGET HEADROOM: reachability-aware remaining mass, decays as B runs without new code.
//
//   Score (Phase A): Σ over the seed's calls of Σ out-edge live weight. Computed lazily.
//
//   Observe (Phase B, REGION-PRECISE): per-call coverage → calibrate. For edge A→B with A,B executed, the
//   edge is CONFIRMED only when B's new PCs land in THIS edge's gated slice R (e.r_funcs, via a PC→func
//   RegionMap) — so a confirm/refute attributes to the specific hypothesis, not "B produced new coverage
//   somewhere". REFUTE when A ran, B ran, but R stayed dark. Falls back to coarse "B produced any new"
//   when no RegionMap / the edge carries no R (old graph). Per-target headroom uses the coarse signal.
// Thread-safe: Observe exclusive, Score/stats shared. observe.py is the offline twin; D2 the causal pass.
#pragma once

#include <cstddef>
#include <cstdint>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace refuzz::program {
class ProgramArtifact;
}

namespace refuzz::fuzzer {

class StaticBeliefGraph {
public:
    // Parse graph_M.tsv (cols: V_A V_B types source rho alpha beta rarity blindness mass weight [r_funcs]).
    // col 12 r_funcs (optional, comma-sep) = the edge's gated slice R's region functions. Also loads the
    // sibling function_block_map.tsv (same dir) as the PC→func RegionMap for region-precision. Returns
    // false if no edges. Single-threaded (load before any engine use).
    bool LoadFromTsv(const std::string& path);

    // Static prior seed value: Σ over the seed's calls of Σ out-edge live weight. Non-syz artifact → 0.
    double Score(const refuzz::program::ProgramArtifact& artifact) const;
    double Score(const std::vector<std::string>& variant_names) const;

    // [Phase B, region-precise] live calibration. executed = variants whose calls ran (precondition A
    // ran). new_by_variant = each executed variant → the globally-new PCs ITS call produced this exec.
    // Edge A→B (A,B∈executed): B's new PCs map (FuncOf) into e.r_funcs → α++ (CONFIRM the specific
    // hypothesis); else → β++ (REFUTE: A ran, B ran, R dark). Coarse fallback ("B produced any new") when
    // no RegionMap or the edge has no R. Per-target headroom bumped from the coarse signal. Thread-safe.
    void Observe(const std::unordered_set<std::string>& executed,
                 const std::unordered_map<std::string, std::vector<std::uint64_t>>& new_by_variant);

    std::size_t edges() const { return edges_; }
    std::size_t variants() const { return src_count_; }   // # SOURCE variants (with ≥1 out-edge)
    bool loaded() const { return loaded_; }
    bool region_precise() const { return rm_loaded_; }     // true iff the RegionMap loaded (else coarse)

    struct Stats {
        std::uint64_t confirmed = 0;
        std::uint64_t refuted   = 0;
        std::uint64_t observed  = 0;
    };
    Stats stats() const;

    // Persist the live (α,β) posterior per edge at run end (the calibration the shadow json's belief_value
    // does NOT capture). One row per edge: V_A V_B types alpha0 beta0 alpha beta rho0 rho_post obs. Offline
    // joins to graph_M by types/kind so a campaign yields the CALIBRATED prior, not just static ρ0.
    bool DumpPosterior(const std::string& path) const;

private:
    struct Edge {
        std::uint32_t b;      // target variant id (interned)
        double        alpha;  // Beta posterior — mutated by Observe
        double        beta;
        double        base;   // weight / ρ_load (constant leverage); weight = ρ·base
        std::vector<std::uint32_t> r_funcs;  // R's region functions (sorted func ids); empty ⇒ coarse edge
        double        alpha0; // prior snapshot at load (immutable) — for the posterior-shift dump
        double        beta0;
        std::string   types;  // "spr:S:kind" — carried for the per-kind calibration read-out
    };

    std::uint32_t Intern(const std::string& name);        // variant name → id (load only)
    int           IdOf(const std::string& name) const;    // variant name → id, or -1 (immutable post-load)
    double        Headroom(std::uint32_t b) const;        // (PF+front)/(PF+front+DARK·dark); lock held

    // RegionMap: PC → containing function id (function_block_map.tsv is one start-PC per function).
    bool          LoadRegionMap(const std::string& path);
    int           FuncOf(std::uint64_t pc) const;         // bisect → func id, or -1
    int           FuncId(const std::string& name) const;  // func name → id, or -1

    std::unordered_map<std::string, std::uint32_t> id_;   // variant name → dense id
    std::vector<std::vector<Edge>>                 out_;   // out_[a] = edges from source variant a
    std::vector<double>                            front_; // front_[v] = times v produced new frontier
    std::vector<double>                            dark_;  // dark_[v]  = times v ran without new frontier
    std::size_t edges_     = 0;
    std::size_t src_count_ = 0;
    bool        loaded_    = false;

    // RegionMap state (immutable post-load): sorted function start PCs + parallel func ids + name→id.
    std::vector<std::uint64_t>                     rm_starts_;
    std::vector<std::uint32_t>                     rm_fnid_;
    std::unordered_map<std::string, std::uint32_t> rm_name2id_;
    bool                                           rm_loaded_ = false;

    mutable std::shared_mutex mtx_;  // guards out_ (α,β) + front_/dark_ + stats_; id_/rm_ immutable post-load
    Stats stats_;
};

} // namespace refuzz::fuzzer

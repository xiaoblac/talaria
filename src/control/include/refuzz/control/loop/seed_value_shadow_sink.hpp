// SeedValueShadowSink — append-only JSONL sink for seed-value signal shadow
// records (docs/plans/seed-value-signals.md §4.2).
//
// One row per mutation outcome: the three seed-value signals of the MUTATED
// (parent) seed — A rarity, B cross-run coverage variance, C state altitude —
// joined with that mutation's realized verdict (cov_gain + crash/abnormal
// flags). Pure observation: it never affects selection. The FuzzerLoop owns one
// instance, constructed only when `scheduler.seed_value_shadow.enabled` is set
// and a logs dir exists; default off → zero overhead.
//
// Header-only so FuzzerLoop can forward-declare it (keeping <fstream> out of the
// loop header) and include the full definition in the .cpp.
#pragma once

#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

namespace refuzz::control {

class SeedValueShadowSink {
public:
    struct Row {
        std::uint64_t seed_id   = 0;   // the mutated (parent) corpus seed
        double        elapsed_s = 0.0; // seconds since session start

        // signal A — rarity-weighted coverage (Σ 1/pc_count) at outcome time.
        double        rarity = 0.0;

        // baseline control — the MAB's own learned value (Ĝ) for this seed. The
        // offline analysis requires each signal to predict yield BEYOND this.
        double        mab_ghat = 0.0;

        // [seed-future-value] structural future(seed) = E[mass] (de-flattened
        // resource-precondition horizon). 0 when seed_horizon_enabled is off →
        // the column is always present, the signal only when the horizon is on.
        double        future = 0.0;

        // [future_cht / Psyzkaller] novelty-masked static call-transition horizon
        // (P_chT): forward signal in the ORDER stratum, orthogonal to `future`.
        // 0 when the horizon / transition table is off.
        double        future_cht = 0.0;

        // [future_band2] band-② uncovered-handler-mass-per-call (the kill-shot
        // candidate). Shadow only; 0 when SeedBand2 (map path) is off.
        double        future_band2 = 0.0;

        // [belief-graph] the forward signal under test: the parent seed's static 8-mechanism
        // unlock-potential prior. 0 when no graph (belief_graph_path off).
        double        belief_value = 0.0;
        // [belief-graph lineage] make LAGGED payoff attributable — trace a descendant's gain to
        // the high-belief ANCESTOR, not just the direct parent. root_seed_id = the mutation
        // chain's root; lineage_depth = generation. (NEXT increment: threaded from a seed->root
        // map maintained at admit; 0/-1 placeholder until then.)
        std::uint64_t root_seed_id  = 0;
        int           lineage_depth = -1;
        // [belief-graph RAW] record RAW facts, NOT pre-aggregated counts — a count guts re-lensability +
        // post-hoc attribution ("deep" is multi-lens; "frontier-fired" is SOFT responsibility, not a hit
        // count). Offline (scripts/seed_horizon/model/shadow_analyze.py) does ALL judgment: AttributePc maps each
        // new PC -> edge/label/rarity; precond = producer ∈ executed_variants. So dump only the raw facts.
        std::vector<std::uint64_t> new_pcs;            // new coverage PCs this run
        std::vector<std::string>   executed_variants;  // variant names whose calls executed (precond signal)

        // signal B — cross-run coverage variance (stamped at deflake finalize).
        std::uint32_t unstable_pc_count = 0;
        std::uint32_t union_pc_count    = 0;
        std::uint32_t observed_runs     = 0;

        // signal C — state-space altitude of the LIVE (post-minimize) program.
        bool          altitude_valid = false;
        std::uint32_t res_producers  = 0;
        std::uint32_t res_consumers  = 0;
        std::uint32_t distinct_kinds = 0;
        std::uint32_t max_depth      = 0;

        // [Phase 1] PRE-minimize altitude (stamped at minimize). Paired with the
        // post-minimize fields above = how much structure minimize destroyed.
        bool          pre_min_valid  = false;
        std::uint32_t pre_res_prod   = 0;
        std::uint32_t pre_res_cons   = 0;
        std::uint32_t pre_kinds      = 0;
        std::uint32_t pre_depth      = 0;

        // realized yield of this mutation.
        std::uint64_t cov_gain    = 0;
        // signal C's target: rarity-weighted footprint = Σ 1/pc_count over the
        // mutation's full executed cover (how rare the regions it reached are).
        double        rare_cov_gain = 0.0;
        bool          interesting = false;
        // B's race/crash-adjacency target lives in these abnormal flags.
        bool          is_crash              = false;
        bool          is_timeout            = false;
        bool          is_exec_error         = false;
        bool          is_resource_leak      = false;
        bool          is_contract_violation = false;
        bool          is_priority_inversion = false;
        bool          is_stack_overflow     = false;
    };

    explicit SeedValueShadowSink(const std::string& path)
        : out_(path, std::ios::out | std::ios::trunc)
    {}

    void Write(const Row& r)
    {
        if (!out_.good()) {
            return;
        }
        out_ << '{'
             << "\"seed_id\":" << r.seed_id
             << ",\"t\":" << r.elapsed_s
             << ",\"rarity\":" << r.rarity
             << ",\"mab_ghat\":" << r.mab_ghat
             << ",\"future\":" << r.future
             << ",\"future_cht\":" << r.future_cht
             << ",\"future_band2\":" << r.future_band2
             << ",\"belief_value\":" << r.belief_value
             << ",\"root_seed_id\":" << r.root_seed_id
             << ",\"lineage_depth\":" << r.lineage_depth
             << ",\"unstable_pc\":" << r.unstable_pc_count
             << ",\"union_pc\":" << r.union_pc_count
             << ",\"runs\":" << static_cast<unsigned>(r.observed_runs)
             << ",\"alt_valid\":" << (r.altitude_valid ? 1 : 0)
             << ",\"res_prod\":" << r.res_producers
             << ",\"res_cons\":" << r.res_consumers
             << ",\"kinds\":" << r.distinct_kinds
             << ",\"depth\":" << r.max_depth
             << ",\"pre_valid\":" << (r.pre_min_valid ? 1 : 0)
             << ",\"pre_res_prod\":" << r.pre_res_prod
             << ",\"pre_res_cons\":" << r.pre_res_cons
             << ",\"pre_kinds\":" << r.pre_kinds
             << ",\"pre_depth\":" << r.pre_depth
             << ",\"cov_gain\":" << r.cov_gain
             << ",\"rare_cov_gain\":" << r.rare_cov_gain
             << ",\"interesting\":" << (r.interesting ? 1 : 0)
             << ",\"crash\":" << (r.is_crash ? 1 : 0)
             << ",\"timeout\":" << (r.is_timeout ? 1 : 0)
             << ",\"exec_error\":" << (r.is_exec_error ? 1 : 0)
             << ",\"resource_leak\":" << (r.is_resource_leak ? 1 : 0)
             << ",\"contract\":" << (r.is_contract_violation ? 1 : 0)
             << ",\"prio_inv\":" << (r.is_priority_inversion ? 1 : 0)
             << ",\"stack_of\":" << (r.is_stack_overflow ? 1 : 0);
        out_ << ",\"new_pcs\":[";
        for (std::size_t i = 0; i < r.new_pcs.size(); ++i) {
            out_ << (i ? "," : "") << r.new_pcs[i];
        }
        out_ << "],\"executed_variants\":[";
        for (std::size_t i = 0; i < r.executed_variants.size(); ++i) {
            out_ << (i ? "," : "") << '"' << r.executed_variants[i] << '"';
        }
        out_ << "]}\n";
        if (++since_flush_ >= 64) {
            out_.flush();
            since_flush_ = 0;
        }
    }

private:
    std::ofstream out_;        // flushed + closed on destruction
    std::uint64_t since_flush_ = 0;
};

} // namespace refuzz::control

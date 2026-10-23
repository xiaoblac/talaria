// reFuzz syz_v2 mutator — ChoiceTable (§3.6).
//
// Mirror of `prog/prio.go` for the v2 IR. Computes the syscall-pair
// priority matrix (static + optional dynamic) and exposes a weighted
// choose() that mutator/generator hot paths can use to bias syscall
// selection.
//
// Class-B placement (per `target_ownership.md` §3.1 row
// `defaultChoiceTable`): owned by `mutator/`, built on demand, not
// shipped as codegen state. Concrete consumer modules
// (`engines/syz_v2_engine`, `ops/insert_call`, `generator`) hold a
// `const ChoiceTable&` for the duration of the mutator session.
//
// M0 (§3.6) lands the algorithm + a choice-ref oracle byte-equal to
// the syzkaller-side `tools/syzgen choice-ref` JSON. M1 wires the
// table into generation/mutation hot paths.

#pragma once

#include "refuzz/mutator/linux/syz_v2/random.hpp"
#include "refuzz/program/syz/encoding.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"

#include <cstdint>
#include <vector>

namespace refuzz::fuzzer { class ICorpusStore; }

namespace refuzz::mutator::syz_v2 {

namespace syz = ::refuzz::program::syz;

// Inherits Target::IChoiceTable so the engine can COW-publish a
// shared_ptr snapshot through Target::set_default_choice_table.
// The choose virtual takes a pre-rolled uint64_t random (so non-
// mutator readers don't need RandGen); the existing concrete
// choose(RandGen&, int64_t) overload rolls the bits and forwards.
class ChoiceTable final : public ::refuzz::program::syz::Target::IChoiceTable {
public:
    ChoiceTable() = default;

    // Build the priority matrix. Static-only when `corpus_store` is null
    // (matches the syzkaller `BuildChoiceTable(nil, nil)` shape). When
    // a corpus is provided, the dynamic co-occurrence component is
    // computed by decoding each corpus seed through `decoder`.
    //
    // Disabled / no-generate calls are excluded from the choice space
    // but the matrix retains all rows/cols at their original ID for
    // index stability. Pseudo calls are additionally filtered by the
    // policy so the choose() pool never contains stub / unsupported /
    // cap-mismatched pseudos that the caller explicitly disallowed.
    //
    // The policy parameter is REQUIRED — no default. Oracle tooling
    // (refuzz_syz_v2_choice_ref) must pass a permissive policy to
    // mirror Go's `CalculatePriorities(nil, nil)`; production engine
    // passes its EngineConfig policy (safe default = native-only).
    // Forcing every call site to state intent prevents silent oracle
    // drift; see review notes on PR-2-C.
    //
    // [syscall-enable-whitelist] `enabled_filter` is a per-id mask (1 =
    // enabled). Empty = no whitelist → every non-disabled call is
    // generatable, identical to the pre-whitelist behavior.
    void build(const syz::Target& target,
               const std::vector<std::uint8_t>& enabled_filter = {});
    void build(const syz::Target& target,
               const ::refuzz::fuzzer::ICorpusStore& corpus_store,
               syz::TextDecoder& decoder,
               const std::vector<std::uint8_t>& enabled_filter = {});

    // Pick a syscall id (1:1 with prog/prio.go:316-338): 5% uniform fallback,
    // else a weighted CDF lookup over the anchor's `runs_` row, where the anchor
    // is `prev_id` when usable, else a uniformly-random generatable call
    // (`prev_id < 0` is the latter — still weighted, NOT a plain-uniform pick).
    uint64_t choose(RandGen& r, int64_t prev_id) const;

    // IChoiceTable adapter: pre-rolled 64-bit random source. The
    // RandGen overload above forwards into this body.
    std::uint64_t choose(std::uint64_t prev_id,
                         std::uint64_t random_64) const override;

    // Read-only access for oracle / debugging.
    bool   ready() const { return !prios_.empty(); }
    bool   generatable(uint64_t id) const {
        return id < runs_.size() && !runs_[id].empty();
    }
    bool   enabled_call(uint64_t id) const override {
        return id < enabled_.size() && enabled_[id] != 0;
    }
    size_t syscall_count() const { return prios_.size(); }
    std::size_t enabled_count() const override { return enabled_count_; }

    // Diagnostic counter for the dynamic-prio rebuild's
    // artifact-first contract. Bumps when a corpus seed lacks
    // seed.artifact and the rebuild has to TextDecoder.decode the
    // payload (legacy path). Production v2 sessions must keep this
    // at 0; oracle pins it.
    static std::uint64_t payload_fallback_count();
    static void          reset_payload_fallback_count_for_test();
    const std::vector<std::vector<int32_t>>& prios()        const { return prios_; }
    const std::vector<uint8_t>&              enabled_mask() const { return enabled_; }

private:
    void compute_static_prio();
    void compute_dynamic_prio(const ::refuzz::fuzzer::ICorpusStore& corpus,
                              syz::TextDecoder& decoder);
    void normalize_rows();
    void apply_self_priority();
    void build_runs();

    const syz::Target*                target_ = nullptr;
    std::vector<std::vector<int32_t>> prios_;
    std::vector<std::vector<int32_t>> runs_;
    std::vector<uint8_t>              enabled_;        // size N; 1 if enabled (disabled+no_generate excluded)
    std::vector<uint64_t>             generatable_ids_;
    size_t                            enabled_count_ = 0;
};

} // namespace refuzz::mutator::syz_v2

// hints_apply.hpp — Epic 5 PR-5-C
//
// Mirror of `prog/hints.go` algorithm — public entry points that the
// SyzV2MutatorEngine override calls into. Free-function form per memory
// `feedback_adapt_three_tiers`: cross-cutting orchestrator at the
// algorithm level; per-Type policy stays in `program/syz` `Type::method`
// virtuals (`useless_hint`, `is_pad`, etc.).
//
// Surface (1:1 port; per memory `feedback_porting_keep_candidate_set_minimal`):
//   - shrink_expand(v, comps, bitsize, image)
//   - check_const_arg / check_data_arg / check_compressed_arg
//   - generate_arg_hints (type-dispatch; mirror generateHints)
//   - mutate_prog_with_hints (top-level; mirror Prog.MutateWithHints)
//
// Module boundary (memory `feedback_adapt_three_tiers`): callers in
// control/ pass typed Prog by const-ref or via SyzV2MutatorEngine
// adapter; control/ never includes these headers directly. The
// `tools/check_hints_module_boundaries.sh` lint enforces this.

#pragma once

#include "refuzz/mutator/linux/syz_v2/hints/comp_map.hpp"
#include "refuzz/program/syz/analysis.hpp"
#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/type.hpp"

#include <cstdint>
#include <functional>
#include <vector>

namespace refuzz::mutator::syz_v2::hints {

// Mirror of `shrink_expand(v, compMap, bitsize, image)` — produce the
// sorted-unique replacer set for one input value `v` of `bitsize` bits.
// `image=true` further restricts candidates per upstream image rules
// (only widths >= 4, drop pure 0/^0). Returns sorted ascending uint64s.
std::vector<uint64_t> ShrinkExpand(uint64_t v,
                                   const CompMap& comps,
                                   uint64_t bitsize,
                                   bool image);

// Mirror of `checkConstArg`. `field` may be nullptr (top-level args
// in TestHintsCheckConstArg fixtures pass nullptr; structured-arg
// callers pass the owning Field for `related_fields` filtering).
// `exec` returns false to abort iteration early (matches upstream
// doMore semantics).
void CheckConstArgHints(::refuzz::program::syz::ConstArg& arg,
                        const ::refuzz::program::syz::Field* field,
                        const CompMap& comps,
                        const std::function<bool()>& exec);

// Mirror of `checkDataArg`. Slides 8-byte windows over data() up to
// length `min(size, maxDataLength=100)`; for each window calls
// shrink_expand and emits each replacement candidate via `exec`.
void CheckDataArgHints(::refuzz::program::syz::DataArg& arg,
                       const CompMap& comps,
                       const std::function<bool()>& exec);

// Mirror of `checkCompressedArg`. Decompresses the buffer, walks
// 4-byte-aligned uint64 windows, runs shrink_expand with image=true,
// re-compresses, then restores. Throws if the buffer is not a valid
// zlib stream — matches upstream `image.MustDecompress` panic.
void CheckCompressedArgHints(::refuzz::program::syz::DataArg& arg,
                             const CompMap& comps,
                             const std::function<bool()>& exec);

// Mirror of `generateHints` — type-dispatch for one Arg. Skips ProcType
// (random proc fails validation), pad ConstType, CsumType (executor
// recomputes), Filename / String-with-values / Glob-with-values
// BufferType, and very small ConstArgs / DataArgs. The remaining ones
// dispatch to CheckConstArgHints / CheckDataArgHints /
// CheckCompressedArgHints. `field` may be nullptr.
void GenerateArgHints(const CompMap& comps,
                      ::refuzz::program::syz::Arg* arg,
                      const ::refuzz::program::syz::Field* field,
                      const std::function<bool()>& exec);

// Mirror of `(*Prog).MutateWithHints`. Clones `src`, walks every Arg
// of `Calls[call_index]` via foreach_arg, calls GenerateArgHints, and
// for each candidate invokes `exec` with a const-ref to the in-place
// mutated clone. The clone state is restored between candidates per
// Type-specific Check helper. Empty / out-of-range call_index is a
// no-op. Returns once `exec` returns false or every arg has been
// processed. Sanitize is called via Target::sanitize_call before each
// `exec` invocation to mirror upstream's `execValidate` (skip
// debug_validate / check_conditions — both upstream-only and not yet
// ported in reFuzz; tracked as Epic 5 plan §10 deferral).
using HintsExecCallback =
    std::function<bool(const ::refuzz::program::syz::Prog&)>;
void MutateProgWithHints(const ::refuzz::program::syz::Prog& src,
                         int call_index,
                         const CompMap& comps,
                         const HintsExecCallback& exec);

} // namespace refuzz::mutator::syz_v2::hints

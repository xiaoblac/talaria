// Mutation ops for the v2 syz family — free-function entries.
//
// Mirrors v1 `linux/syz/ops/syz_mutate_ops.hpp` shape but typed against
// the v2 IR (`refuzz::program::syz::Prog`). Each function below is the
// algorithmic core of one op; the matching `ISyzV2MutatorOp` wrapper
// in `syz_v2_op_wrappers.hpp` calls it and returns its bool result.
//
// In M0 these are stubs that return false — the wrapper machinery and
// engine routing are exercised, but no actual mutation happens. M1
// fills `mute_v2_mutate_arg`; M2 fills splice/insert/remove; M3 fills
// squash_any.

#pragma once

#include "refuzz/mutator/linux/syz_v2/components.hpp"
#include "refuzz/mutator/linux/syz_v2/random.hpp"
#include "refuzz/program/syz/prog.hpp"

namespace refuzz::mutator::syz_v2 {

// Splice — head of `prog` + tail of `ctx.splice_donor`.
// Returns false if donor is null/empty or splice point unsuitable.
// Filled in M2.
bool mute_v2_splice(syz::Prog& prog, SyzV2MutationContext& ctx, RandGen& r);

// Insert one freshly generated call at a random position.
// Uses ctx.gen_state + generator helpers from generator.hpp.
// Filled in M2.
bool mute_v2_insert_call(syz::Prog& prog, SyzV2MutationContext& ctx, RandGen& r);

// Mutate a single arg of a randomly chosen call.
// Filled in M1 (heavyweight: per-type dispatch over 13 type kinds).
bool mute_v2_mutate_arg(syz::Prog& prog, SyzV2MutationContext& ctx, RandGen& r);

// Remove a randomly chosen call (and any consumers of resources it
// produced). Filled in M2.
bool mute_v2_remove_call(syz::Prog& prog, SyzV2MutationContext& ctx, RandGen& r);

// Squash a resource/result arg into a flat data arg with a special
// integer value. Filled in M3.
bool mute_v2_squash_any(syz::Prog& prog, SyzV2MutationContext& ctx, RandGen& r);

} // namespace refuzz::mutator::syz_v2

// reFuzz syz_v2 mutator — splice op (§3.5 M2).
//
// Mirror of `prog/mutation.go::splice`: take the prog's calls up to a
// random cut point, then append the donor's calls (clone) starting
// from another random point, capping at ctx.max_calls. Donor comes
// from ctx.splice_donor; if null, the op declines.

#pragma once

#include "refuzz/mutator/linux/syz_v2/components.hpp"
#include "refuzz/program/syz/prog.hpp"

namespace refuzz::mutator::syz_v2 {

bool splice_impl(syz::Prog& prog, SyzV2MutationContext& ctx, RandGen& r);

} // namespace refuzz::mutator::syz_v2

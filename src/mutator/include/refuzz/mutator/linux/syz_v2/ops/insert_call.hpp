// reFuzz syz_v2 mutator — insertCall op (§3.5 M2).
//
// Mirror of `prog/mutation.go::insertCall`: generate one fresh call
// (via the v2 generator's generate_call) and insert it at a random
// biased position in prog. ctx.gen_state must reflect the current
// prog's resources (the engine sets this up in MutateViaPolicy).

#pragma once

#include "refuzz/mutator/linux/syz_v2/components.hpp"
#include "refuzz/program/syz/prog.hpp"

namespace refuzz::mutator::syz_v2 {

bool insert_call_impl(syz::Prog& prog, SyzV2MutationContext& ctx, RandGen& r);

} // namespace refuzz::mutator::syz_v2

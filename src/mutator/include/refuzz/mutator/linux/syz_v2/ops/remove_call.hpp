// reFuzz syz_v2 mutator — removeCall op (§3.5 M2).
//
// Mirror of `prog/mutation.go::removeCall`: pick a random call, remove
// it, and walk all remaining args clearing ResultArg references that
// pointed into the removed call (otherwise validate fails on
// dangling resource ref). If the prog has 1 call, the op declines —
// removing the sole call would yield an empty prog.

#pragma once

#include "refuzz/mutator/linux/syz_v2/components.hpp"
#include "refuzz/program/syz/prog.hpp"

namespace refuzz::mutator::syz_v2 {

bool remove_call_impl(syz::Prog& prog, SyzV2MutationContext& ctx, RandGen& r);

} // namespace refuzz::mutator::syz_v2

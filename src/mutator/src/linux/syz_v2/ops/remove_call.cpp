// reFuzz syz_v2 mutator — removeCall op (§3.5 M2).
//
// Pick one call, remove it, sweep remaining args for ResultArg refs
// that pointed into the removed call's subtree (clear any dangling).
// Mirror of upstream `Prog.RemoveCall` semantics.

#include "refuzz/mutator/linux/syz_v2/ops/remove_call.hpp"

#include "refuzz/program/syz/transform.hpp"

#include <cstddef>

namespace refuzz::mutator::syz_v2 {

bool remove_call_impl(syz::Prog& prog, SyzV2MutationContext& /*ctx*/, RandGen& r) {
    auto& calls = prog.mutable_calls();
    if (calls.size() <= 1) {
        // Removing the last call would yield an empty prog — refuse so
        // the policy can pick a different op next round.
        return false;
    }

    const std::size_t idx =
        static_cast<std::size_t>(r.rand(static_cast<int>(calls.size())));
    return syz::RemoveCall(prog, idx);
}

} // namespace refuzz::mutator::syz_v2

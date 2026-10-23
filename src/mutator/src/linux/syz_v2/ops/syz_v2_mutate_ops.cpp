// reFuzz syz_v2 mutator — mutation op free-function bodies (§3.5).
//
// M0 stubs; M1/M2/M3 fill in the algorithm. Keeping signatures stable
// from M0 lets later milestones drop in implementation without
// touching wrappers / policies / engine.

#include "refuzz/mutator/linux/syz_v2/ops/syz_v2_mutate_ops.hpp"

#include "refuzz/mutator/linux/syz_v2/ops/insert_call.hpp"
#include "refuzz/mutator/linux/syz_v2/ops/mutate_arg.hpp"
#include "refuzz/mutator/linux/syz_v2/ops/remove_call.hpp"
#include "refuzz/mutator/linux/syz_v2/ops/splice.hpp"
#include "refuzz/mutator/linux/syz_v2/ops/squash_any.hpp"

namespace refuzz::mutator::syz_v2 {

bool mute_v2_splice(syz::Prog& prog,
                    SyzV2MutationContext& ctx,
                    RandGen& r)
{
    return splice_impl(prog, ctx, r);
}

bool mute_v2_insert_call(syz::Prog& prog,
                         SyzV2MutationContext& ctx,
                         RandGen& r)
{
    return insert_call_impl(prog, ctx, r);
}

bool mute_v2_mutate_arg(syz::Prog& prog,
                        SyzV2MutationContext& ctx,
                        RandGen& r)
{
    return mutate_arg_impl(prog, ctx, r);
}

bool mute_v2_remove_call(syz::Prog& prog,
                         SyzV2MutationContext& ctx,
                         RandGen& r)
{
    return remove_call_impl(prog, ctx, r);
}

bool mute_v2_squash_any(syz::Prog& prog,
                        SyzV2MutationContext& ctx,
                        RandGen& r)
{
    return squash_any_impl(prog, ctx, r);
}

} // namespace refuzz::mutator::syz_v2

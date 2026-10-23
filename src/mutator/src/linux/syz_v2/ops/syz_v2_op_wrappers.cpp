// reFuzz syz_v2 mutator — ISyzV2MutatorOp wrapper bodies (§3.5).
//
// Names match v1's syz_* op names without the v1-namespacing prefix —
// distinct from v1 because the v2 ops live in `refuzz::mutator::syz_v2`
// namespace and the engine registers them as v2-side ops.
//
// Weights mirror `prog/mutation.go` MutateOpts {Splice:200, InsertCall:100,
// MutateArg:100, RemoveCall:10, SquashAny:50}.

#include "refuzz/mutator/linux/syz_v2/ops/syz_v2_op_wrappers.hpp"

#include "refuzz/mutator/linux/syz_v2/ops/syz_v2_mutate_ops.hpp"

namespace refuzz::mutator::syz_v2 {

// ----- Splice (200) ---------------------------------------------------
std::string_view SyzV2SpliceOp::Name() const   { return "splice"; }
uint32_t         SyzV2SpliceOp::Weight() const { return 200; }
bool SyzV2SpliceOp::Apply(syz::Prog&            prog,
                          SyzV2MutationContext& ctx,
                          RandGen&              r) const
{
    return mute_v2_splice(prog, ctx, r);
}

// ----- InsertCall (100) ----------------------------------------------
std::string_view SyzV2InsertCallOp::Name() const   { return "insert_call"; }
uint32_t         SyzV2InsertCallOp::Weight() const { return 100; }
bool SyzV2InsertCallOp::Apply(syz::Prog&            prog,
                              SyzV2MutationContext& ctx,
                              RandGen&              r) const
{
    return mute_v2_insert_call(prog, ctx, r);
}

// ----- MutateArg (100) ------------------------------------------------
std::string_view SyzV2MutateArgOp::Name() const   { return "mutate_arg"; }
uint32_t         SyzV2MutateArgOp::Weight() const { return 100; }
bool SyzV2MutateArgOp::Apply(syz::Prog&            prog,
                             SyzV2MutationContext& ctx,
                             RandGen&              r) const
{
    return mute_v2_mutate_arg(prog, ctx, r);
}

// ----- RemoveCall (10) -----------------------------------------------
std::string_view SyzV2RemoveCallOp::Name() const   { return "remove_call"; }
uint32_t         SyzV2RemoveCallOp::Weight() const { return 10; }
bool SyzV2RemoveCallOp::Apply(syz::Prog&            prog,
                              SyzV2MutationContext& ctx,
                              RandGen&              r) const
{
    return mute_v2_remove_call(prog, ctx, r);
}

// ----- SquashAny (50) ------------------------------------------------
std::string_view SyzV2SquashAnyOp::Name() const   { return "squash_any"; }
uint32_t         SyzV2SquashAnyOp::Weight() const { return 50; }
bool SyzV2SquashAnyOp::Apply(syz::Prog&            prog,
                             SyzV2MutationContext& ctx,
                             RandGen&              r) const
{
    return mute_v2_squash_any(prog, ctx, r);
}

} // namespace refuzz::mutator::syz_v2

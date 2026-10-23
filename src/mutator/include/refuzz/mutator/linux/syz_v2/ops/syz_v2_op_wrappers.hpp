// reFuzz syz_v2 mutator — ISyzV2MutatorOp wrappers (§3.5).
//
// Mirror of v1 `syz/ops/syz_op_wrappers.hpp`. Each class wraps the
// matching free function in `syz_v2_mutate_ops.hpp`, exposing the
// uniform op interface the engine + policies select against. Weights
// come from upstream `prog/mutation.go` MutateOpts (Splice=200,
// InsertCall=100, MutateArg=100, SquashAny=50, RemoveCall=10) so that
// SyzV2WeightedMutationPolicy reproduces upstream balanced
// distribution by construction.

#pragma once

#include "refuzz/mutator/linux/syz_v2/components.hpp"

namespace refuzz::mutator::syz_v2 {

class SyzV2SpliceOp final : public ISyzV2MutatorOp {
public:
    std::string_view Name() const override;
    uint32_t         Weight() const override;
    bool             Apply(syz::Prog&            prog,
                           SyzV2MutationContext& ctx,
                           RandGen&              r) const override;
};

class SyzV2InsertCallOp final : public ISyzV2MutatorOp {
public:
    std::string_view Name() const override;
    uint32_t         Weight() const override;
    bool             Apply(syz::Prog&            prog,
                           SyzV2MutationContext& ctx,
                           RandGen&              r) const override;
};

class SyzV2MutateArgOp final : public ISyzV2MutatorOp {
public:
    std::string_view Name() const override;
    uint32_t         Weight() const override;
    bool             Apply(syz::Prog&            prog,
                           SyzV2MutationContext& ctx,
                           RandGen&              r) const override;
};

class SyzV2RemoveCallOp final : public ISyzV2MutatorOp {
public:
    std::string_view Name() const override;
    uint32_t         Weight() const override;
    bool             Apply(syz::Prog&            prog,
                           SyzV2MutationContext& ctx,
                           RandGen&              r) const override;
};

class SyzV2SquashAnyOp final : public ISyzV2MutatorOp {
public:
    std::string_view Name() const override;
    uint32_t         Weight() const override;
    bool             Apply(syz::Prog&            prog,
                           SyzV2MutationContext& ctx,
                           RandGen&              r) const override;
};

} // namespace refuzz::mutator::syz_v2

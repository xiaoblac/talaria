// reFuzz syz_v2 mutator — mutation policy declarations (§3.5).
//
// Mirror of v1 `linux/syz/policies/syz_mutation_policies.hpp` for the
// v2 IR. Two policy shapes mirror upstream's MutateOpts:
//   * SyzV2WeightedMutationPolicy — weighted random pick across the
//     full op registry (= upstream's "balanced" mode);
//   * SyzV2SingleOpPolicy         — always returns one named op
//     (= upstream's mode-restricted single-op runs).

#pragma once

#include "refuzz/mutator/linux/syz_v2/components.hpp"

#include <string>

namespace refuzz::mutator::syz_v2 {

class SyzV2WeightedMutationPolicy final : public ISyzV2MutationPolicy {
public:
    explicit SyzV2WeightedMutationPolicy(std::string name);

    std::string_view Name() const override;
    const ISyzV2MutatorOp* SelectOp(
        const std::vector<std::unique_ptr<ISyzV2MutatorOp>>& registry,
        const ::refuzz::fuzzer::Seed&                        seed,
        const syz::Prog&                                     prog,
        const SyzV2MutationContext&                          ctx,
        RandGen&                                             r) const override;

private:
    std::string name_;
};

class SyzV2SingleOpPolicy final : public ISyzV2MutationPolicy {
public:
    SyzV2SingleOpPolicy(std::string name, std::string op_name);

    std::string_view Name() const override;
    const ISyzV2MutatorOp* SelectOp(
        const std::vector<std::unique_ptr<ISyzV2MutatorOp>>& registry,
        const ::refuzz::fuzzer::Seed&                        seed,
        const syz::Prog&                                     prog,
        const SyzV2MutationContext&                          ctx,
        RandGen&                                             r) const override;

private:
    std::string name_;
    std::string op_name_;
};

} // namespace refuzz::mutator::syz_v2

// reFuzz syz_v2 mutator — mutation policy bodies (§3.5).
//
// Algorithmic shape identical to v1 syz; the only differences are types
// (v2 IR `Prog` + RandGen + ISyzV2* interfaces) and namespace.

#include "refuzz/mutator/linux/syz_v2/policies/syz_v2_mutation_policies.hpp"

#include <cstdint>
#include <utility>

namespace refuzz::mutator::syz_v2 {

// ============================================================
// SyzV2WeightedMutationPolicy
// ============================================================

SyzV2WeightedMutationPolicy::SyzV2WeightedMutationPolicy(std::string name)
    : name_(std::move(name))
{}

std::string_view SyzV2WeightedMutationPolicy::Name() const
{
    return name_;
}

const ISyzV2MutatorOp* SyzV2WeightedMutationPolicy::SelectOp(
    const std::vector<std::unique_ptr<ISyzV2MutatorOp>>& registry,
    const ::refuzz::fuzzer::Seed& /*seed*/,
    const syz::Prog& /*prog*/,
    const SyzV2MutationContext& /*ctx*/,
    RandGen& r) const
{
    uint64_t total = 0;
    for (const auto& op : registry) {
        if (op) {
            total += op->Weight();
        }
    }
    if (total == 0) {
        return nullptr;
    }

    uint64_t roll = r.rand_range(0, total - 1);
    for (const auto& op : registry) {
        if (!op) {
            continue;
        }
        const uint32_t weight = op->Weight();
        if (roll < weight) {
            return op.get();
        }
        roll -= weight;
    }
    return nullptr;
}

// ============================================================
// SyzV2SingleOpPolicy
// ============================================================

SyzV2SingleOpPolicy::SyzV2SingleOpPolicy(std::string name, std::string op_name)
    : name_(std::move(name))
    , op_name_(std::move(op_name))
{}

std::string_view SyzV2SingleOpPolicy::Name() const
{
    return name_;
}

const ISyzV2MutatorOp* SyzV2SingleOpPolicy::SelectOp(
    const std::vector<std::unique_ptr<ISyzV2MutatorOp>>& registry,
    const ::refuzz::fuzzer::Seed& /*seed*/,
    const syz::Prog& /*prog*/,
    const SyzV2MutationContext& /*ctx*/,
    RandGen& /*r*/) const
{
    for (const auto& op : registry) {
        if (op && op->Name() == op_name_) {
            return op.get();
        }
    }
    return nullptr;
}

} // namespace refuzz::mutator::syz_v2

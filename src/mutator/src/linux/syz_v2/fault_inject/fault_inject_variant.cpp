// Copyright 2026 reFuzz project author -------youngkk.
//
// fault_inject_variant.cpp — implementation. See header for contract.

#include "refuzz/mutator/linux/syz_v2/fault_inject/fault_inject_variant.hpp"

#include "refuzz/program/syz/clone.hpp"

namespace refuzz::mutator::linux::syz_v2::fault_inject {

std::unique_ptr<refuzz::program::syz::Prog>
MakeFaultInjectVariant(const refuzz::program::syz::Prog& prog,
                       int call_index, int nth)
{
    if (call_index < 0) {
        return nullptr;
    }
    const auto n = static_cast<int>(prog.calls().size());
    if (call_index >= n) {
        return nullptr;
    }
    auto clone = refuzz::program::syz::DeepClone(prog);
    if (clone == nullptr) {
        return nullptr;
    }
    auto& target_call = clone->mutable_calls()[static_cast<std::size_t>(call_index)];
    auto props = target_call->props();
    props.fail_nth = nth;
    target_call->set_props(props);
    return clone;
}

}  // namespace refuzz::mutator::linux::syz_v2::fault_inject

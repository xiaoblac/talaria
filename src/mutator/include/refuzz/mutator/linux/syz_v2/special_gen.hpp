// reFuzz syz_v2 mutator — concrete IGen implementation.
//
// Mirror of syzkaller `prog.Gen`. Bridges the abstract
// Target::IGen vtable consumed by SpecialType bodies (which live in
// program/syz/linux/) into the mutator's RandGen + GenState +
// generate_arg / mutate_single_arg surface.
//
// Constructed per SpecialType invocation; lifetime is one
// generate_arg call. Not thread-safe; one mutator session uses one
// GenImpl at a time.

#pragma once

#include "refuzz/mutator/linux/syz_v2/gen_state.hpp"
#include "refuzz/mutator/linux/syz_v2/random.hpp"
#include "refuzz/program/syz/target.hpp"

#include <cstdint>
#include <memory>
#include <vector>

namespace refuzz::mutator::syz_v2 {

namespace syz = ::refuzz::program::syz;

class GenImpl final : public syz::Target::IGen {
public:
    GenImpl(RandGen& r, GenState& s) noexcept : r_(r), s_(s) {}

    GenImpl(const GenImpl&)            = delete;
    GenImpl& operator=(const GenImpl&) = delete;
    GenImpl(GenImpl&&)                 = delete;
    GenImpl& operator=(GenImpl&&)      = delete;

    std::unique_ptr<syz::Arg> generate_arg(
        const syz::Type* t, syz::Dir d,
        std::vector<std::unique_ptr<syz::Call>>* calls) override;

    std::unique_ptr<syz::Arg> generate_special_arg(
        const syz::Type* t, syz::Dir d,
        std::vector<std::unique_ptr<syz::Call>>* calls) override;

    std::vector<std::unique_ptr<syz::Call>> mutate_arg(syz::Arg* arg) override;

    std::unique_ptr<syz::Arg> alloc(
        const syz::PtrType* t, syz::Dir d,
        std::unique_ptr<syz::Arg> inner,
        std::vector<std::unique_ptr<syz::Call>>* calls) override;

    bool n_out_of(std::uint64_t a, std::uint64_t b) override;
    bool one_of(int n)                              override;
    int  rand(int n)                                override;

    const syz::Target& target() const override;

private:
    RandGen&  r_;
    GenState& s_;
};

} // namespace refuzz::mutator::syz_v2

#include "refuzz/mutator/linux/syz_v2/special_gen.hpp"

#include "refuzz/mutator/linux/syz_v2/generator.hpp"
#include "refuzz/mutator/linux/syz_v2/ops/mutate_arg.hpp"
#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/type.hpp"

namespace refuzz::mutator::syz_v2 {

std::unique_ptr<syz::Arg> GenImpl::generate_arg(
    const syz::Type* t, syz::Dir d,
    std::vector<std::unique_ptr<syz::Call>>* calls) {
    auto gr = ::refuzz::mutator::syz_v2::generate_arg(r_, s_, t, d);
    if (calls != nullptr && !gr.calls.empty()) {
        for (auto& c : gr.calls) calls->push_back(std::move(c));
    }
    return std::move(gr.arg);
}

std::unique_ptr<syz::Arg> GenImpl::generate_special_arg(
    const syz::Type* t, syz::Dir d,
    std::vector<std::unique_ptr<syz::Call>>* calls) {
    auto gr = ::refuzz::mutator::syz_v2::generate_arg_no_special(r_, s_, t, d);
    if (calls != nullptr && !gr.calls.empty()) {
        for (auto& c : gr.calls) calls->push_back(std::move(c));
    }
    return std::move(gr.arg);
}

std::vector<std::unique_ptr<syz::Call>>
GenImpl::mutate_arg(syz::Arg* arg) {
    // Producer calls created during the per-type mutation get pushed
    // into s_.pending_extras_ by the resource-arg mutator. We drain
    // here and return them so the SpecialType caller can splice them
    // ahead of the consumer call (Target::SpecialTypeFn's
    // extra_calls out param). Note: gen_state.pending_extras_ is
    // drained at the engine op-apply boundary too (PR-3-A4); this
    // method takes ownership for the SpecialType caller's lifetime.
    ::refuzz::mutator::syz_v2::mutate_single_arg(r_, s_, arg);
    return s_.take_pending_extras();
}

std::unique_ptr<syz::Arg> GenImpl::alloc(
    const syz::PtrType* t, syz::Dir d,
    std::unique_ptr<syz::Arg> inner,
    std::vector<std::unique_ptr<syz::Call>>* /*calls*/) {
    if (t == nullptr) return nullptr;
    const std::uint64_t inner_size =
        (inner && inner->type() && !inner->type()->var_len())
            ? inner->type()->size()
            : (inner ? inner->size() : 0);
    const std::uint64_t inner_align =
        (inner && inner->type()) ? inner->type()->align() : 0;
    const std::uint64_t addr =
        s_.ma().alloc(inner_size == 0 ? 1 : inner_size,
                      inner_align == 0 ? 1 : inner_align);
    auto a = std::make_unique<syz::PointerArg>();
    a->set_type(t);
    a->set_dir(d);
    a->set_address(addr);
    a->set_res(std::move(inner));
    return a;
}

bool GenImpl::n_out_of(std::uint64_t a, std::uint64_t b) {
    // Narrowing to int: RandGen mirrors upstream randGen.nOutOf's
    // (int, int) signature. SpecialType bodies use small constants
    // (the largest upstream uses is r.nOutOf(1000, 1011) in USB ID
    // patching), all well within int range. The wider IGen ABI
    // (uint64_t) is intentional so the abstract interface in
    // program/syz does not bake mutator-side typing into the
    // contract; PR-3-D closure may revisit if any future caller
    // ever needs > INT_MAX values.
    return r_.n_out_of(static_cast<int>(a), static_cast<int>(b));
}

bool GenImpl::one_of(int n) {
    return r_.one_of(n);
}

int GenImpl::rand(int n) {
    return static_cast<int>(r_.rand(n));
}

const syz::Target& GenImpl::target() const {
    return s_.target();
}

} // namespace refuzz::mutator::syz_v2

// reFuzz syz_v2 mutator — squashAny op (§3.5 M3).

#include "refuzz/mutator/linux/syz_v2/ops/squash_any.hpp"

#include "refuzz/mutator/linux/syz_v2/ops/mutate_arg.hpp"
#include "refuzz/program/syz/analysis.hpp"
#include "refuzz/program/syz/any.hpp"
#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/type.hpp"

#include <utility>
#include <vector>

namespace refuzz::mutator::syz_v2 {

namespace {

// [align syz] = syz prog/mutation.go:17 maxBlobLen = 100<<10 (100 KiB). 见
// mutate_arg.cpp 同名常量注释。
constexpr uint64_t kMaxBlobLen = 100 << 10;

} // namespace

// Faithful port of prog/mutation.go::squashAny: pick a complex (squashable)
// pointer, collapse its structured pointee into a flat ANYUNION array of
// ANYBLOB/ANYRES (squash_ptr), then mutate one of the resulting blobs. This
// is how the fuzzer explores "what if this structured memory were arbitrary
// bytes" — the structural exploration the old blob-only tweak couldn't reach.
bool squash_any_impl(syz::Prog& prog, SyzV2MutationContext& ctx, RandGen& r) {
    if (ctx.target == nullptr) return false;
    const syz::Target& target = *ctx.target;

    // [mutation.go:139] Pick a random complex pointer.
    auto cands = syz::complex_ptrs(target, prog);
    if (cands.empty()) return false;
    const syz::ComplexPtr& cp = cands[r.rand(static_cast<int>(cands.size()))];
    syz::PointerArg* ptr = cp.arg;
    if (ptr == nullptr) return false;
    // [mutation.go:149] Honor the no_squash syscall attribute.
    if (cp.call != nullptr && cp.call->meta() != nullptr &&
        cp.call->meta()->attrs().no_squash) {
        return false;
    }

    // [mutation.go:152-154] Squash the structured pointee into an ANYUNION
    // array (unless it is already an any-ptr). squash_ptr is a no-op for
    // non-squashable content, so re-check before relying on it.
    if (!syz::is_any_ptr(target, ptr->type())) {
        syz::squash_ptr(target, ptr);
    }
    if (!syz::is_any_ptr(target, ptr->type()) || ptr->res() == nullptr) {
        return false;  // squash declined → op declines, engine picks another
    }

    // [mutation.go:155-165] Collect the in-direction ANYBLOB DataArgs now
    // under the pointer (out blobs carry caller length only).
    std::vector<syz::DataArg*> blobs;
    syz::foreach_sub_arg(ptr->res(), [&](syz::Arg* a, syz::ArgCtx*) {
        if (a != nullptr && a->arg_kind() == syz::ArgKind::kData &&
            a->dir() != syz::Dir::kOut) {
            blobs.push_back(static_cast<syz::DataArg*>(a));
        }
    });
    if (blobs.empty()) return false;

    // [mutation.go:174-178] Mutate one blob (ANYBLOB is varlen → may grow).
    const uint64_t base_size = ptr->res()->size();
    syz::DataArg* picked = blobs[r.rand(static_cast<int>(blobs.size()))];
    std::vector<uint8_t> data = picked->data();
    data = mutate_data_blob(r, std::move(data), 0, kMaxBlobLen);
    picked->set_data(std::move(data));

    // [mutation.go:179-183] If the pointee grew, re-allocate the pointer's
    // address so the larger payload doesn't overlap a neighbour.
    if (ctx.gen_state != nullptr) {
        const uint64_t new_size = ptr->res()->size();
        if (base_size < new_size) {
            const syz::Type* rt = ptr->res()->type();
            const uint64_t align =
                (rt != nullptr && rt->align() != 0) ? rt->align() : 1;
            const uint64_t addr =
                ctx.gen_state->ma().alloc(new_size == 0 ? 1 : new_size, align);
            ptr->set_address(addr);
        }
    }
    return true;
}

} // namespace refuzz::mutator::syz_v2

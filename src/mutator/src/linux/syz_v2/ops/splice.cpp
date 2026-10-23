// reFuzz syz_v2 mutator — splice op (§3.5 M2).
//
// The donor (ctx.splice_donor) may ALIAS a live corpus seed's typed Prog:
// the typed hot path (MutateTyped in engines/syz_v2_engine.cpp) hands out
// artifact->As<Prog>(), a shared_ptr to the very object the corpus holds —
// no copy. So splice MUST treat the donor as read-only: it DeepClones the
// donor and splices the CLONE's calls into prog, never the original.
// Mirrors upstream prog/mutation.go (`p0 := ...; p0c := p0.Clone()`).
//
// (Earlier this const_cast'd the donor and moved+cleared its calls in
// place, under a "donor is a throwaway copy" assumption that held only on
// the old bytes path — where the donor was freshly decoded. On the typed
// path that emptied the LIVE corpus seed in memory → next time that seed
// was mutated its clone had 0 calls → kSkipped → endless empty-skip →
// corpus decay. Cloning here restores the invariant the bytes world
// enforced for free: every mutation input is a private copy.)
//
// DeepClone remaps ResultArg cross-call refs within the clone, so the
// spliced-in calls are self-consistent. Trimming after splice can remove
// calls; the cleanup walker after trim clears any ResultArg.res_ that
// points into a removed Call subtree (mirrors upstream Prog.RemoveCall).

#include "refuzz/mutator/linux/syz_v2/ops/splice.hpp"

#include "refuzz/program/syz/clone.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/transform.hpp"

#include <cstddef>
#include <memory>
#include <utility>
#include <vector>

namespace refuzz::mutator::syz_v2 {

bool splice_impl(syz::Prog& prog, SyzV2MutationContext& ctx, RandGen& r) {
    if (ctx.splice_donor == nullptr) return false;
    if (prog.calls().empty()) return false;
    if (ctx.splice_donor->calls().empty()) return false;
    if (static_cast<int>(prog.calls().size()) >= ctx.max_calls) return false;

    // DeepClone the donor — it may alias a live corpus seed (typed path).
    // We move the CLONE's calls into prog; the original is never touched.
    auto donor_copy = syz::DeepClone(*ctx.splice_donor);
    if (!donor_copy) return false;
    auto& donor_calls = donor_copy->mutable_calls();
    if (donor_calls.empty()) return false;

    auto& dst = prog.mutable_calls();
    const std::size_t cut =
        static_cast<std::size_t>(r.rand(static_cast<int>(dst.size())));

    std::vector<std::unique_ptr<syz::Call>> merged;
    merged.reserve(dst.size() + donor_calls.size());
    for (std::size_t i = 0; i < cut; ++i) merged.push_back(std::move(dst[i]));
    for (auto& dc : donor_calls) {
        if (dc) merged.push_back(std::move(dc));
    }
    for (std::size_t i = cut; i < dst.size(); ++i) {
        if (dst[i]) merged.push_back(std::move(dst[i]));
    }
    // No donor_calls.clear() needed — donor_copy is a local that dies here.
    dst = std::move(merged);

    if (static_cast<int>(dst.size()) > ctx.max_calls) {
        const std::size_t keep = static_cast<std::size_t>(ctx.max_calls);
        if (!syz::RemoveCallRange(prog, keep, dst.size() - keep)) {
            return false;
        }
    }
    return true;
}

} // namespace refuzz::mutator::syz_v2

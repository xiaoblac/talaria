// reFuzz syz_v2 mutator — insertCall op (§3.5 M2).
//
// Generate one fresh call (or producer chain) via generate_call, insert
// at a biased random position. The current GenState (built by the
// engine from prog's existing calls) drives resource availability for
// the new call's input refs.

#include "refuzz/mutator/linux/syz_v2/ops/insert_call.hpp"

#include "refuzz/mutator/linux/syz_v2/generator.hpp"
#include "refuzz/program/syz/prog.hpp"

#include <algorithm>
#include <utility>
#include <vector>

namespace refuzz::mutator::syz_v2 {

bool insert_call_impl(syz::Prog& prog, SyzV2MutationContext& ctx, RandGen& r) {
    if (ctx.gen_state == nullptr) return false;
    if (static_cast<int>(prog.calls().size()) >= ctx.max_calls) return false;

    // Bias toward inserting near the end (mirror upstream's
    // biasedRand(len+1, 5) — higher probability for higher index).
    const int n = static_cast<int>(prog.calls().size());
    const int idx = r.biased_rand(n + 1, 5);

    // [v2 Epic 7 PR-12 B2 — Step 3] 上游 prog/mutation.go::insertCall:
    //     idx := r.biasedRand(len(p.Calls)+1, 5)
    //     var c *Call
    //     if idx < len(p.Calls) { c = p.Calls[idx] }
    //     s := analyze(ctx.ct, ctx.corpus, p, c)
    //     calls := r.generateCall(s, p, idx)
    // boundary = "插入位置上现存的那个 call"(顶住该 call,新 call 插在它前面);
    // idx == len → boundary nullptr → resources 含全 prog。
    const syz::Call* boundary =
        (idx < n) ? prog.calls()[static_cast<std::size_t>(idx)].get() : nullptr;
    ctx.gen_state->analyze_for_mutation_boundary(prog, boundary);

    // [syz-parity rand.go:629-638] Bias the ChoiceTable selection on a
    // UNIFORMLY-RANDOM call in [0, idx) — the insertion point — exactly like
    // syz generateCall(s, p, insertionPoint=idx). NOT the program's last
    // call (that was the old reFuzz behavior and ignored the insertion
    // position entirely). A randomly-picked no_generate call leaves bias=-1,
    // and choose() then anchors on a random generatable call (prio.go:321).
    int64_t bias = -1;
    if (idx > 0) {
        const auto& bc = prog.calls()[static_cast<std::size_t>(r.rand(idx))];
        if (bc && bc->meta() != nullptr && !bc->meta()->attrs().no_generate) {
            bias = static_cast<int64_t>(bc->meta()->id());
        }
    }
    auto generated = generate_call(r, *ctx.gen_state, bias);
    if (generated.empty()) return false;

    auto& dst = prog.mutable_calls();
    const size_t pos = static_cast<size_t>(std::min(idx, n));

    std::vector<std::unique_ptr<syz::Call>> merged;
    merged.reserve(dst.size() + generated.size());
    for (size_t i = 0; i < pos; ++i) merged.push_back(std::move(dst[i]));
    for (auto& g : generated) {
        if (g) {
            ctx.gen_state->analyze(g.get());
            merged.push_back(std::move(g));
        }
    }
    for (size_t i = pos; i < dst.size(); ++i) {
        if (dst[i]) merged.push_back(std::move(dst[i]));
    }
    dst = std::move(merged);

    // Trim from tail (matching upstream: it removes from `idx` onward,
    // but the practical invariant is just "<= max_calls"; tail trim
    // simulates RemoveCall(idx). The newly inserted call we want to
    // KEEP, so we trim from the back rather than from the insertion
    // point).
    while (static_cast<int>(dst.size()) > ctx.max_calls) {
        dst.pop_back();
    }
    return true;
}

} // namespace refuzz::mutator::syz_v2

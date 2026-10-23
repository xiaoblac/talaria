// Implementation of refuzz/program/syz/clone.hpp (§3.10 step 2).
//
// Two-pass walk: pass 1 deep-copies every Call/Arg, recording the
// old-ResultArg → new-ResultArg map; pass 2 walks the cloned tree and
// rewrites every `ResultArg::res_` from the OLD pointer (placeholder
// stored at clone time) to the NEW one. References that don't have a
// mapping (i.e. point outside the source) are zeroed in the clone.

#include "refuzz/program/syz/clone.hpp"

#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/prog.hpp"

#include <unordered_map>
#include <utility>

namespace refuzz::program::syz {

// §3.11 follow-up P8a — Arg::clone() type-method dispatch.
// Each subclass owns its own clone semantics; the cross-arg
// ResultMap (CloneCtx::result_map) threads through for the post-pass
// remap.

// ============================================================
// Arg::clone — convenience overload (no cross-arg context).
// ============================================================
std::unique_ptr<Arg> Arg::clone() const {
    CloneCtx ctx;
    return clone(ctx);
}

// ============================================================
// Per-subclass clone() overrides. Bodies lifted verbatim from the
// previous CloneXxxArg free functions.
// ============================================================

std::unique_ptr<Arg> ConstArg::clone(CloneCtx&) const {
    auto a = std::make_unique<ConstArg>();
    a->set_type(type());
    a->set_dir(dir());
    a->set_val(val_);
    return a;
}

std::unique_ptr<Arg> DataArg::clone(CloneCtx&) const {
    auto a = std::make_unique<DataArg>();
    a->set_type(type());
    a->set_dir(dir());
    if (!data_.empty()) {
        a->set_data(data_);
    } else {
        a->set_out_size(out_size_);
    }
    return a;
}

std::unique_ptr<Arg> PointerArg::clone(CloneCtx& ctx) const {
    auto a = std::make_unique<PointerArg>();
    a->set_type(type());
    a->set_dir(dir());
    a->set_address(address_);
    a->set_vma_size(vma_size_);
    if (res_ != nullptr) {
        a->set_res(res_->clone(ctx));
    }
    return a;
}

std::unique_ptr<Arg> GroupArg::clone(CloneCtx& ctx) const {
    auto a = std::make_unique<GroupArg>();
    a->set_type(type());
    a->set_dir(dir());
    for (const auto& child : inner_) {
        a->add_inner(child->clone(ctx));
    }
    return a;
}

std::unique_ptr<Arg> UnionArg::clone(CloneCtx& ctx) const {
    auto a = std::make_unique<UnionArg>();
    a->set_type(type());
    a->set_dir(dir());
    a->set_index(index_);
    a->set_transient(transient_);
    if (option_ != nullptr) {
        a->set_option(option_->clone(ctx));
    }
    return a;
}

// ResultArg clone: register the old→new mapping, store the OLD
// reference pointer via `set_res_raw` as a placeholder. Pass 2
// (Prog-level remap) rewrites to the cloned counterpart.
//
// `set_res_raw` is used (NOT `set_res`) because the latter inserts
// `this` into the source ResultArg's uses_ forward-edge set,
// polluting cross-Prog state. The Prog-level remap walks the cloned
// tree post-pass, calls `set_res()` with the cloned counterpart, and
// correctly establishes forward edges in the cloned graph.
std::unique_ptr<Arg> ResultArg::clone(CloneCtx& ctx) const {
    auto a = std::make_unique<ResultArg>();
    a->set_type(type());
    a->set_dir(dir());
    a->set_op_div(op_div_);
    a->set_op_add(op_add_);
    a->set_val(val_);
    a->set_res_raw(const_cast<ResultArg*>(res_));
    ctx.result_map.emplace(this, a.get());
    return a;
}

namespace {

using ResultMap = std::unordered_map<const ResultArg*, ResultArg*>;

// [v1 free-function CloneXxxArg switch — ROLLBACK: re-add the per-subclass
// helpers above plus this CloneArg switch]
// [v2 method-dispatch — 当前版本]
// CloneArg shrinks to a one-liner that delegates to the virtual method.
std::unique_ptr<Arg> CloneArg(const Arg& src, ResultMap& map) {
    CloneCtx ctx;
    ctx.result_map = std::move(map);
    auto out = src.clone(ctx);
    map = std::move(ctx.result_map);
    return out;
}

// CloneResultArg helper kept as a thin wrapper for DeepClone's
// per-call ret cloning (it needs to register the mapping for the
// ret slot specifically). Body matches ResultArg::clone() but
// uses local ResultMap for backward compat with DeepClone's
// existing flow.
std::unique_ptr<ResultArg> CloneResultArg(const ResultArg& src,
                                          ResultMap&       map) {
    CloneCtx ctx;
    ctx.result_map = std::move(map);
    auto a = src.clone(ctx);
    map = std::move(ctx.result_map);
    // ResultArg::clone() returned an Arg*; we know the dynamic type
    // because the static dispatch on ResultArg.
    return std::unique_ptr<ResultArg>(static_cast<ResultArg*>(a.release()));
}

void RemapArg(Arg* a, const ResultMap& map) {
    if (a == nullptr) return;
    switch (a->arg_kind()) {
        case ArgKind::kConst:
        case ArgKind::kData:
            return;
        case ArgKind::kPointer: {
            auto* pa = static_cast<PointerArg*>(a);
            RemapArg(pa->res(), map);
            return;
        }
        case ArgKind::kGroup: {
            auto* ga = static_cast<GroupArg*>(a);
            for (auto& child : ga->mutable_inner()) {
                RemapArg(child.get(), map);
            }
            return;
        }
        case ArgKind::kUnion: {
            auto* ua = static_cast<UnionArg*>(a);
            RemapArg(ua->option(), map);
            return;
        }
        case ArgKind::kResult: {
            auto* ra = static_cast<ResultArg*>(a);
            // After CloneResultArg, ra->res() temporarily holds the OLD
            // pointer. Replace with the cloned counterpart, or null if
            // the source reference was outside the cloned scope.
            const ResultArg* old_ref = ra->res();
            if (old_ref == nullptr) return;
            auto it = map.find(old_ref);
            ra->set_res(it != map.end() ? it->second : nullptr);
            return;
        }
    }
}

} // namespace

std::unique_ptr<Arg> DeepCloneArg(const Arg& src) {
    ResultMap map;
    auto clone = CloneArg(src, map);
    RemapArg(clone.get(), map);
    return clone;
}

std::unique_ptr<Prog> DeepClone(const Prog& src, ResultMap* out_map) {
    auto prog = std::make_unique<Prog>();
    prog->set_target(src.target());
    for (const auto& c : src.comments()) {
        prog->add_comment(c);
    }

    ResultMap map;

    // Pass 1: deep-clone every Call + its Arg tree, populating the
    // ResultArg map. ret is cloned first so subsequent calls' args can
    // reference it via the map.
    for (const auto& src_call : src.calls()) {
        auto new_call = std::make_unique<Call>();
        new_call->set_meta(src_call->meta());
        new_call->set_props(src_call->props());
        new_call->set_comment(src_call->comment());

        if (src_call->ret() != nullptr) {
            new_call->set_ret(CloneResultArg(*src_call->ret(), map));
        }
        for (const auto& a : src_call->args()) {
            new_call->add_arg(CloneArg(*a, map));
        }
        prog->add_call(std::move(new_call));
    }

    // Pass 2: rewrite every ResultArg::res_ in the cloned tree from the
    // OLD pointer (placeholder) to the cloned ResultArg.
    for (auto& call : prog->mutable_calls()) {
        if (call->mutable_ret() != nullptr) {
            RemapArg(call->mutable_ret(), map);
        }
        for (auto& a : call->mutable_args()) {
            RemapArg(a.get(), map);
        }
    }

    if (out_map != nullptr) {
        *out_map = std::move(map);
    }
    return prog;
}

} // namespace refuzz::program::syz

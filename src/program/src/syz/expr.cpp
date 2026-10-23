// Implementation of refuzz/program/syz/expr.hpp — port of prog/expr.go.

#include "refuzz/program/syz/expr.hpp"

#include "refuzz/program/syz/analysis.hpp"
#include "refuzz/program/syz/any.hpp"
#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/size.hpp"
#include "refuzz/program/syz/type.hpp"

#include <utility>

namespace refuzz::program::syz {

std::optional<uint64_t> evaluate_expr(const Expression* e, const ArgFinder& finder) {
    if (e == nullptr) return std::nullopt;
    if (e->expr_kind() == Expression::Kind::kValue) {
        const auto* v = static_cast<const ValueExpr*>(e);
        if (v->path().empty()) {
            return v->value();
        }
        const Arg* a = finder(v->path());
        const ConstArg* c = as_const_arg(a);
        if (c == nullptr) {
            // Referenced field unavailable / squashed / not an int → can't
            // calculate (prog/expr.go: Value.Evaluate returns ok=false).
            return std::nullopt;
        }
        return c->val();
    }
    const auto* b = static_cast<const BinaryExpression*>(e);
    const auto l = evaluate_expr(b->left(), finder);
    if (!l) return std::nullopt;
    const auto rr = evaluate_expr(b->right(), finder);
    if (!rr) return std::nullopt;
    switch (b->op()) {
        case BinaryOperator::kCompareEq:  return (*l == *rr) ? uint64_t{1} : uint64_t{0};
        case BinaryOperator::kCompareNeq: return (*l != *rr) ? uint64_t{1} : uint64_t{0};
        case BinaryOperator::kBinaryAnd:  return *l & *rr;
        case BinaryOperator::kOr:         return (*l != 0 || *rr != 0) ? uint64_t{1} : uint64_t{0};
    }
    return std::nullopt;
}

namespace {

// (ok, calculated): ok = arm condition satisfied (or arm has no condition);
// calculated = the condition could be evaluated. Mirrors checkUnionArg.
std::pair<bool, bool> check_union_arg(int idx, const UnionType* ut,
                                      const ArgFinder& finder) {
    if (idx < 0 || idx >= static_cast<int>(ut->fields().size())) return {true, true};
    const Field& f = ut->fields()[static_cast<size_t>(idx)];
    if (f.condition() == nullptr) return {true, true};
    const auto v = evaluate_expr(f.condition(), finder);
    if (!v) return {true, false};  // could not calculate → leave union as-is
    return {*v != 0, true};
}

std::vector<int> matching_union_args(const UnionType* ut, const ArgFinder& finder) {
    std::vector<int> ret;
    for (int i = 0; i < static_cast<int>(ut->fields().size()); ++i) {
        if (check_union_arg(i, ut, finder).first) ret.push_back(i);
    }
    return ret;
}

} // namespace

void for_each_stale_union(const Target& target, Call* call, const StaleUnionCb& cb) {
    if (call == nullptr) return;
    for (auto& arg_up : call->mutable_args()) {
        if (!arg_up) continue;
        foreach_sub_arg_with_stack(arg_up.get(), [&](Arg* a, ArgCtx* ctx) {
            if (a != nullptr && is_any_ptr(target, a->type())) {
                ctx->stop = true;  // don't descend into a squashed ANY blob
                return;
            }
            if (a == nullptr || a->arg_kind() != ArgKind::kUnion) return;
            const Type* t = a->type();
            if (t == nullptr || t->kind() != TypeKind::kUnion) return;
            const auto* ut = static_cast<const UnionType*>(t);
            if (!ut->is_conditional()) return;
            auto* ua = static_cast<UnionArg*>(a);
            // Resolve condition paths against this union's parent stack
            // (prog/expr.go makeArgFinder: findArg(option, path, parents)).
            const std::vector<Arg*> parents = ctx->parent_stack;
            const ArgFinder finder =
                [&, parents](const std::vector<std::string>& path) -> const Arg* {
                    return find_arg_by_path(ua->option(), path, parents);
                };
            const auto [ok, calculated] = check_union_arg(ua->index(), ut, finder);
            if (!calculated) return;             // unknown → leave as-is
            if (!ua->transient() && ok) return;  // settled & satisfied → not stale
            std::vector<int> matching = matching_union_args(ut, finder);
            if (matching.empty()) return;        // (upstream panics; we skip)
            cb(ua, ut, matching);
        });
    }
}

} // namespace refuzz::program::syz

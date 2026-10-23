// reFuzz syz_v2 — conditional-field expression evaluation.
//
// Mirrors prog/expr.go: evaluate a conditional-union arm's Condition against
// sibling/ancestor field values, and walk a Call for "stale" conditional
// unions (whose current arm no longer matches its condition, or which are
// transient placeholders awaiting selection). The actual re-selection /
// regeneration of a stale arm is the mutator's job (it needs generateArg) —
// see patch_conditional_fields in mutator/.../generator.

#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace refuzz::program::syz {

class Arg;
class Call;
class UnionArg;
class UnionType;
class Expression;
class Target;

// Resolves a condition path to the Arg that supplies its value (a ConstArg),
// or nullptr when it can't be resolved (referenced field absent / squashed).
using ArgFinder = std::function<const Arg*(const std::vector<std::string>&)>;

// Evaluate a condition Expression. std::nullopt = "could not calculate" (a
// referenced field was unavailable / not an int) — callers then leave the
// union as-is. Mirrors BinaryExpression.Evaluate / Value.Evaluate.
std::optional<uint64_t> evaluate_expr(const Expression* e, const ArgFinder& finder);

// Visit every CONDITIONAL UnionArg in `call` whose current arm is stale —
// transient (a placeholder default arm), or its condition is calculable and
// NOT satisfied — invoking `cb` with the union, its type, and the indices of
// arms that currently satisfy their conditions (always non-empty: a
// conditional union always has a no-condition default arm). Mirrors
// prog/expr.go forEachStaleUnion.
using StaleUnionCb =
    std::function<void(UnionArg*, const UnionType*, const std::vector<int>&)>;
void for_each_stale_union(const Target& target, Call* call, const StaleUnionCb& cb);

} // namespace refuzz::program::syz

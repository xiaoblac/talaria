// reFuzz syz_v2 — minimize orchestrator + per-type minimize free
// functions + MinimizeCtx primitive bodies.
//
// **§3.11 follow-up P2**:
//   - Step 1 (landed): MinimizeCtx::try_commit / try_remove_call —
//     in-place + DeepClone snapshot rollback. See header docstring.
//   - Step 2 (this commit): the entire V2 typed minimize subsystem
//     moves here from `crash/repro/.../program_minimizer.cpp`. The
//     run_minimize_typed orchestrator drives trailing/unrelated/
//     reverse call removal, CallProps minimize, per-arg minimize via
//     `TryMinimizeTypedProgArg` switch (Tier B per-type dispatcher).
//     Per-type bodies (`TryTypedXxxMinimize`) live as free functions
//     in this TU; Steps 3-8 turn each body into a thin call to
//     `Type::minimize` overrides. Step 9 deletes the wrappers.
//
// **Module boundary** (per `target_ownership.md §8.1`):
//   - `program/syz/` owns the typed-IR minimize behavior + the
//     orchestrator entry. It does NOT depend on crash/repro/.
//   - `crash/repro/` owns ProgramArtifact ↔ syz::Prog translation +
//     the predicate wrapper (sanitize_fix → assign_sizes → serialize
//     → TestFunc → title-match → payload cache → no-op short-circuit).
//     The pred is a `MinimizePred` injected into `MinimizeCtx`.

#include "refuzz/program/syz/minimize_ctx.hpp"

#include "refuzz/program/syz/analysis.hpp"
#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/clone.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/transform.hpp"
#include "refuzz/program/syz/type.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

namespace refuzz::program::syz {

// ============================================================
// find_arg_slot — locate the unique_ptr<Arg> slot owning `target`.
//
// Mirrors syzkaller `Prog.parent(arg) + replaceArg(arg, with)`.
// Searched containers: PointerArg::res_, GroupArg::inner_,
// UnionArg::option_. Not searched (matches upstream `Prog.parent`):
// Call::ret_ (syscall return; not a minimize target); ResultArg
// has no Arg children.
// ============================================================
namespace {

std::unique_ptr<Arg>* find_arg_slot_descend(std::unique_ptr<Arg>& slot,
                                            const Arg* target) {
    if (slot.get() == target) return &slot;
    if (slot == nullptr) return nullptr;

    switch (slot->arg_kind()) {
    case ArgKind::kPointer: {
        auto* p = static_cast<PointerArg*>(slot.get());
        return find_arg_slot_descend(p->mutable_res_slot(), target);
    }
    case ArgKind::kGroup: {
        auto* g = static_cast<GroupArg*>(slot.get());
        for (auto& el : g->mutable_inner()) {
            if (auto* found = find_arg_slot_descend(el, target)) {
                return found;
            }
        }
        return nullptr;
    }
    case ArgKind::kUnion: {
        auto* u = static_cast<UnionArg*>(slot.get());
        return find_arg_slot_descend(u->mutable_option_slot(), target);
    }
    case ArgKind::kConst:
    case ArgKind::kData:
    case ArgKind::kResult:
        return nullptr;
    }
    return nullptr;
}

std::unique_ptr<Arg>* find_arg_slot_in_prog(Prog& prog, const Arg* target) {
    if (target == nullptr) return nullptr;
    for (auto& call : prog.mutable_calls()) {
        if (call == nullptr) continue;
        for (auto& arg_slot : call->mutable_args()) {
            if (auto* found = find_arg_slot_descend(arg_slot, target)) {
                return found;
            }
        }
    }
    return nullptr;
}

bool ShouldStop(const StopFunc& stop_fn) {
    return stop_fn && stop_fn();
}

// Forward declaration; definition lives in the second anonymous
// namespace block (alongside per-type minimize machinery). C++ unifies
// all `namespace { ... }` blocks in a TU into one anonymous namespace,
// so this forward decl resolves against the later definition.
bool PatchTypedDefaultConditions(Call& call);

// Apply IR invariant repair to every call in `prog`. Mirrors the
// inline `PatchTypedDefaultConditions(call)` calls that the legacy
// scalar minimize mutator made on its single call_index — but extended
// to cover all calls because try_commit / try_remove_call don't track
// which calls the mutation may have affected (a scalar swap can cause
// a conditional union arm in the same call to go transient).
//
// Idempotent + harmless when no conditional unions are stale, so
// blanket-applying is correct (just slightly more work than upstream's
// per-call invocation).
void ApplyConditionalUnionRepairs(Prog& prog) {
    for (auto& call : prog.mutable_calls()) {
        if (call != nullptr) PatchTypedDefaultConditions(*call);
    }
}

} // namespace

// ============================================================
// MinimizeCtx — ctor + commit primitives.
// ============================================================

MinimizeCtx::MinimizeCtx(const Target*          target,
                         std::unique_ptr<Prog>* committed,
                         Prog*                  current,
                         int                    call_index0,
                         MinimizeMode           mode,
                         MinimizePred           pred)
    : target_(target),
      committed_(committed),
      current_(current),
      call_index0_(call_index0),
      mode_(mode),
      pred_(std::move(pred)) {}

bool MinimizeCtx::try_commit(Arg&                   arg,
                             std::unique_ptr<Arg>   replacement) {
    if (current_ == nullptr || replacement == nullptr) {
        return false;
    }

    auto* slot = find_arg_slot_in_prog(*current_, &arg);
    if (slot == nullptr || slot->get() != &arg) {
        return false;
    }

    auto snapshot = DeepClone(*current_);
    if (snapshot == nullptr) {
        return false;
    }

    auto previous = std::move(*slot);
    *slot = std::move(replacement);

    // §3.11 follow-up P2 step 3 — pre-pred IR invariant repair. A
    // scalar swap can leave a conditional union elsewhere with a
    // condition that no longer matches its current arm; patch all
    // calls before sanitize/serialize/pred (mirrors syzkaller
    // `setDefaultConditions` inside `sanitizeCall`).
    ApplyConditionalUnionRepairs(*current_);

    const bool ok = test_current();

    if (ok) {
        ++committed_count_;
        // The header contract treats `Call*` / `Arg*` from before this
        // call as invalidated on success (matching try_in_place /
        // try_remove_call). In-place swap doesn't reshuffle the calls
        // vector, but clearing here keeps the four commit primitives
        // symmetric and avoids tempting future callers to read
        // `current_call_` after a swap.
        current_call_       = nullptr;
        current_call_index_ = -1;
        return true;
    }

    *current_ = std::move(*snapshot);
    current_call_       = nullptr;
    current_call_index_ = -1;
    return false;
}

bool MinimizeCtx::try_remove_call(int call_index) {
    if (current_ == nullptr) {
        return false;
    }
    if (call_index < 0 ||
        call_index >= static_cast<int>(current_->mutable_calls().size())) {
        return false;
    }
    if (call_index0_ >= 0 && call_index == call_index0_) {
        return false;
    }

    auto snapshot = DeepClone(*current_);
    if (snapshot == nullptr) {
        return false;
    }

    if (!RemoveCall(*current_, static_cast<std::size_t>(call_index))) {
        *current_ = std::move(*snapshot);
        current_call_       = nullptr;
        current_call_index_ = -1;
        return false;
    }

    // Same pre-pred IR repair as try_commit — call removal can
    // shift indices used by conditional unions referencing args in
    // surviving calls.
    ApplyConditionalUnionRepairs(*current_);

    const int previous_call_index0 = call_index0_;
    if (call_index0_ >= 0 && call_index < call_index0_) {
        --call_index0_;
    }
    const bool ok = test_current();

    if (ok) {
        ++committed_count_;
        current_call_       = nullptr;
        current_call_index_ = -1;
        return true;
    }

    call_index0_ = previous_call_index0;
    *current_ = std::move(*snapshot);
    current_call_       = nullptr;
    current_call_index_ = -1;
    return false;
}

// ============================================================
// MinimizeCtx::try_in_place — clone-mutate-pred primitive.
//
// Mirrors the prior crash/repro `TryTypedProgCandidate` template:
// clone *current_, run mutator on the clone, run pred on the
// (mutated) clone, and on success swap the clone in for *current_.
//
// Distinct from try_commit / try_remove_call which mutate *current_
// in place + snapshot rollback. Choice of model:
//   - Type method holding `&arg` in the live tree → try_commit.
//   - Path-based mutator that re-locates inside a candidate clone
//     (existing TryTypedXxxMinimize style) → try_in_place.
// ============================================================

bool MinimizeCtx::try_in_place(const char*                stage,
                               std::function<bool(Prog&)> mutator,
                               std::optional<int>         candidate_call_index0) {
    if (current_ == nullptr || !mutator) {
        return false;
    }

    auto candidate = DeepClone(*current_);
    if (candidate == nullptr) {
        return false;
    }

    if (!mutator(*candidate)) {
        return false;
    }

    ++attempt_count_;
    if (!pred_) {
        return false;
    }
    const int pred_call_index0 = candidate_call_index0.value_or(call_index0_);
    if (!pred_(*candidate, pred_call_index0)) {
        return false;
    }

    *current_ = std::move(*candidate);
    ++committed_count_;
    last_stage_ = stage ? stage : "";
    // The clone-mutate model rebinds `*current_` to the candidate's
    // contents (move-assign on Prog moves the calls vector). Any
    // `Call*` / `Arg*` from before this commit are now invalid.
    current_call_       = nullptr;
    current_call_index_ = -1;
    return true;
}

// ============================================================
// V2 typed minimize machinery (moved from crash/repro).
//
// Per-type free functions (TryTypedScalarMinimize, etc.) are Tier B
// dispatchers / pre-Step-3-8 per-type bodies. Steps 3-8 will turn
// each body into a thin call to `Type::minimize` override; Step 9
// deletes the wrappers.
// ============================================================

namespace {

enum class TypedArgPathKind : std::uint8_t {
    kCallArg,
    kPointerRes,
    kGroupElem,
    kUnionOption,
};

struct TypedArgPathStep {
    TypedArgPathKind kind  = TypedArgPathKind::kCallArg;
    std::size_t      index = 0;
};

using TypedArgPath = std::vector<TypedArgPathStep>;

// Stable string serialization of (call_index, TypedArgPath) — used as
// the memoization key for the §3.11 follow-up triedPaths port.
// Mirrors syzkaller's `path += fmt.Sprintf("-%v", field)` chain (see
// prog/minimization.go:298-320). Encoding: "<call_index>:" + per-step
// tag + step.index + ".".  Tags: a=callArg, p=pointerRes,
// g=groupElem, u=unionOption.
std::string SerializeTypedArgPath(std::size_t call_index, const TypedArgPath& path) {
    std::string out;
    out.reserve(8 + path.size() * 4);
    out += std::to_string(call_index);
    out += ':';
    for (const auto& step : path) {
        switch (step.kind) {
        case TypedArgPathKind::kCallArg:     out += 'a'; break;
        case TypedArgPathKind::kPointerRes:  out += 'p'; break;
        case TypedArgPathKind::kGroupElem:   out += 'g'; break;
        case TypedArgPathKind::kUnionOption: out += 'u'; break;
        }
        out += std::to_string(step.index);
        out += '.';
    }
    return out;
}

bool IsTypedAnyPtr(const Type* type) {
    const auto* ptr_type   = as_ptr(type);
    const auto* array_type = ptr_type ? as_array(ptr_type->elem()) : nullptr;
    const auto* union_type = array_type ? as_union(array_type->elem()) : nullptr;
    return union_type != nullptr && union_type->name() == "ANYUNION";
}

struct TypedFoundArg {
    Arg*  arg        = nullptr;
    bool  present    = false;
    bool  is_any_ptr = false;
};

TypedFoundArg FindTypedConditionArg(Arg*                                       pos,
                                    std::vector<std::string>                   path,
                                    const std::vector<std::unique_ptr<Arg>>&   args,
                                    const std::vector<Field>&                  fields,
                                    std::vector<Arg*>                          parents,
                                    int                                        overlay_field);

TypedFoundArg FindTypedConditionField(Arg*                       buf,
                                      std::vector<std::string>   path,
                                      std::vector<Arg*>          parents) {
    if (auto* group_arg = as_group_arg(buf)) {
        const auto* struct_type = as_struct(group_arg->type());
        if (struct_type == nullptr) return {};
        auto* mutable_group = const_cast<GroupArg*>(group_arg);
        return FindTypedConditionArg(buf,
                                     std::move(path),
                                     mutable_group->mutable_inner(),
                                     struct_type->fields(),
                                     std::move(parents),
                                     struct_type->overlay_field());
    }
    if (as_union_arg(buf) != nullptr) {
        static const std::vector<std::unique_ptr<Arg>> kNoArgs;
        static const std::vector<Field>                kNoFields;
        return FindTypedConditionArg(buf,
                                     std::move(path),
                                     kNoArgs,
                                     kNoFields,
                                     std::move(parents),
                                     0);
    }
    return {};
}

TypedFoundArg FindTypedConditionArg(Arg*                                       pos,
                                    std::vector<std::string>                   path,
                                    const std::vector<std::unique_ptr<Arg>>&   args,
                                    const std::vector<Field>&                  fields,
                                    std::vector<Arg*>                          parents,
                                    int                                        overlay_field) {
    (void)pos;
    if (path.empty()) return {};

    const std::string elem = path.front();
    path.erase(path.begin());

    for (std::size_t index = 0; index < args.size(); ++index) {
        (void)overlay_field;
        Arg* buf = args[index].get();
        if (buf == nullptr || index >= fields.size() || elem != fields[index].name()) {
            continue;
        }
        if (IsTypedAnyPtr(buf->type())) {
            return {buf, true, true};
        }
        buf = inner_arg(buf);
        if (buf == nullptr) {
            return {nullptr, true, false};
        }
        if (!path.empty()) {
            return FindTypedConditionField(buf, std::move(path), std::move(parents));
        }
        return {buf, true, false};
    }

    if (elem == "parent") {
        if (parents.empty()) return {};
        Arg* buf = parents.back();
        parents.pop_back();
        if (!path.empty()) {
            return FindTypedConditionField(buf, std::move(path), std::move(parents));
        }
        return {buf, true, false};
    }

    while (!parents.empty()) {
        Arg* buf = parents.back();
        parents.pop_back();
        if (buf == nullptr || buf->type() == nullptr ||
            elem != buf->type()->template_name()) {
            continue;
        }
        if (!path.empty()) {
            return FindTypedConditionField(buf, std::move(path), std::move(parents));
        }
        return {buf, true, false};
    }

    return {};
}

std::optional<std::uint64_t> EvaluateTypedCondition(const Expression*        expr,
                                                    UnionArg&                union_arg,
                                                    const std::vector<Arg*>& parents) {
    if (expr == nullptr) return std::nullopt;
    switch (expr->expr_kind()) {
    case Expression::Kind::kValue: {
        const auto* value = static_cast<const ValueExpr*>(expr);
        if (value->path().empty()) {
            return value->value();
        }
        auto found = FindTypedConditionArg(union_arg.option(),
                                           value->path(),
                                           {},
                                           {},
                                           parents,
                                           0);
        if (!found.present || found.is_any_ptr || found.arg == nullptr) {
            return std::nullopt;
        }
        const auto* const_arg = as_const_arg(found.arg);
        if (const_arg == nullptr) return std::nullopt;
        return const_arg->val();
    }
    case Expression::Kind::kBinary: {
        const auto* binary = static_cast<const BinaryExpression*>(expr);
        const auto left  = EvaluateTypedCondition(binary->left(),  union_arg, parents);
        const auto right = EvaluateTypedCondition(binary->right(), union_arg, parents);
        if (!left.has_value() || !right.has_value()) return std::nullopt;
        switch (binary->op()) {
        case BinaryOperator::kCompareEq:  return *left == *right ? 1 : 0;
        case BinaryOperator::kCompareNeq: return *left != *right ? 1 : 0;
        case BinaryOperator::kBinaryAnd:  return *left & *right;
        case BinaryOperator::kOr:         return (*left != 0 || *right != 0) ? 1 : 0;
        }
        break;
    }
    }
    return std::nullopt;
}

struct TypedConditionCheck {
    bool ok         = true;
    bool calculated = true;
};

TypedConditionCheck CheckTypedUnionField(const UnionType&         union_type,
                                         int                      field_index,
                                         UnionArg&                union_arg,
                                         const std::vector<Arg*>& parents) {
    if (field_index < 0 ||
        field_index >= static_cast<int>(union_type.fields().size())) {
        return {false, true};
    }
    const auto& field = union_type.fields()[static_cast<std::size_t>(field_index)];
    if (field.condition() == nullptr) {
        return {true, true};
    }
    const auto value = EvaluateTypedCondition(field.condition(), union_arg, parents);
    if (!value.has_value()) {
        return {true, false};
    }
    return {*value != 0, true};
}

std::vector<int> MatchingTypedUnionFields(const UnionType&         union_type,
                                          UnionArg&                union_arg,
                                          const std::vector<Arg*>& parents) {
    std::vector<int> indices;
    for (std::size_t index = 0; index < union_type.fields().size(); ++index) {
        if (CheckTypedUnionField(union_type,
                                 static_cast<int>(index),
                                 union_arg,
                                 parents).ok) {
            indices.push_back(static_cast<int>(index));
        }
    }
    return indices;
}

std::optional<int> TypedUnionDefaultField(const UnionType& union_type) {
    if (union_type.fields().empty()) return std::nullopt;
    if (union_type.is_conditional()) {
        if (union_type.fields().back().condition() != nullptr) {
            return std::nullopt;
        }
        return static_cast<int>(union_type.fields().size()) - 1;
    }
    return 0;
}

bool PatchTypedDefaultConditions(Call& call) {
    bool changed  = false;
    bool progress = true;
    while (progress) {
        progress = false;
        for (auto& call_arg : call.mutable_args()) {
            foreach_sub_arg_with_stack(call_arg.get(),
                [&](Arg* arg, ArgCtx* ctx) {
                    auto* union_arg     = as_union_arg(arg);
                    auto* mutable_union = const_cast<UnionArg*>(union_arg);
                    const auto* union_type = union_arg ? as_union(union_arg->type()) : nullptr;
                    if (mutable_union == nullptr || union_type == nullptr ||
                        !union_type->is_conditional()) {
                        return;
                    }
                    const auto current = CheckTypedUnionField(*union_type,
                                                              mutable_union->index(),
                                                              *mutable_union,
                                                              ctx->parent_stack);
                    if (!current.calculated ||
                        (!mutable_union->transient() && current.ok)) {
                        return;
                    }
                    const auto matches = MatchingTypedUnionFields(*union_type,
                                                                  *mutable_union,
                                                                  ctx->parent_stack);
                    if (matches.empty()) return;
                    int field_index = matches.front();
                    if (const auto default_index = TypedUnionDefaultField(*union_type)) {
                        field_index = *default_index;
                    }
                    const auto& field =
                        union_type->fields()[static_cast<std::size_t>(field_index)];
                    auto replacement = field.type() != nullptr
                        ? field.type()->default_arg(field.dir(mutable_union->dir()))
                        : nullptr;
                    if (replacement == nullptr) return;
                    mutable_union->set_index(field_index);
                    mutable_union->set_option(std::move(replacement));
                    mutable_union->set_transient(false);
                    changed  = true;
                    progress = true;
                    ctx->stop = true;
                });
            if (progress) break;
        }
    }
    return changed;
}

Arg* LookupTypedArg(Call& call, const TypedArgPath& path) {
    if (path.empty() || path.front().kind != TypedArgPathKind::kCallArg ||
        path.front().index >= call.mutable_args().size()) {
        return nullptr;
    }
    Arg* arg = call.mutable_args()[path.front().index].get();
    for (std::size_t depth = 1; depth < path.size(); ++depth) {
        if (arg == nullptr) return nullptr;
        const auto& step = path[depth];
        switch (step.kind) {
        case TypedArgPathKind::kPointerRes: {
            auto* pointer_arg = as_pointer_arg(arg);
            arg = const_cast<Arg*>(pointer_arg ? pointer_arg->res() : nullptr);
            break;
        }
        case TypedArgPathKind::kGroupElem: {
            auto* group_arg = const_cast<GroupArg*>(as_group_arg(arg));
            if (group_arg == nullptr || step.index >= group_arg->mutable_inner().size()) {
                return nullptr;
            }
            arg = group_arg->mutable_inner()[step.index].get();
            break;
        }
        case TypedArgPathKind::kUnionOption: {
            auto* union_arg = as_union_arg(arg);
            arg = const_cast<Arg*>(union_arg ? union_arg->option() : nullptr);
            break;
        }
        case TypedArgPathKind::kCallArg:
            return nullptr;
        }
    }
    return arg;
}

void CollectTypedArgPaths(Arg*                       arg,
                          TypedArgPath               prefix,
                          std::vector<TypedArgPath>& paths) {
    if (arg == nullptr) return;
    paths.push_back(prefix);
    switch (arg->arg_kind()) {
    case ArgKind::kPointer: {
        auto* pointer_arg = static_cast<PointerArg*>(arg);
        if (pointer_arg->res() != nullptr) {
            auto next = prefix;
            next.push_back({TypedArgPathKind::kPointerRes, 0});
            CollectTypedArgPaths(pointer_arg->res(), std::move(next), paths);
        }
        break;
    }
    case ArgKind::kGroup: {
        auto* group_arg = static_cast<GroupArg*>(arg);
        for (std::size_t index = 0; index < group_arg->mutable_inner().size(); ++index) {
            auto next = prefix;
            next.push_back({TypedArgPathKind::kGroupElem, index});
            CollectTypedArgPaths(group_arg->mutable_inner()[index].get(),
                                 std::move(next), paths);
        }
        break;
    }
    case ArgKind::kUnion: {
        auto* union_arg = static_cast<UnionArg*>(arg);
        if (union_arg->option() != nullptr) {
            auto next = prefix;
            next.push_back({TypedArgPathKind::kUnionOption, 0});
            CollectTypedArgPaths(union_arg->option(), std::move(next), paths);
        }
        break;
    }
    case ArgKind::kConst:
    case ArgKind::kData:
    case ArgKind::kResult:
        break;
    }
}

std::vector<TypedArgPath> CollectTypedArgPaths(Call& call) {
    std::vector<TypedArgPath> paths;
    for (std::size_t index = 0; index < call.mutable_args().size(); ++index) {
        CollectTypedArgPaths(call.mutable_args()[index].get(),
                             TypedArgPath{{TypedArgPathKind::kCallArg, index}},
                             paths);
    }
    return paths;
}

// ============================================================
// Per-type minimize free functions. Steps 3-8 turn these into thin
// wrappers around `Type::minimize` overrides.
// ============================================================

// ============================================================
// §3.11 follow-up P2 step 9 — Single dispatcher.
//
// After Steps 3-8, every per-type minimize body lives as a
// `Type::minimize` virtual override (above this anonymous
// namespace). The 6 `TryTypedXxxMinimize` thin wrappers were
// collapsed here: a single `TryMinimizeTypedProgArg` dispatcher
// handles the (call_index, path) → live-arg lookup, injects
// `dispatch_lookup` for type methods that need re-lookup
// (Array/Resource/Buffer/Union), and clears it on return.
//
// Type::minimize default impl returns false, so types that don't
// override (Const/Len/Csum/Vma/Struct) just no-op.
// ============================================================

// RAII guard pairing set_dispatch_lookup(...) with set_dispatch_lookup({}).
// Pure scope discipline: ensures the per-call lookup never leaks past
// `arg->type()->minimize(...)` even if a future change introduces an
// exception path inside a type method.
struct ScopedDispatchLookup {
    MinimizeCtx& ctx;
    ScopedDispatchLookup(MinimizeCtx&                  c,
                         MinimizeCtx::DispatchLookup   f)
        : ctx(c) {
        ctx.set_dispatch_lookup(std::move(f));
    }
    ~ScopedDispatchLookup() { ctx.set_dispatch_lookup({}); }
    ScopedDispatchLookup(const ScopedDispatchLookup&)            = delete;
    ScopedDispatchLookup& operator=(const ScopedDispatchLookup&) = delete;
};

bool TryMinimizeTypedProgArg(MinimizeCtx&        ctx,
                             std::size_t         call_index,
                             const TypedArgPath& path) {
    Prog& current = *ctx.current();
    if (call_index >= current.calls().size()) return false;
    Arg* arg = LookupTypedArg(*current.mutable_calls()[call_index], path);
    if (arg == nullptr || arg->type() == nullptr) return false;

    // Inject a path-aware re-lookup closure for type methods that
    // iterate or clone-mutate. Type methods that don't read
    // dispatch_lookup (IntType / FlagsType / ProcType / PtrType)
    // simply ignore it; the unconditional set/clear is cheap.
    ScopedDispatchLookup guard(ctx,
        [call_index, path](Prog& p) -> Arg* {
            if (call_index >= p.mutable_calls().size()) return nullptr;
            return LookupTypedArg(*p.mutable_calls()[call_index], path);
        });

    std::string path_str = SerializeTypedArgPath(call_index, path);
    return arg->type()->minimize(ctx, *arg, path_str);
}

bool MinimizeTypedProgArgs(MinimizeCtx& ctx, const StopFunc& stop_fn) {
    Prog& current = *ctx.current();
    // §3.11 follow-up — port syzkaller `triedPaths` memoization.
    // Each (call_index, typed_arg_path) is attempted at most once per
    // Minimize invocation. Marking happens whether the attempt
    // committed or not.
    std::unordered_set<std::string> tried_paths;

    bool changed  = false;
    bool progress = true;
    while (progress) {
        progress = false;
        for (std::size_t call_index = 0; call_index < current.calls().size(); ++call_index) {
            if (ShouldStop(stop_fn)) return changed;
            const auto& call = current.calls()[call_index];
            if (call == nullptr ||
                (call->meta() != nullptr && call->meta()->attrs().no_minimize)) {
                continue;
            }
            const auto paths = CollectTypedArgPaths(*current.mutable_calls()[call_index]);
            for (const auto& path : paths) {
                if (ShouldStop(stop_fn)) return changed;
                std::string key = SerializeTypedArgPath(call_index, path);
                if (tried_paths.count(key) != 0) continue;
                if (!TryMinimizeTypedProgArg(ctx, call_index, path)) {
                    tried_paths.insert(std::move(key));
                    continue;
                }
                tried_paths.insert(std::move(key));
                changed  = true;
                progress = true;
                break;
            }
            if (progress) break;
        }
    }
    return changed;
}

bool MinimizeTypedCallProps(MinimizeCtx& ctx, const StopFunc& stop_fn) {
    Prog& current = *ctx.current();
    bool changed  = false;
    bool progress = true;
    while (progress) {
        progress = false;
        for (std::size_t call_index = 0; call_index < current.calls().size(); ++call_index) {
            if (ShouldStop(stop_fn)) return changed;
            const auto props = current.calls()[call_index]->props();
            if (is_default_call_props(props)) continue;

            for (const auto& candidate_props : minimize_call_props(props)) {
                if (ShouldStop(stop_fn)) return changed;
                if (!ctx.try_in_place("call props",
                    [call_index, candidate_props](Prog& candidate) {
                        if (call_index >= candidate.mutable_calls().size()) return false;
                        candidate.mutable_calls()[call_index]->set_props(candidate_props);
                        return true;
                    })) {
                    continue;
                }
                changed  = true;
                progress = true;
                break;
            }
            if (progress) break;
        }
    }
    return changed;
}

bool RemoveTypedCallsByKeep(Prog& candidate, const std::vector<bool>& keep) {
    if (keep.size() != candidate.calls().size()) return false;
    const std::size_t keep_count = std::count(keep.begin(), keep.end(), true);
    if (keep_count == 0 || keep_count == keep.size()) return false;

    for (std::size_t index = keep.size(); index > 0; --index) {
        const std::size_t call_index = index - 1;
        if (keep[call_index]) continue;
        if (!RemoveCallRange(candidate, call_index, 1)) return false;
    }
    return !candidate.calls().empty();
}

bool RemoveTypedTrailingCalls(MinimizeCtx&    ctx,
                              const StopFunc& stop_fn,
                              int             protected_index) {
    Prog& current = *ctx.current();
    if (protected_index < 0 ||
        protected_index >= static_cast<int>(current.calls().size()) ||
        current.calls().size() <= static_cast<std::size_t>(protected_index) + 1) {
        return false;
    }

    bool        changed = false;
    std::size_t chunk   = (current.calls().size() -
                           static_cast<std::size_t>(protected_index) - 1) / 2;
    if (chunk == 0) chunk = 1;

    while (chunk >= 1 &&
           current.calls().size() > static_cast<std::size_t>(protected_index) + 1) {
        if (ShouldStop(stop_fn)) return changed;

        bool progress = false;
        while (current.calls().size() > static_cast<std::size_t>(protected_index) + 1) {
            const std::size_t tail_count = current.calls().size() -
                                            static_cast<std::size_t>(protected_index) - 1;
            if (tail_count < chunk) break;

            const std::size_t start = current.calls().size() - chunk;
            if (start <= static_cast<std::size_t>(protected_index)) break;

            if (!ctx.try_in_place("call trailing",
                [start, chunk](Prog& candidate) {
                    return RemoveCallRange(candidate, start, chunk);
                })) {
                break;
            }
            changed  = true;
            progress = true;
        }

        if (chunk == 1) break;
        if (!progress) chunk /= 2;
    }
    return changed;
}

bool RemoveTypedUnrelatedCalls(MinimizeCtx& ctx, int& protected_index) {
    Prog& current = *ctx.current();
    if (current.calls().size() < 3 ||
        protected_index < 0 ||
        protected_index >= static_cast<int>(current.calls().size())) {
        return false;
    }

    const std::size_t anchor = static_cast<std::size_t>(protected_index);
    const auto        keep   = RelatedCalls(current, anchor);
    const std::size_t keep_count = std::count(keep.begin(), keep.end(), true);
    const std::size_t original_calls = current.calls().size();
    if (keep_count == 0 || keep_count == original_calls) {
        return false;
    }

    int         remapped_anchor = -1;
    std::size_t next_index      = 0;
    for (std::size_t index = 0; index < keep.size(); ++index) {
        if (!keep[index]) continue;
        if (index == anchor) remapped_anchor = static_cast<int>(next_index);
        ++next_index;
    }
    if (remapped_anchor < 0) {
        return false;
    }

    const bool committed = ctx.try_in_place("call unrelated",
        [&keep](Prog& candidate) {
            return RemoveTypedCallsByKeep(candidate, keep);
        },
        remapped_anchor);
    if (!committed) {
        return false;
    }
    protected_index = remapped_anchor;
    ctx.set_call_index0(remapped_anchor);
    return true;
}

bool RemoveTypedCallsReverse(MinimizeCtx&    ctx,
                             const StopFunc& stop_fn,
                             int             skip_index) {
    Prog& current = *ctx.current();
    bool  changed = false;
    for (int index = static_cast<int>(current.calls().size()) - 1;
         index >= 0 && current.calls().size() > 1;
         --index) {
        if (ShouldStop(stop_fn)) return changed;
        if (skip_index >= 0 && index == skip_index) continue;

        if (ctx.try_remove_call(index)) {
            ctx.set_stage("call remove");
            changed = true;
        }
    }
    return changed;
}

} // namespace

// ============================================================
// §3.11 follow-up P2 step 3 — IntType / FlagsType / ProcType
// `minimize` overrides.
//
// Mirror of syzkaller `prog/minimization.go::(*IntType).minimize` /
// `(*FlagsType).minimize` / `(*ProcType).minimize`. All three share
// the same shape: crash-snapshot mode only, propose the type's
// default value via `default_arg(dir)`, monotonic shrink (skip if
// the default isn't strictly smaller than current), commit via
// `ctx.try_commit(arg, replacement)` (in-place + snapshot rollback,
// with conditional-union repair applied between swap and pred).
//
// The `path` parameter is the orchestrator's triedPaths string key;
// the type method ignores it (the orchestrator's
// MinimizeTypedProgArgs outer loop does the memoization).
// ============================================================

namespace {

// Shared shrink-via-default helper for all three IntTypeCommon
// subclasses. Returns try_commit's verdict (true on accepted commit,
// false otherwise). Caller is responsible for any type-specific
// guard (e.g., ProcType non-optional skip) before invoking.
bool TryDefaultReplaceScalar(MinimizeCtx& ctx, Arg& arg) {
    if (ctx.mode() != MinimizeMode::kCrashSnapshot) return false;

    const auto* original = as_const_arg(&arg);
    const auto* type     = original ? original->type() : nullptr;
    if (original == nullptr || type == nullptr) return false;

    auto replacement = type->default_arg(arg.dir());
    const auto* default_const = as_const_arg(replacement.get());
    if (default_const == nullptr) return false;

    // Monotonic shrink: skip when the default isn't strictly less
    // than current. Without this guard, FlagsType / ProcType
    // candidates can grow under always-true predicates and
    // ping-pong with the next outer-loop walk's default-replace.
    if (default_const->val() == original->val()) return false;
    if (default_const->val() >  original->val()) return false;

    if (!ctx.try_commit(arg, std::move(replacement))) return false;
    // Match the legacy "arg scalar" stage tag so MinimizeResult
    // .minimize_stage reporting is byte-equal to the pre-Step-3
    // free-function form (covered by minimize_typed_args_test).
    ctx.set_stage("arg scalar");
    return true;
}

} // namespace

bool IntType::minimize(MinimizeCtx& ctx, Arg& arg, std::string& path) const {
    (void)path;
    return TryDefaultReplaceScalar(ctx, arg);
}

bool FlagsType::minimize(MinimizeCtx& ctx, Arg& arg, std::string& path) const {
    (void)path;
    return TryDefaultReplaceScalar(ctx, arg);
}

bool ProcType::minimize(MinimizeCtx& ctx, Arg& arg, std::string& path) const {
    (void)path;
    // Mirrors upstream skip on non-optional ProcType — a non-optional
    // pid value defaulted to ~0 would break syscalls expecting a real
    // pid.
    if (!optional()) return false;
    return TryDefaultReplaceScalar(ctx, arg);
}

// ============================================================
// §3.11 follow-up P2 step 5 — PtrType::minimize override.
//
// Mirrors the prior `TryTypedPointerNull` body: when the pointer's
// pointee (`res()`) is non-null, propose a fully nulled replacement
// (address=0, vma_size=0, res=nullptr) and commit via try_commit.
// The dropped pointee subtree's ResultArg dtors handle C0
// forward-edge cleanup automatically (see arg.hpp).
//
// Mode is unchecked here — upstream skips MinimizeCorpusMode and
// non-optional+squashable; reFuzz's existing TryTypedPointerNull
// has no such guards and was byte-equal-26/26 against upstream
// goldens, so no extra skip is added (per the "porting candidate
// set strict match upstream" rule, in the inverse direction —
// don't add reFuzz-only divergences).
// ============================================================

bool PtrType::minimize(MinimizeCtx& ctx, Arg& arg, std::string& path) const {
    (void)path;

    const auto* original = as_pointer_arg(&arg);
    if (original == nullptr || original->res() == nullptr) return false;

    auto replacement = std::make_unique<PointerArg>();
    replacement->set_type(this);
    replacement->set_dir(arg.dir());
    replacement->set_address(0);
    replacement->set_vma_size(0);
    // res_ defaults to nullptr.

    if (!ctx.try_commit(arg, std::move(replacement))) return false;
    ctx.set_stage("arg ptr");
    return true;
}

// ============================================================
// §3.11 follow-up P2 step 6 — ResourceType::minimize override.
//
// Mirrors the prior `TryTypedResourceMinimize` body: when a
// ResultArg consumer (`arg.res() != nullptr`) is observed in
// kCrashSnapshot mode, propose dropping its producer link
// (`set_res(nullptr)`) and resetting val/op_div/op_add to the
// ResourceType's default value.
//
// **Why try_in_place, not try_commit**: ResultArg has deleted
// move/copy because its destructor maintains C0 forward-edge
// invariants (uses_ bookkeeping). Swapping a ResultArg slot via
// try_commit would orphan the OLD arg's `uses_` consumers (their
// res_ would be nulled by the OLD arg's dtor instead of being
// rewired to the new replacement). The DeepClone path inside
// try_in_place does a Prog-level ResultArg remap so the cloned
// tree is internally consistent; in-place field mutation on the
// CLONED ResultArg is safe.
// ============================================================

// ============================================================
// §3.11 follow-up P2 step 7 — BufferType::minimize override.
//
// Mirrors the prior `TryTypedBufferMinimize` body. Builds a list
// of candidate (size or data) replacements based on
// `buffer_kind()`, then attempts each via try_in_place; first
// accepted candidate wins.
//
// Per-kind logic:
//   - kBlobRand / kBlobRange: halving-step size shrink from
//     `original.data().size() - min_len` down to 1. Crash mode
//     emits only the first step (then breaks).
//   - kFilename (var_len only): trim trailing '\0' / 'a'; if
//     no_z, drop the NUL terminator entirely; else re-NUL after
//     trim.
//   - kString / kGlob / kText / kCompressed: skipped (content-typed;
//     not size-shrinkable per upstream).
//
// **try_in_place not try_commit**: each candidate iteration after
// the first needs to re-lookup the live arg in *current_ (try_commit
// rollback rebinds the calls vector, invalidating &arg). The
// dispatch_lookup closure injected by the dispatcher provides this.
// (DataArg has no ResultArg cross-refs so try_commit slot swap
// would be safe in principle, but the multi-candidate loop forces
// us into the same dispatch_lookup pattern as Array/Resource.)
// ============================================================

// ============================================================
// §3.11 follow-up P2 step 8 — UnionType::minimize override.
//
// Mirrors the prior `TryTypedUnionMinimize` body:
//   - Compute the "default arm" index:
//       * non-conditional union → 0
//       * conditional union with last field having nullptr
//         condition → fields().size() - 1
//       * conditional union without an unconditional last field →
//         skip (no default available)
//   - Skip if the live UnionArg is already at default_index with a
//     default option (no progress).
//   - Single try_in_place candidate: in the cloned UnionArg, set
//     index = default_index and option = default_arg(field.type()).
//
// Like Resource/Array/Buffer this uses try_in_place + dispatch_lookup
// because UnionArg::option may contain ResultArg cross-refs whose
// C0 invariants are maintained by the DeepClone Prog-level remap.
// ============================================================

bool UnionType::minimize(MinimizeCtx& ctx, Arg& arg, std::string& path) const {
    (void)path;

    if (fields().empty()) return false;

    const auto* original = as_union_arg(&arg);
    if (original == nullptr) return false;

    const auto& lookup = ctx.dispatch_lookup();
    if (!lookup) return false;

    int default_index = 0;
    if (is_conditional()) {
        if (fields().back().condition() == nullptr) {
            default_index = static_cast<int>(fields().size()) - 1;
        } else {
            return false;
        }
    }

    if (default_index < 0 ||
        default_index >= static_cast<int>(fields().size())) {
        return false;
    }

    // Skip when already in default arm with default option.
    if (default_index == original->index() &&
        is_default_arg(original->option())) {
        return false;
    }

    if (fields()[static_cast<std::size_t>(default_index)].type() == nullptr) {
        return false;
    }

    return ctx.try_in_place("arg union",
        [lookup, default_index](Prog& candidate) -> bool {
            auto* arg_clone = lookup(candidate);
            auto* union_arg = const_cast<UnionArg*>(as_union_arg(arg_clone));
            if (union_arg == nullptr) return false;
            const auto* ut = as_union(union_arg->type());
            if (ut == nullptr ||
                default_index < 0 ||
                default_index >= static_cast<int>(ut->fields().size())) {
                return false;
            }
            const auto& field = ut->fields()[static_cast<std::size_t>(default_index)];
            if (field.type() == nullptr) return false;
            auto replacement = field.type()->default_arg(field.dir(union_arg->dir()));
            if (replacement == nullptr) return false;
            union_arg->set_index(default_index);
            union_arg->set_option(std::move(replacement));
            return true;
        });
}

bool BufferType::minimize(MinimizeCtx& ctx, Arg& arg, std::string& path) const {
    (void)path;

    const auto* original = as_data_arg(&arg);
    if (original == nullptr ||
        arg.dir() == Dir::kOut ||
        is_compressed() ||
        original->data().empty()) {
        return false;
    }

    const auto& lookup = ctx.dispatch_lookup();
    if (!lookup) return false;

    std::vector<std::size_t>              candidate_sizes;
    std::vector<std::vector<std::uint8_t>> candidate_data;
    auto add_unique_size = [&](std::size_t size) {
        if (size == 0 || size == original->data().size()) return;
        if (std::find(candidate_sizes.begin(), candidate_sizes.end(), size) !=
            candidate_sizes.end()) return;
        candidate_sizes.push_back(size);
    };
    auto add_unique_data = [&](std::vector<std::uint8_t> d) {
        if (d.empty() || d == original->data()) return;
        if (std::find(candidate_data.begin(), candidate_data.end(), d) !=
            candidate_data.end()) return;
        candidate_data.push_back(std::move(d));
    };

    switch (buffer_kind()) {
    case BufferKind::kBlobRand:
    case BufferKind::kBlobRange: {
        const std::size_t min_len =
            buffer_kind() == BufferKind::kBlobRange
                ? static_cast<std::size_t>(range_begin())
                : 0;
        std::size_t step = original->data().size() > min_len
            ? original->data().size() - min_len
            : 0;
        while (step > 0) {
            const std::size_t next_size = original->data().size() - step;
            if (next_size >= min_len) add_unique_size(next_size);
            step /= 2;
            if (ctx.mode() == MinimizeMode::kCrash) break;
        }
        break;
    }
    case BufferKind::kString:
    case BufferKind::kGlob:
        return false;
    case BufferKind::kFilename: {
        if (!var_len()) return false;
        std::size_t trimmed = original->data().size();
        while (trimmed > 0 &&
               (original->data()[trimmed - 1] == 0 ||
                original->data()[trimmed - 1] == 'a')) {
            --trimmed;
        }
        if (!no_z() && trimmed < original->data().size()) {
            std::vector<std::uint8_t> data(original->data().begin(),
                                            original->data().begin() +
                                                static_cast<std::ptrdiff_t>(trimmed));
            data.push_back(0);
            add_unique_data(std::move(data));
        } else {
            add_unique_size(trimmed);
        }
        break;
    }
    case BufferKind::kText:
    case BufferKind::kCompressed:
        return false;
    }

    // Size-based candidates (truncate live data to new_size).
    for (std::size_t new_size : candidate_sizes) {
        if (ctx.try_in_place("arg buffer",
            [lookup, new_size](Prog& candidate) -> bool {
                auto* arg_clone = lookup(candidate);
                auto* data_arg  = const_cast<DataArg*>(as_data_arg(arg_clone));
                if (data_arg == nullptr || data_arg->data().size() == new_size) return false;
                auto data = data_arg->data();
                data.resize(new_size);
                data_arg->set_data(std::move(data));
                return true;
            })) {
            return true;
        }
    }

    // Data-replacement candidates (whole-buffer swap).
    for (const auto& data : candidate_data) {
        if (ctx.try_in_place("arg buffer",
            [lookup, data](Prog& candidate) -> bool {
                auto* arg_clone = lookup(candidate);
                auto* data_arg  = const_cast<DataArg*>(as_data_arg(arg_clone));
                if (data_arg == nullptr || data_arg->data() == data) return false;
                data_arg->set_data(data);
                return true;
            })) {
            return true;
        }
    }

    return false;
}

bool ResourceType::minimize(MinimizeCtx& ctx, Arg& arg, std::string& path) const {
    (void)path;

    if (ctx.mode() != MinimizeMode::kCrashSnapshot) return false;

    const auto* original = as_result_arg(&arg);
    if (original == nullptr || original->res() == nullptr) return false;

    const auto& lookup = ctx.dispatch_lookup();
    if (!lookup) return false;

    const std::uint64_t default_val = default_value();

    return ctx.try_in_place("arg resource",
        [lookup, default_val](Prog& candidate) -> bool {
            auto* arg_clone   = lookup(candidate);
            auto* result_arg  = const_cast<ResultArg*>(as_result_arg(arg_clone));
            if (result_arg == nullptr || result_arg->res() == nullptr) return false;
            // set_res(nullptr) properly removes self from the cloned
            // producer's uses_ (C0 invariant).
            result_arg->set_res(nullptr);
            result_arg->set_op_div(0);
            result_arg->set_op_add(0);
            result_arg->set_val(default_val);
            return true;
        });
}

// ============================================================
// §3.11 follow-up P2 step 4 — ArrayType::minimize override.
//
// Mirrors the prior crash/repro `TryTypedArrayMinimize` body:
//   - Fast path: 3+ elements, range_begin == 0 → try clearing the
//     inner vector once. If it commits, return.
//   - Per-element peel-from-end: while the live array's size is
//     above min_elements, attempt to drop the last element. The
//     loop re-lookups via `ctx.dispatch_lookup()` because each
//     successful try_in_place commit invalidates the prior &arg
//     pointer.
//
// The mode skip mirrors upstream `(*ArrayType).minimize`: peel only
// runs in non-Crash modes (kCrashSnapshot or kCallsOnly with size
// above min). Fast path runs in any mode.
// ============================================================

bool ArrayType::minimize(MinimizeCtx& ctx, Arg& arg, std::string& path) const {
    (void)path;

    const auto* original = as_group_arg(&arg);
    if (original == nullptr || original->inner().empty()) return false;

    const auto& lookup = ctx.dispatch_lookup();
    if (!lookup) return false;  // dispatcher must inject lookup; fail closed.

    const std::size_t min_elements =
        array_kind() == ArrayKind::kRangeLen
            ? static_cast<std::size_t>(range_begin())
            : 0;

    // Fast path: clear-all when 3+ elements and range_begin == 0.
    if (original->inner().size() >= 3 && range_begin() == 0) {
        if (ctx.try_in_place("arg array",
            [lookup](Prog& candidate) {
                auto* arg_clone = lookup(candidate);
                auto* group_arg = const_cast<GroupArg*>(as_group_arg(arg_clone));
                if (group_arg == nullptr || group_arg->mutable_inner().empty()) return false;
                group_arg->mutable_inner().clear();
                return true;
            })) {
            return true;
        }
    }

    if (ctx.mode() == MinimizeMode::kCrash ||
        original->inner().size() <= min_elements) {
        return false;
    }

    // Peel from end. Re-lookup live array between iterations because
    // each successful commit moves a candidate clone into *current_,
    // invalidating prior Arg pointers.
    bool any_committed = false;
    while (true) {
        const auto* live = as_group_arg(lookup(*ctx.current()));
        if (live == nullptr || live->inner().size() <= min_elements) break;
        const std::size_t remove_index = live->inner().size() - 1;
        const bool committed = ctx.try_in_place("arg array",
            [lookup, remove_index](Prog& candidate) {
                auto* arg_clone = lookup(candidate);
                auto* group_arg = const_cast<GroupArg*>(as_group_arg(arg_clone));
                if (group_arg == nullptr ||
                    remove_index >= group_arg->mutable_inner().size()) {
                    return false;
                }
                group_arg->mutable_inner().erase(
                    group_arg->mutable_inner().begin() +
                    static_cast<std::ptrdiff_t>(remove_index));
                return true;
            });
        if (!committed) break;
        any_committed = true;
    }
    return any_committed;
}

// ============================================================
// run_minimize_typed — orchestrator entry. Mirror of the prior
// `RunMinimizeTypedInPlace` in crash/repro.
// ============================================================

MinimizeOutcome run_minimize_typed(MinimizeCtx& ctx, const StopFunc& stop_fn) {
    MinimizeOutcome out;
    if (ctx.current() == nullptr || ctx.current()->calls().empty()) {
        out.succeeded   = false;
        out.last_stage  = ctx.last_stage();
        return out;
    }

    int protected_index = ctx.call_index0();
    if (protected_index < 0 ||
        protected_index >= static_cast<int>(ctx.current()->calls().size())) {
        protected_index = -1;
    }

    if (protected_index >= 0) {
        RemoveTypedTrailingCalls(ctx, stop_fn, protected_index);
        RemoveTypedUnrelatedCalls(ctx, protected_index);
    }
    RemoveTypedCallsReverse(ctx, stop_fn, protected_index);

    if (ctx.mode() != MinimizeMode::kCallsOnly) {
        MinimizeTypedCallProps(ctx, stop_fn);
        MinimizeTypedProgArgs(ctx, stop_fn);
    }

    out.succeeded       = !ShouldStop(stop_fn);
    out.attempt_count   = ctx.attempt_count();
    out.committed_count = ctx.committed_count();
    out.last_stage      = ctx.last_stage();
    return out;
}

} // namespace refuzz::program::syz

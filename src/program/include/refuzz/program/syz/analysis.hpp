// Walker for prog/Call/Arg trees + ArgCtx context. Mirrors prog/analysis.go
// foreachArg / foreachSubArg / parentStack semantics.

#pragma once

#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"

#include <cstdint>
#include <functional>
#include <vector>

namespace refuzz::program::syz {

struct ArgCtx {
    std::vector<std::unique_ptr<Arg>>* parent       = nullptr;  // Call.args or GroupArg.inner of containing struct
    const std::vector<Field>*          fields       = nullptr;  // matching field list
    const Field*                       field        = nullptr;  // field descriptor for current arg, if any
    PointerArg*                        base         = nullptr;  // pointer to heap object containing this arg
    uint64_t                           offset       = 0;        // offset of this arg from base
    bool                               stop         = false;
    std::vector<Arg*>                  parent_stack;            // populated only when use_stack=true
    bool                               use_stack    = false;
};

using ArgVisitor = std::function<void(Arg*, ArgCtx*)>;

void foreach_arg(Call* c, const ArgVisitor& f);
void foreach_sub_arg(Arg* a, const ArgVisitor& f);
void foreach_sub_arg_with_stack(Arg* a, const ArgVisitor& f);

// Returns the innermost arg behind any chain of pointers (mirrors InnerArg).
Arg* inner_arg(Arg* a);

// ============================================================
// TypeCtx + foreach_type — type-tree visitor.
//
// Mirrors syzkaller `prog/types.go::ForeachType` + `TypeCtx`. Walks
// every Type reachable from a syscall's args/ret (or a single arg
// type), invoking `cb` per Type with rich context.
//
// reFuzz adaptation:
//   - cb receives `const Type*` (reFuzz Types are arena-owned and
//     immutable at runtime; upstream's `*Type` mutability is for
//     pkg/compiler finalize, not relevant here).
//   - `ctx.stop = true` skips subtypes of the current type
//     (pre-order iteration only).
//   - struct/union recursion is pruned via `(type, dir, optional)`
//     seen set, matching upstream's `seenKey`.
//
// Used by: hints uselessHints/relatedFields computation, validation,
// CallContainsAny / ArgContainsAny, csum lookup, and any future pass
// that needs to walk the static type schema. Replaces ad-hoc
// per-pass walkers (the §3.11 inner_arg-style "I wrote my own
// walker and forgot kVma" trap).
// ============================================================

class SyscallMeta;

struct TypeCtx {
    const SyscallMeta*  meta     = nullptr;   // owning syscall (null for foreach_arg_type)
    Dir                 dir      = Dir::kIn;
    const Type* const*  ptr      = nullptr;   // address of the slot holding this Type*
    bool                optional = false;
    bool                stop     = false;     // set by callback to skip subtypes
};

using TypeVisitor = std::function<void(const Type*, TypeCtx*)>;

// Pre-order walk over every Type reachable from each syscall's
// args/ret in `target`. `seen` is per-syscall (matches upstream "lots
// of users need to visit each struct per-syscall"). Direction
// propagates per Field; optional bit is OR-cumulated through the path.
void foreach_type(const Target& target, const TypeVisitor& cb);

// Walk a single syscall's args/ret types.
void foreach_call_type(const SyscallMeta* meta, const TypeVisitor& cb);

// Pre-order walk starting at a single Type (anchor dir = kIn,
// optional = false). Useful for "type-local" passes (e.g.,
// is-this-an-anyptr).
void foreach_arg_type(const Type* root, const TypeVisitor& cb);

} // namespace refuzz::program::syz

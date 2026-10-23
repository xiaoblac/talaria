// Deep clone helpers for the syz_v2 IR (§3.10 step 2).
//
// Per `docs/typed-program-pipeline/000_plan.md` D4, the clone helper
// belongs in `program/syz` because it is an IR ownership operation,
// not mutation policy. Mutators that need to edit a program clone the
// immutable artifact-owned `Prog`, mutate the clone, and publish a new
// artifact (D4 immutable artifact + mutable clone).
//
// Invariants:
//   - Each Call / Arg subtree is duplicated; the clone is structurally
//     independent of the source.
//   - Schema-side pointers (Target*, Type*, SyscallMeta*) are shared
//     verbatim — they point into the global immutable schema and must
//     not be deep-copied.
//   - ResultArg cross-call references (`ResultArg::res_`) are remapped
//     from old → new in the cloned tree; references that pointed
//     outside the source program (a bug for well-formed inputs) are
//     left as nullptr in the clone.
//   - Determinism: cloning is a pure structural copy with a single
//     pointer-table remap pass. No randomness, no schema lookup.

#pragma once

#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/prog.hpp"

#include <memory>
#include <unordered_map>

namespace refuzz::program::syz {

// Public alias for the ResultArg src→dst remap a deep clone produces.
// Mirror of upstream cloneCalls' argMap; used by resourceCentric to
// find the cloned counterpart of a candidate ResultArg chosen on the
// source program.
using ResultMap = std::unordered_map<const ResultArg*, ResultArg*>;

// Deep-clone a whole Prog. Returned Prog owns its Call / Arg subtree.
// O(N) in argument count. When `out_map` is non-null, it is populated
// with every src→dst ResultArg pair (mirror of upstream cloneWithMap).
std::unique_ptr<Prog> DeepClone(const Prog& src, ResultMap* out_map = nullptr);

// Deep-clone a single Arg subtree. ResultArg references inside the
// subtree are remapped to the cloned counterparts where possible;
// references that point outside the subtree are zeroed.
std::unique_ptr<Arg> DeepCloneArg(const Arg& src);

} // namespace refuzz::program::syz

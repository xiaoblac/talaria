// Size computation for LenType auto-fixup. Mirrors prog/size.go
// assignSizesArray + assignSizes + assignArgSize + assignSize +
// findArg + computeSize.

#pragma once

#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/type.hpp"

#include <unordered_set>
#include <vector>

namespace refuzz::program::syz {

class Prog;  // fwd (defined in prog.hpp)

// Walk `args` (matched against `fields`) and assign LenType ConstArg.Val
// for each arg present in `autos`. Removes processed arg from autos.
void assign_sizes_array(const Target&                                target,
                        std::vector<std::unique_ptr<Arg>>&           args,
                        const std::vector<Field>&                    fields,
                        std::unordered_set<const Arg*>*              autos);

// Recompute ALL LenType args (autos=nullptr → unconditional) for every call in
// `prog`, from the current arg tree. Idempotent. Mirrors syzkaller calling
// Target.assignSizesCall(c) after each mutation/generation (prog/mutation.go:269,
// rand.go). Use as a finalize pass before lowering a post-mutation /
// post-generation typed Prog to exec-wire, so stored len/bytesize args
// (bpf$PROG_LOAD insn_cnt, iov / sockaddr / mount-data lengths, ...) match the
// body. No-op when prog.target() is null or a call lacks meta.
void assign_sizes_prog(Prog& prog);

// Resolve a field-name path (as used by LenType sizing AND conditional-union
// condition references) to its target Arg, starting from `start` and walking
// up the `parents` stack. Returns nullptr when the path can't be resolved
// (callers treat that as "value unknown"). Mirrors prog/size.go findArg used
// via prog/expr.go makeArgFinder.
Arg* find_arg_by_path(Arg* start, const std::vector<std::string>& path,
                      const std::vector<Arg*>& parents);

} // namespace refuzz::program::syz

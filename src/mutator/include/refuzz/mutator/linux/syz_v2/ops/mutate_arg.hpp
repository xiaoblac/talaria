// reFuzz syz_v2 mutator — mutateArg dispatch (§3.5 M1).
//
// Mirror of `prog/mutation.go::mutateArg` + the 13 per-type `mutate()`
// methods + helpers (mutateInt / mutateAlignedInt / regenerate /
// mutationArgs.collectArg / chooseArg / getMutationPrio).
//
// Strategy (differs from upstream Go in implementation, preserves
// algorithm shape): instead of upstream's `replaceArg(arg, newArg)`
// which relies on Go's struct-copy-via-interface trick, we mutate
// each chosen arg's members in place via the v2 IR's setters. This
// avoids needing "find this arg's slot in its parent" tree-walks
// and works for every per-type mutator that prog/mutation.go
// implements (each one either tweaks scalar members on the same
// concrete subclass — Int/Flags/Buffer/Proc/Vma/Resource — or
// modifies a vector child set — Array — or replaces a scalar
// child slot via the v2 IR's exposed setter — Ptr.res, Union.option).

#pragma once

#include "refuzz/mutator/linux/syz_v2/components.hpp"
#include "refuzz/mutator/linux/syz_v2/gen_state.hpp"
#include "refuzz/mutator/linux/syz_v2/random.hpp"
#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/prog.hpp"

#include <cstdint>
#include <vector>

namespace refuzz::mutator::syz_v2 {

// Top-level entry. Picks one Call (priority-weighted by aggregate arg
// mutation priority), one Arg inside it (priority-weighted), and runs
// the per-type mutator. Returns true on success; false when no
// eligible call/arg or the chosen op declined (matches upstream
// `mutator.mutateArg`).
//
// On success, prog may have inserted producer calls before the chosen
// call (e.g. when mutating a ResourceArg requires a chain of producer
// syscalls) — those are added in place; caller does not need to
// post-process.
bool mutate_arg_impl(syz::Prog& prog, SyzV2MutationContext& ctx, RandGen& r);

// Per-arg mutation entry consumed by Target::IGen::mutate_arg
// (mutator-side concrete impl). Dispatches to the per-type mutator
// based on arg->type()->kind(). Producer calls created by a
// ResourceType mutation get pushed into gs.pending_extras_; caller
// drains the buffer at the appropriate splice boundary.
// Returns true on success.
bool mutate_single_arg(RandGen& r, GenState& gs, syz::Arg* arg);

// [syz-parity prog/mutation.go::mutateData] Apply a geometric number of
// byte-level mutations to `data` (the 7-operator table: flip-bit,
// insert/remove/append bytes, replace/add-delta/interesting-value int),
// keeping its length within [min_len, max_len]. Shared by buffer mutation
// (mutate_buffer_arg) and squashAny so the operator set never drifts apart.
std::vector<uint8_t> mutate_data_blob(RandGen& r, std::vector<uint8_t> data,
                                      uint64_t min_len, uint64_t max_len);

} // namespace refuzz::mutator::syz_v2

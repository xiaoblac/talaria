// reFuzz syz_v2 mutator — top-level generation entry.
//
// Mirror of prog/generation.go::Target.Generate + prog/rand.go's
// generate{Call,ParticularCall,Args,Arg} dispatch.

#pragma once

#include "refuzz/mutator/linux/syz_v2/gen_state.hpp"
#include "refuzz/mutator/linux/syz_v2/random.hpp"
#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/type.hpp"

#include <memory>
#include <vector>

namespace refuzz::mutator::syz_v2 {

namespace syz = ::refuzz::program::syz;

// Pair returned by per-type generate(): the value itself + any extra
// resource-chain calls that need to be inserted before this arg's call.
struct GenResult {
    std::unique_ptr<syz::Arg>                arg;
    std::vector<std::unique_ptr<syz::Call>>  calls;
};

// Generate a value for `type`. May return calls if type is ResourceType
// and a producer chain has to be created.
GenResult generate_arg(RandGen& r, GenState& s, const syz::Type* type,
                       syz::Dir dir);

// Bypasses the SpecialType dispatch hook on the outer type. Used by
// GenImpl::generate_special_arg so SpecialType bodies can drive the
// per-kind default walk on their own type without re-triggering
// the dispatch hook (mirror of upstream's
// `generateArgImpl(..., ignoreSpecial=true)`, rand.go:720).
GenResult generate_arg_no_special(RandGen& r, GenState& s,
                                  const syz::Type* type, syz::Dir dir);

// Generate the field list for a syscall or a struct.
struct GenFieldsResult {
    std::vector<std::unique_ptr<syz::Arg>>   args;
    std::vector<std::unique_ptr<syz::Call>>  calls;
};

GenFieldsResult generate_args(RandGen& r, GenState& s,
                              const std::vector<syz::Field>& fields,
                              syz::Dir parent_dir);

// Generate a single call (and any required resource-chain extras).
// `prev_call_id` (default -1) biases ChoiceTable selection when the
// state has one; -1 means "first call" / no bias and falls back to
// uniform pick over generatable syscalls.
std::vector<std::unique_ptr<syz::Call>>
generate_call(RandGen& r, GenState& s, int64_t prev_call_id = -1);

// Generate a particular syscall (no random pick).
std::vector<std::unique_ptr<syz::Call>>
generate_particular_call(RandGen& r, GenState& s, const syz::SyscallMeta* meta);

// Resolve every conditional union in `call` to a condition-matching arm
// (mirror prog/expr.go::patchConditionalFields). gen_union emits transient
// default arms; this picks/regenerates the correct arm once sibling fields
// exist. Returns producer calls for the regenerated arms — generation prepends
// them before the call; mutation routes them through gs.pending_extras_.
// Call after a call's args are fully built or after mutating one of them.
std::vector<std::unique_ptr<syz::Call>>
patch_conditional_fields(RandGen& r, GenState& s, syz::Call& call);

// Recursive producer-chain generator (mirror rand.go::createResource).
// Returns {ResultArg, calls} on success, {nullptr,{}} when no
// compatible ctor is reachable. Caller installs the ResultArg in the
// consumer slot and prepends `calls` before the consumer call.
GenResult create_resource(RandGen& r, GenState& s,
                          const syz::ResourceType* t, syz::Dir d);

// Corpus-walk producer-chain generator (mirror rand.go::resourceCentric).
// Reads typed Prog from seed.artifact (artifact-first); legacy seeds
// without an artifact bump resource_centric_payload_fallback_hits.
GenResult resource_centric(RandGen& r, GenState& s,
                           const syz::ResourceType* t, syz::Dir d);

// Diagnostic counters. Both are thread_local; tests must call the
// reset before relying on them. anyres_spoof_hits bumps on every
// successful ANYRES spoof inside create_resource;
// resource_centric_payload_fallback_hits bumps on every legacy
// payload-decode fallback inside resource_centric. Production v2
// sessions must keep the fallback counter at 0 (artifact-first
// contract); oracle pins it.
uint64_t anyres_spoof_hits();
void     reset_anyres_spoof_hits();

uint64_t resource_centric_payload_fallback_hits();
void     reset_resource_centric_payload_fallback_hits();

// Top-level entry: produce a Prog with `ncalls` calls. ChoiceTable
// (when non-null) drives biased syscall picks via `s.set_choice_table`.
// [impl-kind removed] Pseudo admission is syz's (disabled) attr + the
// enable/disable whitelist baked into the ChoiceTable; no policy param.
class ChoiceTable;
std::unique_ptr<syz::Prog>
generate_program(const syz::Target& target, uint64_t seed, int ncalls,
                 const ChoiceTable* ct = nullptr);

} // namespace refuzz::mutator::syz_v2

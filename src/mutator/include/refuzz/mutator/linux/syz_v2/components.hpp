// reFuzz syz_v2 mutator — op/policy interface contracts (§3.5 M0).
//
// Mirror of v1 `linux/syz/components.hpp` shape (ISyzMutatorOp +
// ISyzMutationPolicy + SyzMutationContext) but typed against the v2 IR
// (`refuzz::program::syz::Prog`) and the v2 RandGen / GenState. Concrete
// op implementations live in `ops/`; concrete policies live in
// `policies/`. SyzV2MutatorEngine owns the registries and routes
// Mutate() through the active policy.
//
// Namespace: `refuzz::mutator::syz_v2`, consistent with random.hpp /
// gen_state.hpp / generator.hpp. Engine class itself stays in
// `refuzz::fuzzer::SyzV2MutatorEngine` to mirror v1's
// `refuzz::fuzzer::SyzMutatorEngine`.

#pragma once

#include "refuzz/mutator/linux/syz_v2/gen_state.hpp"
#include "refuzz/mutator/linux/syz_v2/random.hpp"
#include "refuzz/program/seed.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"

#include <cstdint>
#include <memory>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace refuzz::mutator::syz_v2 {

namespace syz = ::refuzz::program::syz;

class ChoiceTable;

// Long-lived mutation state passed to every op invocation. Lifetime is
// one Mutate() call; ops may borrow but must not outlive the context.
//
// `splice_donor` is provided by the engine when a corpus donor is
// available (M2 splice op uses it; null elsewhere is fine).
//
// `gen_state` and `target` mirror what the v2 generator expects when
// resource-chain creation is needed mid-mutation (e.g. mutateArg of a
// ResourceType arg may need to insert a producer call).
struct SyzV2MutationContext {
    const syz::Target* target       = nullptr;
    const syz::Prog*   splice_donor = nullptr;
    GenState*          gen_state    = nullptr;

    // ChoiceTable for biased syscall picks inside ops that produce new calls
    // (insertCall, mutateArg producer chains). The bias call itself is each
    // op's own uniformly-random prefix pick, passed straight to generate_call
    // — there is intentionally no "previous call" context field (a single
    // fixed anchor would diverge from syz's per-insertion-point random bias).
    const ChoiceTable* choice_table = nullptr;

    // Epic 2 step-3 note: pseudo policy lives on `gen_state`
    // (`gen_state->pseudo_policy()`). Ops that need it must read it
    // there. We deliberately do NOT carry a separate copy here — two
    // slots would risk drift between ChoiceTable build (engine-side)
    // and op consumption (here).

    int max_calls = kMaxCalls;  // mirror prog/rand.go::MaxCalls (40)

    // Picked-call index for ops that mutate a single call's args
    // (mutate_arg sets it after pick). createResource consults it
    // to splice prepended producer calls in front of the consumer.
    // -1 = unset / not-applicable (insert_call, remove_call, splice).
    int affected_call_index = -1;

    // [syz-parity mutation.go:268-270,304-306] Calls whose LenType arg was
    // deliberately mutated this Mutate() (preserve=true). The engine's
    // post-mutation assign_sizes pass MUST skip these calls so the
    // intentionally-inconsistent length survives to the exec-wire instead of
    // being recomputed back to a consistent value. A non-len mutation on the
    // same call clears its entry (that call needs a recompute again).
    std::unordered_set<const syz::Call*> size_preserved_calls;
};

// Mirror of v1 ISyzMutatorOp; receives v2 Prog and mut_v2 RandGen.
//
// `Apply` must leave `prog` in a validate()-passing state on success,
// or return false (and not modify `prog`) when the op cannot make
// progress on the input. Engine treats `false` as "policy may pick a
// different op next round" — it does not retry the same op.
class ISyzV2MutatorOp {
public:
    virtual ~ISyzV2MutatorOp() = default;
    virtual std::string_view Name() const = 0;
    virtual uint32_t         Weight() const = 0;
    virtual bool             Apply(syz::Prog&             prog,
                                   SyzV2MutationContext&  ctx,
                                   RandGen&               r) const = 0;
};

// Mirror of v1 ISyzMutationPolicy; selects which op to run for a given
// (seed, prog) pair. Policies do not call Apply directly — the engine
// does — so policies stay lightweight and focused on selection logic.
class ISyzV2MutationPolicy {
public:
    virtual ~ISyzV2MutationPolicy() = default;
    virtual std::string_view Name() const = 0;
    virtual const ISyzV2MutatorOp* SelectOp(
        const std::vector<std::unique_ptr<ISyzV2MutatorOp>>& registry,
        const ::refuzz::fuzzer::Seed&                        seed,
        const syz::Prog&                                     prog,
        const SyzV2MutationContext&                          ctx,
        RandGen&                                             r) const = 0;
    virtual void OnActivated(
        const std::vector<std::unique_ptr<ISyzV2MutatorOp>>& /*registry*/) const {}
};

} // namespace refuzz::mutator::syz_v2

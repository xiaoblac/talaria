// Unit test for create_resource — port of upstream rand.go::createResource.
// Five deterministic cases. Probabilistic link-rate / spoof-frequency
// oracles live in tools/run_all_oracles.sh.

#include "refuzz/mutator/linux/syz_v2/choice_table.hpp"
#include "refuzz/mutator/linux/syz_v2/gen_state.hpp"
#include "refuzz/mutator/linux/syz_v2/generator.hpp"
#include "refuzz/mutator/linux/syz_v2/random.hpp"
#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/type.hpp"
#include "syz_v2_test_helpers.hpp"

#include <cstdio>
#include <cstdint>
#include <cstdlib>

namespace {

#define CHECK(expr)                                                         \
    do {                                                                    \
        if (!(expr)) {                                                      \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,    \
                         #expr);                                            \
            std::abort();                                                   \
        }                                                                   \
    } while (0)

#define RUN_TEST(fn)                                                        \
    do {                                                                    \
        std::fprintf(stderr, "RUN  %s\n", #fn);                             \
        fn();                                                               \
        std::fprintf(stderr, "OK   %s\n", #fn);                             \
    } while (0)

namespace syz    = ::refuzz::program::syz;
namespace mut_v2 = ::refuzz::mutator::syz_v2;
using ::refuzz::tests::syz_v2::find_resource_type;

// ---------------------------------------------------------------------
// Case 1: empty GenState → create_resource returns {nullptr,{}}; no
// abort. gen_resource then falls back to default value.
// ---------------------------------------------------------------------
void test_empty_state_falls_back() {
    const auto& target = syz::Target::linux_amd64();
    const auto* fd_rt = find_resource_type(target, "fd");
    CHECK(fd_rt != nullptr);

    mut_v2::RandGen r(0xA1A1A1A1ULL);
    mut_v2::GenState s(target);
    // No ChoiceTable, no policy, no corpus: pure default-value path.

    auto result = mut_v2::create_resource(r, s, fd_rt, syz::Dir::kIn);
    // create_resource may succeed if it picks a ctor and materializes
    // it; the empty-state assertion is that NO abort fires. If a chain
    // is produced, it must be self-consistent (calls non-empty AND arg
    // is a ResultArg).
    if (result.arg != nullptr) {
        CHECK(result.arg->type() == fd_rt);
        CHECK(!result.calls.empty());
    } else {
        CHECK(result.calls.empty());
    }

    // Now exercise gen_resource itself (the public dispatch). With an
    // empty state and no policy/CT, it must always return a non-null
    // arg (default value when create_resource fails).
    auto gr = mut_v2::generate_arg(r, s, fd_rt, syz::Dir::kIn);
    CHECK(gr.arg != nullptr);
    CHECK(gr.arg->type() == fd_rt);
}

// ---------------------------------------------------------------------
// Case 2: across multiple seeds, create_resource produces a chain
// whose last call has at least one creates_resources entry compatible
// with the requested resource name. ≥45/50 seeds yield non-empty
// chains (reFuzz fail-soft can return empty for hostile schemas; we
// assert an overwhelming majority succeed on a real Target).
// ---------------------------------------------------------------------
void test_one_ctor_picks_it() {
    const auto& target = syz::Target::linux_amd64();
    const auto* fd_rt = find_resource_type(target, "fd");
    CHECK(fd_rt != nullptr);

    int produced = 0;
    int compat   = 0;
    for (int i = 0; i < 50; ++i) {
        mut_v2::RandGen r(0xB000ULL + i);
        mut_v2::GenState s(target);
        auto result = mut_v2::create_resource(r, s, fd_rt, syz::Dir::kIn);
        if (result.arg == nullptr) continue;
        ++produced;
        CHECK(!result.calls.empty());
        const auto& last = result.calls.back();
        CHECK(last && last->meta() != nullptr);
        for (const syz::ResourceDesc* d : last->meta()->creates_resources()) {
            if (d == nullptr) continue;
            if (target.is_compatible_resource("fd", d->name())) {
                ++compat;
                break;
            }
        }
    }
    std::fprintf(stderr, "  produced=%d compat=%d (of 50)\n", produced, compat);
    CHECK(produced >= 45);
    CHECK(compat   >= 45);
}

// ---------------------------------------------------------------------
// Case 3: recursion is bounded. Drive 200 seeds; instrument
// generate_program (which exercises gen_resource → create_resource →
// generate_particular_call recursion) and confirm no abort fires and
// all programs validate. Per-name recursion is bounded by
// kMaxRecPerName (3) and absolute depth by kMaxDepth (96); both are
// enforced inside generate_arg, so the externally-observable
// invariant is "no abort on any seed".
// ---------------------------------------------------------------------
void test_recursive_depth_bounded() {
    const auto& target = syz::Target::linux_amd64();
    for (int i = 0; i < 200; ++i) {
        auto prog = mut_v2::generate_program(target,
                                             0xC000ULL + i,
                                             /*ncalls=*/8,
                                             /*ct=*/nullptr);
        CHECK(prog != nullptr);
        // Some seeds may produce shorter progs if recursion-guard
        // refuses to descend; that's the intended behavior. Every
        // produced call must carry a meta and be well-formed.
        for (const auto& c : prog->calls()) {
            CHECK(c != nullptr);
            CHECK(c->meta() != nullptr);
        }
    }
}

// ---------------------------------------------------------------------
// Case 4: in_generate_resource latch. With latch already held,
// create_resource refuses to descend into a nested ctor walk —
// returns immediately with the empty result OR a producer-chain
// outcome. The observable invariant: GenState's latch state is
// preserved across the call (RAII guard restores prior).
// ---------------------------------------------------------------------
void test_in_generate_resource_latched() {
    const auto& target = syz::Target::linux_amd64();
    const auto* fd_rt = find_resource_type(target, "fd");
    CHECK(fd_rt != nullptr);

    mut_v2::RandGen r(0xD000ULL);
    mut_v2::GenState s(target);

    // Pre-set latch — simulates being inside an outer createResource.
    s.set_in_generate_resource(true);
    CHECK(s.in_generate_resource() == true);

    // Nested invocation must not unset the latch on return (RAII guard
    // restores prior). gen_resource sees latch held and skips the
    // recurse branches; falls back to existing-or-default.
    auto gr = mut_v2::generate_arg(r, s, fd_rt, syz::Dir::kIn);
    CHECK(gr.arg != nullptr);
    // No producer chain may be materialized when latch was held on
    // entry: gen_resource computes can_recurse = !in_generate_resource()
    // = false, so the resource_centric / create_resource branches are
    // unreachable and gr.calls must be empty (default-value path).
    // Without this assertion, a sign-flip on the latch check would
    // pass test 4 silently.
    CHECK(gr.calls.empty());
    CHECK(s.in_generate_resource() == true);  // latch still held

    // Reset for hygiene.
    s.set_in_generate_resource(false);
    CHECK(s.in_generate_resource() == false);
}

// ---------------------------------------------------------------------
// Case 5: anyres spoof branch is reachable on at least one fixed seed
// across the deterministic sweep. Uses the TU-local diagnostics
// counter g_anyres_spoof_hits (exposed via mut_v2::anyres_spoof_hits)
// — incremented only when the post-swap branch (kind/desc/ctors
// replaced) fires. With a 1/1000 base rate × 5000 seeds, expectation
// is ~5 hits; binomial P(0 hits) ≈ exp(-5) ≈ 0.0067, low enough that
// we assert at least one hit. The probabilistic-frequency bound lives
// in oracle #27 (tools/run_all_oracles.sh), not here.
//
// Without this counter, a regression that gates ANYRES with `if (false)`
// or breaks the spoof_ctors lookup so spoof_ctors is always empty
// would leave the test passing with arg-non-null counts unchanged. The
// counter increment lives inside the swap block, so it tracks reach,
// not just "RNG reached one_of(1000)".
// ---------------------------------------------------------------------
void test_anyres_spoof_deterministic_seed() {
    const auto& target = syz::Target::linux_amd64();
    const auto* fd_rt = find_resource_type(target, "fd");
    CHECK(fd_rt != nullptr);

    mut_v2::reset_anyres_spoof_hits();

    int succeeded = 0;
    for (int i = 0; i < 5000; ++i) {
        mut_v2::RandGen r(0xE0000000ULL + i);
        mut_v2::GenState s(target);
        auto result = mut_v2::create_resource(r, s, fd_rt, syz::Dir::kIn);
        if (result.arg != nullptr) ++succeeded;
    }
    const uint64_t spoofs = mut_v2::anyres_spoof_hits();
    std::fprintf(stderr, "  succeeded=%d spoofs=%llu (of 5000)\n",
                 succeeded, static_cast<unsigned long long>(spoofs));
    CHECK(succeeded >= 4500);  // success rate not regressed by ANYRES
    CHECK(spoofs >= 1);        // ANYRES post-swap branch IS reached
}

} // namespace

int main() {
    RUN_TEST(test_empty_state_falls_back);
    RUN_TEST(test_one_ctor_picks_it);
    RUN_TEST(test_recursive_depth_bounded);
    RUN_TEST(test_in_generate_resource_latched);
    RUN_TEST(test_anyres_spoof_deterministic_seed);
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}

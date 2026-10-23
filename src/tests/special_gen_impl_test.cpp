// Unit test for GenImpl — concrete Target::IGen implementation.
//
// Seven deterministic cases:
//   1. RNG hooks delegate to RandGen — distribution check on one_of(2),
//      always-true on n_out_of(N, N), always-false on n_out_of(0, K),
//      always-true on one_of(1), rand(N) range check.
//   2. target() returns the GenState's target.
//   3. generate_arg produces a non-null Arg for an int type and
//      appends no calls.
//   4. generate_special_arg uses the no-SpecialType path; for a plain
//      IntType it still produces a normal arg and appends no calls.
//   5. alloc wraps `inner` in a PointerArg with a non-zero address
//      and the inner attached as `res`.
//   6. generate_arg's calls-append path: across a deterministic seed
//      sweep on a ResourceType, at least one seed produces a non-empty
//      extras vector and every call is a valid Call with non-null meta.
//   7. mutate_arg smoke: dispatch + ownership transfer of pending_extras.

#include "refuzz/mutator/linux/syz_v2/gen_state.hpp"
#include "refuzz/mutator/linux/syz_v2/random.hpp"
#include "refuzz/mutator/linux/syz_v2/special_gen.hpp"
#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/type.hpp"
#include "syz_v2_test_helpers.hpp"

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <memory>

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

// Locate the first IntType in the linux/amd64 schema for case 3.
const syz::IntType* find_int_type(const syz::Target& target) {
    for (const auto& sc : target.syscalls()) {
        if (!sc) continue;
        for (const auto& f : sc->args()) {
            const syz::Type* t = f.type();
            if (t != nullptr && t->kind() == syz::TypeKind::kInt) {
                return static_cast<const syz::IntType*>(t);
            }
        }
    }
    return nullptr;
}

// Locate any PtrType to wire alloc().
const syz::PtrType* find_ptr_type(const syz::Target& target) {
    for (const auto& sc : target.syscalls()) {
        if (!sc) continue;
        for (const auto& f : sc->args()) {
            const syz::Type* t = f.type();
            if (t != nullptr && t->kind() == syz::TypeKind::kPtr) {
                return static_cast<const syz::PtrType*>(t);
            }
        }
    }
    return nullptr;
}

void test_rng_hooks_delegate() {
    const auto& target = syz::Target::linux_amd64();
    mut_v2::RandGen r(0x11111111ULL);
    mut_v2::GenState s(target);
    mut_v2::GenImpl g(r, s);

    int true_count = 0;
    for (int i = 0; i < 200; ++i) {
        if (g.one_of(2)) ++true_count;
    }
    // 1/2 in 200 trials: expect ~100 ± wide; assert clear non-degenerate.
    CHECK(true_count > 50);
    CHECK(true_count < 150);

    // n_out_of with a == b must always be true.
    for (int i = 0; i < 50; ++i) {
        CHECK(g.n_out_of(7, 7));
    }

    // n_out_of(0, K) must always be false (zero successes out of K).
    for (int i = 0; i < 50; ++i) {
        CHECK(!g.n_out_of(0, 5));
    }

    // one_of(1) must always be true (1/1 chance).
    for (int i = 0; i < 50; ++i) {
        CHECK(g.one_of(1));
    }

    // rand(N) returns [0, N).
    for (int i = 0; i < 100; ++i) {
        const int v = g.rand(17);
        CHECK(v >= 0);
        CHECK(v < 17);
    }
}

void test_target_accessor() {
    const auto& target = syz::Target::linux_amd64();
    mut_v2::RandGen r(0x22222222ULL);
    mut_v2::GenState s(target);
    mut_v2::GenImpl g(r, s);
    CHECK(&g.target() == &target);
}

void test_generate_arg_produces_arg() {
    const auto& target = syz::Target::linux_amd64();
    const auto* it = find_int_type(target);
    CHECK(it != nullptr);

    mut_v2::RandGen r(0x33333333ULL);
    mut_v2::GenState s(target);
    mut_v2::GenImpl g(r, s);

    std::vector<std::unique_ptr<syz::Call>> extra;
    auto arg = g.generate_arg(it, syz::Dir::kIn, &extra);
    CHECK(arg != nullptr);
    CHECK(arg->type() == it);
    CHECK(arg->arg_kind() == syz::ArgKind::kConst);
    CHECK(extra.empty());
}

void test_generate_special_arg_plain_type_no_special_path() {
    // generate_special_arg is the escape hatch used by SpecialType
    // bodies to perform a default one-level walk without re-entering
    // the registered SpecialType dispatch. For a non-special IntType
    // the observable result is a normal generated const arg.
    const auto& target = syz::Target::linux_amd64();
    const auto* it = find_int_type(target);
    CHECK(it != nullptr);

    mut_v2::RandGen r(0x44444444ULL);
    mut_v2::GenState s(target);
    mut_v2::GenImpl g(r, s);

    std::vector<std::unique_ptr<syz::Call>> extra;
    auto arg = g.generate_special_arg(it, syz::Dir::kIn, &extra);
    CHECK(arg != nullptr);
    CHECK(arg->type() == it);
    CHECK(arg->arg_kind() == syz::ArgKind::kConst);
    CHECK(extra.empty());
}

void test_alloc_wraps_inner() {
    const auto& target = syz::Target::linux_amd64();
    const auto* pt = find_ptr_type(target);
    CHECK(pt != nullptr);

    mut_v2::RandGen r(0x55555555ULL);
    mut_v2::GenState s(target);
    mut_v2::GenImpl g(r, s);

    // Construct a 4-byte ConstArg as the inner payload.
    auto inner = std::make_unique<syz::ConstArg>();
    const syz::Type* elem_type = pt->elem();
    CHECK(elem_type != nullptr);
    inner->set_type(elem_type);
    inner->set_dir(syz::Dir::kIn);
    inner->set_val(0);

    std::vector<std::unique_ptr<syz::Call>> extra;
    auto wrapped =
        g.alloc(pt, syz::Dir::kIn, std::move(inner), &extra);
    CHECK(wrapped != nullptr);
    CHECK(wrapped->arg_kind() == syz::ArgKind::kPointer);
    auto* pa = static_cast<syz::PointerArg*>(wrapped.get());
    CHECK(pa->res() != nullptr);
    CHECK(pa->type() == pt);
    // Address 0 is a legitimate first allocation (offset 0 into the
    // mem area); a second alloc must yield a strictly higher address.
    auto another_inner = std::make_unique<syz::ConstArg>();
    another_inner->set_type(elem_type);
    another_inner->set_dir(syz::Dir::kIn);
    auto wrapped2 =
        g.alloc(pt, syz::Dir::kIn, std::move(another_inner), &extra);
    auto* pa2 = static_cast<syz::PointerArg*>(wrapped2.get());
    CHECK(pa2->address() > pa->address());
}

// ---------------------------------------------------------------------
// Case 6: generate_arg's calls-append path.
//
// IntType (case 3) never produces extras, so the GenResult.calls →
// *calls move loop is a no-op there. Drive the same entry on a
// ResourceType across a deterministic seed sweep — at least one seed
// must trigger create_resource (PR-3-A2 path) and yield a non-empty
// extras vector. Every appended Call must be valid (non-null meta).
//
// Without this case, a regression that drops the calls-move loop
// (`for (auto& c : gr.calls) calls->push_back(...)`) would leak
// producer chains out of GenImpl and the IntType-only assertion in
// case 3 wouldn't catch it.
// ---------------------------------------------------------------------
void test_generate_arg_appends_calls() {
    const auto& target = syz::Target::linux_amd64();
    const auto* fd_rt =
        ::refuzz::tests::syz_v2::find_resource_type(target, "fd");
    CHECK(fd_rt != nullptr);

    int seeds_with_extras = 0;
    int total_calls       = 0;
    for (uint64_t i = 0; i < 50; ++i) {
        mut_v2::RandGen  r(0x66660000ULL + i);
        mut_v2::GenState s(target);
        mut_v2::GenImpl  g(r, s);

        std::vector<std::unique_ptr<syz::Call>> extra;
        auto arg = g.generate_arg(fd_rt, syz::Dir::kIn, &extra);
        CHECK(arg != nullptr);
        CHECK(arg->type() == fd_rt);
        for (const auto& c : extra) {
            CHECK(c != nullptr);
            CHECK(c->meta() != nullptr);
            ++total_calls;
        }
        if (!extra.empty()) ++seeds_with_extras;
    }
    std::fprintf(stderr,
                 "  seeds_with_extras=%d total_calls=%d (of 50 seeds)\n",
                 seeds_with_extras, total_calls);
    // create_resource fires on roughly the (8/10 prefer-existing fail)
    // ∩ (4/5 createResource arm) sub-tree — empty initial state means
    // pick_existing_resource fails ⇒ createResource is the dominant
    // branch on a fresh GenState. ≥ 1 of 50 seeds is a very loose bar.
    CHECK(seeds_with_extras >= 1);
}

// ---------------------------------------------------------------------
// Case 7: mutate_arg smoke.
//
// Two invariants verified in one test:
//  (a) Dispatch: g.mutate_arg(int_arg) returns a (possibly empty)
//      vector and leaves no orphaned producer calls — pending_extras
//      buffer is empty after the call. Int mutation itself doesn't
//      push extras, so this is the baseline.
//  (b) Ownership transfer: pre-pushing a fake call to pending_extras
//      then calling g.mutate_arg(...) MUST surface that fake (and
//      anything mutate_single_arg pushed) in the returned vector and
//      clear the GenState buffer. A regression that omitted the
//      `s_.take_pending_extras()` in GenImpl::mutate_arg would leave
//      the fake stranded in the buffer — the engine op-apply boundary
//      would then re-splice it into a wrong prog (or the next
//      Mutate's GenState if reused). This case locks the contract.
// ---------------------------------------------------------------------
void test_mutate_arg_smoke() {
    const auto& target = syz::Target::linux_amd64();
    const auto* it = find_int_type(target);
    CHECK(it != nullptr);

    // (a) Baseline: int arg, empty pending_extras.
    {
        mut_v2::RandGen  r(0x77770000ULL);
        mut_v2::GenState s(target);
        mut_v2::GenImpl  g(r, s);

        auto int_arg = std::make_unique<syz::ConstArg>();
        int_arg->set_type(it);
        int_arg->set_dir(syz::Dir::kIn);
        int_arg->set_val(0);

        CHECK(!s.has_pending_extras());
        auto extras = g.mutate_arg(int_arg.get());
        // Int mutation doesn't generate producer chains.
        CHECK(extras.empty());
        // Buffer must be empty — GenImpl::mutate_arg drained it.
        CHECK(!s.has_pending_extras());
    }

    // (b) Ownership transfer: pre-push a fake, mutate_arg must drain.
    {
        mut_v2::RandGen  r(0x77770001ULL);
        mut_v2::GenState s(target);
        mut_v2::GenImpl  g(r, s);

        auto int_arg = std::make_unique<syz::ConstArg>();
        int_arg->set_type(it);
        int_arg->set_dir(syz::Dir::kIn);
        int_arg->set_val(0);

        auto fake = std::make_unique<syz::Call>();
        syz::Call* raw_fake = fake.get();
        s.push_pending_extra(std::move(fake));
        CHECK(s.has_pending_extras());

        auto extras = g.mutate_arg(int_arg.get());
        // Must contain the pre-pushed fake (and any extras mutate_single_arg
        // happened to push, though Int mutation doesn't add any).
        CHECK(extras.size() >= 1);
        bool found_fake = false;
        for (const auto& c : extras) {
            if (c.get() == raw_fake) { found_fake = true; break; }
        }
        CHECK(found_fake);
        // Buffer drained: contract holds.
        CHECK(!s.has_pending_extras());
    }
}

} // namespace

int main() {
    RUN_TEST(test_rng_hooks_delegate);
    RUN_TEST(test_target_accessor);
    RUN_TEST(test_generate_arg_produces_arg);
    RUN_TEST(test_generate_special_arg_plain_type_no_special_path);
    RUN_TEST(test_alloc_wraps_inner);
    RUN_TEST(test_generate_arg_appends_calls);
    RUN_TEST(test_mutate_arg_smoke);
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}

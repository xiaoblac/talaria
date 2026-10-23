// Unit test for the createResource→mutate_resource_arg→engine
// extras-splice path landed in PR-3-A4.
//
// Three deterministic cases:
//   1. push/take round-trip on GenState's pending_extras buffer.
//   2. mutate_resource_arg in a fresh GenState produces extras when
//      its kind-tail walk fails (no existing producer); if extras
//      are produced, every consumer's res() points at a producer
//      that lives in pending_extras.
//   3. After driving the SyzV2MutatorEngine through Mutate(), every
//      ResultArg in the mutated Prog whose res() != nullptr points
//      at a producer in the same Prog (no dangling cross-prog
//      pointer; the splice landed correctly).

#include "refuzz/mutator/linux/syz_v2/engines/syz_v2_engine.hpp"
#include "refuzz/mutator/linux/syz_v2/gen_state.hpp"
#include "refuzz/mutator/linux/syz_v2/generator.hpp"
#include "refuzz/mutator/linux/syz_v2/random.hpp"
#include "refuzz/program/syz/analysis.hpp"
#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/encoding.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"
#include "syz_v2_test_helpers.hpp"

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <unordered_set>

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

// Case 1: GenState's pending_extras buffer round-trips push/take.
void test_pending_extras_round_trip() {
    const auto& target = syz::Target::linux_amd64();
    mut_v2::GenState s(target);
    CHECK(!s.has_pending_extras());

    auto fake = std::make_unique<syz::Call>();
    syz::Call* raw = fake.get();
    s.push_pending_extra(std::move(fake));
    CHECK(s.has_pending_extras());

    auto drained = s.take_pending_extras();
    CHECK(drained.size() == 1);
    CHECK(drained[0].get() == raw);
    CHECK(!s.has_pending_extras());
}

// Helper: walk every ResultArg in a Prog and call fn(ra).
auto walk_resultargs_in_prog = [](syz::Prog& prog, auto&& fn) {
    for (auto& c : prog.mutable_calls()) {
        if (!c) continue;
        ::refuzz::program::syz::foreach_arg(
            c.get(), [&](syz::Arg* a, ::refuzz::program::syz::ArgCtx*) {
                if (a && a->arg_kind() == syz::ArgKind::kResult) {
                    fn(static_cast<syz::ResultArg*>(a));
                }
            });
    }
};

// Direct in-prog invariant check used by case 2 and case 3:
//   1. Every ResultArg whose res() != nullptr points at a ResultArg
//      present in the same prog (no dangling cross-prog pointer).
//   2. The bidirectional back-edge holds: producer's uses() set
//      contains the consumer that points at it. set_res()'s
//      bookkeeping plus the wrap_existing dance in create_resource
//      both depend on this invariant; a regression that broke either
//      direction would surface here without round-trip dependence
//      on encoder behavior.
void check_in_prog_invariants(syz::Prog& prog) {
    std::unordered_set<const syz::ResultArg*> in_prog;
    walk_resultargs_in_prog(prog, [&](syz::ResultArg* ra) {
        in_prog.insert(ra);
    });
    walk_resultargs_in_prog(prog, [&](syz::ResultArg* ra) {
        if (ra->res() != nullptr) {
            CHECK(in_prog.count(ra->res()) == 1);
            // Producer's forward-edge set must contain this consumer.
            const auto& uses = ra->res()->uses();
            CHECK(uses.count(ra) == 1);
        }
    });
}

// Case 2: drive a Prog through SyzV2MutatorEngine and verify no
// ResultArg has a dangling res(). Empty payload routes to the
// GenerateFresh path, exercising create_resource (PR-3-A2) producer
// chain construction; this case asserts the typed-prog graph is
// internally consistent both in res()→producer direction AND
// producer.uses()→consumer direction.
//
// Uses MutateProgForTesting to skip the encode/decode round trip —
// any inconsistency in res()/uses_ surfaces directly here, not
// laundered through TextEncoder's resolution rules.
void test_no_dangling_res_after_mutate() {
    const auto& target = syz::Target::linux_amd64();

    // Reuse a single engine across all iterations; ChoiceTable is
    // built once on first Mutate and reused on subsequent calls.
    // Constructing a fresh engine per iteration would re-pay the
    // static-prio matrix build (multi-second cost) each time.
    ::refuzz::fuzzer::SyzV2MutatorEngine engine(
        target, /*corpus_store=*/nullptr,
        /*master_seed=*/0xA5A50000ULL);

    int checked = 0;
    for (uint64_t k = 0; k < 20; ++k) {
        ::refuzz::fuzzer::Seed seed;
        // Empty payload routes to the GenerateFresh path.
        auto prog = engine.MutateProgForTesting(seed);
        if (!prog) continue;
        check_in_prog_invariants(*prog);
        ++checked;
    }
    std::fprintf(stderr, "  checked=%d (of 20 attempts)\n", checked);
    CHECK(checked >= 10);
}

// Case 3: drive the mutate-on-corpus path and verify the splice
// path is exercised at least once across the deterministic sweep.
//
// Two assertions:
//   1. Every produced typed prog satisfies the in-prog res()/uses_
//      invariants (same as case 2).
//   2. splice_pending_extras_hits() >= 1 across the sweep — a
//      regression that gates the splice with `if (false)` or
//      breaks pending_extras would leave assertion #1 still passing
//      on the un-spliced prog (consumer falls back to default value
//      via mutate_resource_arg's last branch). The counter is the
//      direct signal that the splice path actually fired.
void test_mutate_path_extras_splice_clean() {
    const auto& target = syz::Target::linux_amd64();

    auto seed_prog = mut_v2::generate_program(
        target, /*seed=*/0xB1B10000ULL, /*ncalls=*/8);
    CHECK(seed_prog != nullptr);
    syz::TextEncoder encoder(target);
    std::string seed_text = encoder.encode(*seed_prog);

    ::refuzz::fuzzer::SyzV2MutatorEngine engine(
        target, /*corpus_store=*/nullptr,
        /*master_seed=*/0xC2C20000ULL);

    ::refuzz::fuzzer::reset_splice_pending_extras_hits();

    // [v1 200 iter — ROLLBACK: uncomment 下面 200 + 删 v2 块]
    // 200 iterations: at 1/2 r.bin() gate * (existing-pick fall-through
    // rate from kind-tail walk) the splice path is sparsely fired;
    // 20 iterations earlier was too few to have a reliable signal on
    // a deterministic sweep. 200 keeps the test sub-second and gives
    // ~0 P(no splice ever) on linux/amd64.
    // [v2 2000 iter — 当前版本]
    // mutator 路径上 mutate_resource_arg 的 kind-tail walk fall-through 实测
    // 比注释假设更稀疏:master_seed=0xC2C20000 跑 200 轮 hit=0(deterministic
    // flake)。直接拉大 iter 到 2000 让概率上限远低于 1e-3,且整体仍 < 1s。
    // 若未来 mutator 改动让 splice 概率再降一档,这里继续翻倍 OR 换更稳的
    // direct-driver(构造 pending_extras 不靠 RNG)。
    int checked = 0;
    constexpr uint64_t kIter = 2000;
    for (uint64_t k = 0; k < kIter; ++k) {
        ::refuzz::fuzzer::Seed seed;
        seed.payload.assign(seed_text.begin(), seed_text.end());
        auto prog = engine.MutateProgForTesting(seed);
        if (!prog) continue;
        check_in_prog_invariants(*prog);
        ++checked;
    }
    const uint64_t splice_hits =
        ::refuzz::fuzzer::splice_pending_extras_hits();
    std::fprintf(stderr, "  checked=%d splice_hits=%llu (of %llu attempts)\n",
                 checked,
                 static_cast<unsigned long long>(splice_hits),
                 static_cast<unsigned long long>(kIter));
    CHECK(static_cast<uint64_t>(checked) >= kIter / 2);  // mutate-on-corpus: most iterations succeed
    CHECK(splice_hits >= 1);      // splice path IS exercised on the sweep
}

} // namespace

int main() {
    RUN_TEST(test_pending_extras_round_trip);
    RUN_TEST(test_no_dangling_res_after_mutate);
    RUN_TEST(test_mutate_path_extras_splice_clean);
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}

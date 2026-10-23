// hints_random_smoke_test.cpp — Epic 5 PR-5-C
//
// Adapt of `prog/hints_test.go::TestHintsRandom`. Upstream runs N
// random-generated programs through MutateWithHints with random comps
// to confirm the algorithm is panic-free under noisy input. reFuzz
// port skips the full Generate() integration (heavy dependency on
// ChoiceTable + Target) and instead drives ShrinkExpand + GenerateArgHints
// at the algorithmic surface with deterministic-but-varied randomized
// inputs. Goal: catch crashes / OOMs in the candidate-funnel logic;
// not a fidelity oracle (TestHintsCheckConstArg / DataArg / ShrinkExpand
// already cover that).

#include "refuzz/mutator/linux/syz_v2/hints/comp_map.hpp"
#include "refuzz/mutator/linux/syz_v2/hints/hints_apply.hpp"
#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/type.hpp"

#include <cstdio>
#include <memory>
#include <random>

#define CHECK(cond)                                                                \
    do {                                                                           \
        if (!(cond)) {                                                             \
            std::fprintf(stderr, "CHECK failed: %s (line %d)\n", #cond, __LINE__); \
            return 1;                                                              \
        }                                                                          \
    } while (0)

namespace hints = refuzz::mutator::syz_v2::hints;
namespace syz   = refuzz::program::syz;

int main()
{
    constexpr int kIters = 50;  // upstream uses iters/10 ≈ ~hundreds; reduced for ctest cadence
    std::mt19937_64 rng(0xc0ffeeull);  // deterministic seed (literal kept small enough for u64)

    for (int i = 0; i < kIters; ++i) {
        // Build a random CompMap with 1-32 entries.
        hints::CompMap comps;
        const int n_entries = static_cast<int>((rng() % 32) + 1);
        for (int j = 0; j < n_entries; ++j) {
            const uint64_t op1 = rng();
            const uint64_t op2 = rng();
            const uint64_t pc  = rng();
            comps.Add(pc, op1, op2, /*is_const=*/(rng() & 1) == 0);
        }

        // ShrinkExpand on a random uint64 with a random bitsize ∈ {8,16,32,64}.
        const uint64_t v = rng();
        const uint64_t bitsizes[] = {8, 16, 32, 64};
        const uint64_t bitsize = bitsizes[rng() % 4];
        const auto a = hints::ShrinkExpand(v, comps, bitsize, /*image=*/false);
        const auto b = hints::ShrinkExpand(v, comps, bitsize, /*image=*/true);
        // No specific size assertion — just exercise the path.
        (void)a;
        (void)b;

        // Drive GenerateArgHints on a random ConstArg with int sizes
        // 1/2/4/8 (cf. CheckConstArgHints type-skips small types).
        const uint64_t sizes[] = {1, 2, 4, 8};
        const uint64_t sz = sizes[rng() % 4];
        syz::IntType it;
        it.set_name("rand_int");
        it.set_size(sz);
        syz::ConstArg arg;
        arg.set_type(&it);
        arg.set_dir(syz::Dir::kIn);
        arg.set_val(v);
        int candidates = 0;
        bool exploded = false;
        hints::GenerateArgHints(comps, &arg, /*field=*/nullptr, [&]() -> bool {
            ++candidates;
            if (candidates >= 10000) {
                exploded = true;
                return false;
            }
            return candidates < 200;     // bound iteration so the loop terminates
        });
        CHECK(!exploded);
    }

    std::printf("hints_random_smoke_test PASSED (%d iters)\n", kIters);
    return 0;
}

// hints_limiter_test.cpp — Epic 5 PR-5-C
//
// 1:1 port of `prog/hints_test.go::TestHintsLimiter`. Verifies the
// per-PC cap (10 attempts) is applied across multiple Limit calls
// (state accumulates in the limiter).

#include "refuzz/mutator/linux/syz_v2/hints/comp_map.hpp"
#include "refuzz/mutator/linux/syz_v2/hints/hints_limiter.hpp"

#include <cstdio>
#include <unordered_map>

#define CHECK(cond)                                                                \
    do {                                                                           \
        if (!(cond)) {                                                             \
            std::fprintf(stderr, "CHECK failed: %s (line %d)\n", #cond, __LINE__); \
            return 1;                                                              \
        }                                                                          \
    } while (0)

namespace hints = refuzz::mutator::syz_v2::hints;

namespace {

// Mirror upstream `perPCCount(comps)`: count pcs per pc-key.
std::unordered_map<uint64_t, int> PerPcCount(const hints::CompMap& comps) {
    std::unordered_map<uint64_t, int> res;
    for (const auto& [op1, op2_map] : comps.data()) {
        (void)op1;
        for (const auto& [op2, pcs] : op2_map) {
            (void)op2;
            for (uint64_t pc : pcs) {
                res[pc]++;
            }
        }
    }
    return res;
}

} // namespace

int main()
{
    hints::HintsLimiter limiter;

    // === Base case (upstream lines 798-827) ===
    // pc=1000 → 1 attempt, pc=2000 → 9, pc=3000 → 10, pc=4000 → 11, pc=5000 → 20.
    // After Limit: 1000→1, 2000→9, 3000→10, 4000→10, 5000→10.
    hints::CompMap comps;
    comps.Add(1000, 1000, 1100, /*is_const=*/true);
    for (uint64_t i = 0; i < 9; ++i) {
        comps.Add(2000, 2000 + i, 2100 + i, /*is_const=*/true);
    }
    for (uint64_t i = 0; i < 10; ++i) {
        comps.Add(3000, 3000 + i, 3100 + i, /*is_const=*/true);
    }
    for (uint64_t i = 0; i < 11; ++i) {
        comps.Add(4000, 4000 + i, 4100 + i, /*is_const=*/true);
    }
    for (uint64_t i = 0; i < 20; ++i) {
        comps.Add(5000, 5000 + i, 5100 + i, /*is_const=*/true);
    }
    auto before = PerPcCount(comps);
    CHECK(before[1000] == 1);
    CHECK(before[2000] == 9);
    CHECK(before[3000] == 10);
    CHECK(before[4000] == 11);
    CHECK(before[5000] == 20);

    limiter.Limit(comps);
    auto after = PerPcCount(comps);
    CHECK(after[1000] == 1);
    CHECK(after[2000] == 9);
    CHECK(after[3000] == 10);
    CHECK(after[4000] == 10);
    CHECK(after[5000] == 10);

    // === Accumulation case (upstream lines 829-849) ===
    // Three PCs each get 3 more attempts. Limiter has previous totals:
    //   1000 → 1, 2000 → 9, 3000 → 10.
    // After +3 each:  1000 → 4 (kept), 2000 → 12 (kept 1 — first attempt
    // brings counter to 10 inclusive; subsequent 2 over the cap drop),
    // 3000 → 13 (already at 10 — all 3 drop).
    hints::CompMap comps2;
    for (uint64_t i = 0; i < 3; ++i) {
        comps2.Add(1000, 1000 + i, 1100 + i, /*is_const=*/true);
    }
    for (uint64_t i = 0; i < 3; ++i) {
        comps2.Add(2000, 2000 + i, 2100 + i, /*is_const=*/true);
    }
    for (uint64_t i = 0; i < 3; ++i) {
        comps2.Add(3000, 3000 + i, 3100 + i, /*is_const=*/true);
    }
    auto before2 = PerPcCount(comps2);
    CHECK(before2[1000] == 3);
    CHECK(before2[2000] == 3);
    CHECK(before2[3000] == 3);

    limiter.Limit(comps2);
    auto after2 = PerPcCount(comps2);
    CHECK(after2[1000] == 3);  // 1+3=4 ≤ 10 → all kept
    CHECK(after2[2000] == 1);  // 9+1=10 ≤ 10 → keep 1; rest drop
    CHECK(after2[3000] == 0);  // already at 10 → all 3 drop

    std::printf("hints_limiter_test PASSED\n");
    return 0;
}

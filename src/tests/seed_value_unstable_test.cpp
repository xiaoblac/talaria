// reFuzz seed-value signal B — ComputeUnstableRatio oracle.
//
// Verifies the cross-execution coverage-variance helper (race-proximity
// signal, docs/plans/seed-value-signals.md §2.2). The helper takes the same
// runs[r][c] deflake data ComputeFullStableCover consumes, but reports the
// "unstable" side it discards: per-run the PC footprint is unioned across all
// calls, then a PC is "unstable" iff it appears in some-but-not-all runs.
//
// Properties checked:
//   (1) empty / single run → no variance (n<2 → zero);
//   (2) identical runs → unstable=0, union=#distinct;
//   (3) a PC present in only one run → counted unstable;
//   (4) k-of-n: PC in all runs = stable, PC in some = unstable;
//   (5) PROGRAM-LEVEL union — a PC in run A call 0 and run B call 1 is
//       "present in both runs" (cross-call placement must not matter);
//   (6) within-run dedup — a PC hit by two calls of one run votes once.

#include "refuzz/control/stage/stable_cover.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

#define CHECK(cond)                                                         \
    do {                                                                    \
        if (!(cond)) {                                                      \
            std::fprintf(stderr, "CHECK failed: %s (%s:%d)\n", #cond,       \
                         __FILE__, __LINE__);                               \
            std::abort();                                                   \
        }                                                                   \
    } while (0)

using Runs = std::vector<std::vector<std::vector<std::uint64_t>>>;
using refuzz::control::ComputeUnstableRatio;

int main()
{
    // (1) empty → zero.
    {
        auto s = ComputeUnstableRatio(Runs{});
        CHECK(s.union_pc_count == 0);
        CHECK(s.unstable_pc_count == 0);
    }

    // (1) single run → no variance defined (n<2).
    {
        Runs runs = {{{1, 2, 3}}};
        auto s = ComputeUnstableRatio(runs);
        CHECK(s.union_pc_count == 0);
        CHECK(s.unstable_pc_count == 0);
    }

    // (2) two identical runs → all stable.
    {
        Runs runs = {{{1, 2}}, {{1, 2}}};
        auto s = ComputeUnstableRatio(runs);
        CHECK(s.union_pc_count == 2);
        CHECK(s.unstable_pc_count == 0);
    }

    // (3) a PC present in only one of two runs → unstable.
    {
        Runs runs = {{{1, 2, 3}}, {{1, 2}}};  // PC 3 only in run 0
        auto s = ComputeUnstableRatio(runs);
        CHECK(s.union_pc_count == 3);
        CHECK(s.unstable_pc_count == 1);
    }

    // (4) three runs, k-of-n: PC 1 in all (stable), PC 2 in 2-of-3 (unstable).
    {
        Runs runs = {{{1, 2}}, {{1, 2}}, {{1}}};
        auto s = ComputeUnstableRatio(runs);
        CHECK(s.union_pc_count == 2);
        CHECK(s.unstable_pc_count == 1);  // only PC 2
    }

    // (5) program-level union: PC 5 in run0 call0 and run1 call1 → both runs.
    {
        Runs runs = {{{5}, {}}, {{}, {5}}};
        auto s = ComputeUnstableRatio(runs);
        CHECK(s.union_pc_count == 1);
        CHECK(s.unstable_pc_count == 0);  // present in both runs → stable
    }

    // (6) within-run dedup: PC 7 hit twice in run0, once in run1 → one vote each.
    {
        Runs runs = {{{7}, {7}}, {{7}}};
        auto s = ComputeUnstableRatio(runs);
        CHECK(s.union_pc_count == 1);
        CHECK(s.unstable_pc_count == 0);
    }

    // Mixed: PC 1 stable (all 3), PC 2 in 1-of-3, PC 3 in 2-of-3 → 2 unstable.
    {
        Runs runs = {{{1, 2}}, {{1, 3}}, {{1, 3}}};
        auto s = ComputeUnstableRatio(runs);
        CHECK(s.union_pc_count == 3);
        CHECK(s.unstable_pc_count == 2);  // PC 2 and PC 3
    }

    std::printf("seed_value_unstable_test: OK\n");
    return 0;
}

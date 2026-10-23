// hints_inplace_intersect_test.cpp — Epic 5 PR-5-C
//
// 1:1 port of `prog/hints_test.go::TestInplaceIntersect`. Ensures
// CompMap.InplaceIntersect drops (op1, op2, pc) triples not present
// in the other map; empty op2 → drop op1; empty pc → drop op2.

#include "refuzz/mutator/linux/syz_v2/hints/comp_map.hpp"

#include <cstdio>

#define CHECK(cond)                                                                \
    do {                                                                           \
        if (!(cond)) {                                                             \
            std::fprintf(stderr, "CHECK failed: %s (line %d)\n", #cond, __LINE__); \
            return 1;                                                              \
        }                                                                          \
    } while (0)

namespace hints = refuzz::mutator::syz_v2::hints;

int main()
{
    // Upstream fixture (hints_test.go:752-766):
    //   m1: 0xdead → {0x1, 0x2}, 0xbeef → {0x3, 0x4}, 0xffff → {0x5}
    //   m2: 0xdead → {0x2}, 0xbeef → {0x3, 0x6}, 0xeeee → {0x6}
    //   want: 0xdead → {0x2}, 0xbeef → {0x3}
    //
    // PCs are not constrained by the fixture (compSet uses pc=1); we
    // use pc=0x1 uniformly. Add() with is_const=true keeps the (op1,
    // op2) pair single-direction (no swap recursion) — matches
    // upstream `compSet` shape.
    hints::CompMap m1;
    m1.Add(0x1, 0xdead, 0x1, /*is_const=*/true);
    m1.Add(0x1, 0xdead, 0x2, /*is_const=*/true);
    m1.Add(0x1, 0xbeef, 0x3, /*is_const=*/true);
    m1.Add(0x1, 0xbeef, 0x4, /*is_const=*/true);
    m1.Add(0x1, 0xffff, 0x5, /*is_const=*/true);

    hints::CompMap m2;
    m2.Add(0x1, 0xdead, 0x2, /*is_const=*/true);
    m2.Add(0x1, 0xbeef, 0x3, /*is_const=*/true);
    m2.Add(0x1, 0xbeef, 0x6, /*is_const=*/true);
    m2.Add(0x1, 0xeeee, 0x6, /*is_const=*/true);

    m1.InplaceIntersect(m2);

    // 0xdead → {0x2} only.
    const auto* dead = m1.Find(0xdead);
    CHECK(dead != nullptr);
    CHECK(dead->size() == 1);
    CHECK(dead->find(0x2) != dead->end());

    // 0xbeef → {0x3} only.
    const auto* beef = m1.Find(0xbeef);
    CHECK(beef != nullptr);
    CHECK(beef->size() == 1);
    CHECK(beef->find(0x3) != beef->end());

    // 0xffff → dropped (no overlap with m2).
    CHECK(m1.Find(0xffff) == nullptr);
    // 0xeeee → never in m1.
    CHECK(m1.Find(0xeeee) == nullptr);

    // Total record count = 2 (one pc per (op1,op2) pair, 2 pairs survive).
    CHECK(m1.Len() == 2);

    std::printf("hints_inplace_intersect_test PASSED\n");
    return 0;
}

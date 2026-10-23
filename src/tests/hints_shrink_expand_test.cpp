// hints_shrink_expand_test.cpp — Epic 5 PR-5-C
//
// 1:1 port of `prog/hints_test.go::TestHintsShrinkExpand` (9 sub-cases).
// Pure ShrinkExpand verification — no Type construction needed.

#include "refuzz/mutator/linux/syz_v2/hints/comp_map.hpp"
#include "refuzz/mutator/linux/syz_v2/hints/hints_apply.hpp"

#include <cstdio>
#include <vector>

#define CHECK(cond)                                                                \
    do {                                                                           \
        if (!(cond)) {                                                             \
            std::fprintf(stderr, "CHECK failed: %s (line %d)\n", #cond, __LINE__); \
            return 1;                                                              \
        }                                                                          \
    } while (0)

namespace hints = refuzz::mutator::syz_v2::hints;

namespace {

// Build a CompMap from a list of (op1, op2_set...) entries. PCs are
// uniformly 1 (matches upstream `compSet` — pc value only matters for
// HintsLimiter, which ShrinkExpand doesn't query).
hints::CompMap MakeMap(std::initializer_list<std::pair<uint64_t, std::vector<uint64_t>>> entries) {
    hints::CompMap m;
    for (const auto& [op1, op2s] : entries) {
        for (uint64_t op2 : op2s) {
            m.Add(0x1, op1, op2, /*is_const=*/true);
        }
    }
    return m;
}

bool VecEq(const std::vector<uint64_t>& got, const std::vector<uint64_t>& want) {
    if (got.size() != want.size()) return false;
    for (size_t i = 0; i < got.size(); ++i) {
        if (got[i] != want[i]) return false;
    }
    return true;
}

void DumpVec(const char* label, const std::vector<uint64_t>& v) {
    std::fprintf(stderr, "%s: [", label);
    bool first = true;
    for (uint64_t x : v) {
        if (!first) std::fprintf(stderr, ", ");
        first = false;
        std::fprintf(stderr, "0x%llx", static_cast<unsigned long long>(x));
    }
    std::fprintf(stderr, "]\n");
}

#define EXPECT_VEC_EQ(got, want)                                          \
    do {                                                                  \
        if (!VecEq((got), (want))) {                                      \
            DumpVec("got", (got));                                        \
            DumpVec("want", (want));                                      \
            std::fprintf(stderr, "vec mismatch (line %d)\n", __LINE__);   \
            return 1;                                                     \
        }                                                                 \
    } while (0)

// === Shrink tests ===

int Case_Shrink16() {
    // f(0x1234) — u8 b = (u8)0x34, u16 w = 0x1234.
    auto comps = MakeMap({
        {0x34,   {0xab}},
        {0x1234, {0xcdcd}},
    });
    auto got = hints::ShrinkExpand(0x1234, comps, /*bitsize=*/64, /*image=*/false);
    EXPECT_VEC_EQ(got, std::vector<uint64_t>({0x12ab, 0xcdcd}));
    return 0;
}

int Case_Shrink32() {
    auto comps = MakeMap({
        {0x78,       {0xab}},
        {0x5678,     {0xcdcd}},
        {0x12345678, {0xefefefef}},
    });
    auto got = hints::ShrinkExpand(0x12345678, comps, 64, false);
    EXPECT_VEC_EQ(got, std::vector<uint64_t>({0x123456ab, 0x1234cdcd, 0xefefefef}));
    return 0;
}

int Case_Shrink64() {
    auto comps = MakeMap({
        {0xef,               {0xab, 0xef}},
        {0xcdef,             {0xcdcd}},
        {0x90abcdef,         {0xefefefef}},
        {0x1234567890abcdef, {0x0101010101010101ull}},
    });
    auto got = hints::ShrinkExpand(0x1234567890abcdefull, comps, 64, false);
    EXPECT_VEC_EQ(got, std::vector<uint64_t>({
        0x0101010101010101ull,
        0x1234567890abcdabull,
        0x1234567890abcdcdull,
        0x12345678efefefefull,
    }));
    return 0;
}

int Case_ShrinkWiderReplacer1() {
    auto comps = MakeMap({{0x34, {0x1bab}}});
    auto got = hints::ShrinkExpand(0x1234, comps, 64, false);
    EXPECT_VEC_EQ(got, std::vector<uint64_t>{});
    return 0;
}

int Case_ShrinkWiderReplacer2() {
    auto comps = MakeMap({{0x34, {0xfffffffffffffffdull}}});
    auto got = hints::ShrinkExpand(0x1234, comps, 64, false);
    EXPECT_VEC_EQ(got, std::vector<uint64_t>({0x12fd}));
    return 0;
}

// === Extend tests ===

int Case_Extend8() {
    auto comps = MakeMap({{0xffffffffffffffffull, {0xfffffffffffffffeull}}});
    auto got = hints::ShrinkExpand(0xff, comps, 64, false);
    EXPECT_VEC_EQ(got, std::vector<uint64_t>({0xfe}));
    return 0;
}

int Case_Extend16() {
    auto comps = MakeMap({{0xffffffffffffffffull, {0xfffffffffffffffeull}}});
    auto got = hints::ShrinkExpand(0xffff, comps, 64, false);
    EXPECT_VEC_EQ(got, std::vector<uint64_t>({0xfffe}));
    return 0;
}

int Case_Extend32() {
    auto comps = MakeMap({{0xffffffffffffffffull, {0xfffffffffffffffeull}}});
    auto got = hints::ShrinkExpand(0xffffffff, comps, 64, false);
    EXPECT_VEC_EQ(got, std::vector<uint64_t>({0xfffffffe}));
    return 0;
}

int Case_ExtendWiderReplacer() {
    auto comps = MakeMap({{0xffffffffffffffffull, {0xfffffffffffffeffull}}});
    auto got = hints::ShrinkExpand(0xff, comps, 64, false);
    EXPECT_VEC_EQ(got, std::vector<uint64_t>{});
    return 0;
}

} // namespace

int main()
{
    int rc = 0;
    rc |= Case_Shrink16();
    rc |= Case_Shrink32();
    rc |= Case_Shrink64();
    rc |= Case_ShrinkWiderReplacer1();
    rc |= Case_ShrinkWiderReplacer2();
    rc |= Case_Extend8();
    rc |= Case_Extend16();
    rc |= Case_Extend32();
    rc |= Case_ExtendWiderReplacer();
    if (rc == 0) std::printf("hints_shrink_expand_test PASSED\n");
    return rc;
}

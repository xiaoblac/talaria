// hints_check_const_arg_test.cpp — Epic 5 PR-5-C
//
// 1:1 port of `prog/hints_test.go::TestHintsCheckConstArg`. Iterates
// over CheckConstArgHints with various size+bitsize+input combinations
// and asserts that the candidate sequence (the order callbacks fire)
// matches upstream's expected list. Upstream uses `target.SyscallMap
// ["test$hint_int"]` with a struct of named fields per (size, bitsize)
// pair; reFuzz constructs a synthetic IntType inline since the type
// shape needed by ShrinkExpand is fully captured by `size` /
// `bitfield_length`. `field` is nullptr (matches upstream call site).

#include "refuzz/mutator/linux/syz_v2/hints/comp_map.hpp"
#include "refuzz/mutator/linux/syz_v2/hints/hints_apply.hpp"
#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/type.hpp"

#include <cstdio>
#include <memory>
#include <vector>

#define CHECK(cond)                                                                \
    do {                                                                           \
        if (!(cond)) {                                                             \
            std::fprintf(stderr, "CHECK failed: %s (line %d)\n", #cond, __LINE__); \
            return 1;                                                              \
        }                                                                          \
    } while (0)

namespace hints = refuzz::mutator::syz_v2::hints;
namespace syz   = refuzz::program::syz;

namespace {

std::unique_ptr<syz::IntType> MakeIntType(uint64_t size_bytes, uint64_t bitsize) {
    auto t = std::make_unique<syz::IntType>();
    t->set_name("test_int");
    t->set_size(size_bytes);
    if (bitsize != 0 && bitsize != size_bytes * 8) {
        // Mirror upstream `int<size>_<bitsize>` field shape: bitfield
        // of `bitsize` bits embedded in a `size_bytes`-byte unit.
        t->set_bitfield(/*off=*/0, /*len=*/bitsize, /*unit=*/size_bytes, /*unit_off=*/0);
    }
    return t;
}

std::unique_ptr<syz::IntType> MakeIntTypeWithFormat(uint64_t size_bytes,
                                                    syz::BinaryFormat fmt) {
    auto t = std::make_unique<syz::IntType>();
    t->set_name("test_int_str");
    t->set_size(size_bytes);
    t->set_format(fmt);
    return t;
}

hints::CompMap MakeMap(std::initializer_list<std::pair<uint64_t, std::vector<uint64_t>>> entries) {
    hints::CompMap m;
    for (const auto& [op1, op2s] : entries) {
        for (uint64_t op2 : op2s) m.Add(0x1, op1, op2, /*is_const=*/true);
    }
    return m;
}

struct Case {
    const char*           name;
    uint64_t              in;
    uint64_t              size_bytes;
    uint64_t              bitsize;     // 0 = use size_bytes*8
    hints::CompMap        comps;
    std::vector<uint64_t> want;
    // [v2 PR-5-C fix #2] When set, override the type's BinaryFormat —
    // exercises the str-formatted branch (TypeBitSize returns 64).
    bool                  use_str_format = false;
    syz::BinaryFormat     str_format     = syz::BinaryFormat::kStrHex;
};

int RunCase(const Case& tc) {
    std::fprintf(stderr, "  [RUN] %s\n", tc.name);
    std::unique_ptr<syz::IntType> type;
    if (tc.use_str_format) {
        type = MakeIntTypeWithFormat(tc.size_bytes, tc.str_format);
    } else {
        type = MakeIntType(tc.size_bytes, tc.bitsize);
    }
    syz::ConstArg arg;
    arg.set_type(type.get());
    arg.set_dir(syz::Dir::kIn);
    arg.set_val(tc.in);

    std::vector<uint64_t> got;
    hints::CheckConstArgHints(arg, /*field=*/nullptr, tc.comps, [&]() {
        got.push_back(arg.val());
        return true;
    });

    if (got.size() != tc.want.size()) {
        std::fprintf(stderr, "  [FAIL] %s: size %zu != %zu\n",
                     tc.name, got.size(), tc.want.size());
        return 1;
    }
    for (size_t i = 0; i < got.size(); ++i) {
        if (got[i] != tc.want[i]) {
            std::fprintf(stderr, "  [FAIL] %s: got[%zu]=0x%llx want=0x%llx\n",
                         tc.name, i,
                         static_cast<unsigned long long>(got[i]),
                         static_cast<unsigned long long>(tc.want[i]));
            return 1;
        }
    }
    std::fprintf(stderr, "  [PASS] %s\n", tc.name);
    return 0;
}

} // namespace

int main()
{
    std::vector<Case> tests;
    tests.push_back({"one-replacer-test",
        0xdeadbeef, 4, 0,
        MakeMap({{0xdeadbeef, {0xdeadbeef, 0xcafebabe}}}),
        {0xcafebabe}});
    tests.push_back({"multiple-replacers-test",
        0xabcd, 2, 0,
        MakeMap({{0xabcd, {0x32, 0x33}}}),
        {0x32, 0x33}});
    tests.push_back({"special-ints-test",
        0xabcd, 2, 0,
        MakeMap({{0xabcd, {0x1, 0x2, 0x42}}}),
        {0x42}});
    tests.push_back({"int8-invalid-positive-value",
        0x1234, 1, 0,
        MakeMap({
            {0x34,             {0x88, 0x1122, 0xfffffffffffffffeull, 0xffffffffffffff0aull}},
            {0x1234,           {0xa1}},
            {0xffffffffffffff34ull, {0xaa}},
        }),
        {0x88, 0xfe}});
    tests.push_back({"int8-invalid-negative-value",
        0x12ab, 1, 0,
        MakeMap({
            {0xab,             {0xab, 0xac, 0xabcd}},
            {0xffffffffffffffabull, {0x11, 0x22, 0xffffffffffffff34ull}},
        }),
        {0x11, 0x22, 0xac}});
    tests.push_back({"int16-valid-value-bitsize-12",
        0x3ab, 2, 12,
        MakeMap({
            {0x3ab,             {0x11, 0x1234, 0xfffffffffffffffeull}},
            {0x13ab,            {0xab, 0xffa}},
            {0xffffffffffffffabull, {0xfffffffffffffff1ull}},
            {0xfffffffffffff3abull, {0xff1, 0x12}},
        }),
        {0x11, 0x3f1, 0xffe}});
    tests.push_back({"int16-invalid-value-bitsize-12",
        0x71ab, 2, 12,
        MakeMap({
            {0x1ab, {0x11, 0x1234, 0xfffffffffffffffeull}},
        }),
        {0x11, 0xffe}});
    tests.push_back({"int16-negative-valid-value-bitsize-12",
        0x8ab, 2, 12,
        MakeMap({
            {0x8ab,             {0x11}},
            {0xffffffffffffffabull, {0x12, 0xffffffffffffff0aull}},
            {0xfffffffffffff8abull, {0x13, 0xffffffffffffff00ull}},
        }),
        {0x11, 0x13, 0x812, 0xf00}});
    tests.push_back({"int16-negative-invalid-value-bitsize-12",
        0x88ab, 2, 12,
        MakeMap({
            {0x8ab,             {0x13}},
            {0xfffffffffffff8abull, {0x11, 0xffffffffffffff11ull}},
        }),
        {0x11, 0x13, 0xf11}});
    tests.push_back({"int32-invalid-value",
        0xaabaddcafe, 4, 0,
        MakeMap({{0xbaddcafe, {0xab, 0xabcd, 0xbaddcafe, 0xdeadbeef, 0xaabbccddeeff1122ull}}}),
        {0xab, 0xabcd, 0xdeadbeef}});
    tests.push_back({"int64-valid-value",
        0xdeadc0debaddcafeull, 8, 0,
        MakeMap({{0xdeadc0debaddcafeull, {0xab, 0xabcd, 0xdeadbeef, 0xdeadbeefdeadbeefull}}}),
        {0xab, 0xabcd, 0xdeadbeef, 0xdeadbeefdeadbeefull}});

    // [v2 PR-5-C fix #2] str-formatted int: size_bytes=4 but TypeBitSize→64.
    // Without the format-aware branch, ShrinkExpand would scan at 32-bit
    // width and miss the 64-bit candidate. Uses the same input as the
    // int8 fixture but with kStrHex format → the kernel sees 64 bits;
    // the 64-bit replacer 0xdeadbeefdeadbeef must surface.
    {
        Case c;
        c.name = "int4-str-format-extends-to-64";
        c.in = 0xdeadc0debaddcafeull;
        c.size_bytes = 4;            // small bytewise, but format forces 64-bit
        c.bitsize = 0;
        c.comps = MakeMap({{0xdeadc0debaddcafeull, {0xab, 0xabcd, 0xdeadbeef, 0xdeadbeefdeadbeefull}}});
        c.want = {0xab, 0xabcd, 0xdeadbeef, 0xdeadbeefdeadbeefull};
        c.use_str_format = true;
        c.str_format = syz::BinaryFormat::kStrHex;
        tests.push_back(std::move(c));
    }

    int rc = 0;
    for (const auto& tc : tests) rc |= RunCase(tc);
    if (rc == 0) std::printf("hints_check_const_arg_test PASSED\n");
    return rc;
}

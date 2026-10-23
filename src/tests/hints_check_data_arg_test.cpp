// hints_check_data_arg_test.cpp — Epic 5 PR-5-C
//
// 1:1 port of `prog/hints_test.go::TestHintsCheckDataArg` (7 sub-cases).
// Constructs a synthetic BufferType (kBlobRand, var-len, kIn) and a
// DataArg with the test fixture's input bytes; verifies the produced
// candidate set as a *set* of byte sequences (upstream uses a map,
// matching the unordered nature of CompMap iteration).

#include "refuzz/mutator/linux/syz_v2/hints/comp_map.hpp"
#include "refuzz/mutator/linux/syz_v2/hints/hints_apply.hpp"
#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/type.hpp"

#include <cstdio>
#include <memory>
#include <set>
#include <string>
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

std::unique_ptr<syz::BufferType> MakeBlobBufferType(size_t fixed_size) {
    auto t = std::make_unique<syz::BufferType>();
    t->set_name("test_blob");
    t->set_buffer_kind(syz::BufferKind::kBlobRand);
    t->set_var_len(false);
    t->set_size(fixed_size);
    return t;
}

hints::CompMap MakeMap(std::initializer_list<std::pair<uint64_t, std::vector<uint64_t>>> entries) {
    hints::CompMap m;
    for (const auto& [op1, op2s] : entries) {
        for (uint64_t op2 : op2s) m.Add(0x1, op1, op2, /*is_const=*/true);
    }
    return m;
}

std::string ToStr(const std::vector<uint8_t>& v) {
    return std::string(reinterpret_cast<const char*>(v.data()), v.size());
}

std::vector<uint8_t> FromStr(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

struct Case {
    const char*           name;
    std::string           in;            // raw input bytes
    hints::CompMap        comps;
    std::set<std::string> want;          // expected candidate byte sequences
};

int RunCase(const Case& tc) {
    std::fprintf(stderr, "  [RUN] %s\n", tc.name);
    auto type = MakeBlobBufferType(tc.in.size());
    syz::DataArg arg;
    arg.set_type(type.get());
    arg.set_dir(syz::Dir::kIn);
    arg.set_data(FromStr(tc.in));

    std::set<std::string> got;
    hints::CheckDataArgHints(arg, tc.comps, [&]() {
        got.insert(ToStr(arg.data()));
        return true;
    });

    if (got != tc.want) {
        std::fprintf(stderr, "  [FAIL] %s\n", tc.name);
        std::fprintf(stderr, "    got (%zu):\n", got.size());
        for (const auto& s : got) {
            std::fprintf(stderr, "      ");
            for (uint8_t b : s) std::fprintf(stderr, "%02x", b);
            std::fprintf(stderr, "\n");
        }
        std::fprintf(stderr, "    want (%zu):\n", tc.want.size());
        for (const auto& s : tc.want) {
            std::fprintf(stderr, "      ");
            for (uint8_t b : s) std::fprintf(stderr, "%02x", b);
            std::fprintf(stderr, "\n");
        }
        return 1;
    }
    std::fprintf(stderr, "  [PASS] %s\n", tc.name);
    return 0;
}

} // namespace

int main()
{
    std::vector<Case> tests;

    tests.push_back({"one-replacer-test",
        std::string("\xef\xbe\xad\xde", 4),
        MakeMap({
            {0xdeadbeef, {0xcafebabe, 0xdeadbeef}},
            {0xbeef,     {0xbeef}},
            {0xef,       {0xef}},
        }),
        { std::string("\xbe\xba\xfe\xca", 4) }
    });

    tests.push_back({"multiple-replacers-test",
        std::string("\xcd\xab\x42\x42", 4),
        MakeMap({{0xabcd, {0x44, 0x45}}}),
        {
            std::string("\x44\x00\x42\x42", 4),
            std::string("\x45\x00\x42\x42", 4),
        }
    });

    tests.push_back({"special-ints-test",
        std::string("\xcd\xab\x42\x42", 4),
        MakeMap({{0xabcd, {0x1, 0x45}}}),
        { std::string("\x45\x00\x42\x42", 4) }
    });

    tests.push_back({"different-sizes-test",
        std::string("\xef\xcd\xab\x90\x78\x56\x34\x12", 8),
        MakeMap({
            {0xef,                {0x11}},
            {0xcdef,              {0x2222}},
            {0x90abcdef,          {0x33333333}},
            {0x1234567890abcdefull, {0x4444444444444444ull}},
        }),
        {
            std::string("\x11\xcd\xab\x90\x78\x56\x34\x12", 8),
            std::string("\x22\x22\xab\x90\x78\x56\x34\x12", 8),
            std::string("\x33\x33\x33\x33\x78\x56\x34\x12", 8),
            std::string("\x44\x44\x44\x44\x44\x44\x44\x44", 8),
        }
    });

    tests.push_back({"different-offsets-test",
        std::string("\xab\xab\xab\xab\xab\xab\xab\xab\xab", 9),
        MakeMap({
            {0xab,                {0x11}},
            {0xabab,              {0x2222}},
            {0xabababab,          {0x33333333}},
            {0xababababababababull, {0x4444444444444444ull}},
        }),
        {
            std::string("\x11\xab\xab\xab\xab\xab\xab\xab\xab", 9),
            std::string("\xab\x11\xab\xab\xab\xab\xab\xab\xab", 9),
            std::string("\xab\xab\x11\xab\xab\xab\xab\xab\xab", 9),
            std::string("\xab\xab\xab\x11\xab\xab\xab\xab\xab", 9),
            std::string("\xab\xab\xab\xab\x11\xab\xab\xab\xab", 9),
            std::string("\xab\xab\xab\xab\xab\x11\xab\xab\xab", 9),
            std::string("\xab\xab\xab\xab\xab\xab\x11\xab\xab", 9),
            std::string("\xab\xab\xab\xab\xab\xab\xab\x11\xab", 9),
            std::string("\xab\xab\xab\xab\xab\xab\xab\xab\x11", 9),
            std::string("\x22\x22\xab\xab\xab\xab\xab\xab\xab", 9),
            std::string("\xab\x22\x22\xab\xab\xab\xab\xab\xab", 9),
            std::string("\xab\xab\x22\x22\xab\xab\xab\xab\xab", 9),
            std::string("\xab\xab\xab\x22\x22\xab\xab\xab\xab", 9),
            std::string("\xab\xab\xab\xab\x22\x22\xab\xab\xab", 9),
            std::string("\xab\xab\xab\xab\xab\x22\x22\xab\xab", 9),
            std::string("\xab\xab\xab\xab\xab\xab\x22\x22\xab", 9),
            std::string("\xab\xab\xab\xab\xab\xab\xab\x22\x22", 9),
            std::string("\x33\x33\x33\x33\xab\xab\xab\xab\xab", 9),
            std::string("\xab\x33\x33\x33\x33\xab\xab\xab\xab", 9),
            std::string("\xab\xab\x33\x33\x33\x33\xab\xab\xab", 9),
            std::string("\xab\xab\xab\x33\x33\x33\x33\xab\xab", 9),
            std::string("\xab\xab\xab\xab\x33\x33\x33\x33\xab", 9),
            std::string("\xab\xab\xab\xab\xab\x33\x33\x33\x33", 9),
            std::string("\x44\x44\x44\x44\x44\x44\x44\x44\xab", 9),
            std::string("\xab\x44\x44\x44\x44\x44\x44\x44\x44", 9),
        }
    });

    tests.push_back({"replace-in-the-middle-of-a-larger-blob",
        std::string("\xef\xcd\xab\x90\x78\x56\x34\x12", 8),
        MakeMap({{0xffffffffffff90abull, {0xffffffffffffaabbull}}}),
        { std::string("\xef\xcd\xbb\xaa\x78\x56\x34\x12", 8) }
    });

    tests.push_back({"big-endian-replace",
        std::string("\xef\xcd\xab\x90\x78\x56\x34\x12", 8),
        MakeMap({
            {0xefcd,               {0xaabb, 0xff07}},
            {0x3412,               {0xaabb, 0xff07}},
            {0x9078,               {0xaabb, 0x11223344, 0xff07}},
            {0x90785634,           {0xaabbccdd, 0x11223344}},
            {0xefcdab9078563412ull, {0x1122334455667788ull}},
        }),
        {
            std::string("\xaa\xbb\xab\x90\x78\x56\x34\x12", 8),
            std::string("\xef\xcd\xab\x90\x78\x56\xaa\xbb", 8),
            std::string("\xef\xcd\xab\xaa\xbb\x56\x34\x12", 8),
            std::string("\xef\xcd\xab\xaa\xbb\xcc\xdd\x12", 8),
            std::string("\xef\xcd\xab\x11\x22\x33\x44\x12", 8),
            std::string("\x11\x22\x33\x44\x55\x66\x77\x88", 8),
        }
    });

    int rc = 0;
    for (const auto& tc : tests) rc |= RunCase(tc);
    if (rc == 0) std::printf("hints_check_data_arg_test PASSED\n");
    return rc;
}

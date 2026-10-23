// hints_compressed_image_test.cpp — Epic 5 PR-5-C
//
// 1:1 port of `prog/hints_test.go::TestHintsCompressedImage` (3 cases).
// Wraps the test input in a zlib-compressed buffer (via CompressImage),
// feeds it to GenerateArgHints with BufferType::kCompressed type. The
// algorithm decompresses, walks 4-byte aligned uint64 windows, applies
// shrink_expand with image=true, recompresses, exec, restore.
// Verifies the produced *decompressed* candidate set matches upstream
// (callbacks fire on compressed bytes; we re-decompress to compare).

#include "refuzz/mutator/linux/syz_v2/hints/comp_map.hpp"
#include "refuzz/mutator/linux/syz_v2/hints/hints_apply.hpp"
#include "refuzz/mutator/linux/syz_v2/hints/image_zlib.hpp"
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

std::unique_ptr<syz::BufferType> MakeCompressedBufferType() {
    auto t = std::make_unique<syz::BufferType>();
    t->set_name("test_image");
    t->set_buffer_kind(syz::BufferKind::kCompressed);
    t->set_var_len(true);
    t->set_size(0);
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
    std::string                input;     // raw decompressed bytes
    hints::CompMap             comps;
    std::set<std::string>      want;      // expected decompressed candidates
};

int RunCase(int idx, const Case& tc) {
    std::fprintf(stderr, "  [RUN] case %d\n", idx);
    auto type = MakeCompressedBufferType();
    syz::DataArg arg;
    arg.set_type(type.get());
    arg.set_dir(syz::Dir::kIn);
    arg.set_data(hints::CompressImage(FromStr(tc.input)));

    std::set<std::string> got;
    // GenerateArgHints does the type dispatch (kCompressed → CheckCompressedArgHints).
    hints::GenerateArgHints(tc.comps, &arg, /*field=*/nullptr, [&]() {
        // arg.data() at this point is the compressed mutant; decompress to compare.
        const auto decompressed = hints::MustDecompressImage(arg.data());
        got.insert(ToStr(decompressed));
        return true;
    });

    // Verify arg restored.
    const auto post = hints::MustDecompressImage(arg.data());
    if (ToStr(post) != tc.input) {
        std::fprintf(stderr, "  [FAIL] case %d: arg not restored\n", idx);
        return 1;
    }

    if (got != tc.want) {
        std::fprintf(stderr, "  [FAIL] case %d\n", idx);
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
    std::fprintf(stderr, "  [PASS] case %d\n", idx);
    return 0;
}

} // namespace

int main()
{
    std::vector<Case> tests;

    // Case 0: 4/8-byte aligned ints replaced; 1/2-byte and unaligned ignored.
    tests.push_back({
        std::string("\x00\x11\x22\x33\x44\x55\x66\x77", 8),
        MakeMap({
            {0x00,   {0xaa}},
            {0x11,   {0xaa}},
            {0x1122, {0xaabb}},
            {0x4455, {0xaabb}},
            {0x00112233ull,         {0xaabbccddull}},
            {0x33221100ull,         {0xaabbccddull}},
            {0x44556677ull,         {0xaabbccddull}},
            {0x77665544ull,         {0xaabbccddull}},
            {0x0011223344556677ull, {0xaabbccddeeff9988ull}},
            {0x7766554433221100ull, {0xaabbccddeeff9988ull}},
            {0x11223344ull,         {0xaabbccddull}},
            {0x22334455ull,         {0xaabbccddull}},
        }),
        {
            std::string("\xaa\xbb\xcc\xdd\x44\x55\x66\x77", 8),
            std::string("\xdd\xcc\xbb\xaa\x44\x55\x66\x77", 8),
            std::string("\x00\x11\x22\x33\xaa\xbb\xcc\xdd", 8),
            std::string("\x00\x11\x22\x33\xdd\xcc\xbb\xaa", 8),
            std::string("\xaa\xbb\xcc\xdd\xee\xff\x99\x88", 8),
            std::string("\x88\x99\xff\xee\xdd\xcc\xbb\xaa", 8),
        }
    });

    // Case 1: special values 0 / 0xffffffff are USED as replacers in image mode.
    tests.push_back({
        std::string("\x00\x11\x22\x33\x44\x55\x66\x77", 8),
        MakeMap({{0x00112233ull, {0, 0xffffffffull}}}),
        {
            std::string("\x00\x00\x00\x00\x44\x55\x66\x77", 8),
            std::string("\xff\xff\xff\xff\x44\x55\x66\x77", 8),
        }
    });

    // Case 2: All-0 and all-1 source bytes never replaced.
    tests.push_back({
        std::string("\x00\x00\x00\x00\x00\x00\x00\x00"
                    "\xff\xff\xff\xff\xff\xff\xff\xff"
                    "\x00\x00\x00\x00\x00\x00\x00\x00", 24),
        MakeMap({
            {0,                      {0xaabbccddull}},
            {0xffffffffffffffffull,  {0xaabbccddaabbccddull}},
        }),
        {}  // empty — nothing should be replaced
    });

    int rc = 0;
    for (size_t i = 0; i < tests.size(); ++i) rc |= RunCase(static_cast<int>(i), tests[i]);
    if (rc == 0) std::printf("hints_compressed_image_test PASSED\n");
    return rc;
}

// post-V1-retirement B-6 — RawBytesArtifact 单元 smoke test。
//
// 验证：
//   1. MakeRawBytesArtifact 直构 path：valid()/has_typed_view/canonical_payload
//      都正常；As<RawBytesProgram>() 命中。
//   2. Registry path：MakeArtifactFromCanonicalPayload(kAflRaw, ...) 返回的
//      artifact 与直构 path 行为一致。
//   3. MaterializeExecWire(raw artifact) 是 identity（输出 == 输入 bytes）。
//   4. 错误路径：empty bytes 注入 BuildFromCanonicalPayload 时 unexpected。

#include "refuzz/program/artifact.hpp"
#include "refuzz/program/artifact_materializer.hpp"
#include "refuzz/program/raw_bytes_artifact.hpp"

#include <cstdio>
#include <cstdint>
#include <vector>

#define CHECK(cond)                                                            \
    do {                                                                       \
        if (!(cond)) {                                                         \
            std::fprintf(stderr, "CHECK failed: %s (line %d)\n",               \
                         #cond, __LINE__);                                     \
            return 1;                                                          \
        }                                                                      \
    } while (0)

#define RUN_TEST(fn)                                                           \
    do {                                                                       \
        std::fprintf(stdout, "  %s\n", #fn);                                   \
        if ((fn)() != 0) return 1;                                             \
    } while (0)

namespace {

using refuzz::program::ArtifactMaterializerRegistry;
using refuzz::program::MakeArtifactFromCanonicalPayload;
using refuzz::program::MakeRawBytesArtifact;
using refuzz::program::MaterializeExecWire;
using refuzz::program::ProgramArtifact;
using refuzz::program::ProgramTargetKey;
using refuzz::program::RawBytesProgram;
using refuzz::program::RegisterBuiltinArtifactMaterializers;

int TestDirectMakeRawBytesArtifact()
{
    std::vector<std::uint8_t> bytes{0xde, 0xad, 0xbe, 0xef};
    ProgramTargetKey target{"raw", "x86_64", "v1"};
    auto art = MakeRawBytesArtifact(target, bytes);
    CHECK(art.valid());
    CHECK(art.format() == refuzz::fuzzer::ProgFormat::kAflRaw);
    CHECK(art.target() == target);
    CHECK(art.has_typed_view());
    CHECK(art.has_canonical_payload());

    auto typed = art.As<RawBytesProgram>();
    CHECK(typed != nullptr);
    CHECK(typed->bytes == bytes);

    auto canonical = art.canonical_payload();
    CHECK(canonical != nullptr);
    CHECK(*canonical == bytes);
    return 0;
}

int TestRegistryPathRoundTrip()
{
    RegisterBuiltinArtifactMaterializers();
    std::vector<std::uint8_t> bytes{0x01, 0x02, 0x03, 0x04, 0x05};
    ProgramTargetKey target{"raw", "x86_64", "v1"};

    auto art_or = MakeArtifactFromCanonicalPayload(
        refuzz::fuzzer::ProgFormat::kAflRaw, target, bytes);
    CHECK(art_or.has_value());
    const auto& art = *art_or;
    CHECK(art.valid());
    CHECK(art.format() == refuzz::fuzzer::ProgFormat::kAflRaw);

    auto typed = art.As<RawBytesProgram>();
    CHECK(typed != nullptr);
    CHECK(typed->bytes == bytes);

    auto wire_or = MaterializeExecWire(art);
    CHECK(wire_or.has_value());
    CHECK(*wire_or == bytes);  // identity LowerToExecWire
    return 0;
}

int TestEmptyBytesAcceptedForRawTarget()
{
    // post-V1-retirement: 空 input 对 raw / AFL target 是合法 program。
    // RawBytesMaterializer 必须返回 valid artifact —— canonical_body 是空
    // vector，typed view 是 RawBytesProgram{bytes={}} —— 这样 zero-length
    // seed 也能挂上 artifact，满足"every Seed has an artifact"不变式。
    RegisterBuiltinArtifactMaterializers();
    auto art_or = MakeArtifactFromCanonicalPayload(
        refuzz::fuzzer::ProgFormat::kAflRaw,
        ProgramTargetKey{"raw", "x86_64", "v1"},
        std::vector<std::uint8_t>{});
    CHECK(art_or.has_value());
    const auto& art = *art_or;
    CHECK(art.valid());
    auto typed = art.As<RawBytesProgram>();
    CHECK(typed != nullptr);
    CHECK(typed->bytes.empty());
    auto canonical = art.canonical_payload();
    CHECK(canonical != nullptr);
    CHECK(canonical->empty());
    return 0;
}

} // namespace

int main()
{
    std::fprintf(stdout, "Running raw_bytes_artifact_test...\n");
    RUN_TEST(TestDirectMakeRawBytesArtifact);
    RUN_TEST(TestRegistryPathRoundTrip);
    RUN_TEST(TestEmptyBytesAcceptedForRawTarget);
    std::fprintf(stdout, "All tests passed.\n");
    return 0;
}

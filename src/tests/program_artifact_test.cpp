// §3.10 step-1 unit tests — ProgramArtifact + materializer + codec
// counter wiring.
//
// What this test covers:
//   - construction via MakeArtifactFromCanonicalPayload (disk-load path):
//     typed view eagerly populated, canonical_payload preloaded, no
//     extra decode/encode.
//   - As<syz::Prog>() returns the stored typed view; As<int>() returns
//     null (typed-type mismatch).
//   - target() reflects linux/amd64 + Target::linux_amd64().revision().
//   - canonical_payload() is byte-equal to the input bytes (cache, not
//     re-encode).
//   - MaterializeCanonicalText returns the cached payload.
//   - MaterializeExecWire produces non-empty bytes (matches
//     serialize_for_exec on the typed view) and increments only the
//     wire-encode counter.
//   - CheckTargetOrDie passes on equal key (we do not test the abort
//     branch — D9 says it aborts and we don't want to crash the
//     test binary; a debug-only fork variant can be added later if
//     needed).
//   - Counters: after MakeArtifactFromCanonicalPayload, decode_text == 1,
//     encode_text == 0; subsequent As<>/canonical_payload reads do not
//     touch counters.

#include "refuzz/program/artifact.hpp"
#include "refuzz/program/artifact_materializer.hpp"
#include "refuzz/program/internal/codec_counters.hpp"
#include "refuzz/program/syz/encoding.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string_view>
#include <utility>
#include <vector>

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

namespace pr = refuzz::program;
namespace pcc = refuzz::program::codec_counters;

// A trivial, schema-valid program: getpid is a 0-arg syscall on
// linux/amd64. The text format is just `getpid()\n`. Avoids any
// dependency on corpus files.
constexpr std::string_view kTrivialSyz = "getpid()\n";

std::vector<std::uint8_t> ToBytes(std::string_view sv) {
    return std::vector<std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(sv.data()),
        reinterpret_cast<const std::uint8_t*>(sv.data() + sv.size()));
}

pr::ProgramTargetKey LinuxAmd64Key() {
    const auto& t = refuzz::program::syz::Target::linux_amd64();
    return pr::ProgramTargetKey{t.os(), t.arch(), t.revision()};
}

void TestMakeArtifactFromCanonicalPayload_DiskLoadPath() {
    pcc::ResetForTest();

    auto art_or = pr::MakeArtifactFromCanonicalPayload(
        refuzz::fuzzer::ProgFormat::kSyzProg,
        LinuxAmd64Key(),
        ToBytes(kTrivialSyz));
    CHECK(art_or.has_value());

    pr::ProgramArtifact a = std::move(*art_or);
    CHECK(a.valid());
    CHECK(a.format() == refuzz::fuzzer::ProgFormat::kSyzProg);
    CHECK(a.target() == LinuxAmd64Key());

    // Typed view eagerly populated.
    CHECK(a.has_typed_view());
    auto typed = a.As<refuzz::program::syz::Prog>();
    CHECK(typed != nullptr);
    CHECK(typed->calls().size() == 1);
    CHECK(typed->calls()[0]->meta() != nullptr);

    // Wrong type returns null without aborting.
    CHECK(a.As<int>() == nullptr);

    // canonical_payload preloaded; byte-equal to input.
    CHECK(a.has_canonical_payload());
    auto bytes = a.canonical_payload();
    CHECK(bytes != nullptr);
    CHECK(bytes->size() == kTrivialSyz.size());
    CHECK(std::memcmp(bytes->data(), kTrivialSyz.data(), bytes->size()) == 0);

    // Counters: exactly one decode_text (the load), zero encodes.
    auto c = pcc::ReadForTest();
    CHECK(c.decode_text_calls == 1);
    CHECK(c.encode_text_calls == 0);
    CHECK(c.encode_wire_calls == 0);
    CHECK(c.decode_wire_calls == 0);

    // Reading typed view and canonical_payload again: counters unchanged.
    (void)a.As<refuzz::program::syz::Prog>();
    (void)a.canonical_payload();
    auto c2 = pcc::ReadForTest();
    CHECK(c2.decode_text_calls == 1);
    CHECK(c2.encode_text_calls == 0);
}

void TestMaterializeCanonicalText_UsesCachedPayload() {
    pcc::ResetForTest();
    auto art_or = pr::MakeArtifactFromCanonicalPayload(
        refuzz::fuzzer::ProgFormat::kSyzProg,
        LinuxAmd64Key(),
        ToBytes(kTrivialSyz));
    CHECK(art_or.has_value());
    pr::ProgramArtifact a = std::move(*art_or);

    // After load: 1 decode, 0 encodes (already verified above).
    auto c_after_load = pcc::ReadForTest();
    CHECK(c_after_load.decode_text_calls == 1);
    CHECK(c_after_load.encode_text_calls == 0);

    auto bytes_or = pr::MaterializeCanonicalText(a);
    CHECK(bytes_or.has_value());
    CHECK(*bytes_or != nullptr);
    CHECK((*bytes_or)->size() == kTrivialSyz.size());

    // MaterializeCanonicalText hits the cache; encode_text counter
    // stays put.
    auto c_after = pcc::ReadForTest();
    CHECK(c_after.encode_text_calls == 0);
    CHECK(c_after.decode_text_calls == 1);
}

void TestMaterializeExecWire_BumpsEncodeWire() {
    pcc::ResetForTest();
    auto art_or = pr::MakeArtifactFromCanonicalPayload(
        refuzz::fuzzer::ProgFormat::kSyzProg,
        LinuxAmd64Key(),
        ToBytes(kTrivialSyz));
    CHECK(art_or.has_value());
    pr::ProgramArtifact a = std::move(*art_or);

    auto wire_or = pr::MaterializeExecWire(a);
    CHECK(wire_or.has_value());
    CHECK(!wire_or->empty());

    auto c = pcc::ReadForTest();
    // exactly one wire encode (Executor::Submit does this in production).
    CHECK(c.encode_wire_calls == 1);
    // decode counts: 1 from the disk-load, 0 from MaterializeExecWire.
    CHECK(c.decode_text_calls == 1);
    CHECK(c.encode_text_calls == 0);
}

void TestCheckTargetOrDie_PassesOnMatch() {
    auto art_or = pr::MakeArtifactFromCanonicalPayload(
        refuzz::fuzzer::ProgFormat::kSyzProg,
        LinuxAmd64Key(),
        ToBytes(kTrivialSyz));
    CHECK(art_or.has_value());
    pr::ProgramArtifact a = std::move(*art_or);

    pr::CheckTargetOrDie(a, LinuxAmd64Key());  // must not abort
}

void TestRejectNonLinuxAmd64() {
    pr::ProgramTargetKey wrong{"linux", "arm64", ""};
    auto art_or = pr::MakeArtifactFromCanonicalPayload(
        refuzz::fuzzer::ProgFormat::kSyzProg,
        wrong,
        ToBytes(kTrivialSyz));
    CHECK(!art_or.has_value());
}

} // namespace

int main() {
    pr::RegisterBuiltinArtifactMaterializers();

    RUN_TEST(TestMakeArtifactFromCanonicalPayload_DiskLoadPath);
    RUN_TEST(TestMaterializeCanonicalText_UsesCachedPayload);
    RUN_TEST(TestMaterializeExecWire_BumpsEncodeWire);
    RUN_TEST(TestCheckTargetOrDie_PassesOnMatch);
    RUN_TEST(TestRejectNonLinuxAmd64);
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}

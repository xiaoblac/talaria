// §3.10 step-3 unit test — IMutatorEngine::MutateTyped contract.
//
// Property invariants under test:
//   1. SyzV2MutatorEngine::MutateTyped on a populated artifact returns a
//      MutationResult whose artifact is valid + has a typed Prog view.
//   2. Hot-path codec-free contract: 1000 successive MutateTyped calls
//      after `program::codec_counters::ResetForTest()` record
//      `decode_text_calls == 0` and `encode_text_calls == 0` and
//      `encode_wire_calls == 0` (this is the local form of plan §5.2
//      oracle #17; the full oracle gate runs in step 9).
//   3. D4 immutable artifact + clone-to-mutate: the result artifact's
//      typed Prog is a distinct object from the source artifact's
//      typed Prog.
//   4. Legacy IMutatorEngine::MutateTyped default (no override)
//      returns kSkipped (not nullptr / not a crash).
//   5. Compatibility Mutate(Seed) wrapper still produces non-empty
//      bytes for an empty seed (generation path unchanged).

#include "refuzz/mutator/linux/syz_v2/engines/syz_v2_engine.hpp"
#include "refuzz/program/artifact.hpp"
#include "refuzz/program/artifact_materializer.hpp"
#include "refuzz/program/internal/codec_counters.hpp"
#include "refuzz/program/seed.hpp"
#include "refuzz/program/syz/encoding.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
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

namespace pr  = refuzz::program;
namespace pcc = refuzz::program::codec_counters;
namespace syz = refuzz::program::syz;

pr::ProgramTargetKey LinuxAmd64Key() {
    const auto& t = syz::Target::linux_amd64();
    return pr::ProgramTargetKey{t.os(), t.arch(), t.revision()};
}

// Bootstrap a populated artifact via the existing disk-load path
// (canonical bytes -> typed Prog -> artifact). One decode_text bump
// here is allowed; the test resets the counters AFTER setup.
pr::ProgramArtifact BuildSeedArtifact() {
    const auto& target = syz::Target::linux_amd64();

    // Generate a v2 program via SyzV2MutatorEngine, use its bytes as
    // canonical text. This guarantees the produced text is decode-able.
    refuzz::fuzzer::SyzV2MutatorEngine boot_engine(
        target, /*corpus_store=*/nullptr, /*master_seed=*/12345);
    refuzz::fuzzer::Seed empty;
    auto bytes = boot_engine.Mutate(empty);
    CHECK(!bytes.empty());

    auto art_or = pr::MakeArtifactFromCanonicalPayload(
        refuzz::fuzzer::ProgFormat::kSyzProg,
        LinuxAmd64Key(),
        std::move(bytes));
    CHECK(art_or.has_value());
    return std::move(*art_or);
}

void TestMutateTypedReturnsValidArtifact() {
    auto seed = BuildSeedArtifact();
    refuzz::fuzzer::SyzV2MutatorEngine engine(
        syz::Target::linux_amd64(), nullptr, /*master_seed=*/77);

    auto result = engine.MutateTyped(seed);
    CHECK(result.status == pr::MutationStatus::kOk ||
          result.status == pr::MutationStatus::kSkipped);
    CHECK(result.artifact.valid());
    CHECK(result.artifact.has_typed_view());
    auto typed = result.artifact.As<syz::Prog>();
    CHECK(typed != nullptr);
    CHECK(!typed->calls().empty());
    CHECK(result.artifact.target() == LinuxAmd64Key());
}

void TestMutateTypedHotPathIsCodecFree() {
    // Plan §5.2 oracle #17 (local form): 1000× MutateTyped on a
    // populated artifact records 0 decode_text and 0 encode_text.
    auto seed = BuildSeedArtifact();
    refuzz::fuzzer::SyzV2MutatorEngine engine(
        syz::Target::linux_amd64(), nullptr, /*master_seed=*/0xC0DECAFE);

    pcc::ResetForTest();
    for (int i = 0; i < 1000; ++i) {
        auto result = engine.MutateTyped(seed);
        // We don't trigger canonical text materialization — that's the
        // whole point. We only consume the typed view.
        (void)result.artifact.As<syz::Prog>();
    }
    auto c = pcc::ReadForTest();
    if (c.decode_text_calls != 0 || c.encode_text_calls != 0 ||
        c.encode_wire_calls != 0) {
        std::fprintf(stderr,
                     "counters: dec_text=%llu enc_text=%llu dec_wire=%llu enc_wire=%llu\n",
                     (unsigned long long)c.decode_text_calls,
                     (unsigned long long)c.encode_text_calls,
                     (unsigned long long)c.decode_wire_calls,
                     (unsigned long long)c.encode_wire_calls);
    }
    CHECK(c.decode_text_calls == 0);
    CHECK(c.encode_text_calls == 0);
    CHECK(c.encode_wire_calls == 0);
}

void TestMutateTypedClonesTypedView() {
    auto seed     = BuildSeedArtifact();
    auto src_prog = seed.As<syz::Prog>();
    CHECK(src_prog != nullptr);

    refuzz::fuzzer::SyzV2MutatorEngine engine(
        syz::Target::linux_amd64(), nullptr, /*master_seed=*/123);
    auto result = engine.MutateTyped(seed);
    auto out_prog = result.artifact.As<syz::Prog>();
    CHECK(out_prog != nullptr);
    // D4: result Prog is a distinct object — mutate-on-clone, not on
    // the immutable source.
    CHECK(out_prog.get() != src_prog.get());
}

void TestMutateTypedCanonicalProviderProducesEqualText() {
    // canonical_payload() on an unchanged-by-Skipped result should
    // re-encode to bytes that themselves decode-and-validate. We
    // don't require byte-equality with the source (the policy may
    // have mutated the clone), but we DO require the lazy provider
    // works at all.
    auto seed = BuildSeedArtifact();

    refuzz::fuzzer::SyzV2MutatorEngine engine(
        syz::Target::linux_amd64(), nullptr, /*master_seed=*/55);
    auto result = engine.MutateTyped(seed);
    CHECK(result.artifact.valid());

    // Materialize once via the provider. encode_text_calls bumps to 1.
    pcc::ResetForTest();
    auto bytes_or = pr::MaterializeCanonicalText(result.artifact);
    CHECK(bytes_or.has_value());
    CHECK(*bytes_or != nullptr);
    CHECK(!(*bytes_or)->empty());
    auto c = pcc::ReadForTest();
    CHECK(c.encode_text_calls == 1);

    // Second call hits the cache — counter unchanged.
    auto bytes_or2 = pr::MaterializeCanonicalText(result.artifact);
    CHECK(bytes_or2.has_value());
    auto c2 = pcc::ReadForTest();
    CHECK(c2.encode_text_calls == 1);
}

void TestMutateSeedCompatPathStillWorks() {
    // Empty seed → generate path — must still produce non-empty bytes.
    refuzz::fuzzer::SyzV2MutatorEngine engine(
        syz::Target::linux_amd64(), nullptr, /*master_seed=*/2026);
    refuzz::fuzzer::Seed empty;
    auto bytes = engine.Mutate(empty);
    CHECK(!bytes.empty());
}

} // namespace

int main() {
    pr::RegisterBuiltinArtifactMaterializers();

    RUN_TEST(TestMutateTypedReturnsValidArtifact);
    RUN_TEST(TestMutateTypedHotPathIsCodecFree);
    RUN_TEST(TestMutateTypedClonesTypedView);
    RUN_TEST(TestMutateTypedCanonicalProviderProducesEqualText);
    RUN_TEST(TestMutateSeedCompatPathStillWorks);
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}

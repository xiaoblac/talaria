// §3.11-A / C1-P1 oracle #21 — repro/minimize artifact entry adds zero
// text-codec calls beyond the artifact's own pre-cached materialization.
//
// Scope:
//   * `CrashContext::origin_artifact` is populated by BuildContextOp
//     via MakeArtifactFromCanonicalPayload (one decode at incident
//     build time).
//   * `ReproManager::StageMinimize` prefers the artifact entry on the
//     ProgramMinimizer when the artifact is present.
//   * The artifact entry reads `artifact.As<program::syz::Prog>()`,
//     clones the typed Prog, and serializes candidates with
//     `serialize_for_exec` before calling TestFunc.
//
// What this oracle proves:
//   * Across the whole minimize-via-artifact entry, decode_text_calls
//     and encode_text_calls remain at zero.
//
// What this oracle does NOT prove:
//   * Full C1 algorithm parity. It does not cover typed-graph
//     RelatedCalls, Call.Props, per-type arg minimization, or the
//     20-sample syzkaller golden oracle #24.

#include "refuzz/crash/repro/ops/linuxkernel/syz_ops/minimize/program_minimizer.hpp"
#include "refuzz/mutator/linux/syz_v2/engines/syz_v2_engine.hpp"
#include "refuzz/mutator/mutator_manager.hpp"
#include "refuzz/program/artifact.hpp"
#include "refuzz/program/artifact_materializer.hpp"
#include "refuzz/program/internal/codec_counters.hpp"
#include "refuzz/program/prog_format.hpp"
#include "refuzz/program/seed.hpp"
#include "refuzz/program/syz/target.hpp"

#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>
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

#define CHECK_EQ(a, b)                                                      \
    do {                                                                    \
        const auto av = (a);                                                \
        const auto bv = (b);                                                \
        if (av != bv) {                                                     \
            std::fprintf(stderr, "FAIL %s:%d: %s (%llu) == %s (%llu)\n",    \
                         __FILE__, __LINE__,                                \
                         #a, static_cast<unsigned long long>(av),           \
                         #b, static_cast<unsigned long long>(bv));          \
            std::abort();                                                   \
        }                                                                   \
    } while (0)

namespace cc = ::refuzz::program::codec_counters;

std::vector<std::uint8_t> GenerateProgBytes(uint64_t master_seed) {
    const auto& target = ::refuzz::program::syz::Target::linux_amd64();
    auto engine = std::make_unique<::refuzz::fuzzer::SyzV2MutatorEngine>(
        target, /*corpus_store=*/nullptr, master_seed);
    ::refuzz::fuzzer::MutatorManager manager;
    manager.AddEngine(std::move(engine), /*activate=*/true);
    ::refuzz::fuzzer::Seed empty;
    return manager.Handle().Get().Mutate(empty);
}

std::shared_ptr<const ::refuzz::program::ProgramArtifact>
BuildArtifact(const std::vector<std::uint8_t>& bytes) {
    ::refuzz::program::RegisterBuiltinArtifactMaterializers();
    const auto& t = ::refuzz::program::syz::Target::linux_amd64();
    ::refuzz::program::ProgramTargetKey key{t.os(), t.arch(), t.revision()};
    auto art_or = ::refuzz::program::MakeArtifactFromCanonicalPayload(
        ::refuzz::fuzzer::ProgFormat::kSyzProg, std::move(key), bytes);
    if (!art_or) return nullptr;
    return std::make_shared<const ::refuzz::program::ProgramArtifact>(
        std::move(art_or.value()));
}

::refuzz::crash::TestFunc MakeNoMatchTest() {
    return [](const std::vector<uint8_t>& /*payload*/)
        -> std::pair<bool, std::string> {
        return {false, std::string{}};
    };
}

::refuzz::crash::StopFunc MakeNeverStop() {
    return []() { return false; };
}

// ----- tests -----

// Oracle #21 — minimize artifact entry adds 0 text-codec calls beyond
// the artifact's pre-cached canonical materialization.
void TestArtifactEntryAddsNoTextCodecCalls() {
    auto bytes = GenerateProgBytes(/*master_seed=*/0xC011E + 1);
    CHECK(!bytes.empty());

    // The artifact build performs one decode_text (TextDecoder.decode
    // inside SyzV2Materializer); we count that BEFORE reset so the
    // post-reset counters reflect only the minimize entry path.
    auto artifact = BuildArtifact(bytes);
    CHECK(artifact != nullptr);
    CHECK(artifact->valid());

    cc::ResetForTest();

    ::refuzz::crash::ProgramMinimizer minimizer;
    auto test_fn = MakeNoMatchTest();
    auto stop_fn = MakeNeverStop();

    auto result = minimizer.Minimize(
        *artifact,
        std::move(test_fn),
        std::move(stop_fn),
        ::refuzz::crash::MinimizeMode::kCrash,
        /*guilty_call_index=*/-1);

    const auto counts = cc::ReadForTest();
    std::fprintf(stderr,
                 "  artifact entry: stage=%s | decode_text=%llu encode_text=%llu "
                 "decode_wire=%llu encode_wire=%llu\n",
                 result.minimize_stage.c_str(),
                 static_cast<unsigned long long>(counts.decode_text_calls),
                 static_cast<unsigned long long>(counts.encode_text_calls),
                 static_cast<unsigned long long>(counts.decode_wire_calls),
                 static_cast<unsigned long long>(counts.encode_wire_calls));

    // Acceptance: artifact entry path adds zero text-codec calls and
    // does exercise exec-wire serialization from the typed candidate.
    CHECK_EQ(counts.decode_text_calls, 0u);
    CHECK_EQ(counts.encode_text_calls, 0u);
    CHECK(counts.encode_wire_calls > 0u);
}

} // namespace

int main() {
    std::fprintf(stderr, "RUN  TestArtifactEntryAddsNoTextCodecCalls\n");
    TestArtifactEntryAddsNoTextCodecCalls();
    std::fprintf(stderr, "OK   TestArtifactEntryAddsNoTextCodecCalls\n");

    std::fprintf(stderr, "ALL OK\n");
    return 0;
}

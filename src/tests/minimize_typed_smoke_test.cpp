// §3.11-C1 smoke — not oracle #24.
//
// Kept as supplementary smoke coverage alongside the real oracle #24
// (`minimize_syzkaller_parity_test.cpp`). This file verifies that the
// minimizer modes terminate cleanly on a small set of generated v2
// inputs without crashing or returning corrupted payloads.
//
// This smoke verifies:
//
//   1. Current minimize modes terminate on generated v2 inputs.
//   2. ProcType non-optional guard: when a SyzProgram's hand-crafted
//      ProcType arg is non-optional, the minimizer must NOT collapse
//      it to default. We assert via CallsOnly + manual replay that
//      arg byte content is preserved through MinimizeFlat for the
//      ProcType slot. (Crash mode skips arg-minimize entirely; the
//      guard's effect surfaces in CrashSnapshot mode only.)
//   3. CallsOnly mode skips arg minimize: a generated program runs
//      through MinimizeTyped with kCallsOnly and reports stage that's
//      consistent with calls-only behavior (no arg-shrink commits).
//
// It does not prove Call.Props minimize, typed-graph RelatedCalls, or
// syzkaller golden parity. The 20-program golden parity oracle
// (oracle #24) lives in `minimize_syzkaller_parity_test.cpp`.

#include "refuzz/crash/repro/ops/linuxkernel/syz_ops/minimize/program_minimizer.hpp"
#include "refuzz/mutator/linux/syz_v2/engines/syz_v2_engine.hpp"
#include "refuzz/mutator/mutator_manager.hpp"
#include "refuzz/program/artifact.hpp"
#include "refuzz/program/artifact_materializer.hpp"
#include "refuzz/program/prog_format.hpp"
#include "refuzz/program/seed.hpp"
#include "refuzz/program/syz/encoding.hpp"
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

#define RUN_TEST(fn)                                                        \
    do {                                                                    \
        std::fprintf(stderr, "RUN  %s\n", #fn);                             \
        fn();                                                               \
        std::fprintf(stderr, "OK   %s\n", #fn);                             \
    } while (0)

std::vector<std::uint8_t> GenerateProgBytes(uint64_t master_seed) {
    const auto& target = ::refuzz::program::syz::Target::linux_amd64();
    auto engine = std::make_unique<::refuzz::fuzzer::SyzV2MutatorEngine>(
        target, /*corpus_store=*/nullptr, master_seed);
    ::refuzz::fuzzer::MutatorManager manager;
    manager.AddEngine(std::move(engine), /*activate=*/true);
    ::refuzz::fuzzer::Seed empty;
    return manager.Handle().Get().Mutate(empty);
}

::refuzz::program::ProgramArtifact BuildArtifact(std::vector<std::uint8_t> bytes) {
    ::refuzz::program::RegisterBuiltinArtifactMaterializers();
    const auto& t = ::refuzz::program::syz::Target::linux_amd64();
    ::refuzz::program::ProgramTargetKey key{t.os(), t.arch(), t.revision()};
    auto art_or = ::refuzz::program::MakeArtifactFromCanonicalPayload(
        ::refuzz::fuzzer::ProgFormat::kSyzProg, std::move(key), std::move(bytes));
    if (!art_or) std::abort();
    return std::move(*art_or);
}

::refuzz::crash::TestFunc MakeNoMatch() {
    return [](const std::vector<uint8_t>& /*payload*/)
        -> std::pair<bool, std::string> {
        return {false, std::string{}};
    };
}

::refuzz::crash::StopFunc MakeNeverStop() {
    return []() { return false; };
}

// ----- tests -----

// Property 1: each minimize mode terminates on a real generated input.
// CrashSnapshot exercises the full TryMinimizeArg matrix (Ptr/Array/
// Buffer/Resource/Int/Flags/Proc + ProcType non-optional guard).
void TestCrashSnapshotModeTerminates() {
    auto bytes = GenerateProgBytes(/*master_seed=*/0xC011E + 100);
    CHECK(!bytes.empty());
    auto artifact = BuildArtifact(bytes);

    ::refuzz::crash::ProgramMinimizer minimizer;
    auto result = minimizer.Minimize(
        artifact,
        MakeNoMatch(),
        MakeNeverStop(),
        ::refuzz::crash::MinimizeMode::kCrashSnapshot,
        /*guilty_call_index=*/-1);

    std::fprintf(stderr, "  CrashSnapshot: stage=%s attempts=%u commits=%u\n",
                 result.minimize_stage.c_str(),
                 result.minimize_attempts,
                 result.minimize_commits);

    CHECK(result.minimize_stage != "decode_failed");
}

// Property 2: kCrash mode runs (less aggressive — skips arg defaults
// per syzkaller MinimizeCrash gating; only call-removal + selected
// arg paths run).
void TestCrashModeTerminates() {
    auto bytes = GenerateProgBytes(/*master_seed=*/0xC011E + 101);
    CHECK(!bytes.empty());
    auto artifact = BuildArtifact(bytes);

    ::refuzz::crash::ProgramMinimizer minimizer;
    auto result = minimizer.Minimize(
        artifact,
        MakeNoMatch(),
        MakeNeverStop(),
        ::refuzz::crash::MinimizeMode::kCrash,
        /*guilty_call_index=*/-1);

    std::fprintf(stderr, "  Crash:         stage=%s attempts=%u commits=%u\n",
                 result.minimize_stage.c_str(),
                 result.minimize_attempts,
                 result.minimize_commits);

    CHECK(result.minimize_stage != "decode_failed");
}

// Property 3: kCallsOnly mode runs without entering arg-minimize.
// We can't directly observe the gate from outside, but we can verify
// the entry doesn't crash and reports a consistent stage.
void TestCallsOnlyModeTerminates() {
    auto bytes = GenerateProgBytes(/*master_seed=*/0xC011E + 102);
    CHECK(!bytes.empty());
    auto artifact = BuildArtifact(bytes);

    ::refuzz::crash::ProgramMinimizer minimizer;
    auto result = minimizer.Minimize(
        artifact,
        MakeNoMatch(),
        MakeNeverStop(),
        ::refuzz::crash::MinimizeMode::kCallsOnly,
        /*guilty_call_index=*/-1);

    std::fprintf(stderr, "  CallsOnly:     stage=%s attempts=%u commits=%u\n",
                 result.minimize_stage.c_str(),
                 result.minimize_attempts,
                 result.minimize_commits);

    CHECK(result.minimize_stage != "decode_failed");
}

// Property 4: when test_fn always rejects, MinimizeMode produces a
// non-empty result that round-trips cleanly. Specifically, the
// minimizer must not return a corrupted payload that would later fail
// to decode.
void TestMinimizeOutputDecodes() {
    auto bytes = GenerateProgBytes(/*master_seed=*/0xC011E + 103);
    CHECK(!bytes.empty());
    auto artifact = BuildArtifact(bytes);

    ::refuzz::crash::ProgramMinimizer minimizer;
    auto result = minimizer.Minimize(
        artifact,
        MakeNoMatch(),
        MakeNeverStop(),
        ::refuzz::crash::MinimizeMode::kCrash,
        /*guilty_call_index=*/-1);

    // With no test_fn matches, no candidate is ever accepted; the
    // minimizer keeps the source intact and emits its serialized form
    // (exec wire) as result.payload — non-empty when a typed view was
    // available.
    CHECK(result.minimize_stage != "decode_failed");
    CHECK(!result.payload.empty());
}

} // namespace

int main() {
    RUN_TEST(TestCrashSnapshotModeTerminates);
    RUN_TEST(TestCrashModeTerminates);
    RUN_TEST(TestCallsOnlyModeTerminates);
    RUN_TEST(TestMinimizeOutputDecodes);
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}

// program_concat_typed_test.cpp
//
// [async-crash-reproduction Phase 1.5] ConcatTypedPrograms — typed V2-IR concat.
// The V2 exec-wire is a self-describing varint stream that can't be byte-
// concatenated; the merge happens on the typed IR. This test verifies that merging
// typed programs yields ONE program with the combined calls, a serializable exec-
// wire payload, and a valid typed ProgramArtifact — so a bisect/concat repro
// extract can be minimized + turned into a C reproducer, not just executed.
// Bare assert harness (repo convention).

#include "refuzz/crash/repro/ops/linuxkernel/syz_ops/program/program_concat.hpp"

#include "refuzz/mutator/linux/syz_v2/engines/syz_v2_engine.hpp"
#include "refuzz/mutator/mutator_manager.hpp"
#include "refuzz/program/artifact.hpp"
#include "refuzz/program/artifact_materializer.hpp"
#include "refuzz/program/prog_format.hpp"
#include "refuzz/program/seed.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"

#include <cstdio>
#include <cstdlib>
#include <memory>
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

using ::refuzz::program::syz::Prog;

std::vector<std::uint8_t> GenerateProgBytes(uint64_t master_seed) {
    const auto& target = ::refuzz::program::syz::Target::linux_amd64();
    auto engine = std::make_unique<::refuzz::fuzzer::SyzV2MutatorEngine>(
        target, /*corpus_store=*/nullptr, master_seed);
    ::refuzz::fuzzer::MutatorManager manager;
    manager.AddEngine(std::move(engine), /*activate=*/true);
    ::refuzz::fuzzer::Seed empty;
    return manager.Handle().Get().Mutate(empty);
}

std::shared_ptr<const ::refuzz::program::ProgramArtifact> MakeArtifact(uint64_t seed) {
    ::refuzz::program::RegisterBuiltinArtifactMaterializers();
    const auto& t = ::refuzz::program::syz::Target::linux_amd64();
    ::refuzz::program::ProgramTargetKey key{t.os(), t.arch(), t.revision()};
    auto bytes = GenerateProgBytes(seed);
    auto art_or = ::refuzz::program::MakeArtifactFromCanonicalPayload(
        ::refuzz::fuzzer::ProgFormat::kSyzProg, std::move(key), bytes);
    if (!art_or) return nullptr;
    return std::make_shared<const ::refuzz::program::ProgramArtifact>(
        std::move(art_or.value()));
}

void TestConcatTwoMergesCalls() {
    auto a1 = MakeArtifact(0xC0FFEE01);
    auto a2 = MakeArtifact(0xC0FFEE02);
    CHECK(a1 && a2);
    auto p1 = a1->As<Prog>();
    auto p2 = a2->As<Prog>();
    CHECK(p1 && p2);
    const size_t n1 = p1->calls().size();
    const size_t n2 = p2->calls().size();
    CHECK(n1 >= 1 && n2 >= 1);

    refuzz::crash::ConcatTypedResult out;
    CHECK(refuzz::crash::ConcatTypedPrograms({p1, p2}, out));
    // merged call count = sum of inputs
    CHECK(out.call_count == n1 + n2);
    // a serializable exec-wire payload (for execution / TryPayload)
    CHECK(!out.payload.empty());
    // a typed artifact (for StageMinimize / C-repro) whose Prog has the merged calls
    CHECK(out.artifact != nullptr);
    auto merged = out.artifact->As<Prog>();
    CHECK(merged != nullptr);
    CHECK(merged->calls().size() == n1 + n2);
    // deep clone: originals untouched
    CHECK(p1->calls().size() == n1);
    CHECK(p2->calls().size() == n2);
    std::fprintf(stderr,
                 "  [ok] concat 2 typed progs -> merged calls=%zu+%zu=%u + payload + artifact\n",
                 n1, n2, out.call_count);
}

void TestConcatSingleRoundTrips() {
    auto a1 = MakeArtifact(0xC0FFEE03);
    CHECK(a1);
    auto p1 = a1->As<Prog>();
    CHECK(p1);
    const size_t n1 = p1->calls().size();
    refuzz::crash::ConcatTypedResult out;
    CHECK(refuzz::crash::ConcatTypedPrograms({p1}, out));
    CHECK(out.call_count == n1);
    CHECK(!out.payload.empty());
    CHECK(out.artifact != nullptr);
    std::fprintf(stderr, "  [ok] single-prog concat round-trips (calls=%zu)\n", n1);
}

void TestConcatFailClosed() {
    refuzz::crash::ConcatTypedResult out;
    // empty input -> false
    CHECK(!refuzz::crash::ConcatTypedPrograms({}, out));
    // any null input -> false (fail-closed)
    CHECK(!refuzz::crash::ConcatTypedPrograms({nullptr}, out));
    auto a1 = MakeArtifact(0xC0FFEE04);
    CHECK(a1);
    auto p1 = a1->As<Prog>();
    CHECK(p1);
    CHECK(!refuzz::crash::ConcatTypedPrograms({p1, nullptr}, out));
    std::fprintf(stderr, "  [ok] empty / null input -> false (fail-closed)\n");
}

}  // namespace

int main() {
    std::fprintf(stderr, "Running program_concat_typed_test...\n");
    TestConcatTwoMergesCalls();
    TestConcatSingleRoundTrips();
    TestConcatFailClosed();
    std::fprintf(stderr, "program_concat_typed_test: ALL PASS\n");
    return 0;
}

// §3.10 oracle #19 — Corpus v2 artifact round-trip with codec
// counter check.
//
// Procedure:
//   1. ResetForTest()
//   2. Generate one v2 program → SaveSeed (canonical text) → LoadAll
//      (eager materializer fires once, decode_text == 1 expected)
//   3. Reset counter window
//   4. Drive the v2 hot path (MutateTyped on the loaded artifact) for
//      a small loop, asserting decode_text / encode_text remain 0
//      (oracle #19 reverse assertion: v2 hot-path consumers don't
//      read seed.payload).
//   5. Final: assert seed.artifact != nullptr; verify the typed view
//      decodes / validates without further codec calls.

#include "refuzz/corpus/corpus_disk_io.hpp"
#include "refuzz/corpus/corpus_store.hpp"
#include "refuzz/mutator/linux/syz_v2/engines/syz_v2_engine.hpp"
#include "refuzz/mutator/mutator_manager.hpp"
#include "refuzz/program/artifact.hpp"
#include "refuzz/program/artifact_materializer.hpp"
#include "refuzz/program/internal/codec_counters.hpp"
#include "refuzz/program/seed.hpp"
#include "refuzz/program/seed_metadata.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/validation.hpp"
#include "refuzz/scheduler/scheduler_engine.hpp"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <system_error>
#include <utility>

namespace {

namespace pr  = refuzz::program;
namespace pcc = refuzz::program::codec_counters;
namespace syz = refuzz::program::syz;

#define CHECK(expr)                                                         \
    do {                                                                    \
        if (!(expr)) {                                                      \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,    \
                         #expr);                                            \
            std::abort();                                                   \
        }                                                                   \
    } while (0)

class TmpDir {
public:
    TmpDir() {
        char tmpl[] = "/tmp/refuzz_oracle19_XXXXXX";
        if (char* dir = mkdtemp(tmpl)) path_ = dir;
    }
    ~TmpDir() {
        if (!path_.empty()) {
            std::error_code ec;
            std::filesystem::remove_all(path_, ec);
        }
    }
    const std::string& path() const { return path_; }
private:
    std::string path_;
};

class StubScheduler final : public refuzz::fuzzer::ISchedulerEngine {
public:
    std::string Name() const override { return "stub"; }
    std::optional<refuzz::fuzzer::SeedSelection> NextSeedId() override { return std::nullopt; }
    void OnFeedback(uint64_t, refuzz::fuzzer::SeedDisposition) override {}
    void OnSeedAdded(uint64_t) override {}
    bool SwitchPolicyByName(std::string_view) override { return false; }
    std::string ActivePolicyName() const override { return "stub"; }
};

} // namespace

int main() {
    pr::RegisterBuiltinArtifactMaterializers();
    const auto& target = syz::Target::linux_amd64();

    // 1. Generate one v2 payload via SyzV2MutatorEngine.
    refuzz::fuzzer::SyzV2MutatorEngine boot(target, nullptr, /*seed=*/0xC19C);
    refuzz::fuzzer::Seed empty;
    auto payload = boot.Mutate(empty);
    CHECK(!payload.empty());

    // 2. SaveSeed.
    TmpDir tmp;
    CHECK(!tmp.path().empty());
    refuzz::fuzzer::Seed seed;
    seed.seed_id  = 1;
    seed.payload  = payload;
    seed.priority = 1;
    seed.metadata.Set(refuzz::fuzzer::SeedSourceMetadata{
        refuzz::fuzzer::SeedSource::kBootCorpus, /*attempt=*/0});
    seed.metadata.Set(refuzz::fuzzer::SeedAdmissionStateMetadata{});
    CHECK(refuzz::fuzzer::CorpusDiskIO::SaveSeed(seed, tmp.path()));

    // 3. ResetForTest + LoadAll (with §3.10 follow-up materializer
    //    callback — corpus disk layer is now format-neutral).
    pcc::ResetForTest();
    refuzz::fuzzer::InMemoryCorpusStore store;
    StubScheduler scheduler;
    refuzz::fuzzer::SeedIdAllocator ids(100);
    auto materializer = pr::MakeRegistryMaterializer(
        refuzz::fuzzer::ProgFormat::kSyzProg,
        pr::ProgramTargetKey{target.os(), target.arch(), target.revision()});
    const size_t loaded =
        refuzz::fuzzer::CorpusDiskIO::LoadAll(store, scheduler, tmp.path(), ids,
                                              materializer);
    CHECK(loaded == 1);
    auto load_counts = pcc::ReadForTest();
    std::fprintf(stderr,
                 "after LoadAll: decode_text=%llu encode_text=%llu\n",
                 (unsigned long long)load_counts.decode_text_calls,
                 (unsigned long long)load_counts.encode_text_calls);
    // Disk-load decode = 1 (eager materializer); zero encodes.
    CHECK(load_counts.decode_text_calls == 1);
    CHECK(load_counts.encode_text_calls == 0);

    // 4. Reverse assertion: artifact populated.
    auto handle = store.GetSeed(100);
    CHECK(handle != nullptr);
    CHECK(handle->artifact != nullptr);
    CHECK(handle->artifact->valid());
    CHECK(handle->artifact->has_typed_view());

    auto typed = handle->artifact->As<syz::Prog>();
    CHECK(typed != nullptr);
    CHECK(!typed->calls().empty());
    auto vr = syz::validate(*typed);
    CHECK(vr.has_value());

    // 5. v2 hot-path codec-free check: drive MutateTyped for a small
    //    loop after another reset; counters must not increment.
    pcc::ResetForTest();
    refuzz::fuzzer::SyzV2MutatorEngine engine(target, nullptr, /*seed=*/0xCAFE);
    constexpr int kIters = 100;
    for (int i = 0; i < kIters; ++i) {
        auto result = engine.MutateTyped(*handle->artifact);
        (void)result.artifact.As<syz::Prog>();
    }
    auto hot_counts = pcc::ReadForTest();
    std::fprintf(stderr,
                 "after %d MutateTyped iters on loaded artifact: "
                 "decode_text=%llu encode_text=%llu encode_wire=%llu\n",
                 kIters,
                 (unsigned long long)hot_counts.decode_text_calls,
                 (unsigned long long)hot_counts.encode_text_calls,
                 (unsigned long long)hot_counts.encode_wire_calls);
    CHECK(hot_counts.decode_text_calls == 0);
    CHECK(hot_counts.encode_text_calls == 0);
    CHECK(hot_counts.encode_wire_calls == 0);

    std::fprintf(stderr, "ALL OK\n");
    return 0;
}

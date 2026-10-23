// Copyright 2026 reFuzz project author -------youngkk.
//
// Epic 6 PR-6-D — corpus admit gate refuses FailNth > 0 seeds.
//
// Mirror of upstream `pkg/manager/seeds.go:289-293`:
//
//     for _, call := range p.Calls {
//         if call.Props.FailNth > 0 {
//             return nil, nil, fmt.Errorf("input has fail_nth > 0")
//         }
//     }
//
// **Architectural note (post-review)**: the gate lives in the syz-owned
// `SyzV2Materializer::BuildFromCanonicalPayload` (program/src/syz/
// artifact_materializer.cpp), NOT in `corpus_disk_io.cpp`. Corpus is
// IR-blind per artifact.hpp:111 D2 contract — only syz-owned modules
// (mutator engines, repro/minimize helpers, **materializers**) may call
// `ProgramArtifact::As<syz::Prog>()`. The materializer returns
// `MaterializeError` on FailNth>0 → corpus loader's existing StrictTyped
// fail-closed path (corpus_disk_io.cpp:289-296) drops the seed without
// any IR knowledge.
//
// Plan §3 D-11 + §6.1 #10. 3 harness cases drive the loader through the
// real production materializer (`MakeRegistryMaterializer`) so the test
// exercises the actual D2-respecting wiring:
//   1. CleanProgAdmitted: corpus dir holds 1 clean (FailNth=0) syz prog →
//      materializer succeeds, LoadAll admits 1 seed.
//   2. FailNthBearingProgRejected: corpus dir holds 1 prog with
//      `(fail_nth: 5)` → materializer returns MaterializeError →
//      corpus loader StrictTyped drops it, store stays empty.
//   3. NonSyzPassThrough: bytes-only seed with no materializer +
//      LenientBytes policy passes (gate is syz-format-specific; other
//      formats have no CallProps concept).

#include "refuzz/corpus/corpus_disk_io.hpp"
#include "refuzz/corpus/corpus_store.hpp"
#include "refuzz/corpus/seed_id_allocator.hpp"
#include "refuzz/program/artifact.hpp"
#include "refuzz/program/artifact_materializer.hpp"
#include "refuzz/program/seed.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/scheduler/scheduler_engine.hpp"

#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
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

namespace fs   = std::filesystem;
namespace pr   = ::refuzz::program;
namespace syz  = ::refuzz::program::syz;
namespace fuzz = ::refuzz::fuzzer;

class StubScheduler final : public fuzz::ISchedulerEngine {
public:
    int seed_added_calls = 0;
    std::string Name() const override { return "stub"; }
    std::optional<refuzz::fuzzer::SeedSelection> NextSeedId() override { return std::nullopt; }
    void OnFeedback(std::uint64_t, fuzz::SeedDisposition) override {}
    void OnSeedAdded(std::uint64_t /*seed_id*/) override { ++seed_added_calls; }
    bool SwitchPolicyByName(std::string_view) override { return true; }
    std::string ActivePolicyName() const override { return "stub"; }
};

// Production materializer wired via the registry — exercises the real
// D2-respecting path: corpus loader sees only the opaque
// ArtifactMaterializerFn callable, materialization (and FailNth gating)
// happens inside SyzV2Materializer.
pr::ArtifactMaterializerFn ProductionSyzMaterializer()
{
    const auto& tgt = syz::Target::linux_amd64();
    pr::ProgramTargetKey key{tgt.os(), tgt.arch(), tgt.revision()};
    return pr::MakeRegistryMaterializer(
        refuzz::fuzzer::ProgFormat::kSyzProg, std::move(key));
}

fs::path WritePayload(const fs::path& root, std::uint64_t hex_id,
                      std::string_view content)
{
    char hex[17];
    std::snprintf(hex, sizeof(hex), "%016lx",
                  static_cast<unsigned long>(hex_id));
    fs::path dir = root / hex;
    fs::create_directories(dir);
    fs::path payload_path = dir / "payload.bin";
    {
        std::ofstream f(payload_path, std::ios::binary);
        f.write(content.data(), static_cast<std::streamsize>(content.size()));
    }
    return payload_path;
}

void CleanupTempDir(const fs::path& root)
{
    std::error_code ec;
    fs::remove_all(root, ec);
}

fs::path UniqueTempDir(const std::string& tag)
{
    auto pid = static_cast<unsigned long>(::getpid());
    fs::path root = fs::temp_directory_path() / ("refuzz_pr6d_" + tag + "_" +
                                                 std::to_string(pid));
    CleanupTempDir(root);
    fs::create_directories(root);
    return root;
}

void TestCleanProgAdmitted()
{
    fs::path root = UniqueTempDir("clean");
    WritePayload(root, /*hex_id=*/0x1, "getpid()\n");

    fuzz::InMemoryCorpusStore store;
    StubScheduler scheduler;
    fuzz::SeedIdAllocator alloc;
    const size_t loaded = fuzz::CorpusDiskIO::LoadAll(
        store, scheduler, root.string(), alloc, ProductionSyzMaterializer(),
        fuzz::CorpusLoadPolicy::StrictTyped);

    CHECK(loaded                        == 1);
    CHECK(store.Size()                  == 1);
    CHECK(scheduler.seed_added_calls    == 1);
    CleanupTempDir(root);
}

void TestFailNthBearingProgRejected()
{
    fs::path root = UniqueTempDir("rejected");
    WritePayload(root, /*hex_id=*/0x2, "getpid() (fail_nth: 5)\n");

    fuzz::InMemoryCorpusStore store;
    StubScheduler scheduler;
    fuzz::SeedIdAllocator alloc;
    const size_t loaded = fuzz::CorpusDiskIO::LoadAll(
        store, scheduler, root.string(), alloc, ProductionSyzMaterializer(),
        fuzz::CorpusLoadPolicy::StrictTyped);

    // Gate fired — seed dropped, store + scheduler untouched.
    CHECK(loaded                     == 0);
    CHECK(store.Size()               == 0);
    CHECK(scheduler.seed_added_calls == 0);
    CleanupTempDir(root);
}

void TestNonSyzSeedPassThrough()
{
    // bytes-only seed (no materializer + LenientBytes policy) → no typed
    // artifact, gate is a no-op (FailNth is a syz-target concept).
    fs::path root = UniqueTempDir("non_syz");
    WritePayload(root, /*hex_id=*/0x3, "arbitrary bytes for non-syz target");

    fuzz::InMemoryCorpusStore store;
    StubScheduler scheduler;
    fuzz::SeedIdAllocator alloc;
    const size_t loaded = fuzz::CorpusDiskIO::LoadAll(
        store, scheduler, root.string(), alloc,
        /*materializer=*/{},  // none
        fuzz::CorpusLoadPolicy::LenientBytes);

    CHECK(loaded                     == 1);
    CHECK(store.Size()               == 1);
    CHECK(scheduler.seed_added_calls == 1);
    CleanupTempDir(root);
}

}  // namespace

int main()
{
    pr::RegisterBuiltinArtifactMaterializers();
    RUN_TEST(TestCleanProgAdmitted);
    RUN_TEST(TestFailNthBearingProgRejected);
    RUN_TEST(TestNonSyzSeedPassThrough);
    std::fprintf(stderr, "ALL OK\n");
    return 0;
}

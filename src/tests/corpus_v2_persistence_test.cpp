// §3.9 Corpus pool migration — v2 IR round-trip test.
//
// Verifies "imported / grown / crashed pools all read/write v2 IR" by:
//   1. Generate one program via SyzV2MutatorEngine (canonical .syz text).
//   2. Save it through CorpusDiskIO::SaveSeed (raw bytes + metadata sidecar).
//   3. Reload via CorpusDiskIO::LoadAll.
//   4. Decode the reloaded payload through TextDecoder → syz::Prog.
//   5. Run validation pass — must succeed.
//
// Plus a crash-repro variant exercising LoadCrashRepros path
// (`<diag>/<bucket>/<id>/prog0.bin`) over the same v2 payload.

#include "refuzz/corpus/corpus_disk_io.hpp"
#include "refuzz/corpus/corpus_store.hpp"
#include "refuzz/mutator/linux/syz_v2/engines/syz_v2_engine.hpp"
#include "refuzz/mutator/mutator_manager.hpp"
#include "refuzz/program/artifact_materializer.hpp"   // §3.10 follow-up
#include "refuzz/program/seed.hpp"
#include "refuzz/program/seed_metadata.hpp"
#include "refuzz/program/syz/encoding.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/validation.hpp"
#include "refuzz/scheduler/scheduler_engine.hpp"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <ios>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace {

class TmpDir {
public:
    TmpDir()
    {
        char tmpl[] = "/tmp/refuzz_corpus_v2_XXXXXX";
        if (char* dir = mkdtemp(tmpl)) {
            path_ = dir;
        }
    }
    ~TmpDir()
    {
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
    void OnSeedAdded(uint64_t) override { ++added; }
    bool SwitchPolicyByName(std::string_view) override { return false; }
    std::string ActivePolicyName() const override { return "stub"; }
    int added = 0;
};

// Generate one v2 IR text payload via the engine.
std::vector<uint8_t> GenerateV2Payload()
{
    namespace syz = refuzz::program::syz;
    const auto& target = syz::Target::linux_amd64();
    auto engine = std::make_unique<refuzz::fuzzer::SyzV2MutatorEngine>(
        target,
        /*corpus_store=*/nullptr,
        /*master_seed=*/12345);
    refuzz::fuzzer::MutatorManager manager;
    manager.AddEngine(std::move(engine), /*activate=*/true);
    refuzz::fuzzer::Seed empty;
    return manager.Handle().Get().Mutate(empty);
}

// §3.10 follow-up — build a registry-driven materializer for syz_v2 /
// linux-amd64. The corpus disk layer now requires the caller to
// supply this callback; bytes-only fallback when omitted.
::refuzz::program::ArtifactMaterializerFn MakeSyzV2Materializer() {
    namespace pr  = ::refuzz::program;
    namespace syz = ::refuzz::program::syz;
    const auto& t = syz::Target::linux_amd64();
    return pr::MakeRegistryMaterializer(
        ::refuzz::fuzzer::ProgFormat::kSyzProg,
        pr::ProgramTargetKey{t.os(), t.arch(), t.revision()});
}

// Decode + validate the loaded payload to confirm it survived as v2 IR.
bool DecodeAndValidate(const std::vector<uint8_t>& payload)
{
    namespace syz = refuzz::program::syz;
    if (payload.empty()) return false;
    const auto& target = syz::Target::linux_amd64();
    syz::TextDecoder decoder(target);
    const std::string_view text(reinterpret_cast<const char*>(payload.data()),
                                payload.size());
    auto decoded = decoder.decode(text);
    if (!decoded.has_value() || !decoded.value()) return false;
    auto& prog = *decoded.value();
    if (prog.calls().empty()) return false;
    auto vr = syz::validate(prog);
    return vr.has_value();
}

bool TestImportedV2Pool()
{
    TmpDir tmp;
    assert(!tmp.path().empty());

    auto payload = GenerateV2Payload();
    assert(!payload.empty());
    assert(DecodeAndValidate(payload));  // sanity: engine output is valid v2

    refuzz::fuzzer::Seed seed;
    seed.seed_id = 42;
    seed.payload = payload;
    seed.priority = 1;
    seed.metadata.Set(refuzz::fuzzer::SeedSourceMetadata{
        refuzz::fuzzer::SeedSource::kBootCorpus, /*attempt=*/0});
    seed.metadata.Set(refuzz::fuzzer::SeedAdmissionStateMetadata{});
    assert(refuzz::fuzzer::CorpusDiskIO::SaveSeed(seed, tmp.path()));

    refuzz::fuzzer::InMemoryCorpusStore store;
    StubScheduler scheduler;
    refuzz::fuzzer::SeedIdAllocator ids(100);
    const size_t loaded =
        refuzz::fuzzer::CorpusDiskIO::LoadAll(store, scheduler, tmp.path(), ids,
                                              MakeSyzV2Materializer());
    assert(loaded == 1);
    assert(scheduler.added == 1);

    auto handle = store.GetSeed(100);
    assert(handle != nullptr);
    assert(handle->payload == payload);  // raw bytes byte-equal post-RT
    assert(DecodeAndValidate(handle->payload));  // still parses as valid v2 IR

    // §3.10 step 4 — D6 reverse assertion: v2-loaded seed carries a
    // populated artifact + typed view. The full oracle #19 (with
    // codec_counter check) lives in step 9; this is the structural form.
    assert(handle->artifact != nullptr);
    assert(handle->artifact->valid());
    assert(handle->artifact->has_typed_view());
    auto typed = handle->artifact->As<refuzz::program::syz::Prog>();
    assert(typed != nullptr);
    assert(!typed->calls().empty());
    return true;
}

bool TestCrashReproV2Pool()
{
    TmpDir tmp;
    assert(!tmp.path().empty());

    // Layout matches LoadCrashRepros: <diag>/<bucket>/<id>/prog0.bin.
    namespace fs = std::filesystem;
    const fs::path bucket_dir = fs::path(tmp.path()) / "kernel_crash" /
                                "00000000000000ab";
    fs::create_directories(bucket_dir);

    auto payload = GenerateV2Payload();
    assert(!payload.empty());
    {
        std::ofstream out(bucket_dir / "prog0.bin", std::ios::binary);
        out.write(reinterpret_cast<const char*>(payload.data()),
                  static_cast<std::streamsize>(payload.size()));
    }

    refuzz::fuzzer::InMemoryCorpusStore store;
    StubScheduler scheduler;
    refuzz::fuzzer::SeedIdAllocator ids(200);
    const size_t loaded = refuzz::fuzzer::CorpusDiskIO::LoadCrashRepros(
        store, scheduler, tmp.path(), ids, MakeSyzV2Materializer());
    assert(loaded == 1);

    auto handle = store.GetSeed(200);
    assert(handle != nullptr);
    assert(handle->payload == payload);
    assert(DecodeAndValidate(handle->payload));

    // §3.10 step 4 — same artifact-authoritative invariant on the
    // crash-repro pool path.
    assert(handle->artifact != nullptr);
    assert(handle->artifact->valid());
    return true;
}

} // namespace

int main()
{
    ::refuzz::program::RegisterBuiltinArtifactMaterializers();

    std::fprintf(stdout, "Running corpus_v2_persistence_test...\n");
    if (!TestImportedV2Pool()) {
        std::fprintf(stderr, "TestImportedV2Pool FAILED\n");
        return 1;
    }
    if (!TestCrashReproV2Pool()) {
        std::fprintf(stderr, "TestCrashReproV2Pool FAILED\n");
        return 1;
    }
    std::fprintf(stdout, "PASS\n");
    return 0;
}

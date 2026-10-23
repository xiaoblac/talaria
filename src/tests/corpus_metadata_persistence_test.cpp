#include "refuzz/corpus/corpus_disk_io.hpp"
#include "refuzz/corpus/corpus_store.hpp"
#include "refuzz/program/seed_metadata.hpp"
#include "util/json.hpp"  // [v2 batch 3 PR-W3] JSON 字段断言

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>

namespace {

class TmpDir {
public:
    TmpDir()
    {
        char tmpl[] = "/tmp/refuzz_corpus_meta_XXXXXX";
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

bool TestMetadataRoundTrip()
{
    TmpDir tmp;
    assert(!tmp.path().empty());

    refuzz::fuzzer::Seed seed;
    seed.seed_id = 42;
    seed.payload = {1, 2, 3};
    seed.priority = 7;
    seed.interesting_hits = 9;
    refuzz::fuzzer::TriageStableSignalMetadata stable_meta;
    stable_meta.hashes = {0x101, 0x202};
    stable_meta.guilty_call_index = 0;
    stable_meta.guilty_call_hashes = {0x101};
    stable_meta.exec_status = refuzz::proto::ResultCode::kOk;
    stable_meta.guilty_errno_value = 0;
    stable_meta.guilty_syscall_id = 55;
    seed.metadata.Set(std::move(stable_meta));
    refuzz::fuzzer::SeedAuditMetadata audit;
    audit.target = "linux/amd64";
    audit.origin = "triage";
    audit.crash_title = "KASAN: test";
    audit.coverage_hashes = {0x303};
    audit.pseudo_trace = {"syz_emit_ethernet"};
    audit.unsupported_features = {"pseudo.unsupported"};
    seed.metadata.Set(std::move(audit));
    // [v2 batch 3 PR-W3] write 路径需要显式 set SeedSourceMetadata,否则 writer 不写。
    seed.metadata.Set(refuzz::fuzzer::SeedSourceMetadata{
        refuzz::fuzzer::SeedSource::kMutation, /*attempt=*/3});
    seed.metadata.Set(refuzz::fuzzer::SeedAdmissionStateMetadata{});

    assert(refuzz::fuzzer::CorpusDiskIO::SaveSeed(seed, tmp.path()));
    assert(std::filesystem::exists(
        std::filesystem::path(tmp.path()) / "000000000000002a" / "metadata.json"));

    // [v2 batch 3 PR-W3] 直接读 metadata.json 验 schema 字面等价(JSON 字段名 / 值
    // 格式没改;byte-equal invariant 靠 schema,vector-of-Entry 顺序不影响 dump)。
    {
        std::ifstream in(std::filesystem::path(tmp.path()) / "000000000000002a" / "metadata.json");
        assert(in);
        nlohmann::json root;
        in >> root;
        assert(root.is_object());
        assert(root.contains("seed_source"));
        assert(root["seed_source"].is_object());
        assert(root["seed_source"]["source"] == "mutation");
        assert(root["seed_source"]["attempt"] == 3u);
        assert(root.contains("seed_admission_state"));
        assert(root["seed_admission_state"].is_object());
        assert(root["seed_admission_state"]["state"] == "active");
        assert(root.contains("triage_stable_signal"));
        assert(root["triage_stable_signal"]["hashes"].is_array());
        assert(root["triage_stable_signal"]["guilty_call_index"] == 0);
        assert(root["triage_stable_signal"]["guilty_call_hashes"].is_array());
        assert(root["triage_stable_signal"]["exec_status"] == 0);
        assert(root["triage_stable_signal"]["guilty_errno_value"] == 0);
        assert(root["triage_stable_signal"]["guilty_syscall_id"] == 55u);
        assert(root.contains("audit"));
        assert(root["audit"]["target"] == "linux/amd64");
    }

    refuzz::fuzzer::InMemoryCorpusStore store;
    StubScheduler scheduler;
    refuzz::fuzzer::SeedIdAllocator ids(100);
    assert(refuzz::fuzzer::CorpusDiskIO::LoadAll(store, scheduler, tmp.path(), ids) == 1);
    assert(scheduler.added == 1);

    auto loaded = store.GetSeed(100);
    assert(loaded != nullptr);
    assert(loaded->priority == 7);
    assert(loaded->interesting_hits == 9);
    const auto* stable = loaded->metadata.Get<refuzz::fuzzer::TriageStableSignalMetadata>();
    assert(stable != nullptr);
    assert((stable->hashes == std::vector<uint64_t>{0x101, 0x202}));
    assert(stable->guilty_call_index == 0);
    assert((stable->guilty_call_hashes == std::vector<uint64_t>{0x101}));
    assert(stable->exec_status.has_value());
    assert(*stable->exec_status == refuzz::proto::ResultCode::kOk);
    assert(stable->guilty_errno_value.has_value());
    assert(*stable->guilty_errno_value == 0);
    assert(stable->guilty_syscall_id.has_value());
    assert(*stable->guilty_syscall_id == 55);
    const auto* loaded_audit = loaded->metadata.Get<refuzz::fuzzer::SeedAuditMetadata>();
    assert(loaded_audit != nullptr);
    assert(loaded_audit->target == "linux/amd64");
    assert(loaded_audit->crash_title == "KASAN: test");
    assert((loaded_audit->coverage_hashes == std::vector<uint64_t>{0x303}));
    assert((loaded_audit->pseudo_trace == std::vector<std::string>{"syz_emit_ethernet"}));
    // [v2 batch 3 PR-W3] SeedSourceMetadata round-trip 验证。
    const auto* loaded_src = loaded->metadata.Get<refuzz::fuzzer::SeedSourceMetadata>();
    assert(loaded_src != nullptr);
    assert(loaded_src->source == refuzz::fuzzer::SeedSource::kMutation);
    assert(loaded_src->attempt == 3);
    return true;
}

bool TestMissingSidecarLegacyMigration()
{
    TmpDir tmp;
    assert(!tmp.path().empty());

    namespace fs = std::filesystem;
    const fs::path seed_dir = fs::path(tmp.path()) / "0000000000000007";
    fs::create_directories(seed_dir);

    {
        std::ofstream payload_out(seed_dir / "payload.bin", std::ios::binary);
        payload_out.write("\x42\x42", 2);
    }

    refuzz::fuzzer::InMemoryCorpusStore store;
    StubScheduler scheduler;
    refuzz::fuzzer::SeedIdAllocator ids(200);
    assert(refuzz::fuzzer::CorpusDiskIO::LoadAll(store, scheduler, tmp.path(), ids) == 1);

    auto loaded = store.GetSeed(200);
    assert(loaded != nullptr);
    const auto* src = loaded->metadata.Get<refuzz::fuzzer::SeedSourceMetadata>();
    assert(src != nullptr);
    assert(src->source == refuzz::fuzzer::SeedSource::kBootCorpus);
    assert(src->attempt == 0);
    const auto* admit =
        loaded->metadata.Get<refuzz::fuzzer::SeedAdmissionStateMetadata>();
    assert(admit != nullptr);
    assert(admit->state == refuzz::fuzzer::SeedAdmissionState::kActive);
    return true;
}

bool TestBadMetadataDropsSeed()
{
    TmpDir tmp;
    assert(!tmp.path().empty());

    namespace fs = std::filesystem;
    const fs::path seed_dir = fs::path(tmp.path()) / "0000000000000008";
    fs::create_directories(seed_dir);

    {
        std::ofstream payload_out(seed_dir / "payload.bin", std::ios::binary);
        payload_out.write("\x42\x42", 2);
    }
    {
        std::ofstream meta_out(seed_dir / "metadata.json");
        meta_out << R"({
            "schema_version": 1,
            "seed_id": 8,
            "priority": 1,
            "interesting_hits": 0,
            "seed_source": {"source": "not_a_source", "attempt": 0},
            "seed_admission_state": {"state": "active", "inactive_reason": "", "verify_attempts": 0}
        })";
    }

    refuzz::fuzzer::InMemoryCorpusStore store;
    StubScheduler scheduler;
    refuzz::fuzzer::SeedIdAllocator ids(300);
    assert(refuzz::fuzzer::CorpusDiskIO::LoadAll(store, scheduler, tmp.path(), ids) == 0);
    assert(store.Size() == 0);
    assert(scheduler.added == 0);
    return true;
}

} // namespace

int main()
{
    std::fprintf(stdout, "Running corpus_metadata_persistence_test...\n");
    if (!TestMetadataRoundTrip()) {
        std::fprintf(stderr, "  TestMetadataRoundTrip FAIL\n");
        return 1;
    }
    if (!TestMissingSidecarLegacyMigration()) {
        std::fprintf(stderr, "  TestMissingSidecarLegacyMigration FAIL\n");
        return 1;
    }
    if (!TestBadMetadataDropsSeed()) {
        std::fprintf(stderr, "  TestBadMetadataDropsSeed FAIL\n");
        return 1;
    }
    return 0;
}

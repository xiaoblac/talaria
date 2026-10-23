// xiuos_wire_corpus_loader_test.cpp
//
// XiUOS canonical corpus smoke without QEMU. The modular orchestrator path
// loads pre-encoded wire bytes from <seed>/payload.bin via CorpusDiskIO, not
// JSON descriptor files through XiuosFuzzSession::Bootstrap.

#include "refuzz/corpus/corpus_disk_io.hpp"
#include "refuzz/corpus/corpus_store.hpp"
#include "refuzz/program/xiuos/xiuos_program.hpp"
#include "refuzz/scheduler/scheduler_engine.hpp"

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace {

class TmpDir {
public:
    TmpDir()
    {
        char tmpl[] = "/tmp/refuzz_xiuos_wire_corpus_XXXXXX";
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

class TrackingScheduler final : public refuzz::fuzzer::ISchedulerEngine {
public:
    std::string Name() const override { return "tracking"; }
    std::optional<refuzz::fuzzer::SeedSelection> NextSeedId() override
    {
        if (next_index_ >= added_ids_.size()) {
            return std::nullopt;
        }
        return refuzz::fuzzer::SeedSelection{added_ids_[next_index_++]};
    }
    void OnFeedback(std::uint64_t, refuzz::fuzzer::SeedDisposition) override {}
    void OnSeedAdded(std::uint64_t seed_id) override { added_ids_.push_back(seed_id); }
    bool SwitchPolicyByName(std::string_view) override { return false; }
    std::string ActivePolicyName() const override { return "tracking"; }

    const std::vector<std::uint64_t>& added_ids() const { return added_ids_; }

private:
    std::vector<std::uint64_t> added_ids_;
    std::size_t next_index_ = 0;
};

std::vector<std::uint8_t> MakeWirePayload()
{
    namespace xiuos = refuzz::program::xiuos;

    std::vector<xiuos::XiuosProgramCall> calls;
    xiuos::XiuosProgramCall create{};
    create.api_id = xiuos::XiuosApiId::SemCreate;
    create.argc = 2;
    create.args[0] = 0;
    create.args[1] = 1;
    calls.push_back(create);

    xiuos::XiuosProgramCall destroy{};
    destroy.api_id = xiuos::XiuosApiId::SemDelete;
    destroy.argc = 1;
    destroy.args[0] = 0;
    calls.push_back(destroy);

    return xiuos::XiuosEncodeProgram(
        std::span<const xiuos::XiuosProgramCall>(calls.data(), calls.size()),
        xiuos::XiuosSuiteId::CommonKernel,
        /*flags=*/0);
}

void WriteCanonicalPayload(const std::filesystem::path& root,
                           const std::string& seed_dir,
                           const std::vector<std::uint8_t>& payload)
{
    namespace fs = std::filesystem;
    const fs::path dir = root / seed_dir;
    fs::create_directories(dir);
    std::ofstream out(dir / "payload.bin", std::ios::binary | std::ios::trunc);
    assert(out);
    out.write(reinterpret_cast<const char*>(payload.data()),
              static_cast<std::streamsize>(payload.size()));
}

}  // namespace

int main()
{
    std::fprintf(stdout, "Running xiuos_wire_corpus_loader_test...\n");

    TmpDir tmp;
    assert(!tmp.path().empty());

    const auto payload = MakeWirePayload();
    assert(!payload.empty());
    WriteCanonicalPayload(tmp.path(), "0123456789abcdef", payload);

    refuzz::fuzzer::InMemoryCorpusStore store;
    TrackingScheduler scheduler;
    refuzz::fuzzer::SeedIdAllocator ids(/*start=*/7000);

    const auto loaded = refuzz::fuzzer::CorpusDiskIO::LoadAll(
        store,
        scheduler,
        tmp.path(),
        ids,
        /*materializer=*/{},
        refuzz::fuzzer::CorpusLoadPolicy::LenientBytes);

    assert(loaded == 1);
    assert(store.Size() == 1);
    assert(scheduler.added_ids().size() == 1);
    assert(scheduler.added_ids()[0] == 7000);
    assert(ids.Peek() == 7001);

    const auto seed = store.GetSeed(7000);
    assert(seed != nullptr);
    assert(seed->seed_id == 7000);
    assert(seed->payload == payload);
    assert(seed->artifact == nullptr);

    const auto next = scheduler.NextSeedId();
    assert(next.has_value());
    assert(next->seed_id == 7000);

    return 0;
}

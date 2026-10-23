// boot_inactive_seed_skips_scheduler_test.cpp
//
// [v2 batch 3 G6] CorpusDiskIO::LoadAll 对 SeedAdmissionState=kInactive seed
// 的处理:
//   - **AddSeed 仍调**(physical 保留 supports audit / 后续 GC / future reactivate)
//   - **scheduler.OnSeedAdded 跳过**(inactive seed 不进 scheduler pool,
//     NextSeedId 永远不返该 id)
//   - active seed(或 missing metadata 默认 active)走原 path
//
// 测试场景:
//   写 3 个 seed 目录到 temp corpus dir:
//     - seed_a (no metadata.json)         → active(legacy migration)
//     - seed_b (metadata.json: state=active)  → active
//     - seed_c (metadata.json: state=inactive) → physical AddSeed,scheduler skip
//   LoadAll → 验:
//     - corpus.Size() == 3(三个 seed 都 AddSeed 成功)
//     - mock scheduler.OnSeedAdded 调用次数 == 2(只 a + b)
//     - mock scheduler 收到的 id 集合不含 seed_c 的 id

#include "refuzz/corpus/corpus_disk_io.hpp"
#include "refuzz/corpus/corpus_store.hpp"
#include "refuzz/corpus/seed_id_allocator.hpp"
#include "refuzz/program/seed_metadata.hpp"
#include "refuzz/program/seed_metadata_serde.hpp"
#include "refuzz/scheduler/scheduler_engine.hpp"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

namespace fs = std::filesystem;

namespace {

using refuzz::fuzzer::CorpusDiskIO;
using refuzz::fuzzer::CorpusLoadPolicy;
using refuzz::fuzzer::InMemoryCorpusStore;
using refuzz::fuzzer::ISchedulerEngine;
using refuzz::fuzzer::SeedAdmissionState;
using refuzz::fuzzer::SeedAdmissionStateMetadata;
using refuzz::fuzzer::SeedDisposition;
using refuzz::fuzzer::SeedIdAllocator;

// 跟踪 OnSeedAdded 调用的 mock scheduler。
class TrackingScheduler final : public ISchedulerEngine {
public:
    std::string Name() const override { return "tracking"; }
    std::optional<refuzz::fuzzer::SeedSelection> NextSeedId() override { return std::nullopt; }
    void OnFeedback(std::uint64_t, SeedDisposition) override {}
    void OnSeedAdded(std::uint64_t seed_id) override {
        added_ids_.insert(seed_id);
    }
    bool SwitchPolicyByName(std::string_view) override { return false; }
    std::string ActivePolicyName() const override { return "tracking"; }

    const std::unordered_set<std::uint64_t>& added_ids() const { return added_ids_; }

private:
    std::unordered_set<std::uint64_t> added_ids_;
};

std::string Hex16(std::uint64_t value)
{
    std::ostringstream oss;
    oss << std::hex << std::setfill('0') << std::setw(16) << value;
    return oss.str();
}

// 写一个 seed 目录(payload.bin + 可选 metadata.json)。
void WriteSeedDir(const fs::path& corpus_dir,
                  std::uint64_t synthetic_id,
                  const std::vector<std::uint8_t>& payload,
                  const std::string& metadata_json = "")
{
    const fs::path dir = corpus_dir / Hex16(synthetic_id);
    fs::create_directories(dir);

    {
        std::ofstream out(dir / "payload.bin", std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(payload.data()),
                  static_cast<std::streamsize>(payload.size()));
    }
    if (!metadata_json.empty()) {
        std::ofstream out(dir / "metadata.json", std::ios::trunc);
        out << metadata_json;
    }
}

}  // namespace

int main()
{
    std::fprintf(stdout, "Running boot_inactive_seed_skips_scheduler_test...\n");

    // builtin metadata serdes 注册:让 ReadMetadataSidecar 能识别 seed_admission_state。
    refuzz::fuzzer::RegisterBuiltinSeedMetadataSerdes();

    // 准备 temp corpus dir。
    auto tmp = fs::temp_directory_path() / "boot_inactive_seed_test";
    std::error_code ec;
    fs::remove_all(tmp, ec);
    fs::create_directories(tmp, ec);
    assert(!ec);

    // ── seed_a:no metadata.json → legacy migration active ─────────────────
    WriteSeedDir(tmp, /*synthetic_id=*/1, {0x11, 0x22}, /*metadata=*/"");

    // ── seed_b:metadata 显式 active ────────────────────────────────────────
    WriteSeedDir(tmp, /*synthetic_id=*/2, {0x33, 0x44}, R"({
        "schema_version": 1,
        "seed_id": 0,
        "priority": 1,
        "interesting_hits": 0,
        "seed_source": {
            "source": "boot_corpus",
            "attempt": 0
        },
        "seed_admission_state": {
            "state": "active",
            "inactive_reason": "",
            "verify_attempts": 0
        }
    })");

    // ── seed_c:metadata 显式 inactive(retry exhausted)────────────────────
    WriteSeedDir(tmp, /*synthetic_id=*/3, {0x55, 0x66}, R"({
        "schema_version": 1,
        "seed_id": 0,
        "priority": 1,
        "interesting_hits": 0,
        "seed_source": {
            "source": "boot_corpus",
            "attempt": 0
        },
        "seed_admission_state": {
            "state": "inactive",
            "inactive_reason": "flaky_retry_exhausted",
            "verify_attempts": 5
        }
    })");

    // LoadAll —— LenientBytes 模式即可(不需要 typed materializer)。
    InMemoryCorpusStore store;
    TrackingScheduler scheduler;
    SeedIdAllocator id_alloc;

    const auto loaded = CorpusDiskIO::LoadAll(
        store, scheduler, tmp.string(), id_alloc,
        /*materializer=*/{},
        CorpusLoadPolicy::LenientBytes);
    assert(loaded == 3);  // 三个 seed 都 physical load

    // ── 断言:store.Size() == 3(physical retain) ───────────────────────────
    assert(store.Size() == 3);

    // ── 断言:scheduler.added_ids().size() == 2(active 路径 only)─────────
    assert(scheduler.added_ids().size() == 2);

    // 验 inactive 那个 seed 的 id **不在** added_ids 集合里。
    // 通过 store.ForEachSeed 找到 inactive seed 的 id。
    std::uint64_t inactive_id = 0;
    store.ForEachSeed([&](const refuzz::fuzzer::Seed& s) {
        if (const auto* admit = s.metadata.Get<SeedAdmissionStateMetadata>()) {
            if (admit->state == SeedAdmissionState::kInactive) {
                inactive_id = s.seed_id;
            }
        }
    });
    assert(inactive_id != 0);
    assert(scheduler.added_ids().count(inactive_id) == 0);

    // 清理。
    fs::remove_all(tmp, ec);

    return 0;
}

// PR1 — Corpus Prep Smoothing 严格加载契约测试。
//
// 验证 CorpusDiskIO::LoadAll / LoadCrashRepros 在 CorpusLoadPolicy::StrictTyped
// 下的 fail-closed 行为：materializer 缺失或返回 null 时整 seed drop，**不
// 分配 seed_id、不调 OnSeedAdded、不入 store**。
//
// 配套覆盖 LenientBytes 对照 case：同一组失败输入仍走 v1 keep-bytes 路径。
//
// 直接测的是这次 932 全 abnormal 的根因——bytes-only 僵尸 seed 阻断 bootstrap +
// 被 bytes fallback 原样送到 worker 触发 SIGABRT。

#include "refuzz/corpus/corpus_disk_io.hpp"
#include "refuzz/corpus/corpus_prep_policy.hpp"
#include "refuzz/corpus/corpus_store.hpp"
#include "refuzz/program/artifact_materializer.hpp"
#include "refuzz/program/seed.hpp"
#include "refuzz/scheduler/scheduler_engine.hpp"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <ios>
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
        char tmpl[] = "/tmp/refuzz_corpus_strict_XXXXXX";
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

// 在 <dir>/<hex_id>/<filename> 处写一个长度为 5 字节的 dummy payload。
void WriteDummyPayload(const std::filesystem::path& dir,
                       const char*                  filename,
                       const std::string&           hex_id)
{
    namespace fs = std::filesystem;
    const fs::path subdir = dir / hex_id;
    fs::create_directories(subdir);
    std::ofstream out(subdir / filename, std::ios::binary);
    const char body[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    out.write(body, sizeof(body));
}

// 永远返回 nullptr 的 materializer——模拟 corpus payload 不能 decode 的情形。
::refuzz::program::ArtifactMaterializerFn AlwaysNullMaterializer()
{
    return [](const std::vector<uint8_t>&)
        -> std::shared_ptr<const ::refuzz::program::ProgramArtifact> {
        return nullptr;
    };
}

// Case 1 — StrictTyped + materializer 返回 null：整 seed drop，allocator 不消耗。
bool TestStrictDropOnNullArtifact()
{
    TmpDir tmp;
    assert(!tmp.path().empty());

    WriteDummyPayload(tmp.path(), "payload.bin", "00000000000000aa");
    WriteDummyPayload(tmp.path(), "payload.bin", "00000000000000bb");

    refuzz::fuzzer::InMemoryCorpusStore store;
    StubScheduler                       scheduler;
    refuzz::fuzzer::SeedIdAllocator     ids(/*start=*/100);

    const uint64_t peek_before = ids.Peek();
    const size_t   loaded      = refuzz::fuzzer::CorpusDiskIO::LoadAll(
        store, scheduler, tmp.path(), ids,
        AlwaysNullMaterializer(),
        refuzz::fuzzer::CorpusLoadPolicy::StrictTyped);

    if (loaded != 0)              { std::fprintf(stderr, "loaded=%zu (want 0)\n", loaded); return false; }
    if (store.Size() != 0)        { std::fprintf(stderr, "store.Size=%zu (want 0)\n", store.Size()); return false; }
    if (scheduler.added != 0)     { std::fprintf(stderr, "scheduler.added=%d (want 0)\n", scheduler.added); return false; }
    if (ids.Peek() != peek_before){ std::fprintf(stderr, "ids.Peek=%llu (want %llu)\n",
                                        (unsigned long long)ids.Peek(),
                                        (unsigned long long)peek_before); return false; }
    return true;
}

// Case 2 — StrictTyped + materializer 缺失：等价同样 drop（fail-closed）。
bool TestStrictDropOnMissingMaterializer()
{
    TmpDir tmp;
    assert(!tmp.path().empty());

    WriteDummyPayload(tmp.path(), "payload.bin", "00000000000000cc");

    refuzz::fuzzer::InMemoryCorpusStore store;
    StubScheduler                       scheduler;
    refuzz::fuzzer::SeedIdAllocator     ids(/*start=*/200);

    const uint64_t peek_before = ids.Peek();
    const size_t   loaded      = refuzz::fuzzer::CorpusDiskIO::LoadAll(
        store, scheduler, tmp.path(), ids,
        /*materializer=*/{},
        refuzz::fuzzer::CorpusLoadPolicy::StrictTyped);

    if (loaded != 0)              { std::fprintf(stderr, "loaded=%zu (want 0)\n", loaded); return false; }
    if (store.Size() != 0)        return false;
    if (scheduler.added != 0)     return false;
    if (ids.Peek() != peek_before)return false;
    return true;
}

// Case 3 — LenientBytes 对照：同一 null materializer 下 seed 仍入库（v1 行为）。
bool TestLenientKeepsBytes()
{
    TmpDir tmp;
    assert(!tmp.path().empty());

    WriteDummyPayload(tmp.path(), "payload.bin", "00000000000000dd");

    refuzz::fuzzer::InMemoryCorpusStore store;
    StubScheduler                       scheduler;
    refuzz::fuzzer::SeedIdAllocator     ids(/*start=*/300);

    const size_t loaded = refuzz::fuzzer::CorpusDiskIO::LoadAll(
        store, scheduler, tmp.path(), ids,
        AlwaysNullMaterializer(),
        refuzz::fuzzer::CorpusLoadPolicy::LenientBytes);

    if (loaded != 1)          { std::fprintf(stderr, "loaded=%zu (want 1)\n", loaded); return false; }
    if (store.Size() != 1)    return false;
    if (scheduler.added != 1) return false;

    auto h = store.GetSeed(300);
    if (h == nullptr)         return false;
    if (h->artifact != nullptr) {  // Lenient 路径明确保留 bytes-only seed
        std::fprintf(stderr, "expected bytes-only seed but artifact != nullptr\n");
        return false;
    }
    return true;
}

// Case 4 — LoadCrashRepros 对称：StrictTyped 也走 fail-closed。
// crash repro 路径 (`<diag>/<bucket>/<id>/prog0.bin`) 不能成为新的 bytes-only 入口。
bool TestStrictDropOnCrashReproPath()
{
    TmpDir tmp;
    assert(!tmp.path().empty());

    namespace fs = std::filesystem;
    const fs::path bucket = fs::path(tmp.path()) / "kernel_crash";
    WriteDummyPayload(bucket, "prog0.bin", "00000000000000ee");

    refuzz::fuzzer::InMemoryCorpusStore store;
    StubScheduler                       scheduler;
    refuzz::fuzzer::SeedIdAllocator     ids(/*start=*/400);

    const uint64_t peek_before = ids.Peek();
    const size_t   loaded      = refuzz::fuzzer::CorpusDiskIO::LoadCrashRepros(
        store, scheduler, tmp.path(), ids,
        AlwaysNullMaterializer(),
        refuzz::fuzzer::CorpusLoadPolicy::StrictTyped);

    if (loaded != 0)              return false;
    if (store.Size() != 0)        return false;
    if (scheduler.added != 0)     return false;
    if (ids.Peek() != peek_before)return false;
    return true;
}

// Case 5 — CountArtifactSeeds 行为：bytes-only seed 不算数。
bool TestCountArtifactSeedsExcludesBytesOnly()
{
    refuzz::fuzzer::InMemoryCorpusStore store;

    // 三个 bytes-only seed
    for (uint64_t i = 0; i < 3; ++i) {
        refuzz::fuzzer::Seed s;
        s.seed_id = 500 + i;
        s.payload = {0x01, 0x02};
        s.priority = 1;
        // s.artifact 留 null
        assert(store.AddSeed(std::move(s)));
    }
    if (refuzz::fuzzer::CountArtifactSeeds(store) != 0) {
        std::fprintf(stderr, "CountArtifactSeeds with 3 bytes-only != 0\n");
        return false;
    }
    if (store.Size() != 3) return false;  // sanity：Size() 仍是 3
    return true;
}

} // namespace

int main()
{
    std::fprintf(stdout, "Running corpus_disk_io_strict_drop_test...\n");

    struct Case { const char* name; bool (*fn)(); };
    const Case cases[] = {
        {"strict_drop_on_null_artifact",       &TestStrictDropOnNullArtifact},
        {"strict_drop_on_missing_materializer",&TestStrictDropOnMissingMaterializer},
        {"lenient_keeps_bytes",                &TestLenientKeepsBytes},
        {"strict_drop_on_crash_repro_path",    &TestStrictDropOnCrashReproPath},
        {"count_artifact_seeds_excludes_bytes",&TestCountArtifactSeedsExcludesBytesOnly},
    };
    for (const auto& c : cases) {
        if (!c.fn()) {
            std::fprintf(stderr, "FAIL: %s\n", c.name);
            return 1;
        }
        std::fprintf(stdout, "  ok %s\n", c.name);
    }
    std::fprintf(stdout, "PASS\n");
    return 0;
}

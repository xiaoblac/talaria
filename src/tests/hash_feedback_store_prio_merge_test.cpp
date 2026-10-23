// Copyright 2026 reFuzz project author -------youngkk.
//
// [v2 batch 3 PR-Y] HashFeedbackStore prio merge / persistence 单测。
//
// Cases:
//   1. prio_old < prio_new → prio 升级 max,gain=1(syz DiffRaw parity)
//   2. prio_old > prio_new → prio 不降级,gain=0
//   3. 新 hash → emplace,gain=1
//   4. v2 schema write/read round-trip(prio 保留)
//   5. v1 legacy file load → log warn + return true,seen_ 起空(下次 Save 写 v2)
//   6. HasNewCoverage 不看 prio(CC1)— 升级语义不变

#include "refuzz/feedback/coverage_file.hpp"
#include "refuzz/feedback/signal/hash_feedback_store.hpp"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

std::string MakeTempFile(const std::string& tag)
{
    fs::path tmp = fs::temp_directory_path() / ("hash_feedback_store_test_" + tag + ".bin");
    std::error_code ec;
    fs::remove(tmp, ec);
    return tmp.string();
}

std::vector<refuzz::fuzzer::CoverageFileEntryV2> ReadV2Entries(const std::string& path)
{
    using refuzz::fuzzer::CoverageFileEntryV2;
    using refuzz::fuzzer::CoverageFileHeader;
    using refuzz::fuzzer::kCoverageFileFlagLE;
    using refuzz::fuzzer::kCoverageFileMagic;
    using refuzz::fuzzer::kCoverageFileVersion;

    std::ifstream in(path, std::ios::binary);
    assert(in.is_open());

    CoverageFileHeader hdr;
    in.read(reinterpret_cast<char*>(&hdr), sizeof(hdr));
    assert(in);
    assert(hdr.magic == kCoverageFileMagic);
    assert(hdr.version == kCoverageFileVersion);
    assert(hdr.flags == kCoverageFileFlagLE);
    assert(hdr.reserved == 0);

    std::vector<CoverageFileEntryV2> entries(hdr.count);
    for (auto& entry : entries) {
        in.read(reinterpret_cast<char*>(&entry), sizeof(entry));
        assert(in);
    }
    return entries;
}

bool HasEntry(const std::vector<refuzz::fuzzer::CoverageFileEntryV2>& entries,
              std::uint64_t hash,
              std::uint8_t prio)
{
    for (const auto& entry : entries) {
        if (entry.hash == hash && entry.prio == prio) {
            return true;
        }
    }
    return false;
}

}  // namespace

int main()
{
    using refuzz::fuzzer::HashFeedbackStore;
    using refuzz::fuzzer::CoverageFileHeader;
    using refuzz::fuzzer::CoverageFileEntryV2;
    using refuzz::fuzzer::kCoverageFileMagic;
    using refuzz::fuzzer::kCoverageFileVersion;
    using refuzz::fuzzer::kCoverageFileVersionV1Legacy;
    using refuzz::fuzzer::kCoverageFileFlagLE;

    std::fprintf(stdout, "Running hash_feedback_store_prio_merge_test...\n");

    // ── Case 1: prio_old=0 + prio_new=2 → 升级 max,gain=1 ────────────
    // ── Case 2: prio_old=3 + prio_new=1 → 保 max,gain=0 ──────────────
    // ── Case 3: 新 hash → gain=1 ──────────────────────────────────────
    {
        HashFeedbackStore s;
        // 第一次插入 hash=0xAA prio=0
        std::vector<std::uint64_t> first = {0xAA};
        std::vector<std::uint64_t> novel;
        const size_t g1 = s.MergeCoverage(first, 0, &novel);
        assert(g1 == 1);
        assert((novel == std::vector<std::uint64_t>{0xAA}));
        assert(s.Count() == 1);

        // prio_old=0 + prio_new=2 → max=2;gain=1(syz DiffRaw)
        const size_t g2 = s.MergeCoverage(first, 2, &novel);
        assert(g2 == 1);
        assert((novel == std::vector<std::uint64_t>{0xAA}));
        assert(s.Count() == 1);

        // prio_old=2 + prio_new=1 → max=2(不降级);gain=0
        const size_t g3 = s.MergeCoverage(first, 1, &novel);
        assert(g3 == 0);
        assert(novel.empty());
        assert(s.Count() == 1);

        // 新 hash → emplace + gain=1
        std::vector<std::uint64_t> second = {0xBB};
        const size_t g4 = s.MergeCoverage(second, 5, &novel);
        assert(g4 == 1);
        assert((novel == std::vector<std::uint64_t>{0xBB}));
        assert(s.Count() == 2);
    }

    // ── Case 4: v2 schema write/read round-trip ──────────────────────
    // 写 3 个 hash + 不同 prio,Save 到 file,Load 到新 store,Count + 数据一致。
    {
        HashFeedbackStore s1;
        s1.MergeCoverage({0x1111}, 0);
        s1.MergeCoverage({0x2222}, 7);
        s1.MergeCoverage({0x3333}, 3);
        assert(s1.Count() == 3);

        const std::string path = MakeTempFile("case4");
        const bool saved = s1.SaveToFile(path);
        assert(saved);

        const auto entries_before_load = ReadV2Entries(path);
        assert(entries_before_load.size() == 3);
        assert(HasEntry(entries_before_load, 0x1111, 0));
        assert(HasEntry(entries_before_load, 0x2222, 7));
        assert(HasEntry(entries_before_load, 0x3333, 3));

        HashFeedbackStore s2;
        const bool loaded = s2.LoadFromFile(path);
        assert(loaded);
        assert(s2.Count() == 3);
        // HasNewCoverage 反查 — 三个 hash 都应该已存在
        std::vector<std::uint64_t> probe1 = {0x1111};
        std::vector<std::uint64_t> probe2 = {0x2222};
        std::vector<std::uint64_t> probe3 = {0x3333};
        assert(!s2.HasNewCoverage(probe1));
        assert(!s2.HasNewCoverage(probe2));
        assert(!s2.HasNewCoverage(probe3));

        // 检查 file size 是 v2 格式 16-byte entry
        const auto file_size = fs::file_size(path);
        const auto expected =
            sizeof(CoverageFileHeader) + 3 * sizeof(CoverageFileEntryV2);
        assert(file_size == expected);

        const std::string reload_path = MakeTempFile("case4_after_load");
        const bool saved_after_load = s2.SaveToFile(reload_path);
        assert(saved_after_load);
        const auto entries_after_load = ReadV2Entries(reload_path);
        assert(entries_after_load.size() == 3);
        assert(HasEntry(entries_after_load, 0x1111, 0));
        assert(HasEntry(entries_after_load, 0x2222, 7));
        assert(HasEntry(entries_after_load, 0x3333, 3));

        std::error_code ec;
        fs::remove(path, ec);
        fs::remove(reload_path, ec);
    }

    // ── Case 5: v1 legacy file load → log warn + return true ─────────
    {
        const std::string path = MakeTempFile("case5_v1");
        // 手工写 v1 file:header(version=1)+ 2 个 8-byte hash entry
        {
            std::ofstream out(path, std::ios::binary | std::ios::trunc);
            assert(out.is_open());
            CoverageFileHeader hdr;
            hdr.magic    = kCoverageFileMagic;
            hdr.version  = kCoverageFileVersionV1Legacy;
            hdr.flags    = kCoverageFileFlagLE;
            hdr.count    = 2;
            hdr.reserved = 0;
            out.write(reinterpret_cast<const char*>(&hdr), sizeof(hdr));
            const std::uint64_t h1 = 0xAA;
            const std::uint64_t h2 = 0xBB;
            out.write(reinterpret_cast<const char*>(&h1), sizeof(h1));
            out.write(reinterpret_cast<const char*>(&h2), sizeof(h2));
        }

        HashFeedbackStore s;
        const bool loaded = s.LoadFromFile(path);
        assert(loaded);  // v1 → log warn + return true(不视为 corruption)
        assert(s.Count() == 0);  // seen_ 起空

        // 下次 Save 应写 v2 schema 覆盖原 v1 file
        s.MergeCoverage({0xCC}, 1);
        const bool saved = s.SaveToFile(path);
        assert(saved);

        // verify v2 by re-load
        HashFeedbackStore s2;
        const bool loaded2 = s2.LoadFromFile(path);
        assert(loaded2);
        assert(s2.Count() == 1);
        const auto migrated_entries = ReadV2Entries(path);
        assert(migrated_entries.size() == 1);
        assert(HasEntry(migrated_entries, 0xCC, 1));

        std::error_code ec;
        fs::remove(path, ec);
    }

    // ── Case 6: HasNewCoverage 不看 prio(CC1)── 升级语义不变 ─────────
    {
        HashFeedbackStore s;
        s.MergeCoverage({0x100, 0x200}, 5);
        // 已存在 hash:HasNewCoverage 返 false 无论 prio
        std::vector<std::uint64_t> existing = {0x100, 0x200};
        assert(!s.HasNewCoverage(existing));
        // 新 hash:返 true
        std::vector<std::uint64_t> mixed = {0x100, 0x300};
        assert(s.HasNewCoverage(mixed));
    }

    return 0;
}

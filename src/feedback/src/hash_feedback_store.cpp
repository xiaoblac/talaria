#include "refuzz/feedback/signal/hash_feedback_store.hpp"
#include "refuzz/feedback/coverage_file.hpp"
#include "refuzz/logging/host_logger.hpp"  // [v2 batch 3 PR-Y] B1 — log v1 migration

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>

namespace refuzz::fuzzer {

bool HashFeedbackStore::HasNewCoverage(const std::vector<uint64_t>& cov_hashes) const
{
    // [v2 batch 3 PR-Y CC1] 升级语义不变 — 只看 hash 是否在 map(不看 prio)。
    // seen_ map 的 find 行为兼容 set,语义 1:1 保留;避免破坏
    // KcovCoverageSignal::Sample::interesting=(gain>0) 谓词。
    for (uint64_t h : cov_hashes) {
        if (seen_.find(h) == seen_.end()) {
            return true;
        }
    }
    return false;
}

// [v2 batch 3 PR-Y] +prio 参数;`max(seen_[h], prio)` upgrade-on-merge(CC2).
// Gain mirrors syzkaller signal.DiffRaw: a brand-new hash OR a higher-prio hit
// is new signal and must make KcovCoverageSignal interesting.
size_t HashFeedbackStore::MergeCoverage(const std::vector<uint64_t>& cov_hashes,
                                        std::uint8_t prio)
{
    return MergeCoverage(cov_hashes, prio, nullptr);
}

size_t HashFeedbackStore::MergeCoverage(const std::vector<uint64_t>& cov_hashes,
                                        std::uint8_t prio,
                                        std::vector<uint64_t>* novel_hashes)
{
    size_t gain = 0;
    if (novel_hashes != nullptr) {
        novel_hashes->clear();
    }
    for (uint64_t h : cov_hashes) {
        auto it = seen_.find(h);
        if (it == seen_.end()) {
            seen_.emplace(h, prio);
            ++gain;
            if (novel_hashes != nullptr) {
                novel_hashes->push_back(h);
            }
        } else if (prio > it->second) {
            it->second = prio;
            ++gain;
            if (novel_hashes != nullptr) {
                novel_hashes->push_back(h);
            }
        }
    }
    return gain;
}

// [corpus-pc-export] Dump distinct keys (raw PCs when raw_pc=true) sorted as
// 0x%x/line — read directly by speed-compare's PC-set compare (no grown-corpus replay).
bool HashFeedbackStore::DumpPCsToFile(const std::string& path) const
{
    std::vector<uint64_t> pcs;
    pcs.reserve(seen_.size());
    for (const auto& [pc, prio] : seen_) {
        (void)prio;
        pcs.push_back(pc);
    }
    std::sort(pcs.begin(), pcs.end());
    std::ofstream f(path);
    if (!f) return false;
    for (uint64_t pc : pcs) {
        f << "0x" << std::hex << pc << "\n";
    }
    return f.good();
}

// [v2 batch 3 PR-Y D3] SaveToFile per-entry 16 字节 CoverageFileEntryV2
// (hash uint64 + prio uint8 + 7 byte zero padding)。Header version=2。
// file_size = sizeof(CoverageFileHeader) + count * sizeof(CoverageFileEntryV2)。
bool HashFeedbackStore::SaveToFile(const std::string& path) const
{
    namespace fs = std::filesystem;
    const fs::path final_path(path);
    const fs::path tmp_path = final_path.string() + ".tmp";

    std::error_code ec;
    const fs::path parent = final_path.parent_path();
    if (!parent.empty()) {
        fs::create_directories(parent, ec);
        if (ec) {
            return false;
        }
    }

    {
        std::ofstream out(tmp_path, std::ios::binary | std::ios::trunc);
        if (!out) {
            return false;
        }

        CoverageFileHeader hdr;
        hdr.count = static_cast<uint64_t>(seen_.size());
        out.write(reinterpret_cast<const char*>(&hdr), sizeof(hdr));
        if (!out) {
            std::error_code ignore_ec;
            fs::remove(tmp_path, ignore_ec);
            return false;
        }

        // [v2 PR-Y] 写 16-byte entry。padding 字段在 default ctor 已 = 0。
        for (const auto& [h, prio] : seen_) {
            CoverageFileEntryV2 entry;
            entry.hash = h;
            entry.prio = prio;
            // pad0..pad6 默认 0,无需显式 set。
            out.write(reinterpret_cast<const char*>(&entry), sizeof(entry));
            if (!out) {
                std::error_code ignore_ec;
                fs::remove(tmp_path, ignore_ec);
                return false;
            }
        }
        out.flush();
        if (!out.good()) {
            std::error_code ignore_ec;
            fs::remove(tmp_path, ignore_ec);
            return false;
        }
    }

    fs::rename(tmp_path, final_path, ec);
    if (ec) {
        std::error_code ignore_ec;
        fs::remove(tmp_path, ignore_ec);
        return false;
    }
    return true;
}


// [v2 batch 3 PR-Y D4] LoadFromFile v2 path + v1 legacy migration。
// hdr.version == 2:read 16-byte CoverageFileEntryV2 entries(hash + prio + padding)
// hdr.version == 1(kCoverageFileVersionV1Legacy): log warn + return true,seen_
//                  起空,下次 Save 自然写 v2 覆盖(B1)
// 其他 version / corruption → return false(caller orchestrator.cpp:391-392 已 tolerant)
bool HashFeedbackStore::LoadFromFile(const std::string& path)
{
    namespace fs = std::filesystem;
    std::error_code ec;
    if (!fs::exists(path, ec)) {
        return !ec;
    }
    if (ec) {
        return false;
    }

    const uintmax_t file_size = fs::file_size(path, ec);
    if (ec) {
        return false;
    }
    if (file_size < sizeof(CoverageFileHeader)) {
        return false;
    }

    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return false;
    }

    CoverageFileHeader hdr;
    in.read(reinterpret_cast<char*>(&hdr), sizeof(hdr));
    if (!in) {
        return false;
    }
    if (hdr.magic != kCoverageFileMagic) {
        return false;
    }
    // [v2 PR-Y D4] v1 legacy migration path —— log warn + return true(seen_ 起空)。
    if (hdr.version == kCoverageFileVersionV1Legacy) {
        ::refuzz::logging::HostLineBuilder("HashFeedbackStore", "v1_migration")
            << "v1 coverage file detected at " << path
            << "; migrating to v2 (seen_ starts empty, next SaveToFile rewrites)\n";
        return true;
    }
    if (hdr.version != kCoverageFileVersion) {
        return false;
    }
    if ((hdr.flags & ~kCoverageFileFlagLE) != 0) {
        return false;
    }
    if ((hdr.flags & kCoverageFileFlagLE) == 0) {
        return false;
    }
    if (hdr.reserved != 0) {
        return false;
    }

    // [v2 PR-Y D3] entry 16 字节(was 8 字节 in v1)。
    if (hdr.count > (std::numeric_limits<uint64_t>::max() - sizeof(CoverageFileHeader)) / sizeof(CoverageFileEntryV2)) {
        return false;
    }
    const uint64_t expected = static_cast<uint64_t>(sizeof(CoverageFileHeader)) +
                              hdr.count * static_cast<uint64_t>(sizeof(CoverageFileEntryV2));
    if (file_size != expected) {
        return false;
    }

    // [v2 PR-Y D3] read 16-byte CoverageFileEntryV2 entries(hash + prio + padding)。
    CoverageFileEntryV2 entry;
    for (uint64_t i = 0; i < hdr.count; ++i) {
        in.read(reinterpret_cast<char*>(&entry), sizeof(entry));
        if (!in) {
            return false;
        }
        // emplace 等价 set 的 insert(已有 hash 不覆盖,跟 v1 行为对齐 — load 是
        // 起 fresh state,无 prio 冲突;runtime MergeCoverage 才走 max upgrade)。
        seen_.emplace(entry.hash, entry.prio);
    }
    return true;
}

size_t HashFeedbackStore::Count() const
{
    return seen_.size();
}

} // namespace refuzz::fuzzer

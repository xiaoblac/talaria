#pragma once

#include "refuzz/fuzzer/interfaces.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <random>
#include <shared_mutex>
#include <unordered_map>
#include <vector>

namespace refuzz::fuzzer {


// [v2 admit-worker async — 当前版本]
//   异步 admit worker(独立线程跑 RebuildChoiceTable + SaveSeed)会并发 ForEachSeed,
//   主 fuzz 线程仍 AddSeed/MarkInteresting,因此必须线程安全。
//   设计:
//     - mu_ 是 shared_mutex
//     - AddSeed / MarkInteresting / SampleSeedId 持 unique_lock
//     - GetSeed / Size 持 shared_lock
//     - ForEachSeed 关键:锁内只复制 SeedHandle 列表,锁外遍历调 visitor。
//       目的是避免 worker 长 visit(rebuild O(corpus)) 期间挡住主线程 AddSeed。
class InMemoryCorpusStore final : public ICorpusStore {
public:
    bool AddSeed(Seed seed) override;
    SeedHandle GetSeed(uint64_t seed_id) const override;
    void ForEachSeed(const SeedVisitor& visitor) const override;
    std::optional<uint64_t> SampleSeedId(std::mt19937_64& rng) const override;
    void MarkInteresting(uint64_t seed_id) override;
    size_t Size() const override;
    // [P4 corpus minimization] unique_lock; erase from seeds_ map + order_ vector.
    bool RemoveSeed(uint64_t seed_id) override;
    // [v2 batch 3 G6] copy-on-write 更新 seed.metadata。unique_lock + 重 emplace
    // 新 shared_ptr<Seed>(避免 GetSeed 拿到的 SeedHandle 被并发改)。详 .cpp。
    bool UpdateSeedMetadata(uint64_t seed_id, SeedMetadataUpdater updater) override;

private:
    mutable std::shared_mutex mu_;
    std::vector<uint64_t> order_;
    std::unordered_map<uint64_t, std::shared_ptr<Seed>> seeds_;
};

} // namespace refuzz::fuzzer

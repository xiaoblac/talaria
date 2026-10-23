#pragma once

#include "refuzz/fuzzer/feedback_verdict.hpp"   // SeedDisposition — 透传给 fuzzer_concepts.hpp 等消费者（曾反向依赖 feedback/）
#include "refuzz/core/metadata.hpp"  // [v2 batch 3 G6] MetadataMap for UpdateSeedMetadata callback
#include "refuzz/program/seed.hpp"
#include "refuzz/proto_domain/types.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <vector>

namespace refuzz::fuzzer {

using SeedHandle = std::shared_ptr<const Seed>;
using SeedVisitor = std::function<void(const Seed&)>;
// [v2 batch 3 G6] callback signature for ICorpusStore::UpdateSeedMetadata。
// caller mutate metadata.Set/Get/etc;callback 在 store 内部 unique_lock 下执行,
// **不允许嵌套调用 store 其它方法**(deadlock 风险)。
using SeedMetadataUpdater = std::function<void(refuzz::core::MetadataMap&)>;

class ICorpusStore {
public:
    virtual ~ICorpusStore() = default;
    virtual bool AddSeed(Seed seed) = 0;
    virtual SeedHandle GetSeed(uint64_t seed_id) const = 0;
    virtual void ForEachSeed(const SeedVisitor& visitor) const = 0;
    virtual std::optional<uint64_t> SampleSeedId(std::mt19937_64& rng) const = 0;
    virtual void MarkInteresting(uint64_t seed_id) = 0;
    virtual size_t Size() const = 0;

    // [P4 corpus minimization] Remove a seed by id. Default no-op so legacy /
    // test stores aren't forced to implement it. The real impl (InMemoryCorpusStore)
    // drops the seed so CorpusManager::MaybeMinimizeCorpus can prune
    // coverage-subsumed seeds (greedy minimal-set, mirrors syz corpus.Minimize).
    // The caller also InvalidateSeed()s the scheduler so the pools stay consistent.
    virtual bool RemoveSeed(uint64_t /*seed_id*/) { return false; }

    // [v2 batch 3 G6] copy-on-write metadata 更新。
    // - seed_id 不存在 → no-op,return false
    // - updater 在 unique_lock 内调,**不要在 callback 内访问 store 其它方法**
    // - implementations 应保证 GetSeed 看到 updater 完成后的新 metadata
    // 默认实现:no-op + return false(legacy ICorpusStore impl 不强制实现;
    // G6 corpus_verify_consumer 只对 InMemoryCorpusStore 可工作)。
    virtual bool UpdateSeedMetadata(uint64_t /*seed_id*/,
                                     SeedMetadataUpdater /*updater*/) {
        return false;
    }
};

class IFeedbackStore {
public:
    virtual ~IFeedbackStore() = default;

    // [v2 batch 3 PR-Y — 加 prio 参数] PR-Y Step 5 prio packing 路径。
    // KcovCoverageSignal::Sample 按 signal ownership unit 算 SignalAttributes
    // → IPriorityCalculator.Calculate(attrs) → prio 应用于该 unit 的 hashes。
    // KcovCmpSignal 等 neutral 调用方传 prio=0(MakeKcovCmpEntry 不消费 priority_calculator)。
    // HashFeedbackStore impl mirrors syzkaller signal.DiffRaw: gain counts a
    // brand-new hash OR a hit at higher prio. `HasNewCoverage` remains hash-only.
    virtual bool HasNewCoverage(const std::vector<uint64_t>& cov_hashes) const = 0;
    virtual size_t MergeCoverage(const std::vector<uint64_t>& cov_hashes,
                                 std::uint8_t prio) = 0;
    virtual size_t MergeCoverage(const std::vector<uint64_t>& cov_hashes,
                                 std::uint8_t prio,
                                 std::vector<uint64_t>* novel_hashes)
    {
        if (novel_hashes != nullptr) {
            novel_hashes->clear();
        }
        return MergeCoverage(cov_hashes, prio);
    }
    virtual bool SaveToFile(const std::string& path) const { (void)path; return false; }
    virtual bool LoadFromFile(const std::string& path) { (void)path; return false; }
    virtual size_t Count() const { return 0; }
};

} // namespace refuzz::fuzzer

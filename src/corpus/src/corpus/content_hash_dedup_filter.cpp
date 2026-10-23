// content_hash_dedup_filter.cpp —— SubT-D / G8 corpus content dedup filter.
//
// [syz corpus.go:140 / progsMap parity — merge, not reject] 语义从「见过就 reject」
// 改为「见过就报告既有 seed_id 让 CorpusManager MERGE」:
//   - Test()        恒放行(content-dup 不再由本 filter 拒;空 payload 交
//                   NonEmptyPayloadFilter)。
//   - DuplicateOf() FNV-1a 64-bit(seed.payload)命中 hash_to_id → 返回既有 seed_id;
//                   CorpusManager 据此 union 新 signal/cover 进既有 seed。
//   - OnSeedAdded() 记 hash→id 与 id→hash(仅首个 owner 占 hash;重复不覆盖)。
//   - OnSeedRemoved() sweep 驱逐时 erase,使 hash_to_id 随 corpus 收缩 —— 否则驱逐过
//                   的 program 被永久拉黑、无法像 syz 那样 re-admit(progsMap delete)。
//
// FNV-1a 64-bit:无加密需求;collision 概率 N²/2^64 对 100K seed 约 10^-9,可接受;0 依赖。
//
// Thread safety:shared_mutex 保护双 map。Test/DuplicateOf 读 / OnSeedAdded/
// OnSeedRemoved 写。CorpusManager admit/evict 是单 Tick 线程,但 BootstrapFiltersFromStore
// 走 ForEachSeed snapshot 模式,可能跟其它线程并发 — 加锁防御。

#include "refuzz/corpus/corpus_manager.hpp"

#include "refuzz/program/seed.hpp"

#include <cstdint>
#include <optional>
#include <shared_mutex>
#include <unordered_map>

namespace refuzz::fuzzer {

namespace {

// FNV-1a 64-bit (Fowler-Noll-Vo). 标准常量:
//   offset_basis = 0xcbf29ce484222325
//   prime        = 0x100000001b3
uint64_t Fnv1a64(const uint8_t* data, size_t len)
{
    uint64_t hash = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < len; ++i) {
        hash ^= static_cast<uint64_t>(data[i]);
        hash *= 0x100000001b3ULL;
    }
    return hash;
}

}  // namespace

struct ContentHashDedupFilter::Impl {
    mutable std::shared_mutex mu;
    std::unordered_map<uint64_t, uint64_t> hash_to_id;  // content hash → live owner seed_id
    std::unordered_map<uint64_t, uint64_t> id_to_hash;  // seed_id → its content hash (for erase)
};

ContentHashDedupFilter::ContentHashDedupFilter()
    : impl_(std::make_unique<Impl>())
{}

ContentHashDedupFilter::~ContentHashDedupFilter() = default;

bool ContentHashDedupFilter::Test(const Seed& /*seed*/, const CorpusContext& /*ctx*/) const
{
    // content-dedup 不再在此 reject —— CorpusManager 经 DuplicateOf MERGE。恒放行。
    return true;
}

std::optional<uint64_t> ContentHashDedupFilter::DuplicateOf(const Seed& seed,
                                                            const CorpusContext& /*ctx*/) const
{
    if (seed.payload.empty()) {
        return std::nullopt;  // 空 payload 由 NonEmptyPayloadFilter 处理
    }
    const uint64_t h = Fnv1a64(seed.payload.data(), seed.payload.size());
    std::shared_lock<std::shared_mutex> lk(impl_->mu);
    auto it = impl_->hash_to_id.find(h);
    if (it == impl_->hash_to_id.end()) {
        return std::nullopt;
    }
    return it->second;
}

void ContentHashDedupFilter::OnSeedAdded(const Seed& seed)
{
    if (seed.payload.empty()) {
        return;
    }
    const uint64_t h = Fnv1a64(seed.payload.data(), seed.payload.size());
    std::unique_lock<std::shared_mutex> lk(impl_->mu);
    // 仅首个 owner 占 hash(重复由 merge 路径吸收,正常不会走到这;boot 语料若含
    // 重复 payload 则保留第一个 owner)。id→hash 始终记录本 seed 自己的 hash。
    impl_->hash_to_id.emplace(h, seed.seed_id);
    impl_->id_to_hash[seed.seed_id] = h;
}

void ContentHashDedupFilter::OnSeedRemoved(std::uint64_t seed_id)
{
    std::unique_lock<std::shared_mutex> lk(impl_->mu);
    auto it = impl_->id_to_hash.find(seed_id);
    if (it == impl_->id_to_hash.end()) {
        return;
    }
    const uint64_t h = it->second;
    // 仅当该 hash 的 owner 确是本 seed 才 erase(防 boot 重复 payload 误删他人 owner)。
    auto owner = impl_->hash_to_id.find(h);
    if (owner != impl_->hash_to_id.end() && owner->second == seed_id) {
        impl_->hash_to_id.erase(owner);
    }
    impl_->id_to_hash.erase(it);
}

}  // namespace refuzz::fuzzer

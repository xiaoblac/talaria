#include "refuzz/corpus/corpus_store.hpp"

#include <algorithm>
#include <memory>
#include <mutex>
#include <random>
#include <shared_mutex>
#include <vector>

namespace refuzz::fuzzer {


// [v2 admit-worker async — 当前版本]
//   ForEachSeed 走 snapshot 模式:锁内只复制 shared_ptr 列表,锁外迭代 visitor。
//   目的是把 RebuildChoiceTable 之类的长 visit 从临界区里搬出去,主线程 AddSeed
//   不被挡住。snapshot 拿到的是 visit 起点的状态;此后 admit 不可见 — 这是异步
//   rebuild 的天然语义,worker 下一轮 batch 会再读最新 corpus。

bool InMemoryCorpusStore::AddSeed(Seed seed)
{
    if (seed.payload.empty()) {
        return false;
    }
    std::unique_lock<std::shared_mutex> lk(mu_);
    if (seeds_.find(seed.seed_id) != seeds_.end()) {
        return false;
    }
    order_.push_back(seed.seed_id);
    seeds_.emplace(seed.seed_id, std::make_shared<Seed>(std::move(seed)));
    return true;
}

SeedHandle InMemoryCorpusStore::GetSeed(uint64_t seed_id) const
{
    std::shared_lock<std::shared_mutex> lk(mu_);
    auto it = seeds_.find(seed_id);
    if (it == seeds_.end()) {
        return nullptr;
    }
    return it->second;
}

void InMemoryCorpusStore::ForEachSeed(const SeedVisitor& visitor) const
{
    if (!visitor) {
        return;
    }
    // 锁内 snapshot:把 shared_ptr<const Seed> 拷出 vector,锁外 visit。
    // shared_ptr 本身的引用计数线程安全,visit 期间 seed 内容只读,无 race。
    std::vector<SeedHandle> snapshot;
    {
        std::shared_lock<std::shared_mutex> lk(mu_);
        snapshot.reserve(order_.size());
        for (const uint64_t seed_id : order_) {
            auto it = seeds_.find(seed_id);
            if (it != seeds_.end() && it->second) {
                snapshot.push_back(it->second);
            }
        }
    }
    for (const auto& h : snapshot) {
        visitor(*h);
    }
}

std::optional<uint64_t> InMemoryCorpusStore::SampleSeedId(std::mt19937_64& rng) const
{
    // SampleSeedId 持 shared_lock 即可:order_ 自身只读,distribution 与 rng 是局部的。
    std::shared_lock<std::shared_mutex> lk(mu_);
    if (order_.empty()) {
        return std::nullopt;
    }
    std::uniform_int_distribution<size_t> dist(0, order_.size() - 1);
    return order_[dist(rng)];
}

void InMemoryCorpusStore::MarkInteresting(uint64_t seed_id)
{
    // MarkInteresting 改写 Seed 字段,与 ForEachSeed snapshot 内 visit 可能并发读同一 Seed。
    // 这里两个写字段都是 trivially copyable int,做 unique_lock 即够;visitor 看到旧值或新值
    // 都不会破坏 invariants(priority/interesting_hits 是单调累加的统计量,容忍短暂读旧)。
    std::unique_lock<std::shared_mutex> lk(mu_);
    auto it = seeds_.find(seed_id);
    if (it == seeds_.end()) {
        return;
    }
    it->second->interesting_hits++;
    it->second->priority++;
}

size_t InMemoryCorpusStore::Size() const
{
    std::shared_lock<std::shared_mutex> lk(mu_);
    return order_.size();
}

// [P4 corpus minimization] Drop a coverage-subsumed seed. unique_lock (same as
// AddSeed). Erase from the map (O(1)) + the order_ vector (O(n) shift). Called
// from CorpusManager::MaybeMinimizeCorpus, which runs in the loop/Tick thread;
// the async admit-worker operates on its own Seed copies (not the store), so
// concurrent admit is safe at the store-lock level. ForEachSeed snapshots hold
// shared_ptr refs, so a seed removed mid-visit stays alive for that visitor.
bool InMemoryCorpusStore::RemoveSeed(uint64_t seed_id)
{
    std::unique_lock<std::shared_mutex> lk(mu_);
    auto it = seeds_.find(seed_id);
    if (it == seeds_.end()) {
        return false;
    }
    seeds_.erase(it);
    order_.erase(std::remove(order_.begin(), order_.end(), seed_id), order_.end());
    return true;
}

// [v2 batch 3 G6] copy-on-write 更新 seed.metadata。
//
// 设计:
//   - unique_lock 下 deep-copy 旧 Seed,在 copy 上跑 updater,然后 emplace 新
//     shared_ptr<Seed> 替换 map slot。
//   - 这样 ForEachSeed snapshot 持的旧 SeedHandle 仍指向旧 Seed,不会 race read
//     mutate 中的 MetadataMap(MetadataMap 内部 std::map / variant 不是 trivially
//     atomic;直接 mutate 会让 reader 看到 partial state → UB)。
//   - MarkInteresting 用直接 mutate 是因为它只动 trivially-copyable int 字段
//     (即便 reader 看到旧/新值也是合法计数);UpdateSeedMetadata 走 metadata 路径
//     要保 type-safe,不能复用 in-place mutate 模式。
//
// 性能:deep copy 整个 Seed(包括 payload 字节数组)— corpus_verify_consumer
// 调用频率低(只在 retry 决策时一次/seed),vs 安全收益,可接受。
//
// updater 在 unique_lock 内执行 — caller **不允许在 callback 内访问 store 其它
// 方法**(deadlock)。详 hpp 注释。
bool InMemoryCorpusStore::UpdateSeedMetadata(uint64_t seed_id, SeedMetadataUpdater updater)
{
    if (!updater) {
        return false;
    }
    std::unique_lock<std::shared_mutex> lk(mu_);
    auto it = seeds_.find(seed_id);
    if (it == seeds_.end() || !it->second) {
        return false;
    }
    // deep-copy 旧 Seed,在 copy 上跑 updater。
    auto new_seed = std::make_shared<Seed>(*it->second);
    updater(new_seed->metadata);
    it->second = std::move(new_seed);
    return true;
}

} // namespace refuzz::fuzzer

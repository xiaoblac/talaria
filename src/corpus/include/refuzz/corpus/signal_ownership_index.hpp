#pragma once

#include <cstdint>
#include <unordered_map>

namespace refuzz::fuzzer {

// [coverage-ownership bound] 语料"最小覆盖集"的边-owner 快照,由周期性的批量选举
// (CorpusManager::EstablishInvariantFromStore,= syz signal.Minimize 的移植)重建。
//
// 不变量:每条被覆盖的边(signal element)恰好记一个最优 owner。"最优"判据
// (BetterOwner):per-edge prio 高 > payload 小 > seed_id 小(port 自 syz
// signal.Minimize 的 per-element best-prio,success-hit 边集中所有权)。
//
// 角色边界:本快照**只是覆盖事实**(谁最优覆盖每条边),用于 (a) 暴露
// corpus_owned_edges 指标、(b) 给 sweep 的抛弃判定提供 owner 表。它**不门准入、
// 也不存"变异价值"**——那条轴属于 scheduler/MAB 层。
//
// 线程:单写者(CorpusManager Tick 线程),无内部锁。
class SignalOwnershipIndex {
public:
    struct OwnerRecord {
        std::uint64_t seed_id = 0;
        std::uint8_t  prio    = 0;  // owner 在该边上的 per-edge prio
        std::uint32_t size    = 0;  // owner payload 大小(tie-break)
    };

    // 用预先算好的 edge→owner 表整体替换快照(批量 sweep 的产物)。
    void Install(std::unordered_map<std::uint64_t, OwnerRecord> owner_of_edge)
    {
        owner_of_edge_ = std::move(owner_of_edge);
    }

    void Clear() { owner_of_edge_.clear(); }

    // corpus 覆盖的 distinct 稳定边数(= 语料大小的内生上界解释量)。
    std::size_t OwnedEdges() const { return owner_of_edge_.size(); }

    // per-edge best-owner 判据。static,CorpusManager 的批量选举复用。
    static bool BetterOwner(std::uint8_t prio, std::uint32_t size, std::uint64_t id,
                            const OwnerRecord& cur)
    {
        // 高 prio 胜;tie → 小程序胜(syz favors smaller);tie → 小 seed_id(确定性/更老)。
        if (prio != cur.prio) return prio > cur.prio;
        if (size != cur.size) return size < cur.size;
        return id < cur.seed_id;
    }

private:
    std::unordered_map<std::uint64_t /*edge*/, OwnerRecord> owner_of_edge_;
};

}  // namespace refuzz::fuzzer

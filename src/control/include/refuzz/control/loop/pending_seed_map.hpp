#pragma once
// [Step 6 stage 清场] PendingSeedMap —— 从退役的 stages/triage_stage.hpp 迁出。
//
// 候选区 / triage-pending 的显式运行时共享态:纯 seed_id → Seed 映射(无 executor_id
// 概念,故不复用 InflightRegistry)。**loop 拥有**实例(FuzzerLoop::catch_all_pending_ /
// assembler bundle.pending_seed_map);candidate feeder job + orchestrator(物化 boot
// corpus)按引用借用。为避免跨组件借用时形成外部锁约定,map 自带互斥。

#include "refuzz/program/seed.hpp"

#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <utility>

namespace refuzz::control {

class PendingSeedMap {
public:
    void Put(refuzz::fuzzer::Seed s)
    {
        const auto id = s.seed_id;
        std::lock_guard<std::mutex> lk(mu_);
        map_.insert_or_assign(id, std::move(s));
    }

    // 取出并从 map 移除（典型用法）。
    std::optional<refuzz::fuzzer::Seed> Take(std::uint64_t seed_id)
    {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = map_.find(seed_id);
        if (it == map_.end()) return std::nullopt;
        auto s = std::move(it->second);
        map_.erase(it);
        return s;
    }

    // 拷贝读取（不删除）。
    std::optional<refuzz::fuzzer::Seed> Peek(std::uint64_t seed_id) const
    {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = map_.find(seed_id);
        if (it == map_.end()) return std::nullopt;
        return it->second;
    }

    void Erase(std::uint64_t seed_id)
    {
        std::lock_guard<std::mutex> lk(mu_);
        map_.erase(seed_id);
    }
    std::size_t Size() const
    {
        std::lock_guard<std::mutex> lk(mu_);
        return map_.size();
    }
    void Clear()
    {
        std::lock_guard<std::mutex> lk(mu_);
        map_.clear();
    }

    // 枚举所有暂存 seed（只读访问）。candidate feeder 的 boot-candidate bootstrap
    // 用它逐个 emit ② verify。单线程访问,无锁。
    void ForEach(const std::function<void(const refuzz::fuzzer::Seed&)>& fn) const
    {
        if (!fn) return;
        std::lock_guard<std::mutex> lk(mu_);
        for (const auto& [id, seed] : map_) {
            (void)id;
            fn(seed);
        }
    }
    bool Contains(std::uint64_t seed_id) const
    {
        std::lock_guard<std::mutex> lk(mu_);
        return map_.find(seed_id) != map_.end();
    }

private:
    mutable std::mutex mu_;
    std::unordered_map<std::uint64_t, refuzz::fuzzer::Seed> map_;
};

} // namespace refuzz::control

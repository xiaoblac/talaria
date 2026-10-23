#include "refuzz/queue/task_queue.hpp"

#include "refuzz/core/time.hpp"

#include <chrono>
#include <utility>

namespace refuzz::queue {

// 按 tier 尾部入队,O(1) 持锁。tier 默认 Triage(③)(既有直接 Push 调用点全走此路 → 单档
// FIFO,逐字节等价旧纯 FIFO);生产者/arbiter 据语义打对应档。important 不再影响顺序。
bool InMemoryTaskQueue::Push(HostFuzzTask task, TaskTier tier)
{
    std::lock_guard<std::mutex> lock(mu_);
    if (closed_) {
        return false;
    }
    if (task.executor_id == 0) {
        return false;
    }
    if (task.trace.sampled) {
        task.trace.task_queue_push_ts_us = refuzz::core::MonotonicNowUs();
    }
    tiers_[static_cast<std::size_t>(tier)].push_back(std::move(task));
    cv_.notify_one();
    return true;
}

HostFuzzTask InMemoryTaskQueue::PopFront(std::size_t idx)
{
    HostFuzzTask task = std::move(tiers_[idx].front());
    tiers_[idx].pop_front();
    if (task.trace.sampled) {
        task.trace.task_queue_pop_ts_us = refuzz::core::MonotonicNowUs();
    }
    return task;
}

std::optional<HostFuzzTask> InMemoryTaskQueue::Pop(std::chrono::milliseconds timeout)
{
    std::unique_lock<std::mutex> lock(mu_);
    const auto deadline = std::chrono::steady_clock::now() + timeout;

    while (true) {
        // 严格 Order:① CandidateTriage ② Candidate ③ Triage —— 高档非空必先给。
        for (std::size_t t = static_cast<std::size_t>(TaskTier::CandidateTriage);
             t <= static_cast<std::size_t>(TaskTier::Triage); ++t) {
            if (!tiers_[t].empty()) {
                return PopFront(t);
            }
        }
        // ④ Smash 与 ⑤ Explore:Alternate(3)。两档都有 → 每 3 次让 1 次给 Explore(镜像 syz
        // `Alternate.Next` 每 nth 次返回 nil → 落到 genFuzz);只有一档非空 → 直接给,不空转。
        const std::size_t kSmash   = static_cast<std::size_t>(TaskTier::Smash);
        const std::size_t kExplore = static_cast<std::size_t>(TaskTier::Explore);
        const bool has_smash   = !tiers_[kSmash].empty();
        const bool has_explore = !tiers_[kExplore].empty();
        if (has_smash && has_explore) {
            ++alternate_counter_;
            return (alternate_counter_ % kAlternateNth == 0) ? PopFront(kExplore)
                                                             : PopFront(kSmash);
        }
        if (has_smash) {
            return PopFront(kSmash);
        }
        if (has_explore) {
            return PopFront(kExplore);
        }
        // 全档皆空。
        if (closed_) {
            return std::nullopt;
        }
        if (cv_.wait_until(lock, deadline) == std::cv_status::timeout) {
            return std::nullopt;
        }
    }
}

size_t InMemoryTaskQueue::PendingSize()
{
    std::lock_guard<std::mutex> lock(mu_);
    std::size_t total = 0;
    for (const auto& d : tiers_) {
        total += d.size();
    }
    return total;
}

void InMemoryTaskQueue::Close()
{
    {
        std::lock_guard<std::mutex> lock(mu_);
        closed_ = true;
    }
    cv_.notify_all();
}

} // namespace refuzz::queue

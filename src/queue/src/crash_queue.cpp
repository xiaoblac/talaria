#include "refuzz/queue/crash_queue.hpp"

namespace refuzz::queue {

InMemoryCrashQueue::InMemoryCrashQueue(size_t max_pending)
    : max_pending_(max_pending == 0 ? 1 : max_pending)
{}

bool InMemoryCrashQueue::Push(refuzz::proto::CombinedCrashEvent event)
{
    std::lock_guard<std::mutex> lock(mu_);
    // Close 后或队列已满均计为 drop
    if (closed_ || queue_.size() >= max_pending_) {
        dropped_count_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    queue_.push_back(std::move(event));
    cv_.notify_one();
    return true;
}

std::optional<refuzz::proto::CombinedCrashEvent> InMemoryCrashQueue::Pop(
    std::chrono::milliseconds timeout)
{
    std::unique_lock<std::mutex> lock(mu_);
    const auto deadline = std::chrono::steady_clock::now() + timeout;

    while (true) {
        if (!queue_.empty()) {
            refuzz::proto::CombinedCrashEvent event = std::move(queue_.front());
            queue_.pop_front();
            return event;
        }
        // Close 后队列为空则立即返回，不再等待 timeout（drain 能力由非空分支保留）
        if (closed_) {
            return std::nullopt;
        }
        if (cv_.wait_until(lock, deadline) == std::cv_status::timeout) {
            return std::nullopt;
        }
    }
}

size_t InMemoryCrashQueue::PendingSize()
{
    std::lock_guard<std::mutex> lock(mu_);
    return queue_.size();
}

void InMemoryCrashQueue::Close()
{
    {
        std::lock_guard<std::mutex> lock(mu_);
        closed_ = true;
    }
    cv_.notify_all();
}

uint64_t InMemoryCrashQueue::DroppedCount() const
{
    return dropped_count_.load(std::memory_order_acquire);
}

} // namespace refuzz::queue

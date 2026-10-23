#include "refuzz/crash/repro/core/repro_queue.hpp"

#include <iostream>
#include "refuzz/logging/host_logger.hpp"

namespace refuzz::crash {

InMemoryReproQueue::InMemoryReproQueue(size_t max_pending)
    : max_pending_(max_pending)
{}

bool InMemoryReproQueue::Push(CrashContext ctx)
{
    std::lock_guard<std::mutex> lk(mu_);

    if (closed_) {
        refuzz::logging::HostLineBuilder("ReproQueue", "drop") << "incident=" << ctx.incident_id
                  << " reason=queue_closed pending=" << queue_.size()
                  << " capacity=" << max_pending_ << "\n";
        return false;
    }

    if (queue_.size() >= max_pending_) {
        dropped_count_.fetch_add(1, std::memory_order_relaxed);
        refuzz::logging::HostLineBuilder("ReproQueue", "drop") << "incident=" << ctx.incident_id
                  << " reason=queue_full pending=" << queue_.size()
                  << " capacity=" << max_pending_ << "\n";
        return false;
    }

    queue_.push_back(std::move(ctx));
    cv_.notify_one();
    return true;
}

std::optional<CrashContext> InMemoryReproQueue::Pop(std::chrono::milliseconds timeout)
{
    std::unique_lock<std::mutex> lk(mu_);
    cv_.wait_for(lk, timeout, [this]() {
        return !queue_.empty() || closed_;
    });

    if (!queue_.empty()) {
        auto ctx = std::move(queue_.front());
        queue_.pop_front();
        return ctx;
    }

    return std::nullopt;
}

size_t InMemoryReproQueue::PendingSize()
{
    std::lock_guard<std::mutex> lk(mu_);
    return queue_.size();
}

void InMemoryReproQueue::Close()
{
    {
        std::lock_guard<std::mutex> lk(mu_);
        closed_ = true;
    }
    cv_.notify_all();
}

uint64_t InMemoryReproQueue::DroppedCount() const
{
    return dropped_count_.load(std::memory_order_relaxed);
}

ReproQueueSnapshot InMemoryReproQueue::Snapshot() const
{
    std::lock_guard<std::mutex> lk(mu_);
    return ReproQueueSnapshot{
        .pending = queue_.size(),
        .capacity = max_pending_,
        .closed = closed_,
        .dropped = dropped_count_.load(std::memory_order_relaxed),
    };
}

} // namespace refuzz::crash

#include "refuzz/queue/event_queue.hpp"

namespace refuzz::queue {

bool InMemoryEventQueue::Push(refuzz::core::channel_contract::ChannelEvent event)
{
    std::unique_lock<std::mutex> lk(mu_);
    if (closed_) {
        return false;
    }
    queue_.push_back(std::move(event));
    lk.unlock();
    cv_.notify_one();
    return true;
}

std::optional<refuzz::core::channel_contract::ChannelEvent>
InMemoryEventQueue::Pop(std::chrono::milliseconds timeout)
{
    std::unique_lock<std::mutex> lk(mu_);
    // 队列非空或已关闭时立即返回；否则等待 timeout。
    cv_.wait_for(lk, timeout, [this] {
        return !queue_.empty() || closed_;
    });
    if (queue_.empty()) {
        return std::nullopt;
    }
    auto event = std::move(queue_.front());
    queue_.pop_front();
    return event;
}

size_t InMemoryEventQueue::PendingSize() const
{
    std::unique_lock<std::mutex> lk(mu_);
    return queue_.size();
}

void InMemoryEventQueue::Close()
{
    {
        std::unique_lock<std::mutex> lk(mu_);
        closed_ = true;
    }
    cv_.notify_all();
}

} // namespace refuzz::queue

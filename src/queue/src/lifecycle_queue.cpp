#include "refuzz/queue/lifecycle_queue.hpp"

#include <utility>

namespace refuzz::queue {

bool InMemoryLifecycleQueue::Push(
    refuzz::core::channel_contract::RequestLifecycleEvent ev)
{
    std::lock_guard<std::mutex> lk(mu_);
    if (closed_) {
        return false;
    }
    queue_.push_back(ev);
    return true;
}

std::vector<refuzz::core::channel_contract::RequestLifecycleEvent>
InMemoryLifecycleQueue::DrainAll()
{
    std::deque<refuzz::core::channel_contract::RequestLifecycleEvent> taken;
    {
        std::lock_guard<std::mutex> lk(mu_);
        taken.swap(queue_);
    }
    return {std::make_move_iterator(taken.begin()),
            std::make_move_iterator(taken.end())};
}

size_t InMemoryLifecycleQueue::PendingSize() const
{
    std::lock_guard<std::mutex> lk(mu_);
    return queue_.size();
}

void InMemoryLifecycleQueue::Close()
{
    std::lock_guard<std::mutex> lk(mu_);
    closed_ = true;
}

} // namespace refuzz::queue

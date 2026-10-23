#include "refuzz/queue/result_queue.hpp"

#include <chrono>

namespace refuzz::queue {

bool InMemoryResultQueue::Push(proto::ExecResult result)
{
    std::lock_guard<std::mutex> lock(mu_);
    // Close 后拒绝新结果
    if (closed_) {
        return false;
    }
    queue_.push_back(std::move(result));
    cv_.notify_one();
    return true;
}

std::optional<proto::ExecResult> InMemoryResultQueue::Pop(std::chrono::milliseconds timeout)
{
    std::unique_lock<std::mutex> lock(mu_);
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (true) {
        if (!queue_.empty()) {
            proto::ExecResult result = std::move(queue_.front());
            queue_.pop_front();
            return result;
        }
        // Close 后队列为空则立即返回，不再等待 timeout
        if (closed_) {
            return std::nullopt;
        }
        if (cv_.wait_until(lock, deadline) == std::cv_status::timeout) {
            return std::nullopt;
        }
    }
}

void InMemoryResultQueue::Close()
{
    {
        std::lock_guard<std::mutex> lock(mu_);
        closed_ = true;
    }
    cv_.notify_all();
}

} // namespace refuzz::queue

#pragma once

// ChannelEvent 桥接队列（无多态）：Executor 转发事件、FuzzerLoop 消费。
// 与 InMemoryResultQueue 同构：mutex + condition_variable + deque + closed_。

#include "refuzz/core/channel_contract.hpp"

#include <chrono>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <optional>

namespace refuzz::queue {

class InMemoryEventQueue final {
public:
    bool Push(refuzz::core::channel_contract::ChannelEvent event);
    std::optional<refuzz::core::channel_contract::ChannelEvent> Pop(std::chrono::milliseconds timeout);
    size_t PendingSize() const;
    void Close();

private:
    mutable std::mutex mu_;
    std::condition_variable cv_;
    std::deque<refuzz::core::channel_contract::ChannelEvent> queue_;
    bool closed_ = false;
};

} // namespace refuzz::queue

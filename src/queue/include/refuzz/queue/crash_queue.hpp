#pragma once

// Crash 合并事件队列（无多态）：FaultSink / Pipeline 之间的有界缓冲。

#include "refuzz/proto_domain/combined_crash_event.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <deque>
#include <mutex>
#include <optional>

namespace refuzz::queue {

class InMemoryCrashQueue final {
public:
    explicit InMemoryCrashQueue(size_t max_pending = 256);

    bool Push(refuzz::proto::CombinedCrashEvent event);
    std::optional<refuzz::proto::CombinedCrashEvent> Pop(
        std::chrono::milliseconds timeout);
    size_t PendingSize();
    void Close();

    uint64_t DroppedCount() const;

private:
    size_t max_pending_ = 256;
    std::mutex mu_;
    std::condition_variable cv_;
    std::deque<refuzz::proto::CombinedCrashEvent> queue_;
    bool closed_ = false;
    std::atomic<uint64_t> dropped_count_{0};
};

} // namespace refuzz::queue

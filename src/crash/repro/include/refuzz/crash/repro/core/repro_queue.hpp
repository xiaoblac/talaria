#pragma once

#include "refuzz/crash/infra/crash_context.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <deque>
#include <mutex>
#include <optional>

namespace refuzz::crash {

struct ReproQueueSnapshot {
    size_t pending = 0;
    size_t capacity = 0;
    bool closed = false;
    uint64_t dropped = 0;
};

class IReproQueue {
public:
    virtual ~IReproQueue() = default;
    virtual bool Push(CrashContext ctx) = 0;
    virtual std::optional<CrashContext> Pop(std::chrono::milliseconds timeout) = 0;
    virtual size_t PendingSize() = 0;
    virtual void Close() = 0;
    virtual ReproQueueSnapshot Snapshot() const = 0;
};

class InMemoryReproQueue final : public IReproQueue {
public:
    explicit InMemoryReproQueue(size_t max_pending = 64);

    bool Push(CrashContext ctx) override;
    std::optional<CrashContext> Pop(std::chrono::milliseconds timeout) override;
    size_t PendingSize() override;
    void Close() override;
    uint64_t DroppedCount() const;
    ReproQueueSnapshot Snapshot() const override;

private:
    size_t max_pending_ = 64;
    mutable std::mutex mu_;
    std::condition_variable cv_;
    std::deque<CrashContext> queue_;
    bool closed_ = false;
    std::atomic<uint64_t> dropped_count_{0};
};

} // namespace refuzz::crash

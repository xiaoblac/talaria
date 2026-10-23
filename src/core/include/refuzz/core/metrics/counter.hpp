#pragma once

#include <atomic>
#include <cstdint>

namespace refuzz::core::metrics {

// 单调递增计数器(uint64)。lock-free,任意线程可调 Inc()。
// 由 MetricRegistry 拥有并返回稳定引用;publisher 不直接构造。
class Counter {
public:
    Counter() = default;
    Counter(const Counter&) = delete;
    Counter& operator=(const Counter&) = delete;
    Counter(Counter&&) = delete;
    Counter& operator=(Counter&&) = delete;

    void Inc(uint64_t v = 1) noexcept
    {
        value_.fetch_add(v, std::memory_order_relaxed);
    }

    uint64_t Value() const noexcept
    {
        return value_.load(std::memory_order_relaxed);
    }

private:
    std::atomic<uint64_t> value_{0};
};

} // namespace refuzz::core::metrics

#pragma once

#include <atomic>
#include <cstdint>

namespace refuzz::core::metrics {

// 瞬时值(int64,可升可降)。lock-free,任意线程可调 Set/Add。
// 由 MetricRegistry 拥有并返回稳定引用;publisher 不直接构造。
class Gauge {
public:
    Gauge() = default;
    Gauge(const Gauge&) = delete;
    Gauge& operator=(const Gauge&) = delete;
    Gauge(Gauge&&) = delete;
    Gauge& operator=(Gauge&&) = delete;

    void Set(int64_t v) noexcept
    {
        value_.store(v, std::memory_order_relaxed);
    }

    void Add(int64_t delta) noexcept
    {
        value_.fetch_add(delta, std::memory_order_relaxed);
    }

    int64_t Value() const noexcept
    {
        return value_.load(std::memory_order_relaxed);
    }

private:
    std::atomic<int64_t> value_{0};
};

} // namespace refuzz::core::metrics

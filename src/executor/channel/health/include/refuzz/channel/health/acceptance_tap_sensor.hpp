#pragma once

// AcceptanceTapSensor — Phase H 验收 Sensor
//
// 零副作用的 Sensor：每次轮询递增 tick_count_，不上报任何故障。
// 用途：证明新 Assembler 可在不改动既有代码的前提下混入额外 Sensor。

#include "refuzz/channel/health/sensor.hpp"
#include "refuzz/channel/result.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <string_view>
#include <thread>

namespace refuzz::channel::health {

class AcceptanceTapSensor final : public IHealthSensor {
public:
    explicit AcceptanceTapSensor(
        std::chrono::milliseconds poll_interval = std::chrono::milliseconds{500})
        : poll_interval_(poll_interval) {}

    ~AcceptanceTapSensor() override { Stop(); }

    AcceptanceTapSensor(const AcceptanceTapSensor&)            = delete;
    AcceptanceTapSensor& operator=(const AcceptanceTapSensor&) = delete;

    std::string_view Name() const override { return "acceptance_tap"; }

    Result<void> Start(HealthPublisher& publisher) override {
        publisher_ = &publisher;
        stop_flag_.store(false, std::memory_order_relaxed);
        thread_ = std::thread([this] { ThreadMain(); });
        return Result<void>::Ok();
    }

    void Stop() override {
        stop_flag_.store(true, std::memory_order_relaxed);
        cv_.notify_all();
        if (thread_.joinable()) thread_.join();
        if (publisher_) publisher_->NotifyThreadExiting();
        publisher_ = nullptr;
    }

    void Poke() override { cv_.notify_all(); }

    uint64_t TickCount() const noexcept {
        return tick_count_.load(std::memory_order_relaxed);
    }

private:
    void ThreadMain() {
        while (!stop_flag_.load(std::memory_order_relaxed)) {
            if (publisher_ && publisher_->IsSuspended()) {
                publisher_->ParkUntilResumed();
                continue;
            }
            ++tick_count_;
            std::unique_lock<std::mutex> lk(cv_mutex_);
            cv_.wait_for(lk, poll_interval_, [this] {
                return stop_flag_.load(std::memory_order_relaxed);
            });
        }
    }

    std::chrono::milliseconds poll_interval_;
    HealthPublisher*          publisher_ = nullptr;
    std::atomic<uint64_t>     tick_count_{0};
    std::atomic<bool>         stop_flag_{false};
    std::thread               thread_;
    std::mutex                cv_mutex_;
    std::condition_variable   cv_;
};

} // namespace refuzz::channel::health

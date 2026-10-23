#pragma once

// WedgeRelaySensor — Poll→health bridge for the XiUOS wedge timeout (Stage 3).
//
// Detection of "submitted program never returned its RESULT" lives in the data
// plane's Poll() (per-program wall-clock timeout — the de-siloed form of
// XiuosFuzzSession::Step's wedge_initial_drain_ms deadline). Poll frees the
// slot AND latches a wedge flag. But the standard Channel recovery path (reboot)
// is triggered ONLY by health crash events (channel.cpp DrainCrashEvents), never
// by an abnormal DispatchOutcome. So this thin sensor is the only missing link:
// it polls an injected test-and-clear closure (XiuosUartDataPlane::
// ConsumeWedgePending — atomic, NO socket access, so it cannot race the UART
// backbone the way a heartbeat probe would) and, when a wedge was latched,
// publishes one kWorkerDead crash event → recovery reboots QEMU.
//
// It does NOT detect anything itself and never touches the worker; it only
// relays the flag Poll already set.

#include "refuzz/channel/health/sensor.hpp"
#include "refuzz/channel/result.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string_view>
#include <thread>

namespace refuzz::channel::health {

struct WedgeRelaySensorConfig {
    std::chrono::milliseconds check_interval{500};
    std::uint32_t             worker_id = 0;
};

class WedgeRelaySensor final : public IHealthSensor {
public:
    // consume_wedge: atomic test-and-clear; returns true iff a wedge was latched
    // since the last call. Must be cheap + non-blocking + no socket access.
    WedgeRelaySensor(std::function<bool()>   consume_wedge,
                     WedgeRelaySensorConfig  config) noexcept;

    ~WedgeRelaySensor() override;

    WedgeRelaySensor(const WedgeRelaySensor&)            = delete;
    WedgeRelaySensor& operator=(const WedgeRelaySensor&) = delete;

    std::string_view Name() const override { return "wedge_relay"; }

    Result<void> Start(HealthPublisher& publisher) override;
    void         Stop() override;
    void         Poke() override;

private:
    void ThreadMain();

    std::function<bool()>  consume_wedge_;
    WedgeRelaySensorConfig config_;
    HealthPublisher*       publisher_ = nullptr;

    std::thread             thread_;
    std::atomic<bool>       stop_flag_{false};
    std::condition_variable cv_;
    std::mutex              cv_mutex_;
    bool                    thread_running_ = false;
};

} // namespace refuzz::channel::health

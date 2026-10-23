#pragma once

#include "refuzz/core/control.hpp"
#include "refuzz/core/metrics/metric_registry.hpp"

#include <chrono>
#include <deque>

namespace refuzz::telemetry {

struct PolicyMonitorConfig {
    std::chrono::seconds min_dwell{300};
    int window_size = 10;
    double stall_threshold = 0.01;
    int required_windows = 3;
};

class PolicyMonitor {
public:
    explicit PolicyMonitor(core::IPolicyControl& control,
                           PolicyMonitorConfig config = {});

    void Tick(const core::metrics::MetricRegistry& r);
    uint64_t TriggerCount() const;

private:
    bool IsStalled() const;

    core::IPolicyControl& control_;
    std::deque<double> cov_rate_window_;
    std::chrono::steady_clock::time_point last_switch_{};
    std::chrono::seconds min_dwell_{300};
    int window_size_ = 10;
    double stall_threshold_ = 0.01;
    int consecutive_stall_windows_ = 0;
    int required_windows_ = 3;
    uint64_t trigger_count_ = 0;
    uint64_t last_cov_total_ = 0;
    uint64_t last_consumed_ = 0;
};

} // namespace refuzz::telemetry

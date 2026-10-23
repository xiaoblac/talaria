#pragma once

#include "refuzz/core/control.hpp"

#include <atomic>
#include <chrono>
#include <deque>
#include <string>

namespace refuzz::core::metrics {
class MetricRegistry;
}

namespace refuzz::telemetry {

class RunStateStore;

enum class SystemPhase : uint8_t {
    kNormal,
    kDegraded,
    kRecovering,
    kStalled,
};

const char* SystemPhaseName(SystemPhase phase);

struct PolicyProfile {
    std::string mutation_policy;
    std::string scheduling_policy;
    std::string corpus_policy;
};

struct PolicyEngineConfig {
    std::chrono::seconds min_dwell{60};
    int window_size = 10;
    double stall_threshold = 0.01;
    int required_stall_windows = 3;
    double degraded_channel_ratio = 0.5;
    PolicyProfile normal{
        "uniform_random",
        "round_robin",
        "all_filters",
    };
    PolicyProfile stalled{
        "coverage_adaptive",
        "priority",
        "no_filter",
    };
};

class PolicyEngine {
public:
    // [v2 — 当前版本] registry 取代 RuntimeSnapshot 作为数据源
    PolicyEngine(refuzz::core::IPolicyControl& control,
                 RunStateStore* store,
                 const refuzz::core::metrics::MetricRegistry& registry,
                 PolicyEngineConfig config = {});

    // [v2 — 当前版本] Evaluate 不再需要 snapshot 参数，直接读 registry
    void Evaluate();

    SystemPhase CurrentPhase() const;
    uint64_t SwitchCount() const;

private:
    void UpdateCovBaseline();
    bool CheckStalled();
    SystemPhase DeterminePhase();
    bool CooldownPassed() const;
    void ApplyProfile(const PolicyProfile& profile);
    // [v2] 替代 SnapshotMatchesProfile，从 registry 反查当前策略
    bool CurrentPoliciesMatch(const PolicyProfile& profile) const;

    refuzz::core::IPolicyControl& control_;
    RunStateStore* store_ = nullptr;
    // [v2] registry 取代 snapshot 参数
    const refuzz::core::metrics::MetricRegistry& registry_;
    PolicyEngineConfig config_{};
    std::deque<double> cov_rate_window_;
    std::chrono::steady_clock::time_point last_switch_{};
    uint64_t last_cov_total_ = 0;
    uint64_t last_consumed_ = 0;
    int consecutive_stall_windows_ = 0;
    std::atomic<SystemPhase> current_phase_{SystemPhase::kNormal};
    std::atomic<uint64_t> switch_count_{0};
};

} // namespace refuzz::telemetry

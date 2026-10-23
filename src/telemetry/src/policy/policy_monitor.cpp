#include "refuzz/telemetry/policy/policy_monitor.hpp"

#include "refuzz/core/metrics/labels.hpp"

#include <string_view>

namespace refuzz::telemetry {

namespace {

// 线性扫描可接受:fuzzer series 上限约 25 个,monitor 以 1Hz 运行。
uint64_t CounterValue(const core::metrics::MetricRegistry& r,
                      std::string_view name,
                      core::metrics::Labels labels = {})
{
    auto samples = r.CollectPrefix(name);
    for (const auto& s : samples) {
        if (s.name == name && s.labels == labels) {
            return static_cast<uint64_t>(s.value);
        }
    }
    return 0;
}

} // namespace

PolicyMonitor::PolicyMonitor(core::IPolicyControl& control,
                             PolicyMonitorConfig config)
    : control_(control)
    , min_dwell_(config.min_dwell)
    , window_size_(config.window_size)
    , stall_threshold_(config.stall_threshold)
    , required_windows_(config.required_windows)
{}

void PolicyMonitor::Tick(const core::metrics::MetricRegistry& r)
{
    const auto now = std::chrono::steady_clock::now();

    // terminal = completion+abnormal,即真正跑完的 task 数,排除 fault 事件污染。
    const uint64_t cov_total = CounterValue(r, "fuzzer.cov.new_total");
    const uint64_t terminal =
        CounterValue(r, "fuzzer.results", {{"kind", "completion"}}) +
        CounterValue(r, "fuzzer.results", {{"kind", "abnormal"}});

    double cov_rate = 0.0;
    if (terminal > last_consumed_) {
        const uint64_t d_cov = cov_total - last_cov_total_;
        const uint64_t d_cons = terminal - last_consumed_;
        cov_rate = d_cons > 0 ? static_cast<double>(d_cov) / static_cast<double>(d_cons) : 0.0;
    }
    last_cov_total_ = cov_total;
    last_consumed_ = terminal;

    cov_rate_window_.push_back(cov_rate);
    if (static_cast<int>(cov_rate_window_.size()) > window_size_) {
        cov_rate_window_.pop_front();
    }

    if (now - last_switch_ < min_dwell_) {
        return;
    }

    if (IsStalled()) {
        consecutive_stall_windows_++;
    } else {
        consecutive_stall_windows_ = 0;
    }

    if (consecutive_stall_windows_ >= required_windows_) {
        control_.SwitchMutationPolicy("coverage_adaptive");
        control_.SwitchSchedulingPolicy("priority");
        // 停滞时放宽 corpus 准入，提升语料多样性。
        control_.SwitchCorpusAdmissionPolicy("no_filter");
        last_switch_ = now;
        consecutive_stall_windows_ = 0;
        trigger_count_++;
    }
}

uint64_t PolicyMonitor::TriggerCount() const
{
    return trigger_count_;
}

bool PolicyMonitor::IsStalled() const
{
    if (static_cast<int>(cov_rate_window_.size()) < window_size_) {
        return false;
    }
    double sum = 0.0;
    for (double rate : cov_rate_window_) {
        sum += rate;
    }
    const double avg = sum / static_cast<double>(cov_rate_window_.size());
    return avg < stall_threshold_;
}

} // namespace refuzz::telemetry

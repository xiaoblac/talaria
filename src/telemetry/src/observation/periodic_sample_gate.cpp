#include "refuzz/telemetry/observation/periodic_sample_gate.hpp"

#include <stdexcept>

namespace refuzz::telemetry {

PeriodicSampleGate::PeriodicSampleGate(
    std::chrono::seconds interval,
    std::chrono::steady_clock::time_point start)
    : interval_(interval)
    , start_(start)
    , next_deadline_(start + interval)
{
    if (interval_ <= std::chrono::seconds::zero()) {
        throw std::invalid_argument("PeriodicSampleGate interval must be positive");
    }
}

std::uint64_t PeriodicSampleGate::ElapsedSeconds(
    std::chrono::steady_clock::time_point now) const
{
    if (now <= start_) {
        return 0;
    }
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(now - start_).count());
}

std::optional<std::uint64_t> PeriodicSampleGate::Poll(
    std::chrono::steady_clock::time_point now)
{
    if (now < next_deadline_) {
        return std::nullopt;
    }
    const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start_);
    const auto completed_intervals = elapsed.count() / interval_.count();
    next_deadline_ = start_ + interval_ * (completed_intervals + 1);
    return static_cast<std::uint64_t>(elapsed.count());
}

} // namespace refuzz::telemetry

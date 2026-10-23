#pragma once

#include <chrono>
#include <cstdint>
#include <optional>

namespace refuzz::telemetry {

class PeriodicSampleGate {
public:
    PeriodicSampleGate(
        std::chrono::seconds interval,
        std::chrono::steady_clock::time_point start =
            std::chrono::steady_clock::now());

    std::optional<std::uint64_t> Poll(
        std::chrono::steady_clock::time_point now);
    std::uint64_t ElapsedSeconds(
        std::chrono::steady_clock::time_point now) const;

private:
    std::chrono::seconds interval_;
    std::chrono::steady_clock::time_point start_;
    std::chrono::steady_clock::time_point next_deadline_;
};

} // namespace refuzz::telemetry

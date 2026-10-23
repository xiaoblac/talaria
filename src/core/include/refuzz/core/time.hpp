#pragma once

#include <chrono>
#include <cstdint>

namespace refuzz::core {

inline uint64_t MonotonicNowUs() noexcept
{
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch())
            .count());
}

} // namespace refuzz::core

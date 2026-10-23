#pragma once

#include <cstdint>

namespace refuzz::core::metrics {

enum class MetricKind : uint8_t {
    kCounter,
    kGauge,
};

} // namespace refuzz::core::metrics

#include "refuzz/core/metrics/metric_lookup.hpp"

#include <string>

namespace refuzz::core::metrics {

uint64_t CounterValue(const MetricRegistry& registry,
                      std::string_view name,
                      const Labels& labels)
{
    const auto samples = registry.CollectPrefix(std::string(name));
    for (const auto& s : samples) {
        if (s.name == name && s.labels == labels) {
            return static_cast<uint64_t>(s.value);
        }
    }
    return 0;
}

int64_t GaugeValue(const MetricRegistry& registry,
                   std::string_view name,
                   const Labels& labels)
{
    const auto samples = registry.CollectPrefix(std::string(name));
    for (const auto& s : samples) {
        if (s.name == name && s.labels == labels) {
            return s.value;
        }
    }
    return 0;
}

} // namespace refuzz::core::metrics

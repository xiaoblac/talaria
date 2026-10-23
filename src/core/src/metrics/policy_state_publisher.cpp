#include "refuzz/core/metrics/policy_state_publisher.hpp"

#include "refuzz/core/metrics/metric_registry.hpp"

#include <utility>

namespace refuzz::core::metrics {

void PolicyStatePublisher::Bind(MetricRegistry& registry)
{
    std::lock_guard<std::mutex> lk(mu_);
    registry_ = &registry;
}

void PolicyStatePublisher::Set(std::string_view kind, std::string_view name)
{
    if (name.empty()) {
        return;
    }

    std::lock_guard<std::mutex> lk(mu_);
    if (registry_ == nullptr) {
        return;
    }

    const std::string kind_str(kind);
    const std::string name_str(name);

    // No-op if this kind already has name as current.
    auto cur_it = current_.find(kind_str);
    if (cur_it != current_.end() && cur_it->second == name_str) {
        return;
    }

    auto& kind_cache = cache_[kind_str];

    // Look up or create new Gauge.
    Gauge* new_gauge = nullptr;
    auto gauge_it = kind_cache.find(name_str);
    if (gauge_it != kind_cache.end()) {
        new_gauge = gauge_it->second;
    } else {
        new_gauge = &registry_->GaugeOf("fuzzer.current_policy",
                                         {{"kind", kind_str}, {"name", name_str}});
        kind_cache.emplace(name_str, new_gauge);
    }

    // Zero out previous gauge if any.
    if (cur_it != current_.end() && !cur_it->second.empty()) {
        auto prev_it = kind_cache.find(cur_it->second);
        if (prev_it != kind_cache.end()) {
            prev_it->second->Set(0);
        }
    }

    // Set new gauge to 1 and update current.
    new_gauge->Set(1);
    if (cur_it != current_.end()) {
        cur_it->second = name_str;
    } else {
        current_.emplace(kind_str, name_str);
    }
}

} // namespace refuzz::core::metrics

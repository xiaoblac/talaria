#pragma once

#include "refuzz/core/metrics/gauge.hpp"

#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>

namespace refuzz::core::metrics {

class MetricRegistry;

// One-hot Gauge publisher for "fuzzer.current_policy{kind, name}".
//
// On Set(kind, name):
//   - If kind already has name as current, no-op.
//   - Looks up or creates the Gauge for {kind, name}, caches the pointer.
//   - Sets the previous current Gauge for this kind to 0.
//   - Sets the new Gauge to 1 and updates current_[kind].
//
// Thread-safe: cache_ and current_ guarded by mutex; Gauge::Set is lock-free.
class PolicyStatePublisher {
public:
    // Bind to registry. Must be called before Set. Idempotent (re-bind replaces registry).
    void Bind(MetricRegistry& registry);

    // kind ∈ {"mutation", "schedule", "corpus"}
    // Publishes fuzzer.current_policy{kind=kind, name=name}=1,
    // and sets the previously active name gauge to 0.
    // Skips if name is empty or registry is not bound.
    void Set(std::string_view kind, std::string_view name);

private:
    MetricRegistry* registry_ = nullptr;
    std::mutex mu_;
    // kind → (name → Gauge*)
    std::unordered_map<std::string, std::unordered_map<std::string, Gauge*>> cache_;
    // kind → current name
    std::unordered_map<std::string, std::string> current_;
};

} // namespace refuzz::core::metrics

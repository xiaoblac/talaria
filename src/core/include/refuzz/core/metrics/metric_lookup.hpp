#pragma once

#include "refuzz/core/metrics/labels.hpp"
#include "refuzz/core/metrics/metric_registry.hpp"

#include <cstdint>
#include <string_view>

// 同款模式 helper:线性扫 CollectPrefix 结果查单个 series。
// 适用于 1Hz 以下的控制流(PolicyMonitor::Tick / Orchestrator::Stop / run_summary compute),
// 热路径应缓存 Counter&/Gauge& 直接取值,不要调这里。
// 找不到统一返回 0,调用点不用区分 "未注册" 与 "注册但值为 0"。
namespace refuzz::core::metrics {

uint64_t CounterValue(const MetricRegistry& registry,
                      std::string_view name,
                      const Labels& labels = {});

int64_t GaugeValue(const MetricRegistry& registry,
                   std::string_view name,
                   const Labels& labels = {});

} // namespace refuzz::core::metrics

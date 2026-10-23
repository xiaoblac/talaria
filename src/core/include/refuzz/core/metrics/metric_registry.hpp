#pragma once

#include "refuzz/core/metrics/counter.hpp"
#include "refuzz/core/metrics/gauge.hpp"
#include "refuzz/core/metrics/labels.hpp"
#include "refuzz/core/metrics/metric_kind.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace refuzz::core::metrics {

// 进程级 metric registry。
//
// 发布侧:
//   - CounterOf/GaugeOf 幂等(同 name + 同 normalized labels 返回同一引用)
//   - 返回的 Counter&/Gauge& 在 Registry 生命周期内稳定
//   - 发布方应在组件构造期缓存引用,热路径禁止重复调 CounterOf/GaugeOf
//
// 订阅侧:
//   - Collect/CollectPrefix 拉取全量 Sample
//   - Sample.value 统一 int64_t(Counter 值截断,实际 < 2^63 远够用)
//
// 契约错误一律 std::abort:
//   - name / label 正则不合规
//   - 同 name 先注册 Counter 再注册 Gauge(或反之)
//
// series 生命周期:Registry 析构前永不回收。
class MetricRegistry {
public:
    struct Sample {
        std::string name;
        Labels labels;
        MetricKind kind;
        int64_t value;
    };

    MetricRegistry() = default;
    MetricRegistry(const MetricRegistry&) = delete;
    MetricRegistry& operator=(const MetricRegistry&) = delete;
    MetricRegistry(MetricRegistry&&) = delete;
    MetricRegistry& operator=(MetricRegistry&&) = delete;

    // 发布侧。参数以值传入,内部 std::move + NormalizeLabels。
    Counter& CounterOf(std::string name, Labels labels = {});
    Gauge& GaugeOf(std::string name, Labels labels = {});

    // 订阅侧。Collect 排序不保证;消费者需要有序请自行排序。
    std::vector<Sample> Collect() const;
    std::vector<Sample> CollectPrefix(std::string_view prefix) const;

    // 诊断:当前 series 总数(counters + gauges)。
    std::size_t size() const;

private:
    struct Key {
        std::string name;
        Labels labels; // 已规范化

        bool operator==(const Key& other) const noexcept;
    };

    struct KeyHash {
        std::size_t operator()(const Key& k) const noexcept;
    };

    mutable std::shared_mutex mu_;
    std::unordered_map<Key, std::unique_ptr<Counter>, KeyHash> counters_;
    std::unordered_map<Key, std::unique_ptr<Gauge>, KeyHash> gauges_;
};

} // namespace refuzz::core::metrics

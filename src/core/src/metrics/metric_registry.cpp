#include "refuzz/core/metrics/metric_registry.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <iterator>
#include <string>
#include <utility>

namespace refuzz::core::metrics {

namespace {

[[noreturn]] void MetricsAbort(const char* where, const std::string& detail)
{
    std::fprintf(stderr, "[metrics] contract violation in %s: %s\n", where, detail.c_str());
    std::abort();
}

bool IsNameChar(char c, bool first)
{
    if (first) {
        return c >= 'a' && c <= 'z';
    }
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '.';
}

bool IsLabelKeyChar(char c, bool first)
{
    if (first) {
        return (c >= 'a' && c <= 'z') || c == '_';
    }
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
}

bool IsLabelValueChar(char c)
{
    // 可打印 ASCII,排除 '"' '\' '\n' '\r'
    if (c == '"' || c == '\\' || c == '\n' || c == '\r') {
        return false;
    }
    return c >= 0x20 && c <= 0x7E;
}

template<typename Map>
void AbortIfNameClash(const Map& other_map,
                     const std::string& name,
                     const char* other_kind_name)
{
    for (const auto& entry : other_map) {
        if (entry.first.name == name) {
            MetricsAbort("MetricRegistry", std::string("kind conflict: '") + name
                                               + "' already registered as " + other_kind_name);
        }
    }
}

} // namespace

void ValidateName(std::string_view name)
{
    if (name.empty()) {
        MetricsAbort("ValidateName", "name is empty");
    }
    for (std::size_t i = 0; i < name.size(); ++i) {
        if (!IsNameChar(name[i], i == 0)) {
            MetricsAbort("ValidateName",
                         std::string("invalid char in name '") + std::string(name) + "'");
        }
    }
}

void ValidateLabels(const Labels& labels)
{
    for (const auto& [k, v] : labels) {
        if (k.empty()) {
            MetricsAbort("ValidateLabels", "empty label key");
        }
        for (std::size_t i = 0; i < k.size(); ++i) {
            if (!IsLabelKeyChar(k[i], i == 0)) {
                MetricsAbort("ValidateLabels",
                             std::string("invalid label key '") + k + "'");
            }
        }
        for (char c : v) {
            if (!IsLabelValueChar(c)) {
                MetricsAbort("ValidateLabels",
                             std::string("invalid label value for key '") + k + "'");
            }
        }
    }
}

Labels NormalizeLabels(Labels labels)
{
    if (labels.size() < 2) {
        return labels;
    }

    // 按 key 字典序稳定排序(保留后入者在后,供 dedupe 保留 last)
    std::stable_sort(labels.begin(), labels.end(),
                     [](const LabelPair& a, const LabelPair& b) {
                         return a.first < b.first;
                     });

    // 同 key 合并:保留最后一个值(later publisher intent wins)。
    // 扫描时仅在该元素是本 key group 的最后一个(next 不同 或 已是末尾)时复制。
    // 不使用就地 self-move,避免 libstdc++/libc++ 对自赋值的不同行为。
    Labels out;
    out.reserve(labels.size());
    for (std::size_t i = 0; i < labels.size(); ++i) {
        const bool last_of_group =
            (i + 1 == labels.size()) || (labels[i].first != labels[i + 1].first);
        if (last_of_group) {
            out.push_back(std::move(labels[i]));
        }
    }
    return out;
}

bool MetricRegistry::Key::operator==(const Key& other) const noexcept
{
    return name == other.name && labels == other.labels;
}

std::size_t MetricRegistry::KeyHash::operator()(const Key& k) const noexcept
{
    std::size_t h = std::hash<std::string>{}(k.name);
    auto combine = [&h](const std::string& s) {
        h ^= std::hash<std::string>{}(s) + 0x9e3779b9 + (h << 6) + (h >> 2);
    };
    for (const auto& [kk, vv] : k.labels) {
        combine(kk);
        combine(vv);
    }
    return h;
}

Counter& MetricRegistry::CounterOf(std::string name, Labels labels)
{
    ValidateName(name);
    labels = NormalizeLabels(std::move(labels));
    ValidateLabels(labels);

    Key key{std::move(name), std::move(labels)};

    std::unique_lock lock(mu_);
    AbortIfNameClash(gauges_, key.name, "Gauge");
    auto it = counters_.find(key);
    if (it != counters_.end()) {
        return *it->second;
    }
    auto res = counters_.emplace(std::move(key), std::make_unique<Counter>());
    return *res.first->second;
}

Gauge& MetricRegistry::GaugeOf(std::string name, Labels labels)
{
    ValidateName(name);
    labels = NormalizeLabels(std::move(labels));
    ValidateLabels(labels);

    Key key{std::move(name), std::move(labels)};

    std::unique_lock lock(mu_);
    AbortIfNameClash(counters_, key.name, "Counter");
    auto it = gauges_.find(key);
    if (it != gauges_.end()) {
        return *it->second;
    }
    auto res = gauges_.emplace(std::move(key), std::make_unique<Gauge>());
    return *res.first->second;
}

std::vector<MetricRegistry::Sample> MetricRegistry::Collect() const
{
    std::vector<Sample> out;
    std::shared_lock lock(mu_);
    out.reserve(counters_.size() + gauges_.size());
    for (const auto& [k, c] : counters_) {
        out.push_back(Sample{
            .name = k.name,
            .labels = k.labels,
            .kind = MetricKind::kCounter,
            .value = static_cast<int64_t>(c->Value()),
        });
    }
    for (const auto& [k, g] : gauges_) {
        out.push_back(Sample{
            .name = k.name,
            .labels = k.labels,
            .kind = MetricKind::kGauge,
            .value = g->Value(),
        });
    }
    return out;
}

std::vector<MetricRegistry::Sample>
MetricRegistry::CollectPrefix(std::string_view prefix) const
{
    std::vector<Sample> out;
    std::shared_lock lock(mu_);
    auto matches = [&](const std::string& s) {
        return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
    };
    for (const auto& [k, c] : counters_) {
        if (matches(k.name)) {
            out.push_back(Sample{
                .name = k.name,
                .labels = k.labels,
                .kind = MetricKind::kCounter,
                .value = static_cast<int64_t>(c->Value()),
            });
        }
    }
    for (const auto& [k, g] : gauges_) {
        if (matches(k.name)) {
            out.push_back(Sample{
                .name = k.name,
                .labels = k.labels,
                .kind = MetricKind::kGauge,
                .value = g->Value(),
            });
        }
    }
    return out;
}

std::size_t MetricRegistry::size() const
{
    std::shared_lock lock(mu_);
    return counters_.size() + gauges_.size();
}

} // namespace refuzz::core::metrics

#include "refuzz/core/metrics/metric_registry.hpp"

#include <cstdint>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

using refuzz::core::metrics::Counter;
using refuzz::core::metrics::Gauge;
using refuzz::core::metrics::Labels;
using refuzz::core::metrics::MetricKind;
using refuzz::core::metrics::MetricRegistry;

#define CHECK(cond)                                                                           \
    do {                                                                                      \
        if (!(cond)) {                                                                        \
            std::fprintf(stderr, "CHECK failed: %s (line %d)\n", #cond, __LINE__);            \
            return 1;                                                                         \
        }                                                                                     \
    } while (0)

static int TestEmpty()
{
    MetricRegistry r;
    CHECK(r.size() == 0);
    CHECK(r.Collect().empty());
    CHECK(r.CollectPrefix("anything").empty());
    return 0;
}

static int TestCounterOfStable()
{
    MetricRegistry r;
    Counter& c1 = r.CounterOf("foo.bar");
    Counter& c2 = r.CounterOf("foo.bar");
    CHECK(&c1 == &c2);
    c1.Inc();
    CHECK(c2.Value() == 1);
    return 0;
}

static int TestCounterOfLabelsOrder()
{
    MetricRegistry r;
    Counter& c1 = r.CounterOf("foo.bar", {{"a", "1"}, {"b", "2"}});
    Counter& c2 = r.CounterOf("foo.bar", {{"b", "2"}, {"a", "1"}});
    CHECK(&c1 == &c2);
    CHECK(r.size() == 1);
    return 0;
}

static int TestCounterOfLabelsDedupeLast()
{
    MetricRegistry r;
    // 同 key 重复,规范化后保留 last
    Counter& c1 = r.CounterOf("foo.bar", {{"k", "a"}, {"k", "b"}});
    Counter& c2 = r.CounterOf("foo.bar", {{"k", "b"}});
    CHECK(&c1 == &c2);
    return 0;
}

static int TestCounterOfDistinctLabels()
{
    MetricRegistry r;
    Counter& ca = r.CounterOf("foo.bar", {{"kind", "a"}});
    Counter& cb = r.CounterOf("foo.bar", {{"kind", "b"}});
    CHECK(&ca != &cb);
    ca.Inc(10);
    cb.Inc(5);
    CHECK(ca.Value() == 10);
    CHECK(cb.Value() == 5);
    CHECK(r.size() == 2);
    return 0;
}

static int TestCounterIncLockFree()
{
    MetricRegistry r;
    Counter& c = r.CounterOf("foo.bar");
    constexpr int kThreads = 8;
    constexpr int kPerThread = 100000;
    std::vector<std::thread> ts;
    ts.reserve(kThreads);
    for (int i = 0; i < kThreads; ++i) {
        ts.emplace_back([&c] {
            for (int j = 0; j < kPerThread; ++j) {
                c.Inc();
            }
        });
    }
    for (auto& t : ts) {
        t.join();
    }
    CHECK(c.Value() == static_cast<uint64_t>(kThreads) * kPerThread);
    return 0;
}

static int TestGaugeSetAdd()
{
    MetricRegistry r;
    Gauge& g = r.GaugeOf("foo.gauge");
    g.Set(10);
    CHECK(g.Value() == 10);
    g.Add(5);
    CHECK(g.Value() == 15);
    g.Add(-20);
    CHECK(g.Value() == -5);
    return 0;
}

static int TestGaugeAddConcurrent()
{
    MetricRegistry r;
    Gauge& g = r.GaugeOf("foo.gauge");
    constexpr int kThreads = 8;
    constexpr int kPerThread = 100000;
    std::vector<std::thread> ts;
    ts.reserve(kThreads);
    for (int i = 0; i < kThreads; ++i) {
        ts.emplace_back([&g] {
            for (int j = 0; j < kPerThread; ++j) {
                g.Add(1);
            }
        });
    }
    for (auto& t : ts) {
        t.join();
    }
    CHECK(g.Value() == static_cast<int64_t>(kThreads) * kPerThread);
    return 0;
}

static int TestCollectReturnsAll()
{
    MetricRegistry r;
    r.CounterOf("a.b").Inc(3);
    r.CounterOf("a.c").Inc(7);
    r.GaugeOf("a.g").Set(42);

    auto samples = r.Collect();
    CHECK(samples.size() == 3);

    int seen = 0;
    for (const auto& s : samples) {
        if (s.name == "a.b") {
            CHECK(s.kind == MetricKind::kCounter);
            CHECK(s.value == 3);
            ++seen;
        } else if (s.name == "a.c") {
            CHECK(s.kind == MetricKind::kCounter);
            CHECK(s.value == 7);
            ++seen;
        } else if (s.name == "a.g") {
            CHECK(s.kind == MetricKind::kGauge);
            CHECK(s.value == 42);
            ++seen;
        }
    }
    CHECK(seen == 3);
    return 0;
}

static int TestCollectPrefixFilters()
{
    MetricRegistry r;
    r.CounterOf("fuzzer.foo").Inc();
    r.CounterOf("fuzzer.bar").Inc();
    r.CounterOf("executor.baz").Inc();

    CHECK(r.CollectPrefix("fuzzer.").size() == 2);
    CHECK(r.CollectPrefix("executor.").size() == 1);
    CHECK(r.CollectPrefix("nonexistent.").empty());
    return 0;
}

static int TestLargeCardinality()
{
    MetricRegistry r;
    constexpr int kN = 1000;
    for (int i = 0; i < kN; ++i) {
        Counter& c = r.CounterOf("channel.heartbeat_lost",
                                  {{"channel_id", std::to_string(i)}});
        c.Inc(static_cast<uint64_t>(i));
    }
    CHECK(r.size() == static_cast<std::size_t>(kN));

    auto all = r.CollectPrefix("channel.");
    CHECK(all.size() == static_cast<std::size_t>(kN));

    int verified = 0;
    for (const auto& s : all) {
        CHECK(s.labels.size() == 1);
        CHECK(s.labels[0].first == "channel_id");
        int id = std::stoi(s.labels[0].second);
        CHECK(s.value == id);
        ++verified;
    }
    CHECK(verified == kN);
    return 0;
}

static int TestStableReference()
{
    MetricRegistry r;
    Counter& original = r.CounterOf("stable.test");
    original.Inc();
    // 插入 500 个让 hashmap 多次 rehash
    for (int i = 0; i < 500; ++i) {
        r.CounterOf("filler.c" + std::to_string(i)).Inc();
    }
    Counter& again = r.CounterOf("stable.test");
    CHECK(&original == &again);
    CHECK(original.Value() == 1);
    original.Inc();
    CHECK(again.Value() == 2);
    return 0;
}

int main()
{
    struct Case {
        const char* name;
        int (*fn)();
    };
    const Case cases[] = {
        {"Empty", TestEmpty},
        {"CounterOfStable", TestCounterOfStable},
        {"CounterOfLabelsOrder", TestCounterOfLabelsOrder},
        {"CounterOfLabelsDedupeLast", TestCounterOfLabelsDedupeLast},
        {"CounterOfDistinctLabels", TestCounterOfDistinctLabels},
        {"CounterIncLockFree", TestCounterIncLockFree},
        {"GaugeSetAdd", TestGaugeSetAdd},
        {"GaugeAddConcurrent", TestGaugeAddConcurrent},
        {"CollectReturnsAll", TestCollectReturnsAll},
        {"CollectPrefixFilters", TestCollectPrefixFilters},
        {"LargeCardinality", TestLargeCardinality},
        {"StableReference", TestStableReference},
    };
    for (const auto& c : cases) {
        if (c.fn() != 0) {
            std::fprintf(stderr, "FAILED: %s\n", c.name);
            return 1;
        }
        std::printf("PASS: %s\n", c.name);
    }
    return 0;
}

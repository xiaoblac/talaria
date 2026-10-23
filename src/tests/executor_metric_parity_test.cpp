// executor_metric_parity_test.cpp
//
// 方案 4(Bind + Inc/Set smoke 测试):
//   - 构造 MetricRegistry + ExecutorMetrics
//   - Bind → 11 个指针均非 null(8 counters + 3 gauges)
//   - 各 Inc/Set 操作后, registry.CollectPrefix("executor.") 看到 11 个 series 且值正确
//
// 不涉及 Executor 主逻辑(无 ivshmem/QEMU 环境要求)。
//
// [v2 PR-11 B1 expose] materialize_failed counter 加入后从 10→11,
// 详 executor_metrics.hpp 注释。

#include "refuzz/executor/metrics/executor_metrics.hpp"
#include "refuzz/core/metrics/metric_registry.hpp"

#include <cstdio>
#include <cstdint>

using refuzz::core::metrics::MetricRegistry;
using refuzz::executor::metrics::ExecutorMetrics;

#define CHECK(cond)                                                              \
    do {                                                                         \
        if (!(cond)) {                                                           \
            std::fprintf(stderr, "CHECK failed: %s (line %d)\n",                \
                         #cond, __LINE__);                                       \
            return 1;                                                            \
        }                                                                        \
    } while (0)

namespace {

// -- Test 1 ---------------------------------------------------------------
// Bind 后所有 11 个指针非 null,registry size == 11。
int TestExecutorMetricsBindAllNonNull()
{
    MetricRegistry registry;
    ExecutorMetrics m{};
    m.Bind(registry);

    CHECK(m.tasks_submitted           != nullptr);
    CHECK(m.events_forwarded          != nullptr);
    CHECK(m.dispatch_submit_wait_us   != nullptr);
    CHECK(m.dispatch_busy_results     != nullptr);
    CHECK(m.dispatch_backoff_wait_us  != nullptr);
    CHECK(m.dispatch_backoff_episodes != nullptr);
    CHECK(m.events_forward_latency_us != nullptr);
    CHECK(m.materialize_failed        != nullptr);   // [v2 PR-11 B1 expose]
    CHECK(m.dispatch_pending          != nullptr);
    CHECK(m.channels_total            != nullptr);
    CHECK(m.stop_requested            != nullptr);

    // 8 counters + 3 gauges = 11 series
    CHECK(registry.size() == 11);
    return 0;
}

// -- Test 2 ---------------------------------------------------------------
// Counter Inc + Gauge Set 后 CollectPrefix 能读到正确值。
int TestExecutorMetricsIncSetValues()
{
    MetricRegistry registry;
    ExecutorMetrics m{};
    m.Bind(registry);

    // 计数器
    m.tasks_submitted->Inc(3);
    m.events_forwarded->Inc(7);
    m.dispatch_submit_wait_us->Inc(33);
    m.dispatch_busy_results->Inc(4);
    m.dispatch_backoff_wait_us->Inc(1000);
    m.dispatch_backoff_episodes->Inc(2);
    m.events_forward_latency_us->Inc(55);
    m.materialize_failed->Inc(9);          // [v2 PR-11 B1 expose]

    // gauge
    m.dispatch_pending->Set(5);
    m.channels_total->Set(2);
    m.stop_requested->Set(1);

    const auto samples = registry.CollectPrefix("executor.");
    CHECK(samples.size() == 11);

    // 按名查找
    uint64_t tasks_submitted_val = 0;
    uint64_t events_forwarded_val = 0;
    uint64_t submit_wait_us_val = 0;
    uint64_t busy_results_val = 0;
    uint64_t backoff_wait_us_val = 0;
    uint64_t backoff_episodes_val = 0;
    uint64_t event_forward_latency_us_val = 0;
    uint64_t materialize_failed_val = 0;   // [v2 PR-11 B1 expose]
    int64_t  dispatch_pending_val = -1;
    int64_t  channels_total_val = -1;
    int64_t  stop_requested_val = -1;

    for (const auto& s : samples) {
        if (s.name == "executor.tasks_submitted")
            tasks_submitted_val = static_cast<uint64_t>(s.value);
        else if (s.name == "executor.events_forwarded")
            events_forwarded_val = static_cast<uint64_t>(s.value);
        else if (s.name == "executor.dispatch.submit_wait_us")
            submit_wait_us_val = static_cast<uint64_t>(s.value);
        else if (s.name == "executor.dispatch.busy_results")
            busy_results_val = static_cast<uint64_t>(s.value);
        else if (s.name == "executor.dispatch.backoff_wait_us")
            backoff_wait_us_val = static_cast<uint64_t>(s.value);
        else if (s.name == "executor.dispatch.backoff_episodes")
            backoff_episodes_val = static_cast<uint64_t>(s.value);
        else if (s.name == "executor.events.forward_latency_us")
            event_forward_latency_us_val = static_cast<uint64_t>(s.value);
        else if (s.name == "executor.materialize_failed")          // [v2 PR-11 B1 expose]
            materialize_failed_val = static_cast<uint64_t>(s.value);
        else if (s.name == "executor.dispatch.pending")
            dispatch_pending_val = s.value;
        else if (s.name == "executor.channels.total")
            channels_total_val = s.value;
        else if (s.name == "executor.stop_requested")
            stop_requested_val = s.value;
    }

    CHECK(tasks_submitted_val    == 3);
    CHECK(events_forwarded_val   == 7);
    CHECK(submit_wait_us_val     == 33);
    CHECK(busy_results_val       == 4);
    CHECK(backoff_wait_us_val    == 1000);
    CHECK(backoff_episodes_val   == 2);
    CHECK(event_forward_latency_us_val == 55);
    CHECK(materialize_failed_val == 9);    // [v2 PR-11 B1 expose]
    CHECK(dispatch_pending_val   == 5);
    CHECK(channels_total_val     == 2);
    CHECK(stop_requested_val     == 1);
    return 0;
}

// -- Test 3 ---------------------------------------------------------------
// 初始状态下(Bind 但不 Inc/Set):所有值均为 0。
int TestExecutorMetricsInitialValuesZero()
{
    MetricRegistry registry;
    ExecutorMetrics m{};
    m.Bind(registry);

    CHECK(m.tasks_submitted->Value()           == 0);
    CHECK(m.events_forwarded->Value()          == 0);
    CHECK(m.dispatch_submit_wait_us->Value()   == 0);
    CHECK(m.dispatch_busy_results->Value()     == 0);
    CHECK(m.dispatch_backoff_wait_us->Value()  == 0);
    CHECK(m.dispatch_backoff_episodes->Value() == 0);
    CHECK(m.events_forward_latency_us->Value() == 0);
    CHECK(m.materialize_failed->Value()        == 0);   // [v2 PR-11 B1 expose]
    CHECK(m.dispatch_pending->Value()          == 0);
    CHECK(m.channels_total->Value()            == 0);
    CHECK(m.stop_requested->Value()            == 0);
    return 0;
}

} // namespace

int main()
{
    struct Case {
        const char* name;
        int (*fn)();
    };
    const Case cases[] = {
        {"ExecutorMetricsBindAllNonNull",   TestExecutorMetricsBindAllNonNull},
        {"ExecutorMetricsIncSetValues",     TestExecutorMetricsIncSetValues},
        {"ExecutorMetricsInitialValuesZero", TestExecutorMetricsInitialValuesZero},
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

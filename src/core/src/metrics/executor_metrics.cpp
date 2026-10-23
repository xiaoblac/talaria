#include "refuzz/executor/metrics/executor_metrics.hpp"

#include "refuzz/core/metrics/metric_registry.hpp"

namespace refuzz::executor::metrics {

void ExecutorMetrics::Bind(core::metrics::MetricRegistry& r)
{
    tasks_submitted           = &r.CounterOf("executor.tasks_submitted");
    events_forwarded          = &r.CounterOf("executor.events_forwarded");
    dispatch_submit_wait_us   = &r.CounterOf("executor.dispatch.submit_wait_us");
    dispatch_busy_results     = &r.CounterOf("executor.dispatch.busy_results");
    dispatch_backoff_wait_us  = &r.CounterOf("executor.dispatch.backoff_wait_us");
    dispatch_backoff_episodes = &r.CounterOf("executor.dispatch.backoff_episodes");
    events_forward_latency_us = &r.CounterOf("executor.events.forward_latency_us");
    // [v2 PR-11 B1 expose — 当前版本] channeldispatcher submit 边界 MaterializeExecWire
    // 失败计数;详 executor_metrics.hpp。
    materialize_failed        = &r.CounterOf("executor.materialize_failed");

    dispatch_pending = &r.GaugeOf("executor.dispatch.pending");
    channels_total   = &r.GaugeOf("executor.channels.total");
    stop_requested   = &r.GaugeOf("executor.stop_requested");
}

} // namespace refuzz::executor::metrics

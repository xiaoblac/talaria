#pragma once

#include "refuzz/core/metrics/metric_registry.hpp"

namespace refuzz::executor::metrics {

// ExecutorMetrics — Executor 侧 metric 句柄缓存 (Step 4)
//
// 契约:
//   - Bind(registry) 由 Executor 构造期调用一次,所有指针在 registry 生命周期内稳定。
//   - 发布方只持有 ExecutorMetrics*,允许为 nullptr(v1→v2 迁移期 stats/metrics 独立判空)。
//   - 一个 ExecutorMetrics 实例对应一个 executor 实例的全量 series。
//
// 命名取自 docs/telemetry-redesign/020_naming_catalog.md §3.1。
// §3.2 字段(completed/aborted/late_event_drop/stale_completion_drop/inflight/dispatch.round)
// 暂不实现 —— v4 Executor 无对应埋点。
struct ExecutorMetrics {
    // counters (7)
    core::metrics::Counter* tasks_submitted           = nullptr;
    core::metrics::Counter* events_forwarded          = nullptr;
    core::metrics::Counter* dispatch_submit_wait_us   = nullptr;
    core::metrics::Counter* dispatch_busy_results     = nullptr;
    core::metrics::Counter* dispatch_backoff_wait_us  = nullptr;
    core::metrics::Counter* dispatch_backoff_episodes = nullptr;
    core::metrics::Counter* events_forward_latency_us = nullptr;
    // [v2 PR-11 B1 expose — 当前版本] host-side MaterializeExecWire 失败次数。
    // channeldispatcher 在 submit 边界看到 artifact-only task 编码失败时:
    //   - 合成 host-side AbnormalCompletion(kExecError)推回 event_queue,让上游
    //     stage 收到 terminal event 自然收尾(不入 inflight,无 orphan);
    //   - 同时 Inc 此 counter,让操作员观测 mutator IR-invariant 异常频率。
    // 0 = 健康;非 0 = 上游 mutator/repro 产了无法 lower 到 wire 的 typed view,
    // 需查 mutator IR audit。
    core::metrics::Counter* materialize_failed        = nullptr;

    // gauges (3)
    core::metrics::Gauge*   dispatch_pending = nullptr;
    core::metrics::Gauge*   channels_total   = nullptr;
    core::metrics::Gauge*   stop_requested   = nullptr;

    // 一次性绑定。重复调用会在 registry 内部返回相同引用,指针保持稳定。
    void Bind(core::metrics::MetricRegistry& r);
};

} // namespace refuzz::executor::metrics

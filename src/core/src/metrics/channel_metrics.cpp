#include "refuzz/core/metrics/channel_metrics.hpp"

#include "refuzz/core/metrics/metric_registry.hpp"

namespace refuzz::core::metrics {

namespace cc = refuzz::core::channel_contract;

void ChannelMetrics::Bind(MetricRegistry& r, uint32_t channel_id)
{
    const std::string cid = std::to_string(channel_id);

    // ---- §4.1 top-level ----
    generation  = &r.GaugeOf("channel.generation", {{"channel_id", cid}});
    boot_ts_us  = &r.GaugeOf("channel.boot_ts_us",  {{"channel_id", cid}});

    // lifecycle_state one-hot (7 states)
    static const char* kLifecycleNames[7] = {
        "stopped", "booting", "running", "degraded", "recovering", "failed", "closed"
    };
    for (size_t i = 0; i < lifecycle_state.size(); ++i) {
        lifecycle_state[i] = &r.GaugeOf("channel.lifecycle_state",
                                         {{"channel_id", cid},
                                          {"state", kLifecycleNames[i]}});
    }

    // ---- §4.2 runtime ----
    runtime_total_slots         = &r.GaugeOf("channel.runtime.total_slots",        {{"channel_id", cid}});
    runtime_free_slots          = &r.GaugeOf("channel.runtime.free_slots",         {{"channel_id", cid}});
    runtime_inflight            = &r.GaugeOf("channel.runtime.inflight",           {{"channel_id", cid}});
    runtime_registered_workers  = &r.GaugeOf("channel.runtime.registered_workers", {{"channel_id", cid}});
    runtime_quarantined_workers = &r.GaugeOf("channel.runtime.quarantined_workers",{{"channel_id", cid}});

    // ---- §4.3 recovery ----
    // Counters — reserved for 5b; defined here so pointers are stable for future use.
    recovery_runtime_restart  = &r.CounterOf("channel.recovery.runtime_restart", {{"channel_id", cid}});
    recovery_vm_reboot        = &r.CounterOf("channel.recovery.vm_reboot",       {{"channel_id", cid}});

    recovery_consecutive_healthy = &r.GaugeOf("channel.recovery.consecutive_healthy", {{"channel_id", cid}});
    recovery_last_fault_ts_us    = &r.GaugeOf("channel.recovery.last_fault_ts_us",    {{"channel_id", cid}});
    recovery_offline             = &r.GaugeOf("channel.recovery.offline",             {{"channel_id", cid}});
    recovery_in_progress         = &r.GaugeOf("channel.recovery.in_progress",         {{"channel_id", cid}});

    // recovery_active_action one-hot (6 actions)
    static const char* kActionNames[6] = {
        "none", "restart_single_worker", "restart_all_workers",
        "reboot_vm", "fail_channel", "restart_health_monitor"
    };
    for (size_t i = 0; i < recovery_active_action.size(); ++i) {
        recovery_active_action[i] = &r.GaugeOf("channel.recovery.active_action",
                                                {{"channel_id", cid},
                                                 {"action", kActionNames[i]}});
    }

    // ---- §4.4 health ----
    // health_crash Counters — reserved for 5b; defined here so pointers are stable.
    static const char* kCrashKindNames[5] = {
        "kernel", "vm", "worker", "internal", "no_output"};
    for (size_t i = 0; i < health_crash.size(); ++i) {
        health_crash[i] = &r.CounterOf("channel.health.crash",
                                       {{"channel_id", cid},
                                        {"kind", kCrashKindNames[i]}});
    }
    health_sampled_ts_us = &r.GaugeOf("channel.health.sampled_ts_us", {{"channel_id", cid}});

    // worker_liveness_cache is lazily populated in PublishFromSnapshot.

    // ---- §4.5 event aggregation ----
    static const char* kEventKindNames[5] = {
        "lifecycle_changed", "fault_detected", "recovery_started",
        "recovery_completed", "generation_reset"
    };
    for (size_t i = 0; i < event_kind.size(); ++i) {
        event_kind[i] = &r.CounterOf("channel.event",
                                     {{"channel_id", cid},
                                      {"kind", kEventKindNames[i]}});
    }

    // ---- §4.6 input_queue ----
    input_queue_depth         = &r.GaugeOf("channel.input_queue.depth",
                                            {{"channel_id", cid}});
    input_queue_capacity      = &r.GaugeOf("channel.input_queue.capacity",
                                            {{"channel_id", cid}});
    input_queue_full_episodes = &r.CounterOf("channel.input_queue.full_episodes",
                                              {{"channel_id", cid}});
    input_queue_busy_rejects  = &r.CounterOf("channel.input_queue.busy_rejects",
                                              {{"channel_id", cid}});
    input_queue_full_us       = &r.CounterOf("channel.input_queue.full_us",
                                              {{"channel_id", cid}});
}

void ChannelMetrics::PublishFromSnapshot(const cc::ChannelSnapshot& snap,
                                         const cc::ChannelRuntimeSnapshot& runtime,
                                         const cc::HealthMonitorSnapshot& health,
                                         const cc::ChannelRecoverySnapshot& recovery,
                                         MetricRegistry& r)
{
    const std::string cid = std::to_string(snap.channel_id);

    // ---- §4.1 top-level ----
    if (generation)  generation->Set(static_cast<int64_t>(snap.generation));
    if (boot_ts_us)  boot_ts_us->Set(static_cast<int64_t>(snap.boot_ts_us));

    // lifecycle_state one-hot: clear all, set current.
    {
        const auto state_idx = static_cast<size_t>(snap.lifecycle_state);
        for (size_t i = 0; i < lifecycle_state.size(); ++i) {
            if (lifecycle_state[i]) {
                lifecycle_state[i]->Set(i == state_idx ? 1 : 0);
            }
        }
    }

    // ---- §4.2 runtime ----
    if (runtime_total_slots)         runtime_total_slots->Set(static_cast<int64_t>(runtime.total_slots));
    if (runtime_free_slots)          runtime_free_slots->Set(static_cast<int64_t>(runtime.free_slots));
    if (runtime_inflight)            runtime_inflight->Set(static_cast<int64_t>(runtime.inflight));
    if (runtime_registered_workers)  runtime_registered_workers->Set(static_cast<int64_t>(runtime.registered_workers));
    if (runtime_quarantined_workers) runtime_quarantined_workers->Set(static_cast<int64_t>(runtime.quarantined_workers));

    // ---- §4.3 recovery ----
    if (recovery_consecutive_healthy) recovery_consecutive_healthy->Set(static_cast<int64_t>(recovery.consecutive_healthy));
    if (recovery_last_fault_ts_us)    recovery_last_fault_ts_us->Set(static_cast<int64_t>(recovery.last_fault_ts_us));
    if (recovery_offline)             recovery_offline->Set(recovery.offline ? 1 : 0);
    if (recovery_in_progress)         recovery_in_progress->Set(recovery.recovery_in_progress ? 1 : 0);

    // recovery_active_action one-hot: clear all, set current.
    {
        const auto action_idx = static_cast<size_t>(recovery.active_action);
        for (size_t i = 0; i < recovery_active_action.size(); ++i) {
            if (recovery_active_action[i]) {
                recovery_active_action[i]->Set(i == action_idx ? 1 : 0);
            }
        }
    }

    // ---- §4.4 health ----
    if (health_sampled_ts_us) health_sampled_ts_us->Set(static_cast<int64_t>(health.sampled_ts_us));

    // per-worker gauges: lazy-create the whole set per worker_id.
    for (const auto& entry : health.worker_liveness) {
        auto it = worker_liveness_cache.find(entry.worker_id);
        if (it == worker_liveness_cache.end()) {
            const std::string wid = std::to_string(entry.worker_id);
            const Labels id{{"channel_id", cid}, {"worker_id", wid}};
            std::array<Gauge*, kWorkerGaugeCount> g{};
            g[0] = &r.GaugeOf("channel.health.worker_liveness",
                              {{"channel_id", cid}, {"worker_id", wid}, {"state", "alive"}});
            g[1] = &r.GaugeOf("channel.health.worker_liveness",
                              {{"channel_id", cid}, {"worker_id", wid}, {"state", "dead"}});
            g[2] = &r.GaugeOf("channel.health.worker_silent_s", id);
            g[3] = &r.GaugeOf("channel.health.worker_silent_budget_s", id);
            g[4] = &r.GaugeOf("channel.health.worker_proc_epoch", id);
            g[5] = &r.GaugeOf("channel.health.worker_recovering", id);
            g[6] = &r.GaugeOf("channel.health.worker_slot", id);
            it = worker_liveness_cache.emplace(entry.worker_id, g).first;
        }
        // one-hot: alive=0, dead=1
        it->second[0]->Set(entry.is_alive ? 1 : 0);
        it->second[1]->Set(entry.is_alive ? 0 : 1);
        it->second[2]->Set(static_cast<int64_t>(entry.silent_s));
        it->second[3]->Set(static_cast<int64_t>(entry.silent_budget_s));
        it->second[4]->Set(static_cast<int64_t>(entry.proc_epoch));
        it->second[5]->Set(entry.recovering ? 1 : 0);
        it->second[6]->Set(static_cast<int64_t>(entry.slot));
    }
}

} // namespace refuzz::core::metrics

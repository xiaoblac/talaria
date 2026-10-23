// [6b-3 — 当前版本] FuzzerRuntimeSnapshot / ExecutorSnapshot / ChannelSnapshot 三个订阅已删除,
// 本测试改为:ObservabilityProjector 只订阅 channel_event_bus, 其 EmitObserveEvent 路径
// (fault / recovery start / recovery complete / generation reset) 的事件仍然写入 RunStateStore。

#include "refuzz/core/channel_contract.hpp"
#include "refuzz/core/broadcast_bus.hpp"
#include "refuzz/core/channel_contract.hpp"
#include "refuzz/core/metrics/metric_registry.hpp"
#include "refuzz/telemetry/observation/observability_projector.hpp"
#include "refuzz/telemetry/policy/policy_engine.hpp"
#include "refuzz/telemetry/observation/run_state_store.hpp"

#include <algorithm>
#include <chrono>
#include <string>
#include <thread>

namespace {

class FakePolicyControl : public refuzz::core::IPolicyControl {
public:
    void SwitchMutationPolicy(std::string_view name) override
    {
        mutation_policy = std::string(name);
    }

    void SwitchSchedulingPolicy(std::string_view name) override
    {
        scheduling_policy = std::string(name);
    }

    void SwitchCorpusAdmissionPolicy(std::string_view name) override
    {
        corpus_policy = std::string(name);
    }

    std::string mutation_policy;
    std::string scheduling_policy;
    std::string corpus_policy;
};

template<typename Fn>
bool WaitFor(Fn&& fn, std::chrono::milliseconds timeout = std::chrono::milliseconds{500})
{
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (fn()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
    return fn();
}

} // namespace

bool RunProjectorCase(refuzz::core::metrics::MetricRegistry& registry,
                      refuzz::telemetry::RunStateStore& store)
{
    refuzz::core::BroadcastBus<refuzz::core::channel_contract::ChannelObserveEvent> channel_event_bus;

    FakePolicyControl control;
    refuzz::telemetry::PolicyEngine engine(control, &store, registry);
    refuzz::telemetry::ObservabilityConfig cfg;
    cfg.pull_interval = std::chrono::milliseconds{5};
    refuzz::telemetry::ObservabilityProjector projector(
        store,
        channel_event_bus.Subscribe(),
        cfg,
        &engine,
        &registry);

    refuzz::core::channel_contract::ChannelObserveEvent recovery_event;
    recovery_event.kind = refuzz::core::channel_contract::ChannelObserveEventKind::kRecoveryStarted;
    recovery_event.event_id = 100;
    recovery_event.ts_us = 3;
    recovery_event.channel_id = 7;
    recovery_event.generation = 1;
    recovery_event.fault_reason = refuzz::core::channel_contract::ChannelFaultReason::kWorkerHeartbeatLost;
    recovery_event.recovery_action = refuzz::core::channel_contract::RecoveryAction::kRestartSingleWorker;
    channel_event_bus.Publish(recovery_event);

    projector.Start();

    if (!WaitFor([&]() {
        const auto events = store.RecentEvents(8);
        return std::any_of(events.begin(), events.end(), [](const auto& event) {
            return event.subject == "channel_recovery" &&
                   event.kind == refuzz::core::RuntimeEvent::Kind::kRecoveryBegin;
        });
    })) {
        projector.Stop();
        return 1;
    }

    projector.Stop();
    const auto summary = store.LatestRunSummary();
    return summary.has_value();
}

int main()
{
    // [harness-fatal 语义修正] 阶段 1：只有任务级 harness_fatal 计数（没有 channel
    // kFailed 终态）→ 不允许判 run 失败（历史 invariant harness_fatal_zero 已移除）。
    {
        refuzz::core::metrics::MetricRegistry registry;
        registry.CounterOf("fuzzer.generated_tasks").Inc();
        registry.CounterOf("fuzzer.results", {{"kind", "abnormal"}}).Inc();
        registry.CounterOf("fuzzer.results", {{"kind", "harness_fatal"}}).Inc();
        refuzz::telemetry::RunStateStore store;
        if (!RunProjectorCase(registry, store)) {
            return 1;
        }
        const auto summary = store.LatestRunSummary();
        if (!summary.has_value() ||
            summary->invariants.status ==
                refuzz::telemetry::RunSummaryInvariants::Status::kViolated ||
            std::find(summary->invariants.failures.begin(),
                      summary->invariants.failures.end(),
                      "harness_fatal_zero") != summary->invariants.failures.end() ||
            std::find(summary->invariants.failures.begin(),
                      summary->invariants.failures.end(),
                      "channel_failed_zero") != summary->invariants.failures.end()) {
            return 1;
        }
    }

    // [harness-fatal 语义修正] 阶段 2：channel 真正进入 kFailed（lifecycle_state
    // one-hot gauge 的 failed=1）→ 判 run 失败（channel_failed_zero invariant）。
    {
        refuzz::core::metrics::MetricRegistry registry;
        registry.CounterOf("fuzzer.generated_tasks").Inc();
        registry.CounterOf("fuzzer.results", {{"kind", "abnormal"}}).Inc();
        registry.GaugeOf("channel.lifecycle_state",
                         {{"channel_id", "7"}, {"state", "failed"}})
            .Set(1);
        refuzz::telemetry::RunStateStore store;
        if (!RunProjectorCase(registry, store)) {
            return 1;
        }
        const auto summary = store.LatestRunSummary();
        if (!summary.has_value() ||
            summary->invariants.status !=
                refuzz::telemetry::RunSummaryInvariants::Status::kViolated ||
            std::find(summary->invariants.failures.begin(),
                      summary->invariants.failures.end(),
                      "channel_failed_zero") == summary->invariants.failures.end()) {
            return 1;
        }
    }

    return 0;
}

#include "channeldispatcher.hpp"
#include "refuzz/channel/channel.hpp"
#include "refuzz/core/metrics/metric_registry.hpp"
#include "refuzz/proto_domain/types.hpp"
#include "refuzz/proto_wire/ivshmem_protocol.h"
#include "refuzz/queue/event_queue.hpp"
#include "refuzz/queue/task_queue.hpp"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <string>
#include <utility>
#include <vector>

namespace {

namespace cc = refuzz::core::channel_contract;

#define CHECK(cond)                                                              \
    do {                                                                         \
        if (!(cond)) {                                                           \
            std::fprintf(stderr, "CHECK failed: %s (line %d)\n",                \
                         #cond, __LINE__);                                       \
            return 1;                                                            \
        }                                                                        \
    } while (0)

class FakeChannel final : public refuzz::channel::IChannel {
public:
    explicit FakeChannel(uint32_t channel_id) : channel_id_(channel_id) {}

    refuzz::channel::Result<void> Boot() override
    {
        return refuzz::channel::Result<void>::Ok();
    }

    void Close() override {}

    cc::ChannelSubmitResult Submit(const cc::ChannelDispatchRequest& request,
                                   std::chrono::microseconds wait_for_slot) override
    {
        submissions.push_back(request);
        submit_waits.push_back(wait_for_slot);
        return cc::ChannelSubmitResult{submit_status, generation};
    }

    bool DrainEvents(refuzz::channel::EventList& events,
                     std::chrono::microseconds timeout) override
    {
        drain_timeouts.push_back(timeout);
        if (queued_events.empty()) {
            return false;
        }
        while (!queued_events.empty()) {
            events.push_back(std::move(queued_events.front()));
            queued_events.pop_front();
        }
        return true;
    }

    void AttachObservabilityPublishers(
        refuzz::core::BroadcastBus<cc::ChannelSnapshot>*,
        refuzz::core::BroadcastBus<cc::ChannelObserveEvent>*,
        refuzz::core::metrics::ChannelMetrics* = nullptr,
        refuzz::core::metrics::MetricRegistry* = nullptr) override
    {}

    cc::ChannelSnapshot ObserveSnapshot() const override
    {
        cc::ChannelSnapshot snapshot;
        snapshot.channel_id = channel_id_;
        snapshot.generation = generation;
        snapshot.lifecycle_state = cc::ChannelLifecycleState::kRunning;
        return snapshot;
    }

    bool DrainObserveEvents(cc::ChannelObserveEventList&,
                            std::chrono::microseconds) override
    {
        return false;
    }

    cc::ChannelSubmitStatus submit_status = cc::ChannelSubmitStatus::kAccepted;
    uint32_t generation = 1;
    std::vector<cc::ChannelDispatchRequest> submissions;
    std::vector<std::chrono::microseconds> submit_waits;
    std::vector<std::chrono::microseconds> drain_timeouts;
    std::deque<cc::ChannelEvent> queued_events;

private:
    uint32_t channel_id_;
};

uint64_t CounterValue(const refuzz::core::metrics::MetricRegistry& registry,
                      const std::string& name)
{
    for (const auto& sample : registry.CollectPrefix("executor.")) {
        if (sample.name == name) {
            return static_cast<uint64_t>(sample.value);
        }
    }
    return 0;
}

bool HasMetric(const refuzz::core::metrics::MetricRegistry& registry,
               const std::string& name)
{
    for (const auto& sample : registry.CollectPrefix("executor.")) {
        if (sample.name == name) {
            return true;
        }
    }
    return false;
}

// [v1 — refuzz::proto::Task ROLLBACK]
// [v2 — §3.10 step 5 (D7). HostFuzzTask is the queue carrier.]
refuzz::queue::HostFuzzTask MakeTask(uint64_t executor_id)
{
    refuzz::queue::HostFuzzTask task;
    task.executor_id = executor_id;
    task.seed_id = 11;
    task.origin_seed_id = 11;
    task.opts.timeout_ms = 1000;
    task.payload = {0x01, 0x02, 0x03};
    return task;
}

cc::ChannelEvent MakeCompletionEvent(uint64_t event_id, uint64_t executor_id)
{
    cc::ChannelEvent event;
    event.kind = cc::ChannelEvent::Kind::kCompletion;
    event.event_id = event_id;
    event.channel_id = 4;
    event.generation = 1;

    cc::Completion completion;
    completion.ctx.executor_id = executor_id;
    completion.ctx.seed_id = 12;
    completion.ctx.origin_seed_id = 12;
    completion.ctx.trace.sampled = true;
    event.payload = std::move(completion);
    return event;
}

int TestExecutorPreservesTaskExecutorId()
{
    refuzz::core::metrics::MetricRegistry registry;
    refuzz::channeldispatcher::ExecutorConfig cfg;
    cfg.idle_sleep_us = 0;
    refuzz::channeldispatcher::Executor executor(cfg, &registry);
    FakeChannel channel(7);
    executor.AddChannel(&channel);

    refuzz::queue::InMemoryTaskQueue task_queue;
    refuzz::queue::InMemoryEventQueue event_queue;
    auto task = MakeTask(4242);
    task.trace.sampled = true;
    CHECK(task_queue.Push(std::move(task)));

    CHECK(executor.ProcessOnce(task_queue,
                               event_queue,
                               std::chrono::milliseconds{0},
                               std::chrono::microseconds{0}));
    CHECK(channel.submissions.size() == 1);
    CHECK(channel.submissions[0].executor_id == 4242);
    CHECK(channel.submissions[0].seed_id == 11);
    CHECK(channel.submissions[0].trace.task_queue_push_ts_us != 0);
    CHECK(channel.submissions[0].trace.task_queue_pop_ts_us != 0);
    CHECK(channel.submissions[0].trace.task_queue_pop_ts_us >=
          channel.submissions[0].trace.task_queue_push_ts_us);
    CHECK(CounterValue(registry, "executor.tasks_submitted") == 1);
    CHECK(HasMetric(registry, "executor.dispatch.submit_wait_us"));
    return 0;
}

int TestBusyMetric()
{
    refuzz::core::metrics::MetricRegistry registry;
    refuzz::channeldispatcher::ExecutorConfig cfg;
    cfg.idle_sleep_us = 0;
    refuzz::channeldispatcher::Executor executor(cfg, &registry);
    FakeChannel channel(9);
    channel.submit_status = cc::ChannelSubmitStatus::kBusy;
    executor.AddChannel(&channel);

    refuzz::queue::InMemoryTaskQueue task_queue;
    refuzz::queue::InMemoryEventQueue event_queue;
    CHECK(task_queue.Push(MakeTask(5001)));

    executor.ProcessOnce(task_queue,
                         event_queue,
                         std::chrono::milliseconds{0},
                         std::chrono::microseconds{0});
    CHECK(channel.submissions.size() == 1);
    CHECK(channel.submissions[0].trace.task_queue_push_ts_us == 0);
    CHECK(channel.submissions[0].trace.task_queue_pop_ts_us == 0);
    CHECK(CounterValue(registry, "executor.dispatch.busy_results") == 1);
    CHECK(CounterValue(registry, "executor.tasks_submitted") == 0);
    return 0;
}

int TestDefaultIntraThreadedSetsWireFlag()
{
    refuzz::core::metrics::MetricRegistry registry;
    refuzz::channeldispatcher::ExecutorConfig cfg;
    cfg.idle_sleep_us = 0;
    cfg.default_intra_threaded = true;
    refuzz::channeldispatcher::Executor executor(cfg, &registry);
    FakeChannel channel(10);
    executor.AddChannel(&channel);

    refuzz::queue::InMemoryTaskQueue task_queue;
    refuzz::queue::InMemoryEventQueue event_queue;
    CHECK(task_queue.Push(MakeTask(7001)));

    CHECK(executor.ProcessOnce(task_queue,
                               event_queue,
                               std::chrono::milliseconds{0},
                               std::chrono::microseconds{0}));
    CHECK(channel.submissions.size() == 1);
    CHECK((channel.submissions[0].exec_flags & TASK_FLAG_INTRA_MASK) ==
          TASK_FLAG_INTRA_THREADED);
    return 0;
}

int TestCollectCompsKeepsThreadedWhenRequested()
{
    refuzz::core::metrics::MetricRegistry registry;
    refuzz::channeldispatcher::ExecutorConfig cfg;
    cfg.idle_sleep_us = 0;
    cfg.default_intra_threaded = true;
    refuzz::channeldispatcher::Executor executor(cfg, &registry);
    FakeChannel channel(11);
    executor.AddChannel(&channel);

    auto task = MakeTask(7002);
    task.opts.flags |= refuzz::proto::kExecFlagCollectComps;
    task.opts.flags |= refuzz::proto::kExecFlagIntraThreaded;
    task.opts.flags |= refuzz::proto::kExecFlagTraceSampled;

    refuzz::queue::InMemoryTaskQueue task_queue;
    refuzz::queue::InMemoryEventQueue event_queue;
    CHECK(task_queue.Push(std::move(task)));

    CHECK(executor.ProcessOnce(task_queue,
                               event_queue,
                               std::chrono::milliseconds{0},
                               std::chrono::microseconds{0}));
    CHECK(channel.submissions.size() == 1);
    CHECK((channel.submissions[0].exec_flags & TASK_FLAG_COLLECT_COMPS) != 0);
    CHECK((channel.submissions[0].exec_flags & TASK_FLAG_TRACE_SAMPLED) != 0);
    CHECK((channel.submissions[0].exec_flags & TASK_FLAG_INTRA_MASK) ==
          TASK_FLAG_INTRA_THREADED);
    return 0;
}

int TestEventBlockingTimeoutApplies()
{
    refuzz::core::metrics::MetricRegistry registry;
    refuzz::channeldispatcher::ExecutorConfig cfg;
    cfg.event_blocking_timeout_us = 1234;
    refuzz::channeldispatcher::Executor executor(cfg, &registry);
    FakeChannel channel(3);
    executor.AddChannel(&channel);

    refuzz::queue::InMemoryTaskQueue task_queue;
    refuzz::queue::InMemoryEventQueue event_queue;
    executor.ProcessOnce(task_queue,
                         event_queue,
                         std::chrono::milliseconds{0},
                         std::chrono::microseconds{10'000});

    CHECK(channel.drain_timeouts.size() == 2);
    CHECK(channel.drain_timeouts[0] == std::chrono::microseconds{0});
    CHECK(channel.drain_timeouts[1] == std::chrono::microseconds{1234});
    return 0;
}

int TestEventForwardMetrics()
{
    refuzz::core::metrics::MetricRegistry registry;
    refuzz::channeldispatcher::Executor executor({}, &registry);
    FakeChannel channel(4);
    channel.queued_events.push_back(MakeCompletionEvent(7001, 6001));
    executor.AddChannel(&channel);

    refuzz::queue::InMemoryTaskQueue task_queue;
    refuzz::queue::InMemoryEventQueue event_queue;
    CHECK(executor.ProcessOnce(task_queue,
                               event_queue,
                               std::chrono::milliseconds{0},
                               std::chrono::microseconds{0}));
    CHECK(event_queue.PendingSize() == 1);
    auto forwarded = event_queue.Pop(std::chrono::milliseconds{0});
    CHECK(forwarded.has_value());
    const auto* completion = forwarded->AsCompletion();
    CHECK(completion != nullptr);
    CHECK(completion->ctx.trace.executor_event_forwarded_ts_us != 0);
    CHECK(CounterValue(registry, "executor.events_forwarded") == 1);
    CHECK(HasMetric(registry, "executor.events.forward_latency_us"));
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
        {"ExecutorPreservesTaskExecutorId", TestExecutorPreservesTaskExecutorId},
        {"BusyMetric", TestBusyMetric},
        {"DefaultIntraThreadedSetsWireFlag", TestDefaultIntraThreadedSetsWireFlag},
        {"CollectCompsKeepsThreadedWhenRequested",
         TestCollectCompsKeepsThreadedWhenRequested},
        {"EventBlockingTimeoutApplies", TestEventBlockingTimeoutApplies},
        {"EventForwardMetrics", TestEventForwardMetrics},
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

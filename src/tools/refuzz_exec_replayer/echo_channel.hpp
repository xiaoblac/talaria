#pragma once

// EchoChannel — minimal in-process IChannel impl for offline replayer
// smoke tests. Submit() accepts and queues a Completion containing the
// payload echoed back; DrainEvents() returns whatever has accumulated.
//
// PR3-3b's role: prove replayer's Submit/Drain reconcile loop end-to-end
// without QEMU. Production replayer runs are driven by ChannelCatalog
// "qemu_ivshmem_linux"; that wiring lands in PR3-3c.
//
// NOT a substitute for kernel execution — output is just the submitted
// payload. The comparator (PR4) treats EchoChannel output as a no-op
// signal and is expected to skip the join.

#include "refuzz/channel/channel.hpp"

#include <deque>
#include <mutex>

namespace refuzz::oracle::replayer {

class EchoChannel : public refuzz::channel::IChannel {
public:
    EchoChannel() = default;
    ~EchoChannel() override = default;

    refuzz::channel::Result<void> Boot() override;
    void Close() override;

    refuzz::core::channel_contract::ChannelSubmitResult Submit(
        const refuzz::core::channel_contract::ChannelDispatchRequest& request,
        std::chrono::microseconds wait_for_slot) override;
    bool DrainEvents(refuzz::channel::EventList& events,
                     std::chrono::microseconds timeout) override;

    void AttachObservabilityPublishers(
        refuzz::core::BroadcastBus<refuzz::core::channel_contract::ChannelSnapshot>*,
        refuzz::core::BroadcastBus<refuzz::core::channel_contract::ChannelObserveEvent>*,
        refuzz::core::metrics::ChannelMetrics*,
        refuzz::core::metrics::MetricRegistry*) override {}
    refuzz::core::channel_contract::ChannelSnapshot ObserveSnapshot() const override {
        return {};
    }
    bool DrainObserveEvents(
        refuzz::core::channel_contract::ChannelObserveEventList&,
        std::chrono::microseconds) override { return false; }

private:
    std::mutex mu_;
    std::deque<refuzz::core::channel_contract::ChannelEvent> queue_;
    uint64_t next_event_id_ = 1;
    bool booted_ = false;
};

} // namespace refuzz::oracle::replayer

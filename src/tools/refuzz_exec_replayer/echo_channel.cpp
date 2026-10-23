#include "echo_channel.hpp"

#include <chrono>
#include <thread>

namespace refuzz::oracle::replayer {

namespace cc = refuzz::core::channel_contract;

refuzz::channel::Result<void> EchoChannel::Boot() {
    booted_ = true;
    return refuzz::channel::Result<void>::Ok();
}

void EchoChannel::Close() {
    std::lock_guard<std::mutex> lk(mu_);
    booted_ = false;
    queue_.clear();
}

cc::ChannelSubmitResult EchoChannel::Submit(
    const cc::ChannelDispatchRequest& request,
    std::chrono::microseconds /*wait_for_slot*/) {
    std::lock_guard<std::mutex> lk(mu_);
    if (!booted_) {
        return cc::ChannelSubmitResult{cc::ChannelSubmitStatus::kUnavailable, 0};
    }
    if (request.executor_id == 0) {
        // Production channel.cpp:1659 hard-rejects; mirror that here so
        // replayer bugs (forgetting to set executor_id) surface in tests.
        return cc::ChannelSubmitResult{cc::ChannelSubmitStatus::kInvalid, 0};
    }
    cc::ChannelEvent ev;
    ev.kind = cc::ChannelEvent::Kind::kCompletion;
    ev.event_id = next_event_id_++;
    ev.channel_id = 0;
    ev.generation = 0;
    cc::Completion comp;
    comp.ctx.executor_id = request.executor_id;
    comp.ctx.seed_id = request.seed_id;
    comp.ctx.origin_seed_id = request.origin_seed_id;
    comp.ctx.worker_id = 0;
    comp.ctx.proc_id = request.target_proc_id;
    comp.ctx.dispatch_gen = 0;
    comp.ctx.generation = 0;
    comp.ctx.submit_ts_us = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
    comp.ctx.program_payload = request.payload;
    comp.kind = cc::CompletionKind::kNormal;
    comp.output = request.payload;  // echo
    ev.payload = std::move(comp);
    queue_.push_back(std::move(ev));
    return cc::ChannelSubmitResult{cc::ChannelSubmitStatus::kAccepted, 0};
}

bool EchoChannel::DrainEvents(refuzz::channel::EventList& events,
                              std::chrono::microseconds timeout) {
    using clock = std::chrono::steady_clock;
    auto deadline = clock::now() + timeout;
    while (true) {
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (!queue_.empty()) {
                while (!queue_.empty()) {
                    events.push_back(std::move(queue_.front()));
                    queue_.pop_front();
                }
                return true;
            }
        }
        if (timeout.count() <= 0 || clock::now() >= deadline) return false;
        std::this_thread::sleep_for(std::chrono::microseconds(50));
    }
}

} // namespace refuzz::oracle::replayer

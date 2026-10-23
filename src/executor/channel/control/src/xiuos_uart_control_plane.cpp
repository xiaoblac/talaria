#include "refuzz/channel/control/xiuos_uart_control_plane.hpp"

#include <chrono>
#include <stdexcept>

namespace refuzz::channel::control {

namespace {

using refuzz::channel::Error;
using refuzz::channel::ErrorKind;
using refuzz::channel::Result;

}  // namespace

XiuosUartControlPlane::XiuosUartControlPlane(Config cfg)
    : config_(std::move(cfg)) {
    if (!config_.backbone) {
        throw std::invalid_argument(
            "XiuosUartControlPlane: backbone must be non-null");
    }
}

std::uint16_t XiuosUartControlPlane::HeartbeatSeq(std::uint64_t counter) noexcept {
    return static_cast<std::uint16_t>(counter & 0xFFFFu);
}

std::uint64_t XiuosUartControlPlane::NowMicros() noexcept {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}

Result<void> XiuosUartControlPlane::BeginSession() {
    const SessionState s = state_.load();
    switch (s) {
        case SessionState::kIdle:
            state_.store(SessionState::kHandshaking);
            return Result<void>::Ok();
        case SessionState::kHandshaking:
        case SessionState::kReady:
            return Result<void>::Ok();  // idempotent
        case SessionState::kClosing:
        case SessionState::kClosed:
        case SessionState::kFaulted:
            return Error{ErrorKind::kProtocol,
                         "XiuosUartControlPlane::BeginSession: cannot begin from "
                         "Closing/Closed/Faulted; call ResetSession first"};
    }
    return Error{ErrorKind::kProtocol,
                 "XiuosUartControlPlane::BeginSession: unknown SessionState"};
}

Result<void> XiuosUartControlPlane::WaitAllWorkersReady(
    std::chrono::milliseconds timeout) {
    if (ready_.load()) {
        state_.store(SessionState::kReady);
        return Result<void>::Ok();
    }
    // Channel::Boot historically passes 0 ms here, expecting CP impls to
    // supply their own configured ready-timeout (see executor/channel/
    // orchestration/src/channel.cpp). Forwarding 0 verbatim to the backbone
    // would immediately time out. Fall back to config_.ready_timeout, which
    // Assembler wires from ChannelConfig::wait_ready_timeout.
    const auto effective = (timeout > std::chrono::milliseconds(0))
                               ? timeout
                               : config_.ready_timeout;
    auto frame = config_.backbone->WaitFrame(
        infra::XiuosFrameType::Ready, std::nullopt, effective);
    if (!frame.ok()) {
        state_.store(SessionState::kFaulted);
        return frame.error();
    }
    ready_.store(true);
    state_.store(SessionState::kReady);
    return Result<void>::Ok();
}

Result<void> XiuosUartControlPlane::WaitWorkerReady(
    std::uint32_t worker_id, std::chrono::milliseconds timeout) {
    if (worker_id != 0) {
        return Error{ErrorKind::kConfig,
                     "XiuosUartControlPlane::WaitWorkerReady: worker_id must be 0"};
    }
    return WaitAllWorkersReady(timeout);
}

Result<void> XiuosUartControlPlane::ResetSession() {
    // XiUOS worker has no wire-level session reset; the in-kernel worker
    // keeps running, so revocation is cleared and the session is pulled
    // back into a state where BeginSession can succeed again.
    //
    // Recovery reboot calls ResetSession while the CP is usually still Ready.
    // Clear READY unconditionally so the post-reboot WaitAllWorkersReady()
    // waits for the freshly booted XiUOS worker instead of accepting stale
    // readiness from the dead QEMU instance.
    revoked_.store(false);
    ready_.store(false);
    state_.store(SessionState::kIdle);
    return Result<void>::Ok();
}

Result<void> XiuosUartControlPlane::ResetWorkerSession(std::uint32_t worker_id) {
    if (worker_id != 0) {
        return Error{ErrorKind::kConfig,
                     "XiuosUartControlPlane::ResetWorkerSession: worker_id must be 0"};
    }
    return ResetSession();
}

Result<void> XiuosUartControlPlane::ClearProcIsolationState() {
    return Result<void>::Ok();
}

Result<void> XiuosUartControlPlane::EndSession() {
    state_.store(SessionState::kClosed);
    ready_.store(false);
    return Result<void>::Ok();
}

SessionState XiuosUartControlPlane::CurrentState() const {
    return state_.load();
}

std::uint32_t XiuosUartControlPlane::RegisteredWorkerCount() const {
    return (ready_.load() && !revoked_.load()) ? 1u : 0u;
}

bool XiuosUartControlPlane::IsWorkerRegistered(std::uint32_t worker_id) const {
    return worker_id == 0 && ready_.load() && !revoked_.load();
}

void XiuosUartControlPlane::RevokeWorker(std::uint32_t worker_id) {
    if (worker_id == 0) revoked_.store(true);
}

WorkerHeartbeatSample
XiuosUartControlPlane::SampleHeartbeat(std::uint32_t worker_id) {
    WorkerHeartbeatSample sample;
    sample.worker_id = worker_id;
    sample.valid = false;
    if (worker_id != 0 || !ready_.load() || revoked_.load()) {
        return sample;
    }

    const std::uint64_t counter = heartbeat_counter_.fetch_add(1) + 1;
    const std::uint16_t seq = HeartbeatSeq(counter);

    auto send = config_.backbone->SendFrame(infra::XiuosFrameType::Ping, seq, {});
    if (!send.ok()) return sample;

    auto pong = config_.backbone->WaitFrame(
        infra::XiuosFrameType::Pong, seq, config_.heartbeat_timeout);
    if (!pong.ok()) return sample;

    sample.counter = counter;
    sample.sampled_ts_us = NowMicros();
    sample.valid = true;
    return sample;
}

Result<void> XiuosUartControlPlane::RequestCancel(
    std::uint32_t /*worker_id*/, std::uint64_t /*executor_id*/) {
    // XiUOS worker has no mid-program cancel surface. Accept the request
    // silently; ReadCancelAck always returns false, so callers fall back to
    // host timeout + QEMU restart for forceful cancellation.
    return Result<void>::Ok();
}

bool XiuosUartControlPlane::ReadCancelAck(
    std::uint32_t /*worker_id*/, std::uint64_t /*executor_id*/) {
    return false;
}

SendabilityView XiuosUartControlPlane::GetSendabilityView() {
    SendabilityView view;
    view.is_registered = [this](std::uint32_t worker_id) -> bool {
        return IsWorkerRegistered(worker_id);
    };
    view.registered_worker_count = [this]() -> std::uint32_t {
        return RegisteredWorkerCount();
    };
    return view;
}

RegistrationControlHook XiuosUartControlPlane::GetRegistrationHook() {
    return {};  // empty closure; XiUOS DP doesn't write-back registration
}

}  // namespace refuzz::channel::control

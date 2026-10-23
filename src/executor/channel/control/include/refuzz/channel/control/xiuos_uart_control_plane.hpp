#pragma once

// XiuosUartControlPlane — IControlPlane impl over a XiUOS UART backbone.
//
// Phase 2 §B v1. The XiUOS worker is single-instance per kernel image, so
// most of IControlPlane's multi-worker / registration / cancel surface
// degrades to one-of-a-kind semantics:
//   - "session" = one READY frame is observed after Connect
//   - "registered" = worker_id 0 is alive once READY has arrived
//   - "heartbeat" = PING(seq=N) -> PONG(seq=N) round-trip succeeds
//   - "cancel" = no-op (XiUOS worker auto-resets state between PROGRAMs;
//                       there is no wire-level mid-program cancel)
//
// Shares an infra::XiuosUartBackbone with XiuosUartDataPlane via shared_ptr;
// the backbone's pending-frame queue handles the case where CP wants PONG
// while DP is waiting for RESULT (or vice versa) without dropping frames.

#include "refuzz/channel/control/control_plane.hpp"
#include "refuzz/channel/infra/xiuos_uart_backbone.hpp"
#include "refuzz/channel/result.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>

namespace refuzz::channel::control {

class XiuosUartControlPlane final : public IControlPlane {
public:
    struct Config {
        std::shared_ptr<infra::XiuosUartBackbone> backbone;
        // Heartbeat sampling timeout (single PING/PONG round-trip).
        std::chrono::milliseconds  heartbeat_timeout{std::chrono::milliseconds(500)};
        // Fallback ready-timeout used when WaitAllWorkersReady is called with
        // 0 ms (Channel::Boot does exactly this). Assembler injects
        // ChannelConfig::wait_ready_timeout here; tests can override.
        std::chrono::milliseconds  ready_timeout{std::chrono::seconds(60)};
    };

    explicit XiuosUartControlPlane(Config cfg);

    // ───── Session lifecycle ─────
    Result<void> BeginSession() override;
    Result<void> WaitAllWorkersReady(std::chrono::milliseconds timeout) override;
    Result<void> WaitWorkerReady(std::uint32_t worker_id,
                                 std::chrono::milliseconds timeout) override;
    Result<void> ResetSession() override;
    Result<void> ResetWorkerSession(std::uint32_t worker_id) override;
    Result<void> ClearProcIsolationState() override;
    Result<void> EndSession() override;

    // ───── Status / capacity ─────
    SessionState  CurrentState() const override;
    std::uint32_t RegisteredWorkerCount() const override;
    bool          IsWorkerRegistered(std::uint32_t worker_id) const override;
    void          RevokeWorker(std::uint32_t worker_id) override;
    std::uint32_t MaxWorkerSlots() const noexcept override { return kWorkers; }
    std::uint32_t WorkerCount()    const noexcept override { return kWorkers; }

    // ───── Heartbeat ─────
    WorkerHeartbeatSample SampleHeartbeat(std::uint32_t worker_id) override;

    // ───── Cancel (no-op for XiUOS) ─────
    Result<void> RequestCancel(std::uint32_t worker_id, std::uint64_t executor_id) override;
    bool         ReadCancelAck(std::uint32_t worker_id, std::uint64_t executor_id) override;

    // ───── Exports for DataPlane / Channel ─────
    SendabilityView         GetSendabilityView() override;
    RegistrationControlHook GetRegistrationHook() override;

    // Test / introspection: read the config back. Used to verify Assembler
    // wires ChannelConfig::wait_ready_timeout into ready_timeout.
    const Config& config() const noexcept { return config_; }

private:
    static constexpr std::uint32_t kWorkers = 1;

    static std::uint16_t HeartbeatSeq(std::uint64_t counter) noexcept;
    static std::uint64_t NowMicros() noexcept;

    Config                       config_;
    std::atomic<SessionState>    state_{SessionState::kIdle};
    std::atomic<bool>            ready_{false};
    std::atomic<bool>            revoked_{false};
    std::atomic<std::uint64_t>   heartbeat_counter_{0};
};

}  // namespace refuzz::channel::control

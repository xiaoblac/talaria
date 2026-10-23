#pragma once

// XiuosUartDataPlane — IDataPlane impl over a XiUOS UART backbone.
//
// Phase 2 §B v1. Single-worker, single in-flight: XiUOS executes one
// PROGRAM at a time on its in-kernel worker task, so we don't multiplex.
// SubmitInput.payload_data is expected to already be an encoded XiUOS
// PROGRAM payload (output of refuzz::program::xiuos::XiuosEncodeProgram);
// this class only wraps it in the UART PROGRAM frame and decodes RESULT.
//
// Shares its backbone with XiuosUartControlPlane via shared_ptr. The
// backbone's pending-frame queue means a PONG arriving while Poll waits
// for a RESULT (or vice versa) does NOT get dropped.
//
// WakePoller v1: sets an atomic flag; Poll loops in 10ms slices on
// backbone.WaitFrame and re-checks the flag between slices. Bounded wake
// latency = 10ms. A future revision can add an eventfd into the backbone
// for instant wake; see executor/design.md §5.6 "WakePoller" requirements.

#include "refuzz/channel/data/data_plane.hpp"
#include "refuzz/channel/infra/xiuos_uart_backbone.hpp"
#include "refuzz/channel/result.hpp"
#include "refuzz/program/xiuos/xiuos_result.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <vector>

namespace refuzz::channel::data {

class XiuosUartDataPlane final : public IDataPlane {
public:
    struct Config {
        std::shared_ptr<infra::XiuosUartBackbone>  backbone;
        // Bound on a single WaitFrame slice when Poll is asked to block.
        std::chrono::milliseconds                   poll_slice{std::chrono::milliseconds(10)};
        // [Stage 3 wedge timeout] Per-program wall-clock budget. If a submitted
        // program is still in-flight (no RESULT) past this since Submit(), Poll
        // emits a kTimeout DispatchOutcome and frees the single slot. This is the
        // de-siloed form of XiuosFuzzSession::Step's wedge_initial_drain_ms
        // deadline: the worker is single-threaded over one socket, so a wedging
        // program (CHECK→while(1) / WAITING_FOREVER) never returns and would
        // otherwise hold the only slot forever. 0 disables (wait indefinitely).
        std::chrono::milliseconds                   program_timeout{std::chrono::milliseconds(15000)};
    };

    explicit XiuosUartDataPlane(Config cfg);

    // ───── Lifecycle ─────
    Result<void> StartServer() override;  // no host-side server; returns Ok
    Result<void> Prepare() override;       // backbone.Connect()
    void         Close() override;

    void Pause() override;
    void Resume() override;

    // ───── Submit / Poll / Wake ─────
    SubmitOutcome Submit(const SubmitInput& req) override;
    void          Poll(std::vector<DispatchOutcome>& out,
                       std::chrono::microseconds timeout) override;
    void          WakePoller() noexcept override;

    // ───── Reset / inflight ─────
    void                          ResetWorker(std::uint32_t worker_id) override;
    void                          ResetAll() override;
    std::vector<InflightEntry>    SnapshotInflight() const override;

    // ───── Status ─────
    bool          IsPaused() const noexcept override { return paused_.load(); }
    bool          IsClosed() const noexcept override { return closed_.load(); }
    std::uint32_t MaxWorkerSlots() const noexcept override { return kWorkers; }
    bool          IsWorkerSendable(std::uint32_t worker_id) const override;

    // [Stage 3 wedge relay] When Poll() trips the per-program timeout it both
    // frees the slot (emits kTimeout) AND latches this wedge flag. A thin health
    // sensor calls ConsumeWedgePending() (atomic test-and-clear, no socket
    // access — race-free vs the UART backbone) and, on true, publishes one
    // health crash event so the standard Channel recovery path reboots QEMU
    // (a wedged single-threaded worker only un-wedges via reboot). Detection
    // stays in Poll; this is just the Poll→health bridge.
    bool          ConsumeWedgePending() noexcept { return wedge_pending_.exchange(false); }

    // Test / introspection: verify profile/config values were wired by the
    // assembler without exposing transport internals.
    const Config& config() const noexcept { return config_; }

private:
    static constexpr std::uint32_t kWorkers = 1;

    static std::uint16_t SeqFromExecutor(std::uint64_t executor_id) noexcept;
    static DispatchOutcomeKind TranslateStatus(
        refuzz::program::xiuos::XiuosResultStatus s) noexcept;

    Config                       config_;
    std::atomic<bool>            paused_{false};
    std::atomic<bool>            closed_{false};
    std::atomic<bool>            wake_pending_{false};
    // [Stage 3 wedge relay] latched by Poll() on per-program timeout, drained
    // by ConsumeWedgePending() (the health relay sensor). Cleared on Reset.
    std::atomic<bool>            wedge_pending_{false};

    mutable std::mutex           inflight_mu_;
    std::optional<InflightEntry> inflight_;
    std::uint64_t                inflight_start_ts_us_{0};
};

}  // namespace refuzz::channel::data

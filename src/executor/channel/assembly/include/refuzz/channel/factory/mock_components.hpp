#pragma once

// mock_components.hpp — MockAssembler 专用组件（v3.5 Phase G）
//
// 所有类均为 echo/no-op 实现，不启动任何线程/套接字/共享内存。
// 供 MockAssembler::Assemble 装配，替代原 MockChannel 整块实现。
//
// 设计来源：docs/channel-redesign/v3.5/160_phase_G_health_recovery.md §G.9.2

#include "refuzz/channel/control/control_plane.hpp"
#include "refuzz/channel/control/registration_hook.hpp"
#include "refuzz/channel/control/session_timing.hpp"
#include "refuzz/channel/data/data_plane.hpp"
#include "refuzz/channel/evidence/console_source.hpp"
#include "refuzz/channel/result.hpp"
#include "refuzz/channel/substrate/substrate_contract.hpp"

#include <chrono>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace refuzz::channel::factory {

// ── MockSubstrate ─────────────────────────────────────────────────────────────

class MockSubstrate final : public runtime::ISubstrate {
public:
    Result<void> StartVM(uint32_t) override { return Result<void>::Ok(); }
    void         StopVM(uint32_t) override {}
    Result<void> RebootVM(uint32_t) override { return Result<void>::Ok(); }
    bool         IsVMAlive(uint32_t) const noexcept override { return true; }

    Result<void> Close() override { return Result<void>::Ok(); }

    Result<void> CopyFileTo(uint32_t, const std::string&, const std::string&,
                            std::chrono::milliseconds) override
    { return Result<void>::Ok(); }

    Result<std::string> RunCommand(uint32_t, const std::string&,
                                   std::chrono::milliseconds) override
    { return Result<std::string>::Ok(""); }

    Result<void> DeployArtifacts(uint32_t, const runtime::DeployBundle&) override
    { return Result<void>::Ok(); }

    Result<void> StartAllWorkers(uint32_t) override { return Result<void>::Ok(); }
    Result<void> StopAllWorkers(uint32_t)  override { return Result<void>::Ok(); }
    Result<void> StartWorker(uint32_t, uint32_t) override { return Result<void>::Ok(); }
    Result<void> StopWorker(uint32_t, uint32_t)  override { return Result<void>::Ok(); }

    evidence::ConsoleEndpoint DefaultConsoleEndpoint(uint32_t) const override {
        return {};
    }
    runtime::VendorHints Hints(uint32_t) const override { return {}; }
    std::string          Diagnose(uint32_t) const override { return "MockSubstrate"; }
};

// ── MockControlPlane ──────────────────────────────────────────────────────────

class MockControlPlane final : public control::IControlPlane {
public:
    explicit MockControlPlane(uint32_t n_workers)
        : n_workers_(n_workers),
          worker_errors_(n_workers, ERR_OK),
          worker_error_consumes_(n_workers, 0) {}

    Result<void> BeginSession()  override { return Result<void>::Ok(); }
    Result<void> WaitAllWorkersReady(std::chrono::milliseconds) override
    { return Result<void>::Ok(); }
    Result<void> WaitWorkerReady(uint32_t, std::chrono::milliseconds) override
    { return Result<void>::Ok(); }
    Result<void> ResetSession()             override { return Result<void>::Ok(); }
    Result<void> ResetWorkerSession(uint32_t) override { return Result<void>::Ok(); }
    Result<void> ClearProcIsolationState() override { return Result<void>::Ok(); }
    Result<void> EndSession()               override { return Result<void>::Ok(); }

    control::SessionState CurrentState() const override {
        return control::SessionState::kIdle;
    }
    uint32_t RegisteredWorkerCount() const override { return 0; }
    bool     IsWorkerRegistered(uint32_t) const override { return false; }

    void RevokeWorker(uint32_t) override {}

    uint32_t ConsumeWorkerError(uint32_t worker_id) noexcept override
    {
        std::lock_guard<std::mutex> lock(error_mu_);
        if (worker_id >= worker_errors_.size()) return ERR_OK;
        const uint32_t error = worker_errors_[worker_id];
        worker_errors_[worker_id] = ERR_OK;
        if (error != ERR_OK) {
            ++worker_error_consumes_[worker_id];
        }
        return error;
    }

    // Test seam for the guest-published maintenance latch. Production code
    // reaches the same path through IControlPlane::ConsumeWorkerError().
    void LatchWorkerErrorForTest(uint32_t worker_id, uint32_t error_code)
    {
        std::lock_guard<std::mutex> lock(error_mu_);
        if (worker_id < worker_errors_.size()) {
            worker_errors_[worker_id] = error_code;
        }
    }

    uint32_t WorkerErrorConsumeCountForTest(uint32_t worker_id) const
    {
        std::lock_guard<std::mutex> lock(error_mu_);
        return worker_id < worker_error_consumes_.size()
            ? worker_error_consumes_[worker_id] : 0;
    }

    uint32_t WorkerErrorValueForTest(uint32_t worker_id) const
    {
        std::lock_guard<std::mutex> lock(error_mu_);
        return worker_id < worker_errors_.size()
            ? worker_errors_[worker_id] : ERR_OK;
    }

    control::WorkerHeartbeatSample SampleHeartbeat(uint32_t) override { return {}; }

    Result<void> RequestCancel(uint32_t, uint64_t) override { return Result<void>::Ok(); }
    bool         ReadCancelAck(uint32_t, uint64_t) override { return false; }

    control::SendabilityView    GetSendabilityView() override { return {}; }
    control::RegistrationControlHook GetRegistrationHook() override { return {}; }

    uint32_t MaxWorkerSlots() const noexcept override { return n_workers_; }
    uint32_t WorkerCount()    const noexcept override { return n_workers_; }

private:
    uint32_t n_workers_;
    mutable std::mutex error_mu_;
    std::vector<uint32_t> worker_errors_;
    std::vector<uint32_t> worker_error_consumes_;
};

// ── MockDataPlane ─────────────────────────────────────────────────────────────

class MockDataPlane final : public data::IDataPlane {
public:
    explicit MockDataPlane(uint32_t n_workers) : n_workers_(n_workers) {}

    Result<void> Prepare() override { return Result<void>::Ok(); }
    void         Close()   override {
        closed_.store(true, std::memory_order_release);
        WakePoller();
    }

    void Pause()  override {}
    void Resume() override {}

    data::SubmitOutcome Submit(const data::IDataPlane::SubmitInput&) override {
        return data::SubmitOutcome::kSent;
    }

    void Poll(std::vector<data::DispatchOutcome>&,
              std::chrono::microseconds timeout) override {
        if (timeout <= std::chrono::microseconds{0}) return;
        std::unique_lock<std::mutex> lock(wake_mutex_);
        wake_cv_.wait_for(lock, timeout, [this] {
            return wake_pending_.load(std::memory_order_acquire) ||
                   closed_.load(std::memory_order_acquire);
        });
        wake_pending_.store(false, std::memory_order_release);
    }

    void WakePoller() noexcept override {
        wake_pending_.store(true, std::memory_order_release);
        wake_cv_.notify_all();
    }

    void ResetWorker(uint32_t) override {}
    void ResetAll()            override {}

    std::vector<data::InflightEntry> SnapshotInflight() const override {
        return {};
    }

    bool     IsPaused()       const noexcept override { return false; }
    bool     IsClosed()       const noexcept override {
        return closed_.load(std::memory_order_acquire);
    }
    uint32_t MaxWorkerSlots() const noexcept override { return n_workers_; }
    bool     IsWorkerSendable(uint32_t) const override { return true; }

private:
    uint32_t n_workers_;
    mutable std::mutex wake_mutex_;
    std::condition_variable wake_cv_;
    std::atomic<bool> wake_pending_{false};
    std::atomic<bool> closed_{false};
};

// ── NullConsoleSource ─────────────────────────────────────────────────────────

class NullConsoleSource final : public evidence::IConsoleSource {
public:
    Result<void> Open(const evidence::ConsoleEndpoint&) override {
        return Result<void>::Ok();
    }
    std::optional<std::string> ReadLine(std::chrono::milliseconds) override {
        return std::nullopt;
    }
    void Wakeup() override {}
    void Close()  override {}

    State       CurrentState() const override { return State::kOpen; }
    std::string LastError()    const override { return {}; }
};

} // namespace refuzz::channel::factory

#pragma once

#include "worker/adapter/worker_task_channel.hpp"
#include "worker/engine/loop_worker_boot_config.hpp"
#include "worker/engine/execution_domain_registry.hpp"
#include "worker/program_buffers.hpp"
#include "worker/sandbox.hpp"
#include "worker/topology/process_topology.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <variant>

namespace refuzz::worker {

class IExecBackend;
class IObservationBus;

struct InheritedDomainComponents {
    std::reference_wrapper<IExecBackend> backend;
    std::reference_wrapper<IObservationBus> bus;
};

struct ExecRebuiltDomainComponents {};

using DomainComponentBinding = std::variant<
    InheritedDomainComponents,
    ExecRebuiltDomainComponents>;

struct EngineConfig {
    uint32_t exec_timeout_ms = 5000;
    uint32_t daemon_watchdog_ms = 0;
    uint32_t domain_startup_timeout_ms =
        topology::kDefaultDomainStartupTimeoutMs;
    uint32_t domain_startup_attempts = 20;
    uint32_t domain_recovery_attempts = 20;
    uint32_t domain_stop_grace_ms = 2000;
    uint32_t domain_stop_kill_ms = 2000;
    uint32_t domain_stop_runner_ms = 1000;
    uint32_t domain_stop_reap_ms = 2000;
    uint32_t recycle_after = 600;
    uint32_t worker_id = 0;
    int poll_ms = 1;
    SandboxMode sandbox_mode = SandboxMode::kNone;
    size_t transport_mapped_bytes = 0;
    void* transport_shm_base = nullptr;
    size_t transport_shm_size = 0;
    ExecutionDomainTransport execution_transport;
    engine::LoopWorkerBootConfig loop_boot_config =
        engine::MakeLoopWorkerBootConfig();
    std::string executor_path;
    std::string recycle_gate_path;
};

enum class DomainState : uint8_t {
    kStarting = 0,
    kReady,
    kExecuting,
    kStopping,
    kFailed,
    kStopped,
};

enum class TransitionReason : uint8_t {
    kInitialStartup = 0,
    kPeriodicRecycle,
    kTaskWatchdog,
    kTaskCancelled,
    kHarnessFailure,
    kProcRebind,
    kShutdown,
};

enum class DomainRecoveryKind : uint8_t {
    kRecovered = 0,
    kReplacementStartFailed,
    kOwnershipUnreclaimed,
};

enum class RecoveryFailedStage : uint8_t {
    kNone = 0,
    kStopCurrentDomain,
    kStartReplacement,
    kStopPartialReplacement,
    kBudgetExhausted,
};

struct DomainRecoveryResult {
    DomainRecoveryKind kind = DomainRecoveryKind::kOwnershipUnreclaimed;
    RecoveryFailedStage failed_stage = RecoveryFailedStage::kNone;
    topology::DomainStopResult stop_result =
        topology::DomainStopResult::kClean;
    topology::DomainStartResult last_start_result{};
    uint32_t attempts = 0;
    bool start_attempted = false;

    bool Recovered() const {
        return kind == DomainRecoveryKind::kRecovered;
    }
    bool OldDomainIsolated() const {
        return kind != DomainRecoveryKind::kOwnershipUnreclaimed;
    }
};

const char* TransitionReasonName(TransitionReason reason);

class DomainSupervisor {
public:
    DomainSupervisor(IWorkerTaskChannel& task_channel,
                     IExecutionDomainRegistry& domain_registry,
                     DomainComponentBinding components,
                     std::unique_ptr<topology::ProcessTopology> topology,
                     EngineConfig config);

    int Run();
    void RequestStop();
    bool IsRunning() const;

private:
    enum class IdentitySelection : uint8_t {
        kCurrentThenRotate,
        kRotate,
        kExact,
    };

    struct RecoveryContext {
        uint32_t exact_proc_id = PROC_ID_ANY;
        bool domain_already_stopped = false;
        topology::DomainStopResult prior_stop_result =
            topology::DomainStopResult::kClean;
    };

    struct RecoveryPolicy {
        IdentitySelection identity_selection = IdentitySelection::kRotate;
        topology::DomainStopIntent stop_intent =
            topology::DomainStopIntent::kRecovery;
        bool graceful_stop = false;
        bool allow_abandon = false;
        bool count_against_streak = true;
        uint32_t startup_attempts = 1;
    };

    DomainState State() const;
    uint64_t PhaseDeadlineUs() const;
    void EnterState(DomainState state, uint32_t timeout_ms = 0);
    uint32_t RemainingPhaseTimeoutMs() const;
    uint32_t EffectiveDaemonWatchdogMs() const;
    topology::DomainStopPlan MakeStopPlan(
        topology::DomainStopIntent intent,
        bool graceful,
        bool allow_abandon = false) const;
    topology::DomainStopResult StopDomain(
        topology::DomainStopIntent intent,
        bool graceful,
        bool allow_abandon = false);
    bool ProcIdIsDirty(uint32_t proc_id) const;
    bool MarkProcIdDirty(uint32_t proc_id);
    topology::DomainStartResult StartAttempt(
        const topology::DomainIdentity& candidate,
        TransitionReason reason,
        uint32_t attempt,
        bool identity_already_published);
    RecoveryPolicy RecoveryPolicyFor(TransitionReason reason) const;
    DomainRecoveryResult Recover(TransitionReason reason);
    DomainRecoveryResult Recover(TransitionReason reason,
                                 const RecoveryContext& context);
    DomainRecoveryResult Recover(
        TransitionReason reason,
        const RecoveryContext& context,
        const std::function<void()>& on_stop_classified);
    bool MaintainReadyDomain();
    bool PeriodicRecycle();
    void ResetRecoveryStreak();

    IWorkerTaskChannel& task_channel_;
    IExecutionDomainRegistry& domain_registry_;
    DomainComponentBinding components_;
    std::unique_ptr<topology::ProcessTopology> topology_;
    EngineConfig config_;
    topology::ProcIdLane proc_lane_;
    topology::TopologyConfig topology_config_;
    topology::DomainIdentity identity_{};
    uint32_t dirty_proc_mask_ = 0;
    std::atomic<bool> stop_requested_{false};
    std::atomic<DomainState> state_{DomainState::kStarting};
    std::atomic<uint64_t> phase_deadline_us_{0};
    uint64_t reported_in_domain_ = 0;
    std::atomic<uint32_t> recovery_attempts_in_streak_{0};
    bool domain_ready_publication_initialized_ = false;
    bool domain_ready_published_ = false;
    bool domain_active_ = false;
    bool periodic_recycle_deferred_ = false;
};

} // namespace refuzz::worker

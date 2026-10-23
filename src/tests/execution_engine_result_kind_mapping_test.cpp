#include "worker/adapter/worker_adapter.hpp"
#include "worker/backend/exec_backend.hpp"
#include "worker/engine/execution_engine.hpp"
#include "worker/observation/observation_bus.hpp"
#include "worker/profile/worker_profile.hpp"
#include "worker/topology/process_topology.hpp"

#include "refuzz/proto_wire/error_codes.h"
#include "refuzz/proto_wire/ivshmem_protocol.h"

#include <signal.h>

#include <algorithm>
#include <atomic>
#include <barrier>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

volatile sig_atomic_t g_running = 1;

namespace {

class NoopBackend final : public refuzz::worker::IExecBackend {
public:
    void ConfigureProcId(std::uint32_t proc_id) override
    {
        configured_proc_ids.push_back(proc_id);
    }

    int Execute(const std::uint8_t* /*input*/, std::uint32_t /*input_len*/,
                std::uint8_t* /*output*/, std::uint32_t /*output_cap*/,
                std::uint32_t* output_len,
                refuzz::worker::ExecMode /*mode*/ = {}) override
    {
        *output_len = 0;
        return 0;
    }

    const char* Name() const override { return "noop-engine-mapping-backend"; }
    std::vector<std::uint32_t> configured_proc_ids;
};

class ProcTrackingSink final : public refuzz::worker::IObservationSink {
public:
    explicit ProcTrackingSink(std::vector<std::uint32_t>* proc_ids)
        : proc_ids_(proc_ids)
    {}

    void ConfigureProcId(std::uint32_t proc_id) override
    {
        proc_ids_->push_back(proc_id);
    }
    void OnEvent(refuzz::worker::ObservationEvent,
                 const refuzz::worker::ObservationContext&) override {}
    void PackFeedback(std::uint8_t*, std::uint32_t, std::uint32_t*) override {}
    const char* Name() const override { return "proc-tracking"; }

private:
    std::vector<std::uint32_t>* proc_ids_;
};

class FixedTopology final : public refuzz::worker::topology::ProcessTopology {
public:
    FixedTopology(std::vector<refuzz::worker::topology::CollectResult> results,
                  std::vector<std::string>* events,
                  std::uint32_t fail_rebuild_call,
                  refuzz::worker::topology::DomainStopResult recycle_stop_result,
                  refuzz::worker::topology::DomainStopResult
                      startup_cleanup_stop_result)
        : results_(std::move(results)), events_(events),
          fail_rebuild_call_(fail_rebuild_call),
          recycle_stop_result_(recycle_stop_result),
          startup_cleanup_stop_result_(startup_cleanup_stop_result)
    {}

    refuzz::worker::topology::DomainStartResult Setup(
        const refuzz::worker::topology::TopologyConfig& cfg) override
    {
        current_proc_id_ = cfg.identity.proc_id;
        last_startup_timeout_ms_ = cfg.startup_timeout_ms;
        if (!setup_called_) {
            setup_called_ = true;
            return refuzz::worker::topology::MakeDomainStartReady(
                current_proc_id_);
        }
        ++rebuild_count_;
        if (rebuild_count_ == fail_rebuild_call_) {
            if (events_ != nullptr) {
                events_->push_back("rebuild_failed");
            }
            return refuzz::worker::topology::MakeDomainStartRejected(
                current_proc_id_,
                refuzz::worker::engine::LoopStartupStage::kUnknown,
                EIO);
        }
        ++generation_;
        if (events_ != nullptr) {
            events_->push_back("rebuild");
        }
        return refuzz::worker::topology::MakeDomainStartReady(
            current_proc_id_);
    }

    refuzz::worker::topology::DispatchHandle Dispatch(
        const refuzz::worker::topology::ProgramRequest& /*req*/) override
    {
        dispatched_ = true;
        ++dispatch_count_;
        return refuzz::worker::topology::DispatchHandle{generation_};
    }

    refuzz::worker::topology::CollectResult Collect(
        refuzz::worker::topology::DispatchHandle /*h*/,
        std::uint32_t timeout_ms,
        refuzz::worker::topology::CancelPredicate /*cancel*/,
        void* /*cancel_user*/) override
    {
        collected_ = true;
        last_collect_timeout_ms_ = timeout_ms;
        const std::size_t index = collect_count_ < results_.size()
            ? collect_count_ : results_.size() - 1;
        ++collect_count_;
        auto result = results_[index];
        return result;
    }

    pid_t CurrentChildPid() const override { return 1234; }
    std::uint64_t CurrentChildGeneration() const override { return generation_; }
    refuzz::worker::topology::DomainStopResult Stop(
        const refuzz::worker::topology::DomainStopPlan& plan) override
    {
        teardown_called_ = true;
        last_stop_plan_ = plan;
        ++stop_count_;
        if (plan.intent ==
            refuzz::worker::topology::DomainStopIntent::kRecovery) {
            ++recovery_stop_count_;
            last_recovery_stop_plan_ = plan;
        } else if (plan.intent ==
                   refuzz::worker::topology::DomainStopIntent::kPeriodicRecycle) {
            ++periodic_stop_count_;
        } else if (plan.intent ==
                   refuzz::worker::topology::DomainStopIntent::kDaemonShutdown) {
            ++shutdown_stop_count_;
        } else if (plan.intent ==
                   refuzz::worker::topology::DomainStopIntent::kCancellation) {
            ++cancellation_stop_count_;
        } else if (plan.intent ==
                   refuzz::worker::topology::DomainStopIntent::kRequestedProcRebind) {
            ++rebind_stop_count_;
        } else if (plan.intent ==
                   refuzz::worker::topology::DomainStopIntent::kStartupCleanup) {
            ++startup_cleanup_stop_count_;
        }
        if ((plan.intent ==
                 refuzz::worker::topology::DomainStopIntent::kPeriodicRecycle ||
             plan.intent ==
                 refuzz::worker::topology::DomainStopIntent::kRecovery) &&
            recycle_stop_result_ !=
                refuzz::worker::topology::DomainStopResult::kClean) {
            if (events_ != nullptr) {
                events_->push_back("forced_recycle");
            }
            return recycle_stop_result_;
        }
        if (plan.intent ==
                refuzz::worker::topology::DomainStopIntent::kStartupCleanup &&
            startup_cleanup_stop_result_ !=
                refuzz::worker::topology::DomainStopResult::kClean) {
            return startup_cleanup_stop_result_;
        }
        return refuzz::worker::topology::DomainStopResult::kClean;
    }
    bool ExecutionDomainExited() const override { return false; }

    bool setup_called_ = false;
    bool dispatched_ = false;
    bool collected_ = false;
    bool teardown_called_ = false;
    std::uint32_t rebuild_count_ = 0;
    std::uint32_t dispatch_count_ = 0;
    std::uint32_t collect_count_ = 0;
    std::uint32_t stop_count_ = 0;
    std::uint32_t recovery_stop_count_ = 0;
    std::uint32_t periodic_stop_count_ = 0;
    std::uint32_t shutdown_stop_count_ = 0;
    std::uint32_t cancellation_stop_count_ = 0;
    std::uint32_t rebind_stop_count_ = 0;
    std::uint32_t startup_cleanup_stop_count_ = 0;
    refuzz::worker::topology::DomainStopPlan last_stop_plan_{};
    refuzz::worker::topology::DomainStopPlan last_recovery_stop_plan_{};
    std::uint32_t last_collect_timeout_ms_ = 0;
    std::uint32_t last_startup_timeout_ms_ = 0;

private:
    std::vector<refuzz::worker::topology::CollectResult> results_;
    std::vector<std::string>* events_ = nullptr;
    std::uint32_t fail_rebuild_call_ = 0;
    refuzz::worker::topology::DomainStopResult recycle_stop_result_ =
        refuzz::worker::topology::DomainStopResult::kClean;
    refuzz::worker::topology::DomainStopResult startup_cleanup_stop_result_ =
        refuzz::worker::topology::DomainStopResult::kClean;
    std::uint64_t generation_ = 1;
    std::uint32_t current_proc_id_ = 0;
};

class SlowSetupTopology final
    : public refuzz::worker::topology::ProcessTopology {
public:
    refuzz::worker::topology::DomainStartResult Setup(
        const refuzz::worker::topology::TopologyConfig& cfg) override
    {
        ++setup_count_;
        startup_timeouts_ms_.push_back(cfg.startup_timeout_ms);
        startup_deadlines_us_.push_back(cfg.startup_deadline_us);
        std::this_thread::sleep_for(
            std::chrono::milliseconds(cfg.startup_timeout_ms));
        errno = ETIMEDOUT;
        return refuzz::worker::topology::MakeDomainStartStalled(
            cfg.identity.proc_id, errno);
    }

    refuzz::worker::topology::DispatchHandle Dispatch(
        const refuzz::worker::topology::ProgramRequest&) override
    {
        ++dispatch_count_;
        return {};
    }

    refuzz::worker::topology::CollectResult Collect(
        refuzz::worker::topology::DispatchHandle,
        std::uint32_t,
        refuzz::worker::topology::CancelPredicate,
        void*) override
    {
        ++collect_count_;
        return {};
    }

    pid_t CurrentChildPid() const override { return -1; }
    std::uint64_t CurrentChildGeneration() const override { return 0; }
    bool ExecutionDomainExited() const override { return true; }
    refuzz::worker::topology::DomainStopResult Stop(
        const refuzz::worker::topology::DomainStopPlan&) override
    {
        ++stop_count_;
        return refuzz::worker::topology::DomainStopResult::kClean;
    }

    std::uint32_t setup_count_ = 0;
    std::uint32_t dispatch_count_ = 0;
    std::uint32_t collect_count_ = 0;
    std::uint32_t stop_count_ = 0;
    std::vector<std::uint32_t> startup_timeouts_ms_;
    std::vector<std::uint64_t> startup_deadlines_us_;
};

class BlockingStateTopology final
    : public refuzz::worker::topology::ProcessTopology {
public:
    refuzz::worker::topology::DomainStartResult Setup(
        const refuzz::worker::topology::TopologyConfig& cfg) override
    {
        startup_timeout_ms = cfg.startup_timeout_ms;
        startup_deadline_us = cfg.startup_deadline_us;
        setup_entered.store(true, std::memory_order_release);
        WaitForRelease(release_setup);
        return refuzz::worker::topology::MakeDomainStartReady(
            cfg.identity.proc_id);
    }

    refuzz::worker::topology::DispatchHandle Dispatch(
        const refuzz::worker::topology::ProgramRequest&) override
    {
        return {1};
    }

    refuzz::worker::topology::CollectResult Collect(
        refuzz::worker::topology::DispatchHandle,
        std::uint32_t timeout_ms,
        refuzz::worker::topology::CancelPredicate,
        void*) override
    {
        collect_timeout_ms = timeout_ms;
        collect_entered.store(true, std::memory_order_release);
        WaitForRelease(release_collect);
        refuzz::worker::topology::CollectResult result{};
        result.kind = refuzz::worker::topology::CollectKind::kDone;
        result.result_kind =
            refuzz::worker::engine::RuntimeResultKind::kNormal;
        return result;
    }

    pid_t CurrentChildPid() const override { return 123; }
    std::uint64_t CurrentChildGeneration() const override { return 1; }
    bool ExecutionDomainExited() const override { return false; }
    refuzz::worker::topology::DomainStopResult Stop(
        const refuzz::worker::topology::DomainStopPlan& plan) override
    {
        stop_plan = plan;
        stop_entered.store(true, std::memory_order_release);
        WaitForRelease(release_stop);
        return refuzz::worker::topology::DomainStopResult::kClean;
    }

    std::atomic<bool> setup_entered{false};
    std::atomic<bool> collect_entered{false};
    std::atomic<bool> stop_entered{false};
    std::atomic<bool> release_setup{false};
    std::atomic<bool> release_collect{false};
    std::atomic<bool> release_stop{false};
    std::uint32_t startup_timeout_ms = 0;
    std::uint64_t startup_deadline_us = 0;
    std::uint32_t collect_timeout_ms = 0;
    refuzz::worker::topology::DomainStopPlan stop_plan{};

private:
    static void WaitForRelease(const std::atomic<bool>& release)
    {
        while (!release.load(std::memory_order_acquire)) {
            std::this_thread::yield();
        }
    }
};

class SingleTaskAdapter final
    : public refuzz::worker::IWorkerAdapter,
      public refuzz::worker::IWorkerTaskChannel,
      public refuzz::worker::IExecutionDomainRegistry,
      public refuzz::worker::IWorkerRegistrar {
public:
    SingleTaskAdapter(std::uint32_t crash_output_len,
                      bool initial_corpus_triaged,
                      std::vector<std::string>* events,
                      std::uint32_t tasks_to_serve)
        : crash_output_len_after_reset_(crash_output_len),
          initial_corpus_triaged_(initial_corpus_triaged),
          events_(events), tasks_to_serve_(tasks_to_serve)
    {
        std::memset(input_, 0, sizeof(input_));
        std::memset(output_, 0, sizeof(output_));
        task_.input_buf = input_;
        task_.input_len = sizeof(input_);
        task_.output_buf = output_;
        task_.output_cap = sizeof(output_);
        task_.crash_output_len = &crash_output_len_;
        task_.executor_id = 42;
        task_.dispatch_gen = 7;
        task_.flags = 0;
    }

    refuzz::worker::IWorkerTaskChannel& TaskChannel() override
    {
        return *this;
    }
    refuzz::worker::IExecutionDomainRegistry& DomainRegistry() override
    {
        return *this;
    }
    refuzz::worker::IWorkerRegistrar& Registrar() override
    {
        return *this;
    }

    int Init() override { return 0; }
    int Handshake() override { return 0; }
    int Register() override
    {
        ++register_count_;
        return 0;
    }
    bool GetExecutionDomainTransport(
        refuzz::worker::ExecutionDomainTransport* out) const override
    {
        if (out == nullptr) return false;
        *out = {};
        return true;
    }

    std::optional<refuzz::worker::WorkerIO> WaitTask(
        std::chrono::milliseconds /*timeout*/) override
    {
        if (served_count_ < tasks_to_serve_) {
            task_.executor_id = 42 + served_count_;
            task_.dispatch_gen = 7 + served_count_;
            ++served_count_;
            return task_;
        }
        if (on_first_idle_ && !first_idle_observed_) {
            first_idle_observed_ = true;
            if (events_ != nullptr) {
                events_->push_back("idle_callback");
            }
            on_first_idle_();
            return std::nullopt;
        }
        g_running = 0;
        return std::nullopt;
    }

    void ReportDone(const refuzz::worker::TaskResult& result) override
    {
        reported_ = true;
        ++report_count_;
        result_ = result;
        results_.push_back(result);
        if (events_ != nullptr) {
            events_->push_back("report");
        }
    }

    bool CancelRequested() const override { return false; }
    void SetDomainReady(bool ready) override
    {
        domain_ready_events_.push_back(ready);
    }
    void Cleanup() override { ++cleanup_count_; }

    void ResetOutputLen() override
    {
        ++reset_count_;
        crash_output_len_ = crash_output_len_after_reset_;
    }

    std::uint32_t GetCrashOutputLen() const override
    {
        return crash_output_len_;
    }

    bool InitialCorpusTriaged() const override
    {
        return initial_corpus_triaged_;
    }

    std::uint32_t WorkerCount() const override { return worker_count_; }
    refuzz::worker::PersistedProcState LoadProcState() const override
    {
        return proc_state_;
    }
    bool PublishProcState(std::uint32_t proc_id, std::uint32_t epoch) override
    {
        proc_state_.proc_id = proc_id;
        proc_state_.epoch = epoch;
        proc_state_.valid = true;
        published_proc_states_.push_back(proc_state_);
        return true;
    }
    bool PublishDirtyProcMask(std::uint32_t dirty_proc_mask) override
    {
        proc_state_.dirty_proc_mask = dirty_proc_mask;
        published_dirty_proc_masks_.push_back(dirty_proc_mask);
        return true;
    }
    bool PublishMaintenanceError(std::uint32_t error_code) override
    {
        maintenance_errors_.push_back(error_code);
        return true;
    }

    void SetTargetProcId(std::uint32_t proc_id) { task_.target_proc_id = proc_id; }
    void SetWorkerCount(std::uint32_t count) { worker_count_ = count; }
    void SetPersistedProcState(refuzz::worker::PersistedProcState state)
    {
        proc_state_ = state;
    }
    void SetOnFirstIdle(std::function<void()> callback)
    {
        on_first_idle_ = std::move(callback);
    }

    refuzz::worker::TaskResult result_{};
    bool reported_ = false;
    std::uint32_t reset_count_ = 0;
    std::uint32_t report_count_ = 0;
    std::uint32_t cleanup_count_ = 0;
    std::uint32_t register_count_ = 0;
    std::vector<refuzz::worker::TaskResult> results_;
    std::vector<refuzz::worker::PersistedProcState> published_proc_states_;
    std::vector<std::uint32_t> published_dirty_proc_masks_;
    std::vector<std::uint32_t> maintenance_errors_;
    std::vector<bool> domain_ready_events_;

private:
    std::uint32_t served_count_ = 0;
    std::uint8_t input_[4]{};
    std::uint8_t output_[128]{};
    std::uint32_t crash_output_len_after_reset_ = 0;
    std::uint32_t crash_output_len_ = 0;
    bool initial_corpus_triaged_ = true;
    std::vector<std::string>* events_ = nullptr;
    std::uint32_t tasks_to_serve_ = 1;
    refuzz::worker::WorkerIO task_{};
    std::uint32_t worker_count_ = 1;
    refuzz::worker::PersistedProcState proc_state_{};
    std::function<void()> on_first_idle_;
    bool first_idle_observed_ = false;
};

void Check(bool cond, const char* msg)
{
    if (!cond) {
        std::fprintf(stderr, "FAIL: %s\n", msg);
        std::abort();
    }
}

bool WaitForFlag(const std::atomic<bool>& flag)
{
    const auto deadline = std::chrono::steady_clock::now() +
        std::chrono::seconds(2);
    while (!flag.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return flag.load(std::memory_order_acquire);
}

void CheckLifecyclePhaseContracts()
{
    g_running = 1;
    SingleTaskAdapter adapter(0, true, nullptr, 1);
    NoopBackend backend;
    refuzz::worker::ObservationBus bus;
    auto* topology_raw = new BlockingStateTopology();
    std::unique_ptr<refuzz::worker::topology::ProcessTopology> topology(
        topology_raw);

    refuzz::worker::EngineConfig config{};
    config.domain_startup_timeout_ms = 1000;
    config.daemon_watchdog_ms = 1000;
    config.recycle_after = 600;

    refuzz::worker::ExecutionEngine engine(
        adapter, adapter,
        refuzz::worker::InheritedDomainComponents{backend, bus},
        std::move(topology), config);
    std::atomic<int> run_result{-1};
    std::thread runner([&]() {
        run_result.store(engine.Run(), std::memory_order_release);
    });

    Check(WaitForFlag(topology_raw->setup_entered),
          "state test never entered Setup");
    Check(topology_raw->startup_timeout_ms == 1000 &&
              topology_raw->startup_deadline_us != 0,
          "Setup did not receive the startup phase deadline");
    Check(adapter.domain_ready_events_ == std::vector<bool>({false}),
          "startup did not close domain readiness exactly once");
    topology_raw->release_setup.store(true, std::memory_order_release);

    Check(WaitForFlag(topology_raw->collect_entered),
          "state test never entered Collect");
    Check(topology_raw->collect_timeout_ms > 0 &&
              topology_raw->collect_timeout_ms <= 1000,
          "Collect did not receive the execution phase deadline");
    Check(adapter.domain_ready_events_ ==
              std::vector<bool>({false, true}),
          "executing a task republished unchanged domain readiness");
    topology_raw->release_collect.store(true, std::memory_order_release);

    Check(WaitForFlag(topology_raw->stop_entered),
          "state test never entered Stop");
    Check(topology_raw->stop_plan.intent ==
              refuzz::worker::topology::DomainStopIntent::kDaemonShutdown &&
              topology_raw->stop_plan.absolute_deadline_us != 0,
          "shutdown did not receive the supervisor stop deadline");
    topology_raw->release_stop.store(true, std::memory_order_release);
    runner.join();

    Check(run_result.load(std::memory_order_acquire) == 0,
          "lifecycle phase contract run failed");
    Check(adapter.domain_ready_events_ ==
              std::vector<bool>({false, true, false}),
          "domain readiness was not edge-triggered across startup and shutdown");
}

void CheckPostRegisterSetupOrdering()
{
    g_running = 1;
    auto adapter = std::make_unique<SingleTaskAdapter>(0, true, nullptr, 0);
    auto* adapter_raw = adapter.get();
    auto topology = std::make_unique<FixedTopology>(
        std::vector<refuzz::worker::topology::CollectResult>(1),
        nullptr, 0,
        refuzz::worker::topology::DomainStopResult::kClean,
        refuzz::worker::topology::DomainStopResult::kClean);
    auto* topology_raw = topology.get();

    refuzz::worker::DaemonOwnedExecutionComponents components{};
    components.backend = std::make_unique<NoopBackend>();
    components.bus = std::make_unique<refuzz::worker::ObservationBus>();

    refuzz::worker::WorkerProfile profile{};
    profile.name = "startup-order-test";
    profile.adapter = std::move(adapter);
    profile.execution_components = std::move(components);
    profile.topology = std::move(topology);

    bool setup_called = false;
    bool setup_after_register = false;
    bool setup_before_domain = false;
    profile.post_register_setup = [&]() {
        setup_called = true;
        setup_after_register = adapter_raw->register_count_ == 1;
        setup_before_domain = !topology_raw->setup_called_;
    };

    const int rc = refuzz::worker::RunWorkerProfile(profile);
    Check(rc == 0 || rc == 2,
          "post-register setup ordering profile returned an invalid status");
    Check(setup_called && setup_after_register && setup_before_domain,
          "VM setup did not run between daemon registration and domain setup");
    Check(adapter_raw->register_count_ == 1,
          "daemon registration did not occur exactly once");
    Check(adapter_raw->cleanup_count_ == 1,
          "profile cleanup did not run after startup ordering test");
}

void CheckConcurrentTaskClaim()
{
    constexpr std::size_t kClaimants = 8;
    constexpr std::size_t kRounds = 200;

    TaskSlot task{};
    std::atomic<std::uint32_t> winners{0};
    std::barrier<> phase(static_cast<std::ptrdiff_t>(kClaimants + 1));
    std::vector<std::thread> claimants;
    claimants.reserve(kClaimants);

    for (std::size_t claimant = 0; claimant < kClaimants; ++claimant) {
        claimants.emplace_back([&]() {
            for (std::size_t round = 0; round < kRounds; ++round) {
                phase.arrive_and_wait();
                std::uint32_t expected = static_cast<std::uint32_t>(TASK_READY);
                if (__atomic_compare_exchange_n(
                        const_cast<std::uint32_t*>(&task.state),
                        &expected,
                        static_cast<std::uint32_t>(TASK_TAKEN),
                        false,
                        __ATOMIC_ACQ_REL,
                        __ATOMIC_ACQUIRE)) {
                    winners.fetch_add(1u, std::memory_order_relaxed);
                }
                phase.arrive_and_wait();
            }
        });
    }

    for (std::size_t round = 0; round < kRounds; ++round) {
        winners.store(0, std::memory_order_relaxed);
        task_slot_store_state_v3(&task, static_cast<std::uint32_t>(TASK_READY));
        phase.arrive_and_wait();
        phase.arrive_and_wait();
        Check(winners.load(std::memory_order_relaxed) == 1,
              "concurrent task claim did not have exactly one winner");
        Check(task_slot_load_state_v3(&task) ==
                  static_cast<std::uint32_t>(TASK_TAKEN),
              "concurrent task claim did not publish TASK_TAKEN");
    }

    for (auto& claimant : claimants) {
        claimant.join();
    }
}

class ExternalRecycleGateHolder {
public:
    explicit ExternalRecycleGateHolder(std::string path)
        : path_(std::move(path))
    {}

    ~ExternalRecycleGateHolder()
    {
        Release();
    }

    bool Start()
    {
        int ready_fds[2] = {-1, -1};
        int release_fds[2] = {-1, -1};
        if (::pipe(ready_fds) != 0 || ::pipe(release_fds) != 0) {
            return false;
        }
        pid_ = ::fork();
        if (pid_ < 0) {
            return false;
        }
        if (pid_ == 0) {
            ::close(ready_fds[0]);
            ::close(release_fds[1]);
            const int fd =
                ::open(path_.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
            struct flock lock {};
            lock.l_type = F_WRLCK;
            lock.l_whence = SEEK_SET;
            lock.l_start = 0;
            lock.l_len = 0;
            const uint8_t ready =
                fd >= 0 && ::fcntl(fd, F_SETLK, &lock) == 0 ? 1u : 0u;
            (void)::write(ready_fds[1], &ready, sizeof(ready));
            if (ready == 1u) {
                uint8_t release = 0;
                (void)::read(release_fds[0], &release, sizeof(release));
            }
            if (fd >= 0) {
                ::close(fd);
            }
            _exit(ready == 1u ? 0 : 1);
        }

        ::close(ready_fds[1]);
        ::close(release_fds[0]);
        release_fd_ = release_fds[1];
        uint8_t ready = 0;
        const ssize_t received = ::read(ready_fds[0], &ready, sizeof(ready));
        ::close(ready_fds[0]);
        if (received != static_cast<ssize_t>(sizeof(ready)) || ready != 1u) {
            Release();
            return false;
        }
        return true;
    }

    void Release()
    {
        if (release_fd_ >= 0) {
            const uint8_t release = 1;
            (void)::write(release_fd_, &release, sizeof(release));
            ::close(release_fd_);
            release_fd_ = -1;
        }
        if (pid_ > 0) {
            int status = 0;
            while (::waitpid(pid_, &status, 0) < 0 && errno == EINTR) {
            }
            pid_ = -1;
        }
    }

private:
    std::string path_;
    pid_t pid_ = -1;
    int release_fd_ = -1;
};

struct ScenarioResult {
    refuzz::worker::TaskResult task_result{};
    std::uint32_t rebuild_count = 0;
    std::uint32_t dispatch_count = 0;
    std::uint32_t reset_count = 0;
    std::uint32_t report_count = 0;
    std::uint32_t collect_timeout_ms = 0;
    std::uint32_t startup_timeout_ms = 0;
    std::uint32_t stop_count = 0;
    std::uint32_t recovery_stop_count = 0;
    std::uint32_t periodic_stop_count = 0;
    std::uint32_t shutdown_stop_count = 0;
    std::uint32_t cancellation_stop_count = 0;
    std::uint32_t rebind_stop_count = 0;
    std::uint32_t startup_cleanup_stop_count = 0;
    refuzz::worker::topology::DomainStopPlan last_stop_plan{};
    refuzz::worker::topology::DomainStopPlan last_recovery_stop_plan{};
    std::vector<refuzz::worker::TaskResult> task_results;
    std::vector<std::string> events;
    std::vector<refuzz::worker::PersistedProcState> proc_states;
    std::vector<std::uint32_t> dirty_proc_masks;
    std::vector<std::uint32_t> maintenance_errors;
    std::vector<std::uint32_t> backend_proc_ids;
    std::vector<std::uint32_t> bus_proc_ids;
};

ScenarioResult RunSequence(
    std::vector<refuzz::worker::topology::CollectResult> collect_results,
    std::uint32_t adapter_crash_len,
    bool initial_corpus_triaged,
    std::uint32_t recycle_after,
    int expected_run_rc = 0,
    std::uint32_t expected_tasks = 1,
    std::uint32_t fail_rebuild_call = 0,
    std::uint32_t daemon_watchdog_ms = 1000,
    std::uint32_t exec_timeout_ms = 5000,
    std::uint32_t target_proc_id = PROC_ID_ANY,
    refuzz::worker::PersistedProcState persisted_proc_state = {},
    std::uint32_t worker_count = 1,
    refuzz::worker::topology::DomainStopResult recycle_stop_result =
        refuzz::worker::topology::DomainStopResult::kClean,
    bool expect_task_execution = true,
    std::uint32_t domain_startup_attempts = 1,
    std::uint32_t domain_recovery_attempts = 20,
    std::string recycle_gate_path = {},
    std::function<void()> on_first_idle = {},
    refuzz::worker::topology::DomainStopResult startup_cleanup_stop_result =
        refuzz::worker::topology::DomainStopResult::kClean)
{
    g_running = 1;

    ScenarioResult observation;
    SingleTaskAdapter adapter(adapter_crash_len, initial_corpus_triaged,
                              &observation.events, expected_tasks);
    adapter.SetTargetProcId(target_proc_id);
    adapter.SetPersistedProcState(persisted_proc_state);
    adapter.SetWorkerCount(worker_count);
    adapter.SetOnFirstIdle(std::move(on_first_idle));
    NoopBackend backend;
    refuzz::worker::ObservationBus bus;
    bus.AddSink(std::make_unique<ProcTrackingSink>(&observation.bus_proc_ids));
    auto* topology_raw = new FixedTopology(std::move(collect_results),
                                           &observation.events,
                                           fail_rebuild_call,
                                           recycle_stop_result,
                                           startup_cleanup_stop_result);
    std::unique_ptr<refuzz::worker::topology::ProcessTopology> topology(
        topology_raw);

    refuzz::worker::EngineConfig config{};
    config.poll_ms = 1;
    config.daemon_watchdog_ms = daemon_watchdog_ms;
    config.exec_timeout_ms = exec_timeout_ms;
    config.recycle_after = recycle_after;
    config.domain_startup_attempts = domain_startup_attempts;
    config.domain_recovery_attempts = domain_recovery_attempts;
    config.recycle_gate_path = std::move(recycle_gate_path);

    refuzz::worker::ExecutionEngine engine(
        adapter, adapter,
        refuzz::worker::InheritedDomainComponents{backend, bus},
        std::move(topology), config);
    const int rc = engine.Run();

    Check(rc == expected_run_rc, "engine Run returned unexpected status");
    Check(topology_raw->setup_called_, "topology Setup not called");
    Check(topology_raw->dispatched_ == expect_task_execution,
          "topology Dispatch execution state mismatch");
    Check(topology_raw->collected_ == expect_task_execution,
          "topology Collect execution state mismatch");
    Check(topology_raw->teardown_called_, "topology Teardown not called");
    Check(adapter.reported_, "adapter did not receive ReportDone");
    if (adapter.report_count_ != expected_tasks) {
        std::fprintf(stderr,
                     "FAIL: adapter completion count=%u expected=%u "
                     "run_rc=%d expected_rc=%d rebuilds=%u dispatches=%u\n",
                     adapter.report_count_, expected_tasks, rc,
                     expected_run_rc, topology_raw->rebuild_count_,
                     topology_raw->dispatch_count_);
        std::abort();
    }
    Check(adapter.cleanup_count_ == 0,
          "domain lifecycle stopped adapter/heartbeat before profile shutdown");
    Check(adapter.reset_count_ ==
              (expect_task_execution ? expected_tasks : 0),
          "output length reset count did not match served tasks");

    observation.task_result = adapter.result_;
    observation.rebuild_count = topology_raw->rebuild_count_;
    observation.dispatch_count = topology_raw->dispatch_count_;
    observation.reset_count = adapter.reset_count_;
    observation.report_count = adapter.report_count_;
    observation.collect_timeout_ms = topology_raw->last_collect_timeout_ms_;
    observation.startup_timeout_ms = topology_raw->last_startup_timeout_ms_;
    observation.stop_count = topology_raw->stop_count_;
    observation.recovery_stop_count = topology_raw->recovery_stop_count_;
    observation.periodic_stop_count = topology_raw->periodic_stop_count_;
    observation.shutdown_stop_count = topology_raw->shutdown_stop_count_;
    observation.cancellation_stop_count =
        topology_raw->cancellation_stop_count_;
    observation.rebind_stop_count = topology_raw->rebind_stop_count_;
    observation.startup_cleanup_stop_count =
        topology_raw->startup_cleanup_stop_count_;
    observation.last_stop_plan = topology_raw->last_stop_plan_;
    observation.last_recovery_stop_plan =
        topology_raw->last_recovery_stop_plan_;
    observation.task_results = adapter.results_;
    observation.proc_states = adapter.published_proc_states_;
    observation.dirty_proc_masks = adapter.published_dirty_proc_masks_;
    observation.maintenance_errors = adapter.maintenance_errors_;
    observation.backend_proc_ids = backend.configured_proc_ids;
    return observation;
}

refuzz::worker::TaskResult RunOne(
    refuzz::worker::topology::CollectResult collect_result,
    std::uint32_t adapter_crash_len,
    int expected_run_rc = 0,
    std::uint32_t expected_tasks = 1)
{
    return RunSequence({collect_result}, adapter_crash_len,
                       /*initial_corpus_triaged=*/true,
                       /*recycle_after=*/600,
                       expected_run_rc, expected_tasks).task_result;
}

refuzz::worker::topology::CollectResult Done(
    refuzz::worker::engine::RuntimeResultKind kind,
    std::uint32_t output_len,
    std::int32_t status,
    std::uint32_t crash_signal = 0)
{
    refuzz::worker::topology::CollectResult r{};
    r.kind = refuzz::worker::topology::CollectKind::kDone;
    r.output_len = output_len;
    r.status = status;
    r.result_kind = kind;
    r.crash_signal = crash_signal;
    return r;
}

void CheckStartupTimeoutRecovery()
{
    constexpr std::uint32_t kStartupTimeoutMs = 5;
    constexpr std::uint32_t kStartupAttempts = 3;

    g_running = 1;
    SingleTaskAdapter adapter(0, true, nullptr, 0);
    NoopBackend backend;
    refuzz::worker::ObservationBus bus;
    auto* topology_raw = new SlowSetupTopology();
    std::unique_ptr<refuzz::worker::topology::ProcessTopology> topology(
        topology_raw);

    refuzz::worker::EngineConfig config{};
    config.domain_startup_timeout_ms = kStartupTimeoutMs;
    config.domain_startup_attempts = kStartupAttempts;
    config.domain_recovery_attempts = 1;

    refuzz::worker::ExecutionEngine engine(
        adapter, adapter,
        refuzz::worker::InheritedDomainComponents{backend, bus},
        std::move(topology), config);
    const auto start = std::chrono::steady_clock::now();
    const int rc = engine.Run();
    const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();

    Check(rc == 1, "startup timeout did not fail the domain supervisor");
    Check(topology_raw->setup_count_ == kStartupAttempts,
          "startup timeout retry count did not match the configured budget");
    Check(topology_raw->stop_count_ == kStartupAttempts,
          "startup timeout did not clean each failed setup attempt");
    Check(topology_raw->dispatch_count_ == 0 &&
              topology_raw->collect_count_ == 0,
          "startup timeout dispatched a task");
    Check(std::all_of(topology_raw->startup_timeouts_ms_.begin(),
                      topology_raw->startup_timeouts_ms_.end(),
                      [](std::uint32_t timeout_ms) {
                          return timeout_ms == kStartupTimeoutMs;
                      }),
          "startup timeout was not propagated to every setup attempt");
    Check(std::all_of(topology_raw->startup_deadlines_us_.begin(),
                      topology_raw->startup_deadlines_us_.end(),
                      [](std::uint64_t deadline_us) {
                          return deadline_us != 0;
                      }),
          "startup absolute deadline was not propagated to every setup attempt");
    Check(elapsed_ms >=
              static_cast<long long>(kStartupTimeoutMs * kStartupAttempts),
          "slow setup did not exercise the startup deadline path");
    Check(adapter.report_count_ == 0,
          "startup timeout reported a completion without a task");
    Check(adapter.domain_ready_events_ == std::vector<bool>({false}),
          "failed startup republished unchanged domain readiness");
    Check(adapter.cleanup_count_ == 0,
          "startup timeout stopped adapter heartbeat before profile cleanup");
}

} // namespace

int main()
{
    namespace eng = refuzz::worker::engine;
    namespace topo = refuzz::worker::topology;

    CheckLifecyclePhaseContracts();
    CheckPostRegisterSetupOrdering();
    CheckConcurrentTaskClaim();
    CheckStartupTimeoutRecovery();

    for (const std::uint32_t worker_count : {1u, 3u, 8u, 16u}) {
        bool seen[topo::kMaxProcIds]{};
        for (std::uint32_t worker_id = 0; worker_id < worker_count; ++worker_id) {
            topo::ProcIdLane lane(worker_id, worker_count);
            Check(lane.Valid(), "valid proc-id lane was rejected");
            std::uint32_t proc_id = lane.Initial();
            do {
                Check(lane.Owns(proc_id), "lane did not own generated proc id");
                Check(!seen[proc_id], "proc-id lanes overlap");
                seen[proc_id] = true;
                proc_id = lane.Next(proc_id);
            } while (proc_id != lane.Initial());
        }
        for (bool id_seen : seen) {
            Check(id_seen, "proc-id lanes did not cover capacity");
        }
    }

    {
        topo::ProcIdLane lane(/*worker_id=*/1, /*worker_count=*/7);
        const uint32_t dirty = (1u << 1) | (1u << 8) | (1u << 15) |
                               (1u << 22);
        Check(lane.FirstClean(dirty).has_value() &&
                  *lane.FirstClean(dirty) == 29,
              "FirstClean did not skip dirty proc ids");
        Check(lane.NextClean(22, dirty).has_value() &&
                  *lane.NextClean(22, dirty) == 29,
              "NextClean did not select the remaining clean proc id");
        Check(!lane.NextClean(29, dirty | (1u << 29)).has_value(),
              "NextClean reused an exhausted dirty lane");
    }

    {
        const auto result = RunOne(
            Done(eng::RuntimeResultKind::kNormal, 111, 0), 0);
        Check(result.completion_status == COMP_STATUS_OK,
              "normal did not map to OK");
        Check(result.error_code == ERR_OK, "normal error_code not OK");
        Check(result.status == 0, "normal status not success");
        Check(result.output_len == 111, "normal output_len not preserved");
        Check(result.proc_id == 0, "initial task did not use worker's initial proc id");
    }

    {
        const auto scenario = RunSequence(
            {Done(eng::RuntimeResultKind::kNormal, 1, 0)}, 0,
            /*initial_corpus_triaged=*/true,
            /*recycle_after=*/600,
            /*expected_run_rc=*/0,
            /*expected_tasks=*/1,
            /*fail_rebuild_call=*/0,
            /*daemon_watchdog_ms=*/0,
            /*exec_timeout_ms=*/37);
        Check(scenario.collect_timeout_ms == 111,
              "automatic daemon watchdog is not 3x exec timeout");
        Check(scenario.startup_timeout_ms ==
                  topo::kDefaultDomainStartupTimeoutMs,
              "domain startup timeout is not the independent 60s default");
    }

    {
        topo::CollectResult timeout{};
        timeout.kind = topo::CollectKind::kTimeout;
        const auto scenario = RunSequence(
            {timeout}, 0,
            /*initial_corpus_triaged=*/true,
            /*recycle_after=*/600);
        Check(scenario.task_result.completion_status == COMP_STATUS_HUNG,
              "outer watchdog did not map to task hang");
        Check(scenario.task_result.error_code == ERR_DOMAIN_WATCHDOG_TIMEOUT,
              "outer watchdog reason was not preserved");
        Check(scenario.dispatch_count == 1,
              "outer watchdog incorrectly entered harness retry");
        Check(scenario.rebuild_count == 1,
              "outer watchdog did not rotate and rebuild the domain once");
        Check(scenario.recovery_stop_count == 1,
              "outer watchdog bypassed supervisor-directed recovery stop");
        Check(!scenario.last_recovery_stop_plan.graceful &&
                  scenario.last_recovery_stop_plan.allow_abandon &&
                  scenario.last_recovery_stop_plan.graceful_timeout_ms == 2000 &&
                  scenario.last_recovery_stop_plan.kill_timeout_ms == 2000 &&
                  scenario.last_recovery_stop_plan.runner_timeout_ms == 1000 &&
                  scenario.last_recovery_stop_plan.reap_timeout_ms == 2000 &&
                  scenario.last_recovery_stop_plan.absolute_deadline_us != 0,
              "recovery stop deadlines did not come from DomainSupervisor");
        Check(scenario.proc_states.size() == 2 &&
              scenario.proc_states[0].proc_id == 0 &&
              scenario.proc_states[1].proc_id == 1,
              "outer watchdog did not rotate proc id exactly once");
        Check(scenario.backend_proc_ids == std::vector<std::uint32_t>({0, 1}) &&
              scenario.bus_proc_ids == std::vector<std::uint32_t>({0, 1}),
              "rotated proc id was not propagated to backend and observation bus");
        Check(scenario.events.size() >= 2 &&
                  scenario.events[0] == "report" &&
                  scenario.events[1] == "rebuild",
              "task hang was not published before replacement startup");
    }

    {
        topo::CollectResult timeout{};
        timeout.kind = topo::CollectKind::kTimeout;
        const auto scenario = RunSequence(
            {timeout}, 0,
            /*initial_corpus_triaged=*/true,
            /*recycle_after=*/600,
            /*expected_run_rc=*/1,
            /*expected_tasks=*/1,
            /*fail_rebuild_call=*/1,
            /*daemon_watchdog_ms=*/1000,
            /*exec_timeout_ms=*/5000,
            /*target_proc_id=*/PROC_ID_ANY,
            /*persisted_proc_state=*/{},
            /*worker_count=*/1,
            topo::DomainStopResult::kClean,
            /*expect_task_execution=*/true,
            /*domain_startup_attempts=*/3,
            /*domain_recovery_attempts=*/3);
        Check(scenario.task_result.completion_status ==
                  COMP_STATUS_HUNG,
              "failed task-watchdog replacement did not become terminal");
        Check(scenario.task_result.error_code ==
                  ERR_DOMAIN_WATCHDOG_TIMEOUT,
              "task-watchdog result was overwritten by maintenance failure");
        Check(scenario.maintenance_errors ==
                  std::vector<std::uint32_t>{
                      ERR_DOMAIN_REPLACEMENT_START_FAILED},
              "replacement failure was not published independently");
        Check(scenario.events.size() >= 2 &&
                  scenario.events[0] == "report" &&
                  scenario.events[1] == "rebuild_failed",
              "replacement failure ran before task settlement");
        Check(scenario.rebuild_count == 1,
              "task watchdog retried replacement startup more than once");
    }

    {
        topo::CollectResult timeout{};
        timeout.kind = topo::CollectKind::kTimeout;
        const auto scenario = RunSequence(
            {timeout}, 0,
            /*initial_corpus_triaged=*/true,
            /*recycle_after=*/600,
            /*expected_run_rc=*/0,
            /*expected_tasks=*/1,
            /*fail_rebuild_call=*/0,
            /*daemon_watchdog_ms=*/1000,
            /*exec_timeout_ms=*/5000,
            /*target_proc_id=*/PROC_ID_ANY,
            /*persisted_proc_state=*/{},
            /*worker_count=*/1,
            topo::DomainStopResult::kAbandoned);
        Check(scenario.task_result.error_code == ERR_DOMAIN_WATCHDOG_TIMEOUT,
              "abandoned task did not settle as a hang");
        Check(scenario.dirty_proc_masks == std::vector<std::uint32_t>{1u},
              "abandoned proc id was not persisted as dirty");
        Check(scenario.proc_states.size() == 2 &&
                  scenario.proc_states[1].proc_id == 1,
              "replacement reused the abandoned proc id");
        Check(scenario.maintenance_errors.empty(),
              "successful abandoned-domain replacement raised maintenance fault");
    }

    {
        topo::CollectResult timeout{};
        timeout.kind = topo::CollectKind::kTimeout;
        const auto scenario = RunSequence(
            {timeout}, 0,
            /*initial_corpus_triaged=*/true,
            /*recycle_after=*/600,
            /*expected_run_rc=*/1,
            /*expected_tasks=*/1,
            /*fail_rebuild_call=*/0,
            /*daemon_watchdog_ms=*/1000,
            /*exec_timeout_ms=*/5000,
            /*target_proc_id=*/PROC_ID_ANY,
            /*persisted_proc_state=*/{},
            /*worker_count=*/1,
            topo::DomainStopResult::kFailed);
        Check(scenario.task_result.error_code == ERR_DOMAIN_WATCHDOG_TIMEOUT,
              "mechanical stop failure changed task classification");
        Check(scenario.maintenance_errors ==
                  std::vector<std::uint32_t>{
                      ERR_DOMAIN_OWNERSHIP_UNRECLAIMED},
              "mechanical stop failure was not published independently");
        Check(scenario.dirty_proc_masks == std::vector<std::uint32_t>{1u},
              "mechanically failed proc id was not quarantined");
    }

    {
        const auto result = RunOne(
            Done(eng::RuntimeResultKind::kTimeout, 77, 0), 0);
        // [两层语义] program watchdog 判的超时:标签是 TIMEOUT,但**数据照带**。
        // 事实层不压缩信息 —— 超时是事实,超时前已发布(RELEASE 序)的 progress
        // 数据同样是事实,两个都要上报。error_code=ERR_TIMEOUT 把它与 daemon
        // watchdog 的 task hang(ERR_DOMAIN_WATCHDOG_TIMEOUT,见下面的用例)区分开;
        // channel 据此把它分流到 Completion 侧,与 kPartial 同等处理。
        Check(result.completion_status == COMP_STATUS_TIMEOUT,
              "program watchdog did not map to task timeout");
        Check(result.error_code == ERR_TIMEOUT,
              "program watchdog did not use the program timeout reason");
        Check(result.status == -1, "program timeout status not failure");
        Check(result.output_len == 77,
              "program timeout dropped pre-timeout output");
    }

    {
        const auto result = RunOne(
            Done(eng::RuntimeResultKind::kPartial, 77, 0), 0);
        Check(result.completion_status == COMP_STATUS_PARTIAL,
              "partial did not map to PARTIAL");
        Check(result.error_code == ERR_OK, "partial error_code not OK");
        Check(result.status == 0, "partial status not success");
        Check(result.output_len == 77, "partial output_len not preserved");
    }

    {
        const auto scenario = RunSequence(
            {Done(eng::RuntimeResultKind::kCrash, 33, -1, SIGSEGV)}, 0,
            /*initial_corpus_triaged=*/true,
            /*recycle_after=*/600);
        const auto& result = scenario.task_result;
        Check(result.completion_status == COMP_STATUS_CHILD_ABORTED,
              "crash did not map to CHILD_ABORTED");
        Check(result.error_code == ERR_PROGRAM_CHILD_CRASHED,
              "crash did not preserve the program-child cause");
        Check(result.status == -1, "crash status not failure");
        Check(result.output_len == 33, "crash output_len not preserved");
        Check(result.crash_signal == SIGSEGV, "crash_signal not preserved");
        Check(scenario.proc_states.size() == 1 &&
              scenario.proc_states[0].proc_id == 0,
              "fork-server-handled program crash rotated proc id");
    }

    {
        // [语义拆分] kNoResult = 真的没产出(零 progress),**不是错误** → 独立的
        // COMP_STATUS_NO_RESULT + ERR_OK,不再塞进已被删掉的 EXEC_ERROR 口袋。
        const auto result = RunOne(
            Done(eng::RuntimeResultKind::kNoResult, 99, -1), 0);
        Check(result.completion_status == COMP_STATUS_NO_RESULT,
              "no-result did not map to NO_RESULT");
        Check(result.error_code == ERR_OK,
              "no-result should not carry an error code");
        Check(result.output_len == 0, "no-result leaked output_len");
    }

    {
        topo::CollectResult r{};
        r.kind = topo::CollectKind::kChildAborted;
        r.result_kind = eng::RuntimeResultKind::kCrash;
        r.crash_signal = SIGABRT;
        const auto result = RunOne(r, /*adapter_crash_len=*/55);
        Check(result.completion_status == COMP_STATUS_CHILD_ABORTED,
              "child-aborted did not map to CHILD_ABORTED");
        Check(result.error_code == ERR_PROGRAM_CHILD_CRASHED,
              "child-aborted did not preserve the program-child cause");
        Check(result.output_len == 55, "child-aborted did not use crash len fallback");
        Check(result.crash_signal == SIGABRT, "child-aborted signal not preserved");
    }

    {
        topo::CollectResult r{};
        r.kind = topo::CollectKind::kChildAborted;
        r.crash_signal = SIGABRT;
        const auto scenario = RunSequence(
            {r}, 55, /*initial_corpus_triaged=*/true,
            /*recycle_after=*/600);
        Check(scenario.proc_states.size() == 2 &&
              scenario.proc_states.back().proc_id == 1,
              "unexpected loop-child exit did not rotate proc id");
    }

    {
        topo::CollectResult r{};
        r.kind = topo::CollectKind::kCancelled;
        const auto scenario = RunSequence(
            {r}, 0, /*initial_corpus_triaged=*/true,
            /*recycle_after=*/600);
        Check(scenario.task_result.completion_status == COMP_STATUS_CANCELLED &&
              scenario.task_result.error_code == ERR_TASK_CANCELLED &&
              scenario.task_result.cancel_observed,
              "forced cancellation result was not preserved");
        Check(scenario.proc_states.size() == 2 &&
              scenario.proc_states.back().proc_id == 1,
              "forced cancellation did not rotate proc id");
        Check(scenario.cancellation_stop_count == 1 &&
                  scenario.recovery_stop_count == 0,
              "host cancellation used the domain-fault stop intent");
    }

    {
        // child-abort 的执行结果（数据有效）独立于域维护：重建失败不能把任务
        // 压成 infra，必须保持 CHILD_ABORTED，维护失败走 error_latch。
        topo::CollectResult r{};
        r.kind = topo::CollectKind::kChildAborted;
        r.crash_signal = SIGABRT;
        const auto scenario = RunSequence(
            {r}, 55, /*initial_corpus_triaged=*/true,
            /*recycle_after=*/600,
            /*expected_run_rc=*/1,
            /*expected_tasks=*/1,
            /*fail_rebuild_call=*/1,
            /*daemon_watchdog_ms=*/1000,
            /*exec_timeout_ms=*/5000,
            /*target_proc_id=*/PROC_ID_ANY,
            /*persisted_proc_state=*/{},
            /*worker_count=*/1,
            topo::DomainStopResult::kClean);
        Check(scenario.task_result.completion_status ==
                  COMP_STATUS_CHILD_ABORTED &&
              scenario.task_result.error_code == ERR_PROGRAM_CHILD_CRASHED,
              "child-abort was downgraded to infra by rebuild failure");
        Check(scenario.maintenance_errors ==
                  std::vector<std::uint32_t>{
                      ERR_DOMAIN_REPLACEMENT_START_FAILED},
              "child-abort rebuild failure was not latched");
    }

    {
        // cancelled 同理：取消已确认，重建失败是维护问题，不压成 infra。
        topo::CollectResult r{};
        r.kind = topo::CollectKind::kCancelled;
        const auto scenario = RunSequence(
            {r}, 0, /*initial_corpus_triaged=*/true,
            /*recycle_after=*/600,
            /*expected_run_rc=*/1,
            /*expected_tasks=*/1,
            /*fail_rebuild_call=*/1,
            /*daemon_watchdog_ms=*/1000,
            /*exec_timeout_ms=*/5000,
            /*target_proc_id=*/PROC_ID_ANY,
            /*persisted_proc_state=*/{},
            /*worker_count=*/1,
            topo::DomainStopResult::kClean);
        Check(scenario.task_result.completion_status ==
                  COMP_STATUS_CANCELLED &&
              scenario.task_result.error_code == ERR_TASK_CANCELLED &&
              scenario.task_result.cancel_observed,
              "cancelled was downgraded to infra by rebuild failure");
        Check(scenario.maintenance_errors ==
                  std::vector<std::uint32_t>{
                      ERR_DOMAIN_REPLACEMENT_START_FAILED},
              "cancelled rebuild failure was not latched");
    }

    {
        constexpr std::uint32_t kCancellationCount = 20;
        constexpr std::uint32_t kRecoveryBudget = 3;
        topo::CollectResult cancelled{};
        cancelled.kind = topo::CollectKind::kCancelled;
        const auto scenario = RunSequence(
            {cancelled}, 0,
            /*initial_corpus_triaged=*/true,
            /*recycle_after=*/600,
            /*expected_run_rc=*/0,
            /*expected_tasks=*/kCancellationCount,
            /*fail_rebuild_call=*/0,
            /*daemon_watchdog_ms=*/1000,
            /*exec_timeout_ms=*/5000,
            /*target_proc_id=*/PROC_ID_ANY,
            /*persisted_proc_state=*/{},
            /*worker_count=*/1,
            topo::DomainStopResult::kClean,
            /*expect_task_execution=*/true,
            /*domain_startup_attempts=*/1,
            /*domain_recovery_attempts=*/kRecoveryBudget);
        Check(scenario.task_results.size() == kCancellationCount &&
                  std::all_of(
                      scenario.task_results.begin(),
                      scenario.task_results.end(),
                      [](const refuzz::worker::TaskResult& result) {
                          return result.completion_status ==
                                     COMP_STATUS_CANCELLED &&
                                 result.error_code == ERR_TASK_CANCELLED &&
                                 result.cancel_observed;
                      }),
              "consecutive cancellations did not preserve every completion");
        Check(scenario.rebuild_count == kCancellationCount &&
                  scenario.cancellation_stop_count == kCancellationCount &&
                  scenario.recovery_stop_count == 0,
              "consecutive cancellations did not rebuild each domain");
        Check(scenario.proc_states.size() == kCancellationCount + 1,
              "consecutive cancellations did not rotate proc identity");
    }

    {
        const auto scenario = RunSequence(
            {Done(eng::RuntimeResultKind::kHarnessFatal, 0, -1)}, 0,
            /*initial_corpus_triaged=*/true,
            /*recycle_after=*/600,
            /*expected_run_rc=*/0,
            /*expected_tasks=*/1);
        Check(scenario.task_result.completion_status == COMP_STATUS_HARNESS_RECOVERED,
              "successful domain rebuild did not map to HARNESS_RECOVERED");
        Check(scenario.task_result.error_code == ERR_HARNESS_FORK_SERVER_PROTOCOL,
              "missing fatal reason did not fail closed to protocol error");
        Check(scenario.dispatch_count == 1,
              "harness failure retried the same task");
        Check(scenario.rebuild_count == 1,
              "harness failure did not rebuild exactly once");
        Check(scenario.events.size() == 2 &&
              scenario.events[0] == "rebuild" &&
              scenario.events[1] == "report",
              "recovered harness result was published before rebuild");
        Check(scenario.task_result.proc_id == 0 &&
              scenario.proc_states.size() == 2 &&
              scenario.proc_states.back().proc_id == 1,
              "harness recovery did not report old proc and rotate next domain");
    }

    {
        auto cleanup_failure =
            Done(eng::RuntimeResultKind::kHarnessFatal, 0, -1);
        cleanup_failure.fatal_reason =
            eng::HarnessFatalReason::kExecutionDomainCleanupFailed;
        const auto scenario = RunSequence(
            {cleanup_failure}, 0,
            /*initial_corpus_triaged=*/true,
            /*recycle_after=*/600);
        Check(scenario.task_result.completion_status ==
                  COMP_STATUS_HUNG,
              "cleanup failure rebuild did not remain HUNG");
        Check(scenario.task_result.error_code == ERR_HARNESS_CLEANUP_FAILED,
              "cleanup failure reason was not preserved");
        Check(scenario.rebuild_count == 1,
              "cleanup failure did not rebuild exactly once");
    }

    {
        auto reap_failure =
            Done(eng::RuntimeResultKind::kHarnessFatal, 0, -1);
        reap_failure.fatal_reason =
            eng::HarnessFatalReason::kMainChildReapFailed;
        const auto scenario = RunSequence(
            {reap_failure}, 0,
            /*initial_corpus_triaged=*/true,
            /*recycle_after=*/600);
        Check(scenario.task_result.completion_status == COMP_STATUS_HUNG,
              "main-child reap failure rebuild did not remain HUNG");
        Check(scenario.task_result.error_code ==
                  ERR_HARNESS_MAIN_REAP_FAILED,
              "main-child reap failure reason was not preserved");
        Check(scenario.rebuild_count == 1,
              "main-child reap failure did not rebuild exactly once");
    }

    {
        auto reap_timeout =
            Done(eng::RuntimeResultKind::kHarnessFatal, 0, -1);
        reap_timeout.fatal_reason =
            eng::HarnessFatalReason::kStoppedDescendantReapTimeout;
        const auto scenario = RunSequence(
            {reap_timeout}, 0,
            /*initial_corpus_triaged=*/true,
            /*recycle_after=*/600);
        Check(scenario.task_result.completion_status == COMP_STATUS_HUNG,
              "stopped-descendant reap timeout rebuild did not remain HUNG");
        Check(scenario.task_result.error_code ==
                  ERR_HARNESS_STOPPED_REAP_TIMEOUT,
              "stopped-descendant reap timeout reason was not preserved");
        Check(scenario.rebuild_count == 1,
              "stopped-descendant reap timeout did not rebuild exactly once");
    }

    {
        auto kcov_failure =
            Done(eng::RuntimeResultKind::kHarnessFatal, 0, -1);
        kcov_failure.fatal_reason =
            eng::HarnessFatalReason::kKcovStateInvalid;
        const auto scenario = RunSequence(
            {kcov_failure}, 0,
            /*initial_corpus_triaged=*/true,
            /*recycle_after=*/600);
        Check(scenario.task_result.completion_status ==
                  COMP_STATUS_HARNESS_RECOVERED,
              "KCOV failure rebuild did not report HARNESS_RECOVERED");
        Check(scenario.task_result.error_code ==
                  ERR_HARNESS_KCOV_STATE_INVALID,
              "KCOV failure reason was not preserved");
        Check(scenario.rebuild_count == 1,
              "KCOV failure did not rebuild exactly once");
    }

    {
        auto cleanup_failure =
            Done(eng::RuntimeResultKind::kHarnessFatal, 0, -1);
        cleanup_failure.fatal_reason =
            eng::HarnessFatalReason::kExecutionDomainCleanupFailed;
        const auto scenario = RunSequence(
            {cleanup_failure}, 0,
            /*initial_corpus_triaged=*/true,
            /*recycle_after=*/600,
            /*expected_run_rc=*/1,
            /*expected_tasks=*/1,
            /*fail_rebuild_call=*/1);
        Check(scenario.task_result.completion_status ==
                  COMP_STATUS_HUNG,
              "unrecoverable cleanup failure did not remain HUNG");
        Check(scenario.task_result.error_code ==
                  ERR_DOMAIN_REPLACEMENT_START_FAILED,
              "unrecoverable cleanup replacement was misclassified");
    }

    {
        topo::CollectResult r{};
        r.kind = topo::CollectKind::kHarnessFail;
        r.fatal_reason = eng::HarnessFatalReason::kOuterForkEagain;
        const auto result = RunOne(r, 0);
        Check(result.completion_status == COMP_STATUS_HARNESS_RECOVERED,
              "topology harness failure did not report recovered state");
        Check(result.error_code == ERR_HARNESS_OUTER_FORK_EAGAIN,
              "outer-fork EAGAIN reason was not preserved");
    }

    {
        topo::CollectResult hang{};
        hang.kind = topo::CollectKind::kHarnessFail;
        hang.fatal_reason = eng::HarnessFatalReason::kDomainWatchdogTimeout;
        const auto scenario = RunSequence(
            {hang}, 0,
            /*initial_corpus_triaged=*/true,
            /*recycle_after=*/600);
        Check(scenario.task_result.completion_status == COMP_STATUS_HUNG,
              "recovered domain hang did not remain a task hang");
        Check(scenario.task_result.error_code == ERR_DOMAIN_WATCHDOG_TIMEOUT,
              "recovered domain hang lost its watchdog reason");
        Check(scenario.rebuild_count == 1,
              "failed first domain respawn did not enter finite recovery");
    }

    {
        topo::CollectResult hang{};
        hang.kind = topo::CollectKind::kHarnessFail;
        hang.fatal_reason = eng::HarnessFatalReason::kDomainWatchdogTimeout;
        const auto scenario = RunSequence(
            {hang}, 0,
            /*initial_corpus_triaged=*/true,
            /*recycle_after=*/600,
            /*expected_run_rc=*/1,
            /*expected_tasks=*/1,
            /*fail_rebuild_call=*/1,
            /*daemon_watchdog_ms=*/1000,
            /*exec_timeout_ms=*/5000,
            /*target_proc_id=*/PROC_ID_ANY,
            /*persisted_proc_state=*/{},
            /*worker_count=*/1,
            topo::DomainStopResult::kClean,
            /*expect_task_execution=*/true,
            /*domain_startup_attempts=*/3,
            /*domain_recovery_attempts=*/3);
        Check(scenario.task_result.completion_status ==
                  COMP_STATUS_HUNG,
              "terminal task watchdog did not remain a task hang");
        Check(scenario.task_result.error_code ==
                  ERR_DOMAIN_WATCHDOG_TIMEOUT,
              "domain watchdog task result was overwritten");
        Check(scenario.maintenance_errors ==
                  std::vector<std::uint32_t>{
                      ERR_DOMAIN_REPLACEMENT_START_FAILED},
              "domain watchdog replacement failure was not latched");
        Check(scenario.rebuild_count == 1,
              "domain hang retried replacement startup more than once");
    }

    {
        topo::CollectResult failure{};
        failure.kind = topo::CollectKind::kHarnessFail;
        failure.fatal_reason = eng::HarnessFatalReason::kOuterForkEagain;
        const auto scenario = RunSequence(
            {failure}, 0,
            /*initial_corpus_triaged=*/true,
            /*recycle_after=*/600,
            /*expected_run_rc=*/1,
            /*expected_tasks=*/1,
            /*fail_rebuild_call=*/1);
        Check(scenario.task_result.completion_status == COMP_STATUS_HARNESS_FATAL,
              "failed domain rebuild did not report HARNESS_FATAL");
        Check(scenario.task_result.error_code ==
                  ERR_DOMAIN_REPLACEMENT_START_FAILED,
              "safe harness replacement failure was misclassified");
        Check(scenario.report_count == 1,
              "unrecoverable harness failure reported more than once");
        Check(scenario.events.size() == 2 &&
              scenario.events[0] == "rebuild_failed" &&
              scenario.events[1] == "report",
              "unrecoverable harness failure ordering is wrong");
    }

    {
        topo::CollectResult failure{};
        failure.kind = topo::CollectKind::kHarnessFail;
        failure.fatal_reason = eng::HarnessFatalReason::kOuterForkEagain;
        const auto scenario = RunSequence(
            {failure}, 0,
            /*initial_corpus_triaged=*/true,
            /*recycle_after=*/600,
            /*expected_run_rc=*/1,
            /*expected_tasks=*/1,
            /*fail_rebuild_call=*/0,
            /*daemon_watchdog_ms=*/1000,
            /*exec_timeout_ms=*/5000,
            /*target_proc_id=*/PROC_ID_ANY,
            /*persisted_proc_state=*/{},
            /*worker_count=*/1,
            topo::DomainStopResult::kFailed);
        Check(scenario.task_result.completion_status ==
                  COMP_STATUS_HARNESS_FATAL,
              "unreclaimed domain did not report HARNESS_FATAL");
        Check(scenario.task_result.error_code ==
                  ERR_DOMAIN_OWNERSHIP_UNRECLAIMED,
              "stop failure did not preserve ownership loss");
        Check(scenario.rebuild_count == 0,
              "replacement started before old ownership was reclaimed");
    }

    {
        topo::CollectResult failure{};
        failure.kind = topo::CollectKind::kHarnessFail;
        failure.fatal_reason = eng::HarnessFatalReason::kOuterForkEagain;
        const auto scenario = RunSequence(
            {failure}, 0,
            /*initial_corpus_triaged=*/true,
            /*recycle_after=*/600,
            /*expected_run_rc=*/0,
            /*expected_tasks=*/1,
            /*fail_rebuild_call=*/1,
            /*daemon_watchdog_ms=*/1000,
            /*exec_timeout_ms=*/5000,
            /*target_proc_id=*/PROC_ID_ANY,
            /*persisted_proc_state=*/{},
            /*worker_count=*/1,
            topo::DomainStopResult::kClean,
            /*expect_task_execution=*/true,
            /*domain_startup_attempts=*/2);
        Check(scenario.task_result.completion_status ==
                  COMP_STATUS_HARNESS_RECOVERED,
              "transient domain setup failure was not recovered");
        Check(scenario.rebuild_count == 2,
              "domain setup retry count is incorrect");
        Check(scenario.startup_cleanup_stop_count == 1,
              "failed startup bypassed the startup-cleanup stop intent");
        Check(scenario.events.size() >= 3 &&
              scenario.events[0] == "rebuild_failed" &&
              scenario.events[1] == "rebuild" &&
              scenario.events[2] == "report",
              "domain setup retry did not finish before completion report");
    }

    {
        topo::CollectResult first{};
        first.kind = topo::CollectKind::kHarnessFail;
        first.fatal_reason = eng::HarnessFatalReason::kOuterForkEagain;
        const auto scenario = RunSequence(
            {first, Done(eng::RuntimeResultKind::kNormal, 64, 0)}, 0,
            /*initial_corpus_triaged=*/true,
            /*recycle_after=*/600,
            /*expected_run_rc=*/0,
            /*expected_tasks=*/1);
        Check(scenario.task_result.completion_status == COMP_STATUS_HARNESS_RECOVERED,
              "harness failure did not terminate the current task");
        Check(scenario.report_count == 1,
              "harness failure reported more than one completion");
        Check(scenario.dispatch_count == 1,
              "harness failure redispatched the same task");
        Check(scenario.rebuild_count == 1,
              "harness failure did not rebuild for the next task");
    }

    {
        constexpr std::uint32_t kRecoveryBudget = 3;
        topo::CollectResult failure{};
        failure.kind = topo::CollectKind::kHarnessFail;
        failure.fatal_reason = eng::HarnessFatalReason::kOuterForkEagain;
        std::vector<topo::CollectResult> failures(
            kRecoveryBudget + 1, failure);
        const auto scenario = RunSequence(
            std::move(failures), 0,
            /*initial_corpus_triaged=*/true,
            /*recycle_after=*/600,
            /*expected_run_rc=*/1,
            /*expected_tasks=*/kRecoveryBudget + 1,
            /*fail_rebuild_call=*/0,
            /*daemon_watchdog_ms=*/1000,
            /*exec_timeout_ms=*/5000,
            /*target_proc_id=*/PROC_ID_ANY,
            /*persisted_proc_state=*/{},
            /*worker_count=*/1,
            topo::DomainStopResult::kClean,
            /*expect_task_execution=*/true,
            /*domain_startup_attempts=*/1,
            /*domain_recovery_attempts=*/kRecoveryBudget);
        Check(scenario.task_results.size() == kRecoveryBudget + 1,
              "consecutive harness failures lost a completion");
        for (std::size_t i = 0; i < kRecoveryBudget; ++i) {
            Check(scenario.task_results[i].completion_status ==
                      COMP_STATUS_HARNESS_RECOVERED,
                  "recoverable harness failure escalated too early");
        }
        Check(scenario.task_results.back().completion_status ==
                  COMP_STATUS_HARNESS_FATAL,
              "consecutive harness failure limit did not escalate");
        Check(scenario.rebuild_count == kRecoveryBudget,
              "failure-limit task unexpectedly rebuilt a new domain");
        Check(scenario.dispatch_count == kRecoveryBudget + 1,
              "consecutive failure limit changed task dispatch count");
    }

    {
        constexpr std::uint32_t kRecoveryBudget = 3;
        topo::CollectResult failure{};
        failure.kind = topo::CollectKind::kHarnessFail;
        failure.fatal_reason = eng::HarnessFatalReason::kOuterForkEagain;
        std::vector<topo::CollectResult> results(kRecoveryBudget, failure);
        results.push_back(Done(eng::RuntimeResultKind::kNormal, 64, 0));
        results.insert(results.end(), kRecoveryBudget, failure);
        const auto scenario = RunSequence(
            std::move(results), 0,
            /*initial_corpus_triaged=*/true,
            /*recycle_after=*/600,
            /*expected_run_rc=*/0,
            /*expected_tasks=*/kRecoveryBudget * 2 + 1,
            /*fail_rebuild_call=*/0,
            /*daemon_watchdog_ms=*/1000,
            /*exec_timeout_ms=*/5000,
            /*target_proc_id=*/PROC_ID_ANY,
            /*persisted_proc_state=*/{},
            /*worker_count=*/1,
            topo::DomainStopResult::kClean,
            /*expect_task_execution=*/true,
            /*domain_startup_attempts=*/1,
            /*domain_recovery_attempts=*/kRecoveryBudget);
        Check(scenario.task_results.size() == kRecoveryBudget * 2 + 1,
              "failure-streak reset scenario lost a completion");
        Check(scenario.task_results[kRecoveryBudget].completion_status ==
                  COMP_STATUS_OK,
              "successful task in failure-streak scenario was not preserved");
        Check(scenario.task_results.back().completion_status ==
                  COMP_STATUS_HARNESS_RECOVERED,
              "successful task did not reset the harness failure streak");
        Check(scenario.rebuild_count == kRecoveryBudget * 2,
              "failure-streak reset changed rebuild count");
    }

    {
        const auto scenario = RunSequence(
            {Done(eng::RuntimeResultKind::kNormal, 8, 0)}, 0,
            /*initial_corpus_triaged=*/false,
            /*recycle_after=*/1);
        Check(scenario.rebuild_count == 0,
              "periodic recycle ran before initial corpus triage completed");
    }

    {
        const auto scenario = RunSequence(
            {Done(eng::RuntimeResultKind::kNormal, 8, 0)}, 0,
            /*initial_corpus_triaged=*/true,
            /*recycle_after=*/1);
        Check(scenario.rebuild_count == 1,
              "periodic recycle did not run at the threshold");
        Check(scenario.periodic_stop_count == 1,
              "periodic recycle bypassed the supervisor stop plan");
        Check(scenario.events.size() >= 2 &&
              scenario.events[0] == "report" &&
              scenario.events[1] == "rebuild",
              "periodic recycle occurred before ReportDone");
        Check(scenario.proc_states.size() == 1 &&
              scenario.proc_states[0].proc_id == 0 &&
              scenario.backend_proc_ids == std::vector<std::uint32_t>({0}),
              "healthy periodic recycle changed proc identity");
    }

    {
        constexpr std::uint32_t kHealthyTasks = 30;
        constexpr std::uint32_t kRecoveryBudget = 3;
        const auto scenario = RunSequence(
            {Done(eng::RuntimeResultKind::kNormal, 8, 0)}, 0,
            /*initial_corpus_triaged=*/true,
            /*recycle_after=*/1,
            /*expected_run_rc=*/0,
            /*expected_tasks=*/kHealthyTasks,
            /*fail_rebuild_call=*/0,
            /*daemon_watchdog_ms=*/1000,
            /*exec_timeout_ms=*/5000,
            /*target_proc_id=*/PROC_ID_ANY,
            /*persisted_proc_state=*/{},
            /*worker_count=*/1,
            topo::DomainStopResult::kClean,
            /*expect_task_execution=*/true,
            /*domain_startup_attempts=*/1,
            /*domain_recovery_attempts=*/kRecoveryBudget);
        Check(scenario.rebuild_count == kHealthyTasks &&
                  scenario.periodic_stop_count == kHealthyTasks,
              "healthy periodic recycle did not remain unbounded by recovery budget");
        Check(scenario.recovery_stop_count == 0,
              "healthy periodic recycle consumed failure recovery state");
        Check(scenario.proc_states.size() == 1 &&
                  scenario.proc_states.front().proc_id == 0 &&
                  scenario.backend_proc_ids ==
                      std::vector<std::uint32_t>({0}) &&
                  scenario.bus_proc_ids == std::vector<std::uint32_t>({0}),
              "healthy periodic recycle changed proc identity");
        Check(std::all_of(
                  scenario.task_results.begin(),
                  scenario.task_results.end(),
                  [](const refuzz::worker::TaskResult& result) {
                      return result.completion_status == COMP_STATUS_OK &&
                             result.proc_id == 0;
                  }),
              "healthy periodic recycle changed task result identity");
    }

    {
        const std::string gate_path =
            "/tmp/refuzz-recycle-gate-test-" +
            std::to_string(static_cast<long long>(::getpid()));
        (void)::unlink(gate_path.c_str());
        ExternalRecycleGateHolder holder(gate_path);
        Check(holder.Start(), "failed to start external recycle gate holder");
        const auto scenario = RunSequence(
            {Done(eng::RuntimeResultKind::kNormal, 8, 0)}, 0,
            /*initial_corpus_triaged=*/true,
            /*recycle_after=*/1,
            /*expected_run_rc=*/0,
            /*expected_tasks=*/1,
            /*fail_rebuild_call=*/0,
            /*daemon_watchdog_ms=*/1000,
            /*exec_timeout_ms=*/5000,
            /*target_proc_id=*/PROC_ID_ANY,
            /*persisted_proc_state=*/{},
            /*worker_count=*/1,
            topo::DomainStopResult::kClean,
            /*expect_task_execution=*/true,
            /*domain_startup_attempts=*/1,
            /*domain_recovery_attempts=*/20,
            gate_path,
            [&holder]() { holder.Release(); });
        Check(scenario.rebuild_count == 1,
              "deferred periodic recycle did not retry after gate release");
        Check(scenario.events.size() >= 3 &&
              scenario.events[0] == "report" &&
              scenario.events[1] == "idle_callback" &&
              scenario.events[2] == "rebuild",
              "busy recycle gate did not defer rebuild at the idle boundary");
        (void)::unlink(gate_path.c_str());
    }

    {
        const auto scenario = RunSequence(
            {Done(eng::RuntimeResultKind::kNormal, 8, 0)}, 0,
            /*initial_corpus_triaged=*/true,
            /*recycle_after=*/1,
            /*expected_run_rc=*/0,
            /*expected_tasks=*/1,
            /*fail_rebuild_call=*/0,
            /*daemon_watchdog_ms=*/1000,
            /*exec_timeout_ms=*/5000,
            /*target_proc_id=*/PROC_ID_ANY,
            /*persisted_proc_state=*/{},
            /*worker_count=*/1,
            topo::DomainStopResult::kForced);
        Check(scenario.rebuild_count == 1,
              "forced periodic recycle did not rebuild exactly once");
        Check(scenario.events.size() >= 3 &&
              scenario.events[0] == "report" &&
              scenario.events[1] == "forced_recycle" &&
              scenario.events[2] == "rebuild",
              "forced periodic recycle did not rotate after ReportDone");
        Check(scenario.proc_states.size() == 2 &&
              scenario.proc_states[0].proc_id == 0 &&
              scenario.proc_states[1].proc_id == 1 &&
              scenario.backend_proc_ids ==
                  std::vector<std::uint32_t>({0, 1}),
              "forced periodic recycle reused the old proc identity");
    }

    {
        const auto scenario = RunSequence(
            {Done(eng::RuntimeResultKind::kNormal, 8, 0)}, 0,
            /*initial_corpus_triaged=*/true,
            /*recycle_after=*/600,
            /*expected_run_rc=*/0,
            /*expected_tasks=*/1,
            /*fail_rebuild_call=*/0,
            /*daemon_watchdog_ms=*/1000,
            /*exec_timeout_ms=*/5000,
            /*target_proc_id=*/5);
        Check(scenario.task_result.proc_id == 5,
              "requested proc id was not used for the task");
        Check(scenario.proc_states.size() == 2 &&
              scenario.proc_states[0].proc_id == 0 &&
              scenario.proc_states[1].proc_id == 5,
              "requested proc rebind did not persist the selected identity");
        Check(scenario.rebuild_count == 1,
              "requested proc rebind did not rebuild exactly once");
        Check(scenario.rebind_stop_count == 1 &&
                  scenario.recovery_stop_count == 0,
              "requested proc rebind used the domain-fault stop intent");
    }

    {
        const auto scenario = RunSequence(
            {Done(eng::RuntimeResultKind::kNormal, 8, 0)}, 0,
            /*initial_corpus_triaged=*/true,
            /*recycle_after=*/600,
            /*expected_run_rc=*/1,
            /*expected_tasks=*/1,
            /*fail_rebuild_call=*/1,
            /*daemon_watchdog_ms=*/1000,
            /*exec_timeout_ms=*/5000,
            /*target_proc_id=*/5,
            /*persisted_proc_state=*/{},
            /*worker_count=*/1,
            topo::DomainStopResult::kClean,
            /*expect_task_execution=*/false);
        Check(scenario.task_result.proc_id == PROC_ID_ANY,
              "failed proc rebind claimed the requested identity");
        Check(scenario.task_result.completion_status ==
                  COMP_STATUS_HARNESS_FATAL &&
              scenario.task_result.error_code ==
                  ERR_DOMAIN_REPLACEMENT_START_FAILED,
              "failed proc rebind did not report harness fatal");
        Check(scenario.proc_states.size() == 2 &&
              scenario.proc_states[1].proc_id == 5,
              "failed proc rebind did not persist the attempted identity");
    }

    {
        // [dirty-ledger contract] kExact must not retry a candidate that was
        // marked dirty by a failed startup cleanup. The retry branch skips
        // NextClean for kExact, so it has to re-validate the dirty mask before
        // the next StartAttempt instead of reusing the dirty id.
        const auto scenario = RunSequence(
            {Done(eng::RuntimeResultKind::kNormal, 8, 0)}, 0,
            /*initial_corpus_triaged=*/true,
            /*recycle_after=*/600,
            /*expected_run_rc=*/1,
            /*expected_tasks=*/1,
            /*fail_rebuild_call=*/1,
            /*daemon_watchdog_ms=*/1000,
            /*exec_timeout_ms=*/5000,
            /*target_proc_id=*/5,
            /*persisted_proc_state=*/{},
            /*worker_count=*/1,
            topo::DomainStopResult::kClean,
            /*expect_task_execution=*/false,
            /*domain_startup_attempts=*/2,
            /*domain_recovery_attempts=*/20,
            /*recycle_gate_path=*/{},
            /*on_first_idle=*/{},
            topo::DomainStopResult::kFailed);
        Check(scenario.task_result.completion_status ==
                  COMP_STATUS_HARNESS_FATAL &&
              scenario.task_result.error_code ==
                  ERR_DOMAIN_REPLACEMENT_START_FAILED,
              "dirty exact rebind did not fail as a replacement fault");
        Check(scenario.rebuild_count == 1,
              "kExact retried a candidate that became dirty");
        Check(scenario.proc_states.size() == 2 &&
              scenario.proc_states[0].proc_id == 0 &&
              scenario.proc_states[1].proc_id == 5,
              "kExact retry published the dirty candidate identity");
        Check(!scenario.dirty_proc_masks.empty() &&
                  scenario.dirty_proc_masks.back() == (1u << 5),
              "failed startup cleanup did not persist the dirty proc id");
    }

    {
        const auto scenario = RunSequence(
            {Done(eng::RuntimeResultKind::kNormal, 8, 0)}, 0,
            /*initial_corpus_triaged=*/true,
            /*recycle_after=*/600,
            /*expected_run_rc=*/0,
            /*expected_tasks=*/1,
            /*fail_rebuild_call=*/0,
            /*daemon_watchdog_ms=*/1000,
            /*exec_timeout_ms=*/5000,
            /*target_proc_id=*/PROC_ID_ANY,
            refuzz::worker::PersistedProcState{5, 7, true});
        Check(scenario.task_result.proc_id == 6,
              "daemon restart reused the previous process's proc id");
        Check(scenario.proc_states.size() == 1 &&
              scenario.proc_states[0].proc_id == 6 &&
              scenario.proc_states[0].epoch == 8,
              "daemon restart did not persist the rotated proc state");
    }

    std::fprintf(stdout, "OK\n");
    return 0;
}

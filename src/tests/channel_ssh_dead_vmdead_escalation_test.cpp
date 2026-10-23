// channel_ssh_dead_vmdead_escalation_test.cpp
//
// Pins the [当前版本 ssh-dead-escalation] contract in channel.cpp:
// Channel::CheckWorkerRecoveryComplete.
//
// Scenario the regression test targets (mirrors the run-20260520T160047Z
// host_events.txt log):
//   1. HeartbeatSensor publishes a worker_dead crash event.
//   2. HandleFault → HandleWorkerFault → AsyncRecoverWorker calls
//      ExecuteRecovery(kRestartSingleWorker). The mock returns Error{kTimeout}
//      to simulate the VM being unresponsive on SSH.
//   3. loop_thread_ picks up the failure signal in CheckWorkerRecoveryComplete
//      and must NOT re-observe with reason=kWorkerHeartbeatLost (which would
//      let the policy spend two more 5-15 s single-worker attempts on a dead
//      SSH path).  Instead it must re-observe with reason=kVmDead and
//      source_worker_id=UINT32_MAX, so EscalationPolicy::Decide jumps
//      straight to kRebootVm.

#include "refuzz/channel/channel_impl.hpp"
#include "refuzz/channel/factory/channel_builder.hpp"
#include "refuzz/channel/factory/mock_components.hpp"
#include "refuzz/channel/health/health_monitor_contract.hpp"
#include "refuzz/channel/infra/shm_infra.hpp"
#include "refuzz/channel/recovery/recovery_contract.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

namespace cc       = refuzz::core::channel_contract;
namespace ch       = refuzz::channel;
namespace data     = refuzz::channel::data;
namespace factory  = refuzz::channel::factory;
namespace health   = refuzz::channel::health;
namespace infra    = refuzz::channel::infra;
namespace recovery = refuzz::channel::recovery;

namespace {

#define CHECK(cond)                                                                  \
    do {                                                                             \
        if (!(cond)) {                                                               \
            std::fprintf(stderr, "CHECK failed: %s (line %d)\n", #cond, __LINE__);   \
            std::abort();                                                            \
        }                                                                            \
    } while (0)

#define RUN_TEST(fn)                                                                 \
    do {                                                                             \
        std::fprintf(stderr, "[RUN]  %s\n", #fn);                                    \
        fn();                                                                        \
        std::fprintf(stderr, "[PASS] %s\n", #fn);                                    \
    } while (0)

std::string TempPath(const char* suffix)
{
    static std::atomic<uint32_t> counter{0};
    return "/tmp/refuzz_ssh_dead_escalation_" +
           std::to_string(static_cast<long long>(::getpid())) + "_" +
           std::to_string(counter.fetch_add(1)) + "_" + suffix;
}

std::shared_ptr<infra::ShmInfra> MakeShm(const std::string& path)
{
    infra::InfraConfig cfg;
    cfg.shm_path = path;
    cfg.n_workers = 1;
    auto shm = std::make_shared<infra::ShmInfra>(std::move(cfg));
    auto r = shm->Init();
    if (!r.ok()) {
        std::fprintf(stderr, "ShmInfra::Init failed: %s\n", r.error().message.c_str());
        return nullptr;
    }
    return shm;
}

// Minimal IDataPlane — no real wire, just satisfies the contract.
class NoopDataPlane final : public data::IDataPlane {
public:
    ch::Result<void> Prepare() override { return ch::Result<void>::Ok(); }
    void Close() override {}
    void Pause() override {}
    void Resume() override {}

    ch::Result<void> StartServer() override { return ch::Result<void>::Ok(); }

    data::SubmitOutcome Submit(const data::IDataPlane::SubmitInput&) override
    { return data::SubmitOutcome::kSent; }
    void Poll(std::vector<data::DispatchOutcome>&, std::chrono::microseconds) override {}
    void WakePoller() noexcept override {}
    void ResetWorker(uint32_t) override {}
    void ResetAll() override {}
    std::vector<data::InflightEntry> SnapshotInflight() const override { return {}; }
    bool IsPaused() const noexcept override { return false; }
    bool IsClosed() const noexcept override { return false; }
    uint32_t MaxWorkerSlots() const noexcept override { return 1; }
    bool IsWorkerSendable(uint32_t) const override { return true; }
};

class ManualHealthMonitor final : public health::IHealthMonitor {
public:
    ch::Result<void> Start() override { return ch::Result<void>::Ok(); }
    void Stop() noexcept override {}
    void AddSensor(std::unique_ptr<health::IHealthSensor>) override {}
    void BindChannelSignals(health::HealthMonitorView view) noexcept override
    { view_ = std::move(view); }
    void SetWorkerAlive(uint32_t, bool) noexcept override {}
    void RearmSingleWorker(uint32_t) override {}

    bool HasPendingCrashEvents() const noexcept override
    { return has_pending_.load(std::memory_order_acquire); }

    std::vector<health::CrashEvent> DrainCrashEvents() override
    {
        std::lock_guard<std::mutex> lock(mu_);
        std::vector<health::CrashEvent> out;
        out.swap(events_);
        has_pending_.store(false, std::memory_order_release);
        return out;
    }

    void SuspendMonitoring() override {}
    void ResumeMonitoring() override {}
    ch::Result<void> Reboot() override { return ch::Result<void>::Ok(); }
    cc::HealthMonitorSnapshot GetSnapshot() const override { return {}; }

    void PublishWorkerDead()
    {
        health::CrashEvent event;
        event.origin = health::CrashEventOrigin::kHeartbeat;
        event.fragment.kind = cc::CrashKind::kWorkerDead;
        event.fragment.source_worker_id = 0;
        event.fragment.title = "worker dead";
        {
            std::lock_guard<std::mutex> lock(mu_);
            events_.push_back(std::move(event));
            has_pending_.store(true, std::memory_order_release);
        }
        if (view_.loop_cv) view_.loop_cv->notify_one();
        if (view_.wake_poller) view_.wake_poller();
    }

private:
    mutable std::mutex mu_;
    std::vector<health::CrashEvent> events_;
    std::atomic<bool> has_pending_{false};
    health::HealthMonitorView view_;
};

// RecordingRecovery — replaces the real recovery::Recovery with a
// programmable, recording stand-in so the test can:
//   (a) make AsyncRecoverWorker's ExecuteRecovery fail with kTimeout
//   (b) inspect what reason CheckWorkerRecoveryComplete passes to its
//       follow-up ObserveFault.
class RecordingRecovery final : public recovery::IRecovery {
public:
    struct Observation {
        cc::ChannelFaultReason  reason;
        uint32_t                source_worker_id;
        uint32_t                total_workers;
        uint32_t                unusable_workers;
    };
    struct Execution {
        cc::ChannelFaultReason  reason;
        cc::RecoveryAction      action;
        uint32_t                target_worker_id;
    };

    recovery::RecoveryObservationResult ObserveFault(
        uint64_t,
        cc::ChannelFaultReason reason,
        cc::ChannelFaultSource,
        const recovery::FaultContext& ctx) override
    {
        {
            std::lock_guard<std::mutex> lock(mu_);
            observations_.push_back(Observation{
                reason, ctx.source_worker_id,
                ctx.total_workers, ctx.unusable_workers});
        }
        cv_.notify_all();

        recovery::RecoveryObservationResult result;
        result.accepted = true;
        if (reason == cc::ChannelFaultReason::kVmDead) {
            result.recovery_action = cc::RecoveryAction::kRebootVm;
            result.abort_scope     = cc::ChannelAbortScope::kChannel;
            result.target_worker_id = UINT32_MAX;
        } else {
            result.recovery_action = cc::RecoveryAction::kRestartSingleWorker;
            result.abort_scope     = cc::ChannelAbortScope::kSlot;
            result.target_worker_id = ctx.source_worker_id;
        }
        return result;
    }

    ch::Result<recovery::RecoveryResult> ExecuteRecovery(
        cc::ChannelFaultReason reason,
        cc::RecoveryAction     action,
        uint32_t               target_worker_id) override
    {
        {
            std::lock_guard<std::mutex> lock(mu_);
            executions_.push_back(Execution{reason, action, target_worker_id});
        }
        cv_.notify_all();

        if (action == cc::RecoveryAction::kRestartSingleWorker) {
            // Simulate SSH dying mid-recovery — the precise wording is what
            // ExecuteSingleWorkerRestart wraps around the underlying SSH error.
            return ch::Error{
                ch::ErrorKind::kTimeout,
                "StopWorker failed: kill pid=1234 failed: SSH command timed out"};
        }
        // kRebootVm path: let it succeed so the channel completes and the
        // test exits cleanly.
        recovery::RecoveryResult ok;
        ok.action = action;
        return ch::Result<recovery::RecoveryResult>::Ok(std::move(ok));
    }

    bool CompleteFullChannelRecovery(uint64_t, cc::RecoveryAction, bool) override
    { return true; }
    void CompleteSingleWorkerRecovery(uint32_t, bool) override {}
    void NoteHealthy() override {}
    recovery::RecoverySnapshot GetSnapshot() const override { return {}; }
    void Reset() override {}

    std::vector<Observation> Observations() const
    {
        std::lock_guard<std::mutex> lock(mu_);
        return observations_;
    }

    std::vector<Execution> Executions() const
    {
        std::lock_guard<std::mutex> lock(mu_);
        return executions_;
    }

    bool WaitForObservations(std::size_t n, std::chrono::milliseconds timeout)
    {
        std::unique_lock<std::mutex> lock(mu_);
        return cv_.wait_for(lock, timeout, [this, n] {
            return observations_.size() >= n;
        });
    }

    bool WaitForExecutions(std::size_t n, std::chrono::milliseconds timeout)
    {
        std::unique_lock<std::mutex> lock(mu_);
        return cv_.wait_for(lock, timeout, [this, n] {
            return executions_.size() >= n;
        });
    }

private:
    mutable std::mutex mu_;
    std::condition_variable cv_;
    std::vector<Observation> observations_;
    std::vector<Execution>   executions_;
};

struct ChannelHarness {
    ~ChannelHarness()
    {
        if (channel) channel->Close();
        if (!shm_path.empty()) ::unlink(shm_path.c_str());
    }

    std::string shm_path;
    std::shared_ptr<infra::ShmInfra> shm;
    ManualHealthMonitor*  health = nullptr;
    RecordingRecovery*    recovery = nullptr;
    std::unique_ptr<ch::IChannel> channel;
};

std::unique_ptr<ChannelHarness> MakeChannelHarness(uint32_t channel_id)
{
    auto harness = std::make_unique<ChannelHarness>();
    harness->shm_path = TempPath("shm");
    harness->shm = MakeShm(harness->shm_path);
    if (!harness->shm) return nullptr;

    auto dp       = std::make_unique<NoopDataPlane>();
    auto hm       = std::make_unique<ManualHealthMonitor>();
    auto recovery_ = std::make_unique<RecordingRecovery>();
    harness->health   = hm.get();
    harness->recovery = recovery_.get();

    ch::ChannelComponents components;
    components.shm       = harness->shm;
    components.substrate = std::make_unique<factory::MockSubstrate>();
    components.control   = std::make_unique<factory::MockControlPlane>(1);
    components.data      = std::move(dp);
    components.console   = std::make_unique<factory::NullConsoleSource>();
    components.health    = std::move(hm);
    components.recovery  = std::move(recovery_);
    components.channel_cfg.channel_id            = channel_id;
    components.channel_cfg.n_workers             = 1;
    components.channel_cfg.backend_id            = "ssh_dead_escalation_test";
    components.channel_cfg.loop_interval         = std::chrono::milliseconds{20};
    components.channel_cfg.health_check_interval = std::chrono::seconds{10};
    components.channel_cfg.input_queue_capacity  = 8;

    auto built = ch::ChannelBuilder::Build(std::move(components));
    if (!built.ok()) {
        std::fprintf(stderr, "ChannelBuilder failed: %s\n", built.error().message.c_str());
        return nullptr;
    }
    harness->channel = std::move(built.value());

    auto boot = harness->channel->Boot();
    if (!boot.ok()) {
        std::fprintf(stderr, "Channel::Boot failed: %s\n", boot.error().message.c_str());
        return nullptr;
    }
    return harness;
}

// Verify: a worker_dead → SSH-timeout cycle re-observes with kVmDead, not the
// original kWorkerHeartbeatLost.  EscalationPolicy::Decide(kVmDead, ...) → kRebootVm
// so the policy skips the remaining single-worker attempts that would each
// burn another SSH timeout.
void TestSshTimeoutTriggersVmDeadReobservation()
{
    auto harness = MakeChannelHarness(1);
    CHECK(harness != nullptr);

    harness->health->PublishWorkerDead();

    // The async path is: AsyncRecoverWorker calls ExecuteRecovery(kRestartSingleWorker)
    // → returns kTimeout → loop_thread CheckWorkerRecoveryComplete re-observes as
    // kVmDead → ExecuteRecovery(kRebootVm). Wait for both observations AND
    // executions to land so we don't race the loop_thread.
    CHECK(harness->recovery->WaitForObservations(2, std::chrono::seconds{5}));
    CHECK(harness->recovery->WaitForExecutions(2, std::chrono::seconds{5}));

    auto observations = harness->recovery->Observations();
    auto executions   = harness->recovery->Executions();
    CHECK(observations.size() >= 2);
    CHECK(executions.size() >= 2);

    // First observe is the fresh fault from HandleFault → HandleWorkerFault.
    CHECK(observations[0].reason == cc::ChannelFaultReason::kWorkerHeartbeatLost);
    CHECK(observations[0].source_worker_id == 0);

    // Second observe is the post-failure escalation in CheckWorkerRecoveryComplete.
    // The new contract: SSH-bound error (kTimeout) → reason swap to kVmDead with
    // source_worker_id=UINT32_MAX.
    CHECK(observations[1].reason == cc::ChannelFaultReason::kVmDead);
    CHECK(observations[1].source_worker_id == UINT32_MAX);

    // And the policy decision threaded through that observation must have
    // produced an actual ExecuteRecovery(kRebootVm) — confirming the channel
    // doesn't waste budget on more single-worker attempts.
    CHECK(executions[0].action == cc::RecoveryAction::kRestartSingleWorker);
    CHECK(executions[1].action == cc::RecoveryAction::kRebootVm);
}

}  // namespace

int main()
{
    RUN_TEST(TestSshTimeoutTriggersVmDeadReobservation);
    return 0;
}

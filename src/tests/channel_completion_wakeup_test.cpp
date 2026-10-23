#include "refuzz/channel/channel_impl.hpp"
#include "refuzz/channel/data/ivshmem_data_plane.hpp"
#include "refuzz/channel/factory/channel_builder.hpp"
#include "refuzz/channel/factory/mock_components.hpp"
#include "refuzz/channel/health/health_monitor_contract.hpp"
#include "refuzz/channel/infra/shm_infra.hpp"
#include "refuzz/channel/recovery/recovery_contract.hpp"
#include "refuzz/proto_wire/ivshmem_protocol.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <atomic>
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <deque>
#include <functional>
#include <future>
#include <iterator>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace cc = refuzz::core::channel_contract;
namespace ch = refuzz::channel;
namespace data = refuzz::channel::data;
namespace factory = refuzz::channel::factory;
namespace health = refuzz::channel::health;
namespace infra = refuzz::channel::infra;
namespace recovery = refuzz::channel::recovery;
namespace evidence = refuzz::channel::evidence;

namespace {

#define CHECK(cond)                                                                  \
    do {                                                                             \
        if (!(cond)) {                                                               \
            std::fprintf(stderr, "CHECK failed: %s (line %d)\n", #cond, __LINE__);   \
            return 1;                                                                \
        }                                                                            \
    } while (0)

#define RUN_TEST(fn)                                                                 \
    do {                                                                             \
        std::fprintf(stderr, "  [RUN] %s\n", #fn);                                  \
        const int rc = fn();                                                         \
        if (rc != 0) {                                                               \
            std::fprintf(stderr, "  [FAIL] %s\n", #fn);                             \
            return rc;                                                               \
        }                                                                            \
        std::fprintf(stderr, "  [PASS] %s\n", #fn);                                 \
    } while (0)

// DrainEvents may return as soon as one event is queued while the loop thread
// is still publishing the rest of the same incident batch. Collect until the
// expected count arrives (or the deadline expires).
bool DrainEventsCollect(ch::IChannel* channel, ch::EventList& out,
                        std::size_t min_count,
                        std::chrono::milliseconds timeout)
{
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (out.size() < min_count &&
           std::chrono::steady_clock::now() < deadline) {
        ch::EventList batch;
        if (!channel->DrainEvents(batch, std::chrono::milliseconds{20})) {
            continue;
        }
        out.insert(out.end(),
                   std::make_move_iterator(batch.begin()),
                   std::make_move_iterator(batch.end()));
    }
    return out.size() >= min_count;
}

constexpr auto kPollTimeout = std::chrono::seconds(1);
constexpr auto kWakeBudget = std::chrono::milliseconds(75);

std::string TempPath(const char* suffix)
{
    static std::atomic<uint32_t> counter{0};
    return "/tmp/refuzz_channel_wakeup_" + std::to_string(static_cast<long long>(::getpid())) +
           "_" + std::to_string(counter.fetch_add(1)) + "_" + suffix;
}

void StoreTaskState(TaskSlot* slot, TaskSlotState state)
{
    __atomic_store_n(&slot->state, static_cast<uint32_t>(state), __ATOMIC_RELEASE);
}

void StoreCompletionState(CompletionSlot* slot, CompletionSlotState state)
{
    __atomic_store_n(&slot->state, static_cast<uint32_t>(state), __ATOMIC_RELEASE);
}

std::shared_ptr<infra::ShmInfra> MakeShm(const std::string& path,
                                         uint32_t n_workers = 1)
{
    infra::InfraConfig cfg;
    cfg.shm_path = path;
    cfg.n_workers = n_workers;

    auto shm = std::make_shared<infra::ShmInfra>(std::move(cfg));
    auto r = shm->Init();
    if (!r.ok()) {
        std::fprintf(stderr, "ShmInfra::Init failed: %s\n", r.error().message.c_str());
        return nullptr;
    }
    return shm;
}

void PublishCompletion(const std::shared_ptr<infra::ShmInfra>& shm,
                       uint64_t executor_id,
                       uint32_t dispatch_gen,
                       const std::vector<uint8_t>& output,
                       uint32_t status = COMP_STATUS_OK)
{
    auto wv = shm->worker(0);
    std::memcpy(wv.output_pool(), output.data(), output.size());

    auto* task = wv.task_slot();
    StoreTaskState(task, TASK_TAKEN);

    auto* completion = wv.completion_slot();
    completion->executor_id = executor_id;
    completion->dispatch_gen = dispatch_gen;
    completion->status = status;
    completion->error_code = 0;
    completion->crash_signal = 0;
    completion->output_off = 0;
    completion->output_len = static_cast<uint32_t>(output.size());
    StoreCompletionState(completion, COMP_READY);
}

struct MsgWithFd {
    uint64_t value = 0;
    int fd = -1;
};

MsgWithFd RecvMsgWithFd(int sock)
{
    uint8_t buf[8] = {};
    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } ctrl;
    std::memset(&ctrl, 0, sizeof(ctrl));

    struct iovec iov {};
    iov.iov_base = buf;
    iov.iov_len = sizeof(buf);

    struct msghdr msg {};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ctrl.buf;
    msg.msg_controllen = sizeof(ctrl.buf);

    const ssize_t n = recvmsg(sock, &msg, 0);
    if (n != static_cast<ssize_t>(sizeof(buf))) {
        return {0, -2};
    }

    uint64_t value = 0;
    std::memcpy(&value, buf, sizeof(value));

    MsgWithFd out{value, -1};
    struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg != nullptr &&
        cmsg->cmsg_level == SOL_SOCKET &&
        cmsg->cmsg_type == SCM_RIGHTS &&
        cmsg->cmsg_len == CMSG_LEN(sizeof(int))) {
        std::memcpy(&out.fd, CMSG_DATA(cmsg), sizeof(int));
    }
    return out;
}

bool ConnectUnixWithRetry(const std::string& path, int* out_fd)
{
    for (int attempt = 0; attempt < 100; ++attempt) {
        int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0) return false;

        struct sockaddr_un addr {};
        addr.sun_family = AF_UNIX;
        std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);

        if (connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) == 0) {
            *out_fd = fd;
            return true;
        }

        ::close(fd);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return false;
}

data::IvshmemDataPlane MakeIvshmemDp(const std::shared_ptr<infra::ShmInfra>& shm,
                                     bool use_doorbell,
                                     std::string socket_path = {})
{
    auto worker = shm->worker(0);
    if (worker.valid()) {
        __atomic_store_n(&worker.ctrl()->host_state,
                         static_cast<uint32_t>(HOST_REG_GRANTED),
                         __ATOMIC_RELEASE);
        __atomic_store_n(&worker.ctrl()->guest_state,
                         static_cast<uint32_t>(GUEST_REG_READY),
                         __ATOMIC_RELEASE);
    }
    data::IvshmemDataPlaneOptions options;
    options.shm_path = shm->Backbone()->ShmPath();
    options.doorbell_socket_path = std::move(socket_path);
    options.use_doorbell = use_doorbell;
    options.poll_sleep_us = std::chrono::microseconds{100};

    refuzz::channel::control::SendabilityView sendability;
    sendability.is_registered = [](uint32_t) { return true; };
    sendability.registered_worker_count = [] { return 1u; };

    return data::IvshmemDataPlane(
        shm->Backbone(),
        shm.get(),
        std::move(sendability),
        refuzz::channel::control::RegistrationControlHook{},
        std::move(options));
}

class BlockingTestDataPlane final : public data::IDataPlane {
public:
    explicit BlockingTestDataPlane(uint32_t worker_count = 1)
        : worker_count_(worker_count), busy_(worker_count, false)
    {}

    ch::Result<void> Prepare() override { return ch::Result<void>::Ok(); }
    void Close() override {
        closed_.store(true, std::memory_order_release);
        WakePoller();
    }
    void Pause() override
    {
        std::lock_guard<std::mutex> lock(mu_);
        paused_ = true;
    }
    void Resume() override
    {
        std::lock_guard<std::mutex> lock(mu_);
        paused_ = false;
    }

    data::SubmitOutcome Submit(const data::IDataPlane::SubmitInput& req) override
    {
        {
            std::lock_guard<std::mutex> lock(mu_);
            if (req.worker_id >= worker_count_) return data::SubmitOutcome::kInvalid;
            if (paused_) return data::SubmitOutcome::kPaused;
            if (busy_[req.worker_id]) return data::SubmitOutcome::kBusy;
            busy_[req.worker_id] = true;
            last_executor_id_ = req.executor_id;
            last_dispatch_gen_ = req.dispatch_gen;
            inflight_[req.executor_id] = Submitted{
                req.worker_id, req.proc_id, req.executor_id, req.dispatch_gen};
            ++submit_count_;
        }
        cv_.notify_all();
        return data::SubmitOutcome::kSent;
    }

    void Poll(std::vector<data::DispatchOutcome>& out,
              std::chrono::microseconds timeout) override
    {
        std::unique_lock<std::mutex> lock(mu_);
        if (timeout > std::chrono::microseconds{0} &&
            completions_.empty() && !wake_pending_ &&
            !closed_.load(std::memory_order_acquire)) {
            cv_.wait_for(lock, timeout, [this] {
                return !completions_.empty() || wake_pending_ ||
                       closed_.load(std::memory_order_acquire);
            });
        }
        while (!completions_.empty()) {
            out.push_back(std::move(completions_.front()));
            completions_.pop_front();
        }
        wake_pending_ = false;
    }

    void WakePoller() noexcept override
    {
        {
            std::lock_guard<std::mutex> lock(mu_);
            wake_pending_ = true;
        }
        cv_.notify_all();
    }

    void ResetWorker(uint32_t worker_id) override
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (worker_id >= worker_count_) return;
        busy_[worker_id] = false;
        for (auto it = inflight_.begin(); it != inflight_.end();) {
            if (it->second.worker_id == worker_id) {
                it = inflight_.erase(it);
            } else {
                ++it;
            }
        }
    }
    void ResetAll() override
    {
        std::lock_guard<std::mutex> lock(mu_);
        std::fill(busy_.begin(), busy_.end(), false);
        inflight_.clear();
    }
    std::vector<data::InflightEntry> SnapshotInflight() const override
    {
        std::lock_guard<std::mutex> lock(mu_);
        std::vector<data::InflightEntry> out;
        out.reserve(inflight_.size());
        for (const auto& [executor_id, submitted] : inflight_) {
            out.push_back(data::InflightEntry{
                .worker_id = submitted.worker_id,
                .executor_id = executor_id,
                .dispatch_gen = submitted.dispatch_gen,
            });
        }
        return out;
    }
    bool IsPaused() const noexcept override
    {
        std::lock_guard<std::mutex> lock(mu_);
        return paused_;
    }
    bool IsClosed() const noexcept override { return closed_.load(std::memory_order_acquire); }
    uint32_t MaxWorkerSlots() const noexcept override { return worker_count_; }
    bool IsWorkerSendable(uint32_t worker_id) const override
    {
        std::lock_guard<std::mutex> lock(mu_);
        return worker_id < worker_count_ && !paused_ && !busy_[worker_id];
    }

    bool WaitForSubmits(uint32_t count, std::chrono::milliseconds timeout)
    {
        std::unique_lock<std::mutex> lock(mu_);
        return cv_.wait_for(lock, timeout, [this, count] {
            return submit_count_ >= count;
        });
    }

    uint64_t LastExecutorId() const
    {
        std::lock_guard<std::mutex> lock(mu_);
        return last_executor_id_;
    }

    uint32_t LastDispatchGen() const
    {
        std::lock_guard<std::mutex> lock(mu_);
        return last_dispatch_gen_;
    }

    uint32_t SubmitCount() const
    {
        std::lock_guard<std::mutex> lock(mu_);
        return submit_count_;
    }

    bool WasSubmitted(uint64_t executor_id, uint32_t worker_id) const
    {
        std::lock_guard<std::mutex> lock(mu_);
        const auto it = inflight_.find(executor_id);
        return it != inflight_.end() && it->second.worker_id == worker_id;
    }

    void CompleteLast(std::vector<uint8_t> output,
                      data::DispatchOutcomeKind kind = data::DispatchOutcomeKind::kOk,
                      uint32_t error_code = ERR_OK)
    {
        Complete(LastExecutorId(), std::move(output), kind, error_code);
    }

    void Complete(uint64_t executor_id,
                  std::vector<uint8_t> output,
                  data::DispatchOutcomeKind kind = data::DispatchOutcomeKind::kOk,
                  uint32_t error_code = ERR_OK)
    {
        data::DispatchOutcome outcome;
        {
            std::lock_guard<std::mutex> lock(mu_);
            const auto it = inflight_.find(executor_id);
            if (it == inflight_.end()) return;
            outcome.worker_id = it->second.worker_id;
            outcome.proc_id = it->second.proc_id;
            outcome.executor_id = it->second.executor_id;
            outcome.dispatch_gen = it->second.dispatch_gen;
            outcome.kind = kind;
            outcome.error_code = error_code;
            outcome.output = std::move(output);
            busy_[outcome.worker_id] = false;
            inflight_.erase(it);
            completions_.push_back(std::move(outcome));
            wake_pending_ = true;
        }
        cv_.notify_all();
    }

private:
    struct Submitted {
        uint32_t worker_id = 0;
        uint32_t proc_id = cc::kAnyProcId;
        uint64_t executor_id = 0;
        uint32_t dispatch_gen = 0;
    };

    mutable std::mutex mu_;
    std::condition_variable cv_;
    std::deque<data::DispatchOutcome> completions_;
    uint32_t submit_count_ = 0;
    uint64_t last_executor_id_ = 0;
    uint32_t last_dispatch_gen_ = 0;
    uint32_t worker_count_ = 1;
    std::vector<bool> busy_;
    std::unordered_map<uint64_t, Submitted> inflight_;
    bool paused_ = false;
    bool wake_pending_ = false;
    std::atomic<bool> closed_{false};
};

class ManualHealthMonitor final : public health::IHealthMonitor {
public:
    ch::Result<void> Start() override
    {
        started_.store(true, std::memory_order_release);
        return ch::Result<void>::Ok();
    }
    void Stop() noexcept override
    {
        started_.store(false, std::memory_order_release);
    }
    void AddSensor(std::unique_ptr<health::IHealthSensor>) override {}
    void BindChannelSignals(health::HealthMonitorView view) noexcept override { view_ = std::move(view); }
    void SetWorkerAlive(uint32_t, bool) noexcept override {}
    void RearmSingleWorker(uint32_t) override {}

    bool HasPendingCrashEvents() const noexcept override
    {
        return has_pending_.load(std::memory_order_acquire);
    }

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

    bool Started() const noexcept
    {
        return started_.load(std::memory_order_acquire);
    }

    void Publish(health::CrashKind kind,
                 health::CrashEventOrigin origin,
                 uint32_t worker_id,
                 std::string title,
                 std::string console_output = {})
    {
        health::CrashEvent event;
        event.origin = origin;
        event.fragment.kind = kind;
        event.fragment.source_worker_id = worker_id;
        event.fragment.title = std::move(title);
        event.fragment.console_output = std::move(console_output);
        {
            std::lock_guard<std::mutex> lock(mu_);
            events_.push_back(std::move(event));
            has_pending_.store(true, std::memory_order_release);
        }
        if (view_.loop_cv) view_.loop_cv->notify_one();
        if (view_.wake_poller) view_.wake_poller();
    }

    void PublishWorkerDead(uint32_t worker_id = 0)
    {
        Publish(cc::CrashKind::kWorkerDead,
                health::CrashEventOrigin::kHeartbeat,
                worker_id,
                "worker dead");
    }

    void PublishKernelCrash(std::string console_output,
                            uint32_t worker_id = 0)
    {
        Publish(cc::CrashKind::kKernelCrash,
                health::CrashEventOrigin::kSerialPattern,
                worker_id,
                "INFO: task blocked for more than 120 seconds",
                std::move(console_output));
    }

    // 对应 VmAliveSensor 的"聚合前进时钟冻结"：inferred=true 的 no-output，
    // 与 qemu 进程死亡的 kVmDead（inferred=false）区分。
    void PublishNoOutput(std::string title = "guest forward-progress frozen")
    {
        health::CrashEvent event;
        event.origin = health::CrashEventOrigin::kVmLiveness;
        event.fragment.kind = cc::CrashKind::kNoOutput;
        event.fragment.source_worker_id = UINT32_MAX;
        event.fragment.title = std::move(title);
        event.inferred = true;
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
    std::atomic<bool> started_{false};
    health::HealthMonitorView view_;
};

class HealthOrderedSubstrate final : public refuzz::channel::runtime::ISubstrate {
public:
    explicit HealthOrderedSubstrate(const ManualHealthMonitor* health)
        : health_(health)
    {}

    ch::Result<void> StartVM(uint32_t) override { return ch::Result<void>::Ok(); }
    void StopVM(uint32_t) override {}
    ch::Result<void> RebootVM(uint32_t) override { return ch::Result<void>::Ok(); }
    bool IsVMAlive(uint32_t) const override { return true; }
    ch::Result<void> Close() override { return ch::Result<void>::Ok(); }
    ch::Result<void> CopyFileTo(uint32_t, const std::string&, const std::string&,
                                std::chrono::milliseconds) override
    {
        return ch::Result<void>::Ok();
    }
    ch::Result<std::string> RunCommand(uint32_t, const std::string&,
                                       std::chrono::milliseconds) override
    {
        return ch::Result<std::string>::Ok("");
    }
    ch::Result<void> DeployArtifacts(
        uint32_t, const refuzz::channel::runtime::DeployBundle&) override
    {
        return ch::Result<void>::Ok();
    }
    ch::Result<void> StartAllWorkers(uint32_t) override
    {
        if (health_ && health_->Started()) return ch::Result<void>::Ok();
        return ch::Error{ch::ErrorKind::kInfra,
                         "workers started before console health drain"};
    }
    ch::Result<void> StopAllWorkers(uint32_t) override
    {
        return ch::Result<void>::Ok();
    }
    ch::Result<void> StartWorker(uint32_t, uint32_t) override
    {
        if (health_ && health_->Started()) return ch::Result<void>::Ok();
        return ch::Error{ch::ErrorKind::kInfra,
                         "worker started before console health drain"};
    }
    ch::Result<void> StopWorker(uint32_t, uint32_t) override
    {
        return ch::Result<void>::Ok();
    }
    refuzz::channel::evidence::ConsoleEndpoint
    DefaultConsoleEndpoint(uint32_t) const override
    {
        return {};
    }
    refuzz::channel::runtime::VendorHints Hints(uint32_t) const override
    {
        return {};
    }
    std::string Diagnose(uint32_t) const override
    {
        return "HealthOrderedSubstrate";
    }

private:
    const ManualHealthMonitor* health_ = nullptr;
};

class TestRecovery final : public recovery::IRecovery {
public:
    explicit TestRecovery(bool recover_harness_fatal = false,
                          bool recover_classified_faults = true,
                          bool abort_classified_without_recovery = false,
                          std::vector<uint64_t> recovery_inflight_ids = {},
                          std::vector<uint64_t> recovery_inflight_idle_ids = {})
        : recover_harness_fatal_(recover_harness_fatal),
          recover_classified_faults_(recover_classified_faults),
          abort_classified_without_recovery_(abort_classified_without_recovery),
          recovery_inflight_ids_(std::move(recovery_inflight_ids)),
          recovery_inflight_idle_ids_(std::move(recovery_inflight_idle_ids))
    {}

    recovery::RecoveryObservationResult ObserveFault(
        uint64_t,
        cc::ChannelFaultReason reason,
        cc::ChannelFaultSource source,
        const recovery::FaultContext& context) override
    {
        {
            std::lock_guard<std::mutex> lock(mu_);
            observed_reason_ = reason;
            observed_source_ = source;
            ++observation_count_;
        }
        cv_.notify_all();

        recovery::RecoveryObservationResult result;
        result.accepted = true;
        result.abort_scope = cc::ChannelAbortScope::kNone;
        result.recovery_action = cc::RecoveryAction::kNone;
        if (abort_classified_without_recovery_ &&
            reason == cc::ChannelFaultReason::kKernelCrash) {
            result.abort_scope = cc::ChannelAbortScope::kChannel;
            return result;
        }
        if (recover_classified_faults_ &&
            (reason == cc::ChannelFaultReason::kExecutionDomainHung ||
             reason == cc::ChannelFaultReason::kKernelCrash ||
             reason == cc::ChannelFaultReason::kNoOutput)) {
            result.abort_scope = cc::ChannelAbortScope::kChannel;
            result.recovery_action = cc::RecoveryAction::kRebootVm;
        } else if (recover_harness_fatal_ &&
            reason == cc::ChannelFaultReason::kWorkerHarnessFatal) {
            result.abort_scope = cc::ChannelAbortScope::kSlot;
            result.recovery_action = cc::RecoveryAction::kRestartSingleWorker;
            result.target_worker_id = context.source_worker_id;
        }
        return result;
    }

    ch::Result<recovery::RecoveryResult> ExecuteRecovery(
        cc::ChannelFaultReason reason,
        cc::RecoveryAction action,
        uint32_t worker_id) override
    {
        {
            std::lock_guard<std::mutex> lock(mu_);
            executed_ = true;
            executed_reason_ = reason;
            executed_action_ = action;
            executed_worker_id_ = worker_id;
        }
        cv_.notify_all();
        recovery::RecoveryResult result;
        result.action = action;
        result.inflight_executor_ids      = recovery_inflight_ids_;
        result.inflight_idle_executor_ids = recovery_inflight_idle_ids_;
        return ch::Result<recovery::RecoveryResult>::Ok(std::move(result));
    }

    bool CompleteFullChannelRecovery(uint64_t, cc::RecoveryAction, bool) override { return true; }
    void CompleteSingleWorkerRecovery(uint32_t, bool) override {}
    void NoteHealthy() override {}
    recovery::RecoverySnapshot GetSnapshot() const override { return {}; }
    void Reset() override {}

    bool WaitForExecution(std::chrono::milliseconds timeout)
    {
        std::unique_lock<std::mutex> lock(mu_);
        return cv_.wait_for(lock, timeout, [this] { return executed_; });
    }

    bool HasExpectedHarnessRecovery() const
    {
        std::lock_guard<std::mutex> lock(mu_);
        return observed_reason_ == cc::ChannelFaultReason::kWorkerHarnessFatal &&
               observed_source_ == cc::ChannelFaultSource::kChannelInternal &&
               executed_reason_ == cc::ChannelFaultReason::kWorkerHarnessFatal &&
               executed_action_ == cc::RecoveryAction::kRestartSingleWorker &&
               executed_worker_id_ == 0;
    }

    bool HasExpectedClassificationRecovery(cc::ChannelFaultReason reason) const
    {
        std::lock_guard<std::mutex> lock(mu_);
        return observed_reason_ == reason &&
               executed_reason_ == reason &&
               executed_action_ == cc::RecoveryAction::kRebootVm;
    }

    uint32_t ObservationCount() const
    {
        std::lock_guard<std::mutex> lock(mu_);
        return observation_count_;
    }

private:
    bool recover_harness_fatal_ = false;
    bool recover_classified_faults_ = true;
    bool abort_classified_without_recovery_ = false;
    std::vector<uint64_t> recovery_inflight_ids_;
    std::vector<uint64_t> recovery_inflight_idle_ids_;
    mutable std::mutex mu_;
    std::condition_variable cv_;
    bool executed_ = false;
    cc::ChannelFaultReason observed_reason_ = cc::ChannelFaultReason::kWorkerHeartbeatLost;
    cc::ChannelFaultSource observed_source_ = cc::ChannelFaultSource::kHealthMonitor;
    cc::ChannelFaultReason executed_reason_ = cc::ChannelFaultReason::kWorkerHeartbeatLost;
    cc::RecoveryAction executed_action_ = cc::RecoveryAction::kNone;
    uint32_t executed_worker_id_ = UINT32_MAX;
    uint32_t observation_count_ = 0;
};

struct ChannelHarness {
    ~ChannelHarness()
    {
        if (channel) channel->Close();
        if (!shm_path.empty()) ::unlink(shm_path.c_str());
    }

    std::string shm_path;
    std::shared_ptr<infra::ShmInfra> shm;
    factory::MockControlPlane* control = nullptr;
    BlockingTestDataPlane* dp = nullptr;
    ManualHealthMonitor* health = nullptr;
    TestRecovery* recovery = nullptr;
    evidence::ProgressClock* progress = nullptr;
    std::unique_ptr<ch::IChannel> channel;
};

struct ChannelHarnessOptions {
    bool recover_harness_fatal = false;
    bool recover_classified_faults = true;
    bool abort_classified_without_recovery = false;
    std::vector<uint64_t> recovery_inflight_ids;
    std::vector<uint64_t> recovery_inflight_idle_ids;
    uint32_t n_workers = 1;
    std::size_t crash_history_depth = 16;
    std::function<bool(const std::string&)> is_real_kernel_crash;
};

std::unique_ptr<ChannelHarness> MakeChannelHarness(
    uint32_t channel_id,
    ChannelHarnessOptions options = {})
{
    auto harness = std::make_unique<ChannelHarness>();
    harness->shm_path = TempPath("channel_shm");
    harness->shm = MakeShm(harness->shm_path, options.n_workers);
    if (!harness->shm) return nullptr;

    auto dp = std::make_unique<BlockingTestDataPlane>(options.n_workers);
    harness->dp = dp.get();
    auto hm = std::make_unique<ManualHealthMonitor>();
    harness->health = hm.get();
    auto recovery = std::make_unique<TestRecovery>(
        options.recover_harness_fatal,
        options.recover_classified_faults,
        options.abort_classified_without_recovery,
        options.recovery_inflight_ids,
        options.recovery_inflight_idle_ids);
    harness->recovery = recovery.get();
    auto control = std::make_unique<factory::MockControlPlane>(options.n_workers);
    harness->control = control.get();
    auto progress = std::make_unique<evidence::ProgressClock>();
    harness->progress = progress.get();

    ch::ChannelComponents components;
    components.shm = harness->shm;
    components.substrate = std::make_unique<HealthOrderedSubstrate>(hm.get());
    components.control = std::move(control);
    components.data = std::move(dp);
    components.console = std::make_unique<factory::NullConsoleSource>();
    components.health = std::move(hm);
    components.recovery = std::move(recovery);
    components.progress_clock = std::move(progress);
    components.channel_cfg.channel_id = channel_id;
    components.channel_cfg.n_workers = options.n_workers;
    components.channel_cfg.crash_history_depth = options.crash_history_depth;
    components.channel_cfg.backend_id = "wakeup_test";
    components.channel_cfg.loop_interval = std::chrono::milliseconds{100};
    components.channel_cfg.health_check_interval = std::chrono::seconds{10};
    components.channel_cfg.input_queue_capacity = 8;
    components.channel_cfg.is_real_kernel_crash =
        std::move(options.is_real_kernel_crash);

    auto built = ch::ChannelBuilder::Build(std::move(components));
    if (!built.ok()) {
        std::fprintf(stderr, "ChannelBuilder failed: %s\n", built.error().message.c_str());
        return nullptr;
    }

    std::unique_ptr<ch::Channel> concrete = std::move(built.value());
    harness->channel = std::move(concrete);
    auto boot = harness->channel->Boot();
    if (!boot.ok()) {
        std::fprintf(stderr, "Channel::Boot failed: %s\n", boot.error().message.c_str());
        return nullptr;
    }
    return harness;
}

std::unique_ptr<ChannelHarness> MakeChannelHarness(
    uint32_t channel_id,
    bool recover_harness_fatal)
{
    ChannelHarnessOptions options;
    options.recover_harness_fatal = recover_harness_fatal;
    return MakeChannelHarness(channel_id, std::move(options));
}

int TestPlainCompletionBoundedLatency()
{
    const std::string shm_path = TempPath("plain_shm");
    auto shm = MakeShm(shm_path);
    CHECK(shm != nullptr);

    auto dp = MakeIvshmemDp(shm, false);
    auto prepare = dp.Prepare();
    CHECK(prepare.ok());

    std::vector<data::DispatchOutcome> results;
    std::atomic<bool> polling{false};
    std::chrono::steady_clock::time_point completion_ts;
    std::chrono::steady_clock::time_point done_ts;

    std::thread poller([&] {
        polling.store(true, std::memory_order_release);
        dp.Poll(results, kPollTimeout);
        done_ts = std::chrono::steady_clock::now();
    });

    while (!polling.load(std::memory_order_acquire)) {
        std::this_thread::yield();
    }
    std::this_thread::sleep_for(std::chrono::milliseconds{5});
    completion_ts = std::chrono::steady_clock::now();
    PublishCompletion(shm, 11, 7, {1, 2, 3});

    poller.join();
    CHECK(results.size() == 1);
    CHECK(results[0].executor_id == 11);
    CHECK(results[0].dispatch_gen == 7);
    CHECK(results[0].output.size() == 3);
    CHECK(done_ts - completion_ts < kWakeBudget);

    dp.Close();
    ::unlink(shm_path.c_str());
    return 0;
}

int TestPlainPartialCompletionTranslates()
{
    const std::string shm_path = TempPath("plain_partial_shm");
    auto shm = MakeShm(shm_path);
    CHECK(shm != nullptr);

    auto dp = MakeIvshmemDp(shm, false);
    auto prepare = dp.Prepare();
    CHECK(prepare.ok());

    PublishCompletion(shm, 12, 8, {4, 5}, COMP_STATUS_PARTIAL);

    std::vector<data::DispatchOutcome> results;
    dp.Poll(results, std::chrono::milliseconds{10});
    CHECK(results.size() == 1);
    CHECK(results[0].kind == data::DispatchOutcomeKind::kPartial);
    CHECK(results[0].vendor_status == COMP_STATUS_PARTIAL);
    CHECK(results[0].executor_id == 12);
    CHECK(results[0].dispatch_gen == 8);
    CHECK(results[0].output.size() == 2);

    dp.Close();
    ::unlink(shm_path.c_str());
    return 0;
}

int TestPlainHostWakeInterruptsPoll()
{
    const std::string shm_path = TempPath("plain_wake_shm");
    auto shm = MakeShm(shm_path);
    CHECK(shm != nullptr);

    auto dp = MakeIvshmemDp(shm, false);
    auto prepare = dp.Prepare();
    CHECK(prepare.ok());

    std::vector<data::DispatchOutcome> results;
    std::atomic<bool> polling{false};
    std::chrono::steady_clock::time_point wake_ts;
    std::chrono::steady_clock::time_point done_ts;

    std::thread poller([&] {
        polling.store(true, std::memory_order_release);
        dp.Poll(results, kPollTimeout);
        done_ts = std::chrono::steady_clock::now();
    });

    while (!polling.load(std::memory_order_acquire)) {
        std::this_thread::yield();
    }
    std::this_thread::sleep_for(std::chrono::milliseconds{5});
    wake_ts = std::chrono::steady_clock::now();
    dp.WakePoller();

    poller.join();
    CHECK(results.empty());
    CHECK(done_ts - wake_ts < kWakeBudget);

    dp.Close();
    ::unlink(shm_path.c_str());
    return 0;
}

int TestDoorbellCompletionFdInterruptsPoll()
{
    const std::string shm_path = TempPath("doorbell_shm");
    const std::string socket_path = TempPath("doorbell_sock");
    auto shm = MakeShm(shm_path);
    CHECK(shm != nullptr);

    auto dp = MakeIvshmemDp(shm, true, socket_path);
    auto start = dp.StartServer();
    CHECK(start.ok());

    std::promise<int> vm_fd_promise;
    auto vm_fd_future = vm_fd_promise.get_future();
    std::promise<bool> qemu_ready_promise;
    auto qemu_ready_future = qemu_ready_promise.get_future();
    std::atomic<bool> qemu_done{false};

    std::thread qemu_peer([&] {
        int sock = -1;
        if (!ConnectUnixWithRetry(socket_path, &sock)) {
            qemu_ready_promise.set_value(false);
            vm_fd_promise.set_value(-1);
            return;
        }
        for (int i = 0; i < 3; ++i) {
            MsgWithFd msg = RecvMsgWithFd(sock);
            if (msg.fd >= 0) ::close(msg.fd);
            if (msg.fd == -2) {
                qemu_ready_promise.set_value(false);
                vm_fd_promise.set_value(-1);
                ::close(sock);
                return;
            }
        }
        qemu_ready_promise.set_value(true);
        MsgWithFd peer_join = RecvMsgWithFd(sock);
        vm_fd_promise.set_value(peer_join.fd);
        while (!qemu_done.load(std::memory_order_acquire)) {
            std::this_thread::sleep_for(std::chrono::milliseconds{5});
        }
        ::close(sock);
    });
    struct DoorbellCleanup {
        std::atomic<bool>* done = nullptr;
        std::thread* peer = nullptr;
        data::IvshmemDataPlane* dp = nullptr;
        ~DoorbellCleanup()
        {
            if (done) done->store(true, std::memory_order_release);
            if (dp) dp->Close();
            if (peer && peer->joinable()) peer->join();
        }
    } cleanup{&qemu_done, &qemu_peer, &dp};

    CHECK(qemu_ready_future.wait_for(std::chrono::seconds{1}) == std::future_status::ready);
    CHECK(qemu_ready_future.get());

    auto prepare = dp.Prepare();
    if (!prepare.ok()) {
        std::fprintf(stderr, "doorbell Prepare failed: %s\n", prepare.error().message.c_str());
    }
    CHECK(prepare.ok());
    CHECK(vm_fd_future.wait_for(std::chrono::seconds{1}) == std::future_status::ready);
    int vm_fd = vm_fd_future.get();
    CHECK(vm_fd >= 0);

    std::vector<data::DispatchOutcome> results;
    std::atomic<bool> polling{false};
    std::chrono::steady_clock::time_point completion_ts;
    std::chrono::steady_clock::time_point done_ts;

    std::thread poller([&] {
        polling.store(true, std::memory_order_release);
        dp.Poll(results, kPollTimeout);
        done_ts = std::chrono::steady_clock::now();
    });

    while (!polling.load(std::memory_order_acquire)) {
        std::this_thread::yield();
    }
    std::this_thread::sleep_for(std::chrono::milliseconds{5});
    completion_ts = std::chrono::steady_clock::now();
    PublishCompletion(shm, 21, 9, {4, 5});
    const uint64_t one = 1;
    CHECK(::write(vm_fd, &one, sizeof(one)) == static_cast<ssize_t>(sizeof(one)));

    poller.join();
    CHECK(results.size() == 1);
    CHECK(results[0].executor_id == 21);
    CHECK(results[0].dispatch_gen == 9);
    CHECK(done_ts - completion_ts < kWakeBudget);

    ::close(vm_fd);
    qemu_done.store(true, std::memory_order_release);
    ::unlink(shm_path.c_str());
    ::unlink(socket_path.c_str());
    return 0;
}

int TestChannelSubmitWakesDataPlanePoll()
{
    auto harness = MakeChannelHarness(100);
    CHECK(harness != nullptr);

    std::this_thread::sleep_for(std::chrono::milliseconds{10});

    cc::ChannelDispatchRequest req;
    req.executor_id = 101;
    req.seed_id = 1;
    req.payload = {1};

    const auto submit_ts = std::chrono::steady_clock::now();
    auto submit = harness->channel->Submit(req, std::chrono::microseconds{0});
    CHECK(submit.status == cc::ChannelSubmitStatus::kAccepted);
    CHECK(harness->dp->WaitForSubmits(1, std::chrono::milliseconds{200}));
    const auto sent_ts = std::chrono::steady_clock::now();
    CHECK(sent_ts - submit_ts < kWakeBudget);

    harness->channel->Close();
    return 0;
}

int TestChannelCompletionWakesAndQueuesEvent()
{
    auto harness = MakeChannelHarness(101);
    CHECK(harness != nullptr);

    cc::ChannelDispatchRequest req;
    req.executor_id = 202;
    req.seed_id = 2;
    req.payload = {2};
    req.trace.sampled = true;

    auto submit = harness->channel->Submit(req, std::chrono::microseconds{0});
    CHECK(submit.status == cc::ChannelSubmitStatus::kAccepted);
    CHECK(harness->dp->WaitForSubmits(1, std::chrono::milliseconds{200}));

    const auto completion_ts = std::chrono::steady_clock::now();
    harness->dp->CompleteLast({8, 9});

    ch::EventList events;
    CHECK(harness->channel->DrainEvents(events, std::chrono::milliseconds{200}));
    const auto event_ts = std::chrono::steady_clock::now();

    CHECK(events.size() == 1);
    CHECK(events[0].kind == cc::ChannelEvent::Kind::kCompletion);
    const auto* completion = events[0].AsCompletion();
    CHECK(completion != nullptr);
    CHECK(completion->kind == cc::CompletionKind::kNormal);
    CHECK(completion->ctx.executor_id == 202);
    CHECK(completion->output.size() == 2);
    CHECK(completion->ctx.trace.channel_event_queued_ts_us != 0);
    CHECK(event_ts - completion_ts < kWakeBudget);

    harness->channel->Close();
    return 0;
}

int TestChannelPartialCompletionWakesAndQueuesEvent()
{
    auto harness = MakeChannelHarness(103);
    CHECK(harness != nullptr);

    cc::ChannelDispatchRequest req;
    req.executor_id = 303;
    req.seed_id = 3;
    req.payload = {3};

    auto submit = harness->channel->Submit(req, std::chrono::microseconds{0});
    CHECK(submit.status == cc::ChannelSubmitStatus::kAccepted);
    CHECK(harness->dp->WaitForSubmits(1, std::chrono::milliseconds{200}));

    harness->dp->CompleteLast({6, 7}, data::DispatchOutcomeKind::kPartial);

    ch::EventList events;
    CHECK(harness->channel->DrainEvents(events, std::chrono::milliseconds{200}));

    CHECK(events.size() == 1);
    CHECK(events[0].kind == cc::ChannelEvent::Kind::kCompletion);
    const auto* completion = events[0].AsCompletion();
    CHECK(completion != nullptr);
    CHECK(completion->kind == cc::CompletionKind::kPartial);
    CHECK(completion->ctx.executor_id == 303);
    CHECK(completion->output.size() == 2);

    harness->channel->Close();
    return 0;
}

int TestChannelHealthWakesAndQueuesFault()
{
    auto harness = MakeChannelHarness(102);
    CHECK(harness != nullptr);

    std::this_thread::sleep_for(std::chrono::milliseconds{10});
    const auto health_ts = std::chrono::steady_clock::now();
    harness->health->PublishWorkerDead();

    ch::EventList events;
    CHECK(harness->channel->DrainEvents(events, std::chrono::milliseconds{200}));
    const auto event_ts = std::chrono::steady_clock::now();

    CHECK(events.size() == 1);
    CHECK(events[0].kind == cc::ChannelEvent::Kind::kFault);
    CHECK(event_ts - health_ts < kWakeBudget);

    harness->channel->Close();
    return 0;
}

int TestHarnessFatalTriggersConfirmedWorkerRecovery()
{
    auto harness = MakeChannelHarness(104, true);
    CHECK(harness != nullptr);

    cc::ChannelDispatchRequest req;
    req.executor_id = 404;
    req.seed_id = 4;
    req.payload = {4};

    auto submit = harness->channel->Submit(req, std::chrono::microseconds{0});
    CHECK(submit.status == cc::ChannelSubmitStatus::kAccepted);
    CHECK(harness->dp->WaitForSubmits(1, std::chrono::milliseconds{200}));

    harness->dp->CompleteLast({}, data::DispatchOutcomeKind::kHarnessFatal);
    CHECK(harness->recovery->WaitForExecution(std::chrono::milliseconds{200}));
    CHECK(harness->recovery->HasExpectedHarnessRecovery());

    ch::EventList events;
    CHECK(harness->channel->DrainEvents(events, std::chrono::milliseconds{200}));

    bool saw_fatal_completion = false;
    bool saw_internal_fault = false;
    for (const auto& event : events) {
        if (const auto* abnormal = event.AsAbnormal(); abnormal != nullptr) {
            saw_fatal_completion =
                saw_fatal_completion ||
                abnormal->kind == cc::AbnormalKind::kHarnessFatal;
        }
        if (const auto* fault = event.AsFault(); fault != nullptr) {
            saw_internal_fault =
                saw_internal_fault ||
                (fault->kind == cc::FaultKind::kWorkerDead &&
                 fault->origin == cc::FaultOrigin::kChannelInternal);
        }
    }
    CHECK(saw_fatal_completion);
    CHECK(saw_internal_fault);

    harness->channel->Close();
    return 0;
}

int TestReplacementStartFailureLatchRestartsWorker()
{
    auto harness = MakeChannelHarness(105, true);
    CHECK(harness != nullptr);
    CHECK(harness->control != nullptr);

    harness->control->LatchWorkerErrorForTest(
        0, ERR_DOMAIN_REPLACEMENT_START_FAILED);
    harness->dp->WakePoller();
    CHECK(harness->recovery->WaitForExecution(std::chrono::milliseconds{200}));
    CHECK(harness->recovery->HasExpectedHarnessRecovery());

    ch::EventList events;
    CHECK(harness->channel->DrainEvents(events, std::chrono::milliseconds{200}));

    bool saw_internal_fault = false;
    for (const auto& event : events) {
        CHECK(event.AsAbnormal() == nullptr);
        if (const auto* fault = event.AsFault(); fault != nullptr) {
            saw_internal_fault =
                saw_internal_fault ||
                (fault->kind == cc::FaultKind::kWorkerDead &&
                 fault->origin == cc::FaultOrigin::kChannelInternal);
        }
    }
    CHECK(saw_internal_fault);
    CHECK(harness->control->WorkerErrorValueForTest(0) == ERR_OK);
    CHECK(harness->control->WorkerErrorConsumeCountForTest(0) == 1);

    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    CHECK(harness->control->WorkerErrorConsumeCountForTest(0) == 1);
    CHECK(harness->recovery->ObservationCount() == 1);

    harness->channel->Close();
    return 0;
}

int TestOwnershipUnreclaimedEscalatesToVmRecovery()
{
    auto harness = MakeChannelHarness(106);
    CHECK(harness != nullptr);

    cc::ChannelDispatchRequest req;
    req.executor_id = 406;
    req.seed_id = 6;
    req.payload = {6};

    auto submit = harness->channel->Submit(req, std::chrono::microseconds{0});
    CHECK(submit.status == cc::ChannelSubmitStatus::kAccepted);
    CHECK(harness->dp->WaitForSubmits(1, std::chrono::milliseconds{200}));

    harness->dp->CompleteLast(
        {}, data::DispatchOutcomeKind::kHarnessFatal,
        ERR_DOMAIN_OWNERSHIP_UNRECLAIMED);

    ch::EventList events;
    CHECK(DrainEventsCollect(harness->channel.get(), events, 2,
                             std::chrono::milliseconds{300}));
    const auto* abnormal = events[0].AsAbnormal();
    CHECK(abnormal != nullptr);
    CHECK(abnormal->kind == cc::AbnormalKind::kHarnessFatal);
    CHECK(abnormal->ctx.executor_id == 406);
    CHECK(abnormal->ctx.seed_id == 6);
    CHECK(abnormal->diagnostics.error_code == ERR_DOMAIN_OWNERSHIP_UNRECLAIMED);

    bool saw_internal_fault = false;
    for (const auto& event : events) {
        if (const auto* fault = event.AsFault(); fault != nullptr) {
            saw_internal_fault =
                saw_internal_fault ||
                (fault->kind == cc::FaultKind::kWorkerDead &&
                 fault->origin == cc::FaultOrigin::kChannelInternal);
        }
    }
    CHECK(saw_internal_fault);
    CHECK(harness->recovery->WaitForExecution(std::chrono::milliseconds{200}));
    // 15 = 旧域未证明隔离：必须升级 VM reboot（kExecutionDomainHung），
    // 不能走单 worker restart（kWorkerHarnessFatal）。
    CHECK(harness->recovery->HasExpectedClassificationRecovery(
        cc::ChannelFaultReason::kExecutionDomainHung));

    harness->channel->Close();
    return 0;
}

int TestHangPoolHarvestedOnKernelCrash()
{
    auto benign_checks = std::make_shared<std::atomic<uint32_t>>(0);
    ChannelHarnessOptions options;
    options.is_real_kernel_crash = [benign_checks](const std::string&) {
        return benign_checks->fetch_add(1) == 0;
    };
    auto harness = MakeChannelHarness(108, std::move(options));
    CHECK(harness != nullptr);

    cc::ChannelDispatchRequest req;
    req.executor_id = 408;
    req.seed_id = 8;
    req.origin_seed_id = 80;
    req.payload = {8, 0};

    CHECK(harness->channel->Submit(req, std::chrono::microseconds{0}).status ==
          cc::ChannelSubmitStatus::kAccepted);
    CHECK(harness->dp->WaitForSubmits(1, std::chrono::milliseconds{200}));
    harness->dp->CompleteLast({}, data::DispatchOutcomeKind::kTimeout,
                              ERR_DOMAIN_WATCHDOG_TIMEOUT);

    // The task settles immediately as a hang; no retained cohort holds it.
    // 防御性 error 15 的结算+进池由 TestHangKindEntersHangPool 覆盖；这里用
    // error 11，避免 15 附带触发 VM reboot 干扰收获断言。
    ch::EventList settled;
    CHECK(DrainEventsCollect(harness->channel.get(), settled, 1,
                             std::chrono::milliseconds{300}));
    const auto* hang = settled[0].AsAbnormal();
    CHECK(hang != nullptr);
    CHECK(hang->kind == cc::AbnormalKind::kHang);
    CHECK(hang->ctx.executor_id == 408);

    // Later kernel hung-task evidence harvests the whole hang pool.
    harness->health->PublishKernelCrash(
        "INFO: task syz-executor blocked for more than 120 seconds");

    CHECK(harness->recovery->WaitForExecution(std::chrono::milliseconds{300}));
    CHECK(harness->recovery->HasExpectedClassificationRecovery(
        cc::ChannelFaultReason::kKernelCrash));
    CHECK(benign_checks->load() == 1);

    ch::EventList events;
    CHECK(harness->channel->DrainEvents(events, std::chrono::milliseconds{200}));
    CHECK(events.size() == 1);
    const auto* fault = events[0].AsFault();
    CHECK(fault != nullptr);
    CHECK(fault->kind == cc::FaultKind::kKernelCrash);
    CHECK(fault->origin == cc::FaultOrigin::kSerialPattern);
    CHECK(fault->scene.candidate_window.back().executor_id == 408);

    harness->channel->Close();
    return 0;
}

int TestHangSettlementKeepsWorkersFlowing()
{
    ChannelHarnessOptions options;
    options.n_workers = 4;
    auto harness = MakeChannelHarness(109, std::move(options));
    CHECK(harness != nullptr);

    auto submit_to = [&](uint64_t executor_id, uint32_t worker_id, uint8_t payload) {
        cc::ChannelDispatchRequest req;
        req.executor_id = executor_id;
        req.seed_id = executor_id + 1000;
        req.origin_seed_id = executor_id + 2000;
        req.target_worker_id = worker_id;
        req.payload = {payload};
        return harness->channel->Submit(req, std::chrono::microseconds{0}).status;
    };

    CHECK(submit_to(501, 0, 1) == cc::ChannelSubmitStatus::kAccepted);
    CHECK(submit_to(502, 1, 2) == cc::ChannelSubmitStatus::kAccepted);
    CHECK(harness->dp->WaitForSubmits(2, std::chrono::milliseconds{200}));
    harness->dp->Complete(501, {}, data::DispatchOutcomeKind::kTimeout,
                          ERR_DOMAIN_WATCHDOG_TIMEOUT);
    harness->dp->Complete(502, {}, data::DispatchOutcomeKind::kTimeout,
                          ERR_DOMAIN_WATCHDOG_TIMEOUT);

    // Hangs settle immediately and the workers stay usable.
    CHECK(submit_to(503, 2, 3) == cc::ChannelSubmitStatus::kAccepted);
    CHECK(harness->dp->WaitForSubmits(3, std::chrono::milliseconds{200}));
    CHECK(harness->dp->WasSubmitted(503, 2));
    harness->dp->Complete(503, {3});

    CHECK(submit_to(504, 3, 4) == cc::ChannelSubmitStatus::kAccepted);
    CHECK(harness->dp->WaitForSubmits(4, std::chrono::milliseconds{200}));
    CHECK(harness->dp->WasSubmitted(504, 3));

    ch::EventList early;
    CHECK(DrainEventsCollect(harness->channel.get(), early, 3,
                             std::chrono::milliseconds{300}));
    CHECK(early[0].AsAbnormal() != nullptr);
    CHECK(early[0].AsAbnormal()->kind == cc::AbnormalKind::kHang);
    CHECK(early[0].AsAbnormal()->ctx.executor_id == 501);
    CHECK(early[1].AsAbnormal() != nullptr);
    CHECK(early[1].AsAbnormal()->kind == cc::AbnormalKind::kHang);
    CHECK(early[1].AsAbnormal()->ctx.executor_id == 502);
    CHECK(early[2].IsCompletion());
    CHECK(early[2].AsCompletion()->ctx.executor_id == 503);

    // Kernel hang evidence harvests the whole pool: hung 501/502 + completed
    // 503 (Layer-2 history) plus in-flight 504 (Layer-1).
    harness->health->PublishKernelCrash(
        "INFO: task syz.1 blocked for more than 120 seconds");
    CHECK(harness->recovery->WaitForExecution(std::chrono::milliseconds{300}));

    ch::EventList events;
    CHECK(DrainEventsCollect(harness->channel.get(), events, 2,
                             std::chrono::milliseconds{300}));
    const auto* fault = events[0].AsFault();
    CHECK(fault != nullptr);
    CHECK(fault->kind == cc::FaultKind::kKernelCrash);
    CHECK(fault->scene.candidate_window.back().executor_id == 504);
    std::unordered_set<uint64_t> ids;
    for (const auto& candidate : fault->scene.candidate_window) {
        ids.insert(candidate.executor_id);
    }
    CHECK(ids.count(501) == 1);
    CHECK(ids.count(502) == 1);
    CHECK(ids.count(503) == 1);
    const auto* pending = events[1].AsAbnormal();
    CHECK(pending != nullptr && pending->kind == cc::AbnormalKind::kWorkerCrashed);
    CHECK(pending->ctx.executor_id == 504);

    harness->channel->Close();
    return 0;
}

int TestBenignKernelEventSuppressedImmediately()
{
    ChannelHarnessOptions options;
    options.is_real_kernel_crash = [](const std::string&) { return false; };
    auto harness = MakeChannelHarness(111, std::move(options));
    CHECK(harness != nullptr);

    cc::ChannelDispatchRequest req;
    req.executor_id = 511;
    req.seed_id = 11;
    req.payload = {11};
    CHECK(harness->channel->Submit(req, std::chrono::microseconds{0}).status ==
          cc::ChannelSubmitStatus::kAccepted);
    CHECK(harness->dp->WaitForSubmits(1, std::chrono::milliseconds{200}));
    harness->dp->CompleteLast({}, data::DispatchOutcomeKind::kTimeout,
                              ERR_DOMAIN_WATCHDOG_TIMEOUT);

    // The hang settles immediately（error 11 不附带恢复）。
    ch::EventList settled;
    CHECK(DrainEventsCollect(harness->channel.get(), settled, 1,
                             std::chrono::milliseconds{300}));
    CHECK(settled[0].AsAbnormal() != nullptr);
    CHECK(settled[0].AsAbnormal()->kind == cc::AbnormalKind::kHang);

    // Benign kernel text is dropped immediately: no fault, no recovery, and
    // (without retained) no later NoOutput synthesis.
    harness->health->PublishKernelCrash("benign warning text");
    ch::EventList events;
    CHECK(!harness->channel->DrainEvents(events, std::chrono::milliseconds{60}));
    CHECK(events.empty());
    CHECK(harness->recovery->ObservationCount() == 0);

    harness->channel->Close();
    return 0;
}

int TestWatchdogHangSettlesWithoutRetained()
{
    auto harness = MakeChannelHarness(107);
    CHECK(harness != nullptr);
    CHECK(harness->progress != nullptr);

    cc::ChannelDispatchRequest req;
    req.executor_id = 407;
    req.seed_id = 7;
    req.payload = {7};

    auto submit = harness->channel->Submit(req, std::chrono::microseconds{0});
    CHECK(submit.status == cc::ChannelSubmitStatus::kAccepted);
    CHECK(harness->dp->WaitForSubmits(1, std::chrono::milliseconds{200}));

    const uint64_t progress_before = harness->progress->LastUs();
    std::this_thread::sleep_for(std::chrono::milliseconds{2});
    harness->dp->CompleteLast(
        {}, data::DispatchOutcomeKind::kTimeout,
        ERR_DOMAIN_WATCHDOG_TIMEOUT);

    ch::EventList events;
    CHECK(harness->channel->DrainEvents(events, std::chrono::milliseconds{200}));
    CHECK(events.size() == 1);
    const auto* hang = events[0].AsAbnormal();
    CHECK(hang != nullptr);
    CHECK(hang->kind == cc::AbnormalKind::kHang);
    CHECK(hang->diagnostics.error_code == ERR_DOMAIN_WATCHDOG_TIMEOUT);
    CHECK(hang->ctx.executor_id == req.executor_id);
    CHECK(harness->progress->LastUs() > progress_before);

    // No time window exists anymore: error 11 is a settled task hang and must
    // not start recovery by itself.
    CHECK(!harness->recovery->WaitForExecution(std::chrono::milliseconds{80}));
    CHECK(harness->recovery->ObservationCount() == 0);

    harness->channel->Close();
    return 0;
}

int TestHostSynthesizedCancelDoesNotNoteProgress()
{
    ChannelHarnessOptions options;
    options.abort_classified_without_recovery = true;
    auto harness = MakeChannelHarness(112, std::move(options));
    CHECK(harness != nullptr);
    CHECK(harness->progress != nullptr);

    // Guest terminal (hang) advances the progress clock.
    cc::ChannelDispatchRequest req;
    req.executor_id = 512;
    req.seed_id = 12;
    req.payload = {12};
    CHECK(harness->channel->Submit(req, std::chrono::microseconds{0}).status ==
          cc::ChannelSubmitStatus::kAccepted);
    CHECK(harness->dp->WaitForSubmits(1, std::chrono::milliseconds{200}));

    const uint64_t progress_before = harness->progress->LastUs();
    std::this_thread::sleep_for(std::chrono::milliseconds{2});
    harness->dp->CompleteLast({}, data::DispatchOutcomeKind::kTimeout,
                              ERR_DOMAIN_WATCHDOG_TIMEOUT);

    const auto progress_deadline = std::chrono::steady_clock::now() +
        std::chrono::milliseconds{200};
    while (harness->progress->LastUs() <= progress_before &&
           std::chrono::steady_clock::now() < progress_deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds{1});
    }
    CHECK(harness->progress->LastUs() > progress_before);
    const uint64_t guest_terminal_progress = harness->progress->LastUs();

    ch::EventList settled;
    CHECK(harness->channel->DrainEvents(settled, std::chrono::milliseconds{200}));
    CHECK(settled.size() == 1);
    CHECK(settled[0].AsAbnormal() != nullptr);
    CHECK(settled[0].AsAbnormal()->kind == cc::AbnormalKind::kHang);

    // An in-flight task aborted by a host-side kernel crash is host-synthesized
    // and must not advance the clock.
    cc::ChannelDispatchRequest req_b;
    req_b.executor_id = 513;
    req_b.seed_id = 13;
    req_b.payload = {13};
    CHECK(harness->channel->Submit(req_b, std::chrono::microseconds{0}).status ==
          cc::ChannelSubmitStatus::kAccepted);
    CHECK(harness->dp->WaitForSubmits(2, std::chrono::milliseconds{200}));
    CHECK(harness->dp->WasSubmitted(513, 0));

    harness->health->PublishKernelCrash("real kernel crash");
    ch::EventList events;
    CHECK(DrainEventsCollect(harness->channel.get(), events, 2,
                             std::chrono::milliseconds{300}));
    CHECK(events[0].AsFault() != nullptr);
    const auto* cancelled = events[1].AsAbnormal();
    CHECK(cancelled != nullptr);
    CHECK(cancelled->kind == cc::AbnormalKind::kWorkerCrashed);
    CHECK(cancelled->ctx.executor_id == 513);
    CHECK(harness->progress->LastUs() == guest_terminal_progress);
    CHECK(!harness->recovery->WaitForExecution(std::chrono::milliseconds{50}));

    harness->channel->Close();
    return 0;
}

int TestForwardProgressFrozenClassifiedAsNoOutput()
{
    auto harness = MakeChannelHarness(113);
    CHECK(harness != nullptr);

    // VmAliveSensor 的聚合冻结事件（kNoOutput + inferred）必须被 Channel 映射
    // 成 FaultKind::kNoOutput / reason kNoOutput，而不是 kVmDead。
    harness->health->PublishNoOutput();

    ch::EventList events;
    CHECK(DrainEventsCollect(harness->channel.get(), events, 1,
                             std::chrono::milliseconds{300}));
    const auto* fault = events[0].AsFault();
    CHECK(fault != nullptr);
    CHECK(fault->kind == cc::FaultKind::kNoOutput);
    CHECK(harness->recovery->HasExpectedClassificationRecovery(
        cc::ChannelFaultReason::kNoOutput));

    harness->channel->Close();
    return 0;
}

int TestProgramTimeoutNotInHangPool()
{
    // ring depth=2：program timeout 是数据有效的普通完成，只能进 evictable
    // per-worker ring；如果被误放进永久 hang 池，3 条都会出现在收获候选里。
    ChannelHarnessOptions options;
    options.n_workers = 1;
    options.crash_history_depth = 2;
    auto harness = MakeChannelHarness(114, std::move(options));
    CHECK(harness != nullptr);

    auto submit_to = [&](uint64_t executor_id, uint8_t payload) {
        cc::ChannelDispatchRequest req;
        req.executor_id = executor_id;
        req.seed_id = executor_id + 1000;
        req.origin_seed_id = executor_id + 2000;
        req.payload = {payload};
        return harness->channel->Submit(req, std::chrono::microseconds{0}).status;
    };

    CHECK(submit_to(601, 1) == cc::ChannelSubmitStatus::kAccepted);
    CHECK(harness->dp->WaitForSubmits(1, std::chrono::milliseconds{200}));
    harness->dp->CompleteLast({}, data::DispatchOutcomeKind::kTimeout, ERR_TIMEOUT);
    CHECK(submit_to(602, 2) == cc::ChannelSubmitStatus::kAccepted);
    CHECK(harness->dp->WaitForSubmits(2, std::chrono::milliseconds{200}));
    harness->dp->CompleteLast({}, data::DispatchOutcomeKind::kTimeout, ERR_TIMEOUT);
    CHECK(submit_to(603, 3) == cc::ChannelSubmitStatus::kAccepted);
    CHECK(harness->dp->WaitForSubmits(3, std::chrono::milliseconds{200}));
    harness->dp->CompleteLast({}, data::DispatchOutcomeKind::kTimeout, ERR_TIMEOUT);

    ch::EventList settled;
    CHECK(DrainEventsCollect(harness->channel.get(), settled, 3,
                             std::chrono::milliseconds{300}));
    for (const auto& evt : settled) {
        const auto* comp = evt.AsCompletion();
        CHECK(comp != nullptr);
        CHECK(comp->kind == cc::CompletionKind::kTimeout);
    }

    // 内核 hung 证据收获：per-worker ring 只有最近 2 条（602/603），601 已被
    // 逐出；若 601 仍在候选窗口，说明它被错误放进了永久 hang 池。
    harness->health->PublishKernelCrash(
        "INFO: task syz.1 blocked for more than 120 seconds");
    CHECK(harness->recovery->WaitForExecution(std::chrono::milliseconds{300}));

    ch::EventList events;
    CHECK(DrainEventsCollect(harness->channel.get(), events, 1,
                             std::chrono::milliseconds{300}));
    const auto* fault = events[0].AsFault();
    CHECK(fault != nullptr);
    CHECK(fault->kind == cc::FaultKind::kKernelCrash);
    std::unordered_set<uint64_t> ids;
    for (const auto& candidate : fault->scene.candidate_window) {
        ids.insert(candidate.executor_id);
    }
    CHECK(ids.size() == 2);
    CHECK(ids.count(602) == 1);
    CHECK(ids.count(603) == 1);
    CHECK(ids.count(601) == 0);

    harness->channel->Close();
    return 0;
}

int TestHangKindEntersHangPool()
{
    // ring depth=2：三条 worker 显式判定的 HUNG（kHang）必须全部进入永久
    // hang 池，收获时 3 条都在候选窗口（不受 ring evict 限制）。
    ChannelHarnessOptions options;
    options.n_workers = 1;
    options.crash_history_depth = 2;
    auto harness = MakeChannelHarness(115, std::move(options));
    CHECK(harness != nullptr);

    auto submit_to = [&](uint64_t executor_id, uint8_t payload) {
        cc::ChannelDispatchRequest req;
        req.executor_id = executor_id;
        req.seed_id = executor_id + 1000;
        req.origin_seed_id = executor_id + 2000;
        req.payload = {payload};
        return harness->channel->Submit(req, std::chrono::microseconds{0}).status;
    };

    CHECK(submit_to(701, 1) == cc::ChannelSubmitStatus::kAccepted);
    CHECK(harness->dp->WaitForSubmits(1, std::chrono::milliseconds{200}));
    harness->dp->CompleteLast({}, data::DispatchOutcomeKind::kHang,
                              ERR_DOMAIN_WATCHDOG_TIMEOUT);
    CHECK(submit_to(702, 2) == cc::ChannelSubmitStatus::kAccepted);
    CHECK(harness->dp->WaitForSubmits(2, std::chrono::milliseconds{200}));
    harness->dp->CompleteLast({}, data::DispatchOutcomeKind::kHang,
                              ERR_HARNESS_MAIN_REAP_FAILED);
    CHECK(submit_to(703, 3) == cc::ChannelSubmitStatus::kAccepted);
    CHECK(harness->dp->WaitForSubmits(3, std::chrono::milliseconds{200}));
    harness->dp->CompleteLast({}, data::DispatchOutcomeKind::kHang,
                              ERR_HARNESS_MAIN_REAP_FAILED);

    // 三条 kHang（11/8/8）都只结算，不触发恢复；error 15 的恢复语义（→ VM
    // reboot，pool 随 reboot 重置）由 TestOwnershipUnreclaimedEscalatesToVmRecovery
    // 覆盖。
    ch::EventList settled;
    CHECK(DrainEventsCollect(harness->channel.get(), settled, 3,
                             std::chrono::milliseconds{300}));
    std::size_t hang_count = 0;
    for (const auto& evt : settled) {
        const auto* abnormal = evt.AsAbnormal();
        if (abnormal != nullptr) {
            CHECK(abnormal->kind == cc::AbnormalKind::kHang);
            ++hang_count;
        }
    }
    CHECK(hang_count == 3);

    harness->health->PublishKernelCrash(
        "INFO: task syz.1 blocked for more than 120 seconds");
    CHECK(harness->recovery->WaitForExecution(std::chrono::milliseconds{300}));

    ch::EventList events;
    CHECK(DrainEventsCollect(harness->channel.get(), events, 1,
                             std::chrono::milliseconds{300}));
    const auto* fault = events[0].AsFault();
    CHECK(fault != nullptr);
    CHECK(fault->kind == cc::FaultKind::kKernelCrash);
    std::unordered_set<uint64_t> ids;
    for (const auto& candidate : fault->scene.candidate_window) {
        ids.insert(candidate.executor_id);
    }
    CHECK(ids.size() == 3);
    CHECK(ids.count(701) == 1);
    CHECK(ids.count(702) == 1);
    CHECK(ids.count(703) == 1);

    harness->channel->Close();
    return 0;
}

int TestHarnessFatalInfraNotInHangPool()
{
    // HARNESS_FATAL = infra（程序从未执行 / 已证明退出）：即使带 error 15
    // （rebind/未执行路径），也只能进 evictable per-worker ring（depth=2 只留
    // 最近 2 条），绝不能因 error 15 被丢进永久 hang 池。recover_classified_faults
    // 关闭，避免 15 → kExecutionDomainHung 的 mock reboot 把池 Reset 掉。
    ChannelHarnessOptions options;
    options.n_workers = 1;
    options.crash_history_depth = 2;
    options.recover_classified_faults = false;
    auto harness = MakeChannelHarness(116, std::move(options));
    CHECK(harness != nullptr);

    auto submit_to = [&](uint64_t executor_id, uint8_t payload) {
        cc::ChannelDispatchRequest req;
        req.executor_id = executor_id;
        req.seed_id = executor_id + 1000;
        req.origin_seed_id = executor_id + 2000;
        req.payload = {payload};
        return harness->channel->Submit(req, std::chrono::microseconds{0}).status;
    };

    CHECK(submit_to(711, 1) == cc::ChannelSubmitStatus::kAccepted);
    CHECK(harness->dp->WaitForSubmits(1, std::chrono::milliseconds{200}));
    harness->dp->CompleteLast({}, data::DispatchOutcomeKind::kHarnessFatal,
                              ERR_DOMAIN_OWNERSHIP_UNRECLAIMED);
    CHECK(submit_to(712, 2) == cc::ChannelSubmitStatus::kAccepted);
    CHECK(harness->dp->WaitForSubmits(2, std::chrono::milliseconds{200}));
    harness->dp->CompleteLast({}, data::DispatchOutcomeKind::kHarnessFatal,
                              ERR_DOMAIN_OWNERSHIP_UNRECLAIMED);
    CHECK(submit_to(713, 3) == cc::ChannelSubmitStatus::kAccepted);
    CHECK(harness->dp->WaitForSubmits(3, std::chrono::milliseconds{200}));
    harness->dp->CompleteLast({}, data::DispatchOutcomeKind::kHarnessFatal,
                              ERR_DOMAIN_OWNERSHIP_UNRECLAIMED);

    // 每条 kHarnessFatal 都结算为 abnormal + 内部恢复 fault：共 6 个事件。
    ch::EventList settled;
    CHECK(DrainEventsCollect(harness->channel.get(), settled, 6,
                             std::chrono::milliseconds{300}));
    std::size_t harness_fatal_count = 0;
    std::size_t fault_count = 0;
    for (const auto& evt : settled) {
        if (const auto* abnormal = evt.AsAbnormal(); abnormal != nullptr) {
            CHECK(abnormal->kind == cc::AbnormalKind::kHarnessFatal);
            ++harness_fatal_count;
        } else if (evt.AsFault() != nullptr) {
            ++fault_count;
        }
    }
    CHECK(harness_fatal_count == 3);
    CHECK(fault_count == 3);

    harness->health->PublishKernelCrash(
        "INFO: task syz.1 blocked for more than 120 seconds");

    ch::EventList events;
    CHECK(DrainEventsCollect(harness->channel.get(), events, 1,
                             std::chrono::milliseconds{300}));
    const auto* fault = events[0].AsFault();
    CHECK(fault != nullptr);
    CHECK(fault->kind == cc::FaultKind::kKernelCrash);
    std::unordered_set<uint64_t> ids;
    for (const auto& candidate : fault->scene.candidate_window) {
        ids.insert(candidate.executor_id);
    }
    CHECK(ids.size() == 2);
    CHECK(ids.count(712) == 1);
    CHECK(ids.count(713) == 1);
    CHECK(ids.count(711) == 0);

    harness->channel->Close();
    return 0;
}

int TestRebootInflightTerminalNotDuplicated()
{
    // Regression: kKernelCrash → kRebootVm 先经 AbortPendingByScope(kChannel)
    // 结算全部 in-flight 任务，恢复成功后又按 RecoveryResult.inflight_executor_ids
    // 补发一轮 abnormal。旧实现同一 executor_id 会出两个 abnormal 终态，导致
    // run_summary 的 terminal > generated + reexec 不变量在每次 reboot 后多出
    // in-flight 条数。现在恢复结果回填只对仍 pending 的任务生效，重复的必须消失。
    ChannelHarnessOptions options;
    options.recovery_inflight_ids = {901};
    options.recovery_inflight_idle_ids = {};  // 全部按 running（TASK_TAKEN）处理
    auto harness = MakeChannelHarness(117, std::move(options));
    CHECK(harness != nullptr);

    cc::ChannelDispatchRequest req;
    req.executor_id = 901;
    req.seed_id = 901;
    req.origin_seed_id = 0;
    req.payload = {1};
    CHECK(harness->channel->Submit(req, std::chrono::microseconds{0}).status ==
          cc::ChannelSubmitStatus::kAccepted);
    CHECK(harness->dp->WaitForSubmits(1, std::chrono::milliseconds{200}));
    CHECK(harness->dp->WasSubmitted(901, 0));

    harness->health->PublishKernelCrash("real kernel crash");
    CHECK(harness->recovery->WaitForExecution(std::chrono::milliseconds{300}));

    ch::EventList events;
    CHECK(DrainEventsCollect(harness->channel.get(), events, 2,
                             std::chrono::milliseconds{300}));
    // 给 loop_thread_ 一个额外窗口发布可能存在的重复 abnormal。
    std::this_thread::sleep_for(std::chrono::milliseconds{100});
    ch::EventList extra;
    (void)harness->channel->DrainEvents(extra, std::chrono::milliseconds{50});
    events.insert(events.end(),
                  std::make_move_iterator(extra.begin()),
                  std::make_move_iterator(extra.end()));

    CHECK(events.size() == 2);
    CHECK(events[0].AsFault() != nullptr);
    std::size_t abnormal_count = 0;
    for (const auto& evt : events) {
        const auto* abnormal = evt.AsAbnormal();
        if (abnormal != nullptr && abnormal->ctx.executor_id == 901) {
            ++abnormal_count;
            CHECK(abnormal->kind == cc::AbnormalKind::kWorkerCrashed);
        }
    }
    CHECK(abnormal_count == 1);

    harness->channel->Close();
    return 0;
}

} // namespace

int main()
{
    std::fprintf(stderr, "=== channel_completion_wakeup_test ===\n");
    RUN_TEST(TestPlainCompletionBoundedLatency);
    RUN_TEST(TestPlainPartialCompletionTranslates);
    RUN_TEST(TestPlainHostWakeInterruptsPoll);
    RUN_TEST(TestDoorbellCompletionFdInterruptsPoll);
    RUN_TEST(TestChannelSubmitWakesDataPlanePoll);
    RUN_TEST(TestChannelCompletionWakesAndQueuesEvent);
    RUN_TEST(TestChannelPartialCompletionWakesAndQueuesEvent);
    RUN_TEST(TestChannelHealthWakesAndQueuesFault);
    RUN_TEST(TestHarnessFatalTriggersConfirmedWorkerRecovery);
    RUN_TEST(TestReplacementStartFailureLatchRestartsWorker);
    RUN_TEST(TestOwnershipUnreclaimedEscalatesToVmRecovery);
    RUN_TEST(TestHangPoolHarvestedOnKernelCrash);
    RUN_TEST(TestHangSettlementKeepsWorkersFlowing);
    RUN_TEST(TestBenignKernelEventSuppressedImmediately);
    RUN_TEST(TestWatchdogHangSettlesWithoutRetained);
    RUN_TEST(TestHostSynthesizedCancelDoesNotNoteProgress);
    RUN_TEST(TestForwardProgressFrozenClassifiedAsNoOutput);
    RUN_TEST(TestProgramTimeoutNotInHangPool);
    RUN_TEST(TestHangKindEntersHangPool);
    RUN_TEST(TestHarnessFatalInfraNotInHangPool);
    RUN_TEST(TestRebootInflightTerminalNotDuplicated);
    std::fprintf(stderr, "=== ALL PASS ===\n");
    return 0;
}

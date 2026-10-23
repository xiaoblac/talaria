#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "worker/engine/domain_supervisor.hpp"

#include "worker/backend/exec_backend.hpp"
#include "worker/exec_mode.hpp"
#include "worker/log/log_macros.hpp"
#include "worker/observation/observation_bus.hpp"
#include "worker/perf/worker_perf.hpp"

#include "refuzz/proto_wire/error_codes.h"
#include "refuzz/proto_wire/ivshmem_protocol.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <errno.h>
#include <fcntl.h>
#include <limits>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <utility>

// [ExecTL] round-1 execution-timeline, daemon side: A = task claimed from the
// shared-memory slot, D = completion published (slot written + doorbell rung).
// Written straight to the worker diagnostic fd, bypassing the WorkerLog enable
// gate. The worker_perf switch is therefore the explicit gate for both
// collection and output. Keep this predicate identical to loop_runtime.cpp.
namespace {

bool ExecTimelineSampled(uint64_t executor_id)
{
    (void)executor_id;
    return ::refuzz::worker::perf::Enabled();
}

void EmitExecTimelineDaemonLine(uint32_t worker_id, uint64_t executor_id,
                                uint64_t a_us, uint64_t d_us)
{
    char buf[128];
    const int n = ::snprintf(buf, sizeof(buf),
                             "[WORKER][RfzTL] w=%u id=%llu A=%llu D=%llu\n",
                             worker_id,
                             static_cast<unsigned long long>(executor_id),
                             static_cast<unsigned long long>(a_us),
                             static_cast<unsigned long long>(d_us));
    if (n > 0) {
        ::refuzz::worker::log::WriteWorkerLogBytes(buf, static_cast<size_t>(n));
    }
}

// [ExecTL round-2] guest-side saturation sample: cumulative /proc/stat cpu
// jiffies plus procs_running/procs_blocked. The parser diffs consecutive
// lines; with the vCPU count known this yields busy% and runqueue depth inside
// the VM, separating "the mechanism is slow" from "the CPUs are
// oversubscribed".
void EmitCpuStatLine()
{
    const int sfd = ::open("/proc/stat", O_RDONLY | O_CLOEXEC);
    if (sfd < 0) {
        return;
    }
    static char stat_buf[16384];
    const ssize_t n = ::read(sfd, stat_buf, sizeof(stat_buf) - 1);
    ::close(sfd);
    if (n <= 0) {
        return;
    }
    stat_buf[n] = 0;
    unsigned long long v[8] = {};
    if (::sscanf(stat_buf, "cpu %llu %llu %llu %llu %llu %llu %llu %llu",
                 &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6], &v[7]) != 8) {
        return;
    }
    unsigned long long running = 0;
    unsigned long long blocked = 0;
    const char* p = ::strstr(stat_buf, "procs_running ");
    if (p != nullptr) {
        running = ::strtoull(p + sizeof("procs_running ") - 1, nullptr, 10);
    }
    p = ::strstr(stat_buf, "procs_blocked ");
    if (p != nullptr) {
        blocked = ::strtoull(p + sizeof("procs_blocked ") - 1, nullptr, 10);
    }
    const long hz = ::sysconf(_SC_CLK_TCK);
    if (hz <= 0) {
        return;
    }
    char buf[256];
    const int m = ::snprintf(
        buf, sizeof(buf),
        "[WORKER][RfzCPU] t=%llu u=%llu n=%llu s=%llu i=%llu w=%llu hi=%llu"
        " si=%llu st=%llu run=%llu blk=%llu hz=%ld\n",
        static_cast<unsigned long long>(now_us()),
        v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], running, blocked,
        hz);
    if (m > 0) {
        ::refuzz::worker::log::WriteWorkerLogBytes(buf, static_cast<size_t>(m));
    }
}

// Shared-role resource ledger. Each daemon reports cumulative process CPU and
// cumulative published completions; analysis sums deltas across worker IDs and
// computes daemon CPU/request = sum(delta(cpu)) / sum(delta(done)).
void EmitRoleCpuLine(uint32_t worker_id, uint64_t completed)
{
    struct timespec ts {};
    if (::clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts) != 0) {
        return;
    }
    const uint64_t cpu_us = static_cast<uint64_t>(ts.tv_sec) * 1000000ULL +
                            static_cast<uint64_t>(ts.tv_nsec) / 1000ULL;
    char buf[160];
    const int n = ::snprintf(
        buf, sizeof(buf),
        "[WORKER][RfzRoleCPU] w=%u t=%llu cpu=%llu done=%llu\n",
        worker_id,
        static_cast<unsigned long long>(now_us()),
        static_cast<unsigned long long>(cpu_us),
        static_cast<unsigned long long>(completed));
    if (n > 0) {
        ::refuzz::worker::log::WriteWorkerLogBytes(buf, static_cast<size_t>(n));
    }
}

} // namespace

#define LOG(fmt, ...) ::refuzz::worker::log::WorkerLog("[Worker] " fmt "\n", ##__VA_ARGS__)

extern volatile sig_atomic_t g_running;

namespace refuzz::worker {
namespace {

bool CancelFromAdapter(void* user)
{
    auto* task_channel = static_cast<IWorkerTaskChannel*>(user);
    return task_channel != nullptr && task_channel->CancelRequested();
}

enum class RecycleGateAcquireResult : uint8_t {
    kAcquired,
    kBusy,
    kError,
};

class DomainRecycleGate {
public:
    DomainRecycleGate() = default;
    DomainRecycleGate(const DomainRecycleGate&) = delete;
    DomainRecycleGate& operator=(const DomainRecycleGate&) = delete;

    ~DomainRecycleGate()
    {
        if (fd_ >= 0) {
            ::close(fd_);
        }
    }

    RecycleGateAcquireResult TryAcquire(const std::string& path)
    {
        if (path.empty()) {
            return RecycleGateAcquireResult::kAcquired;
        }

        const int fd = ::open(path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        if (fd < 0) {
            return RecycleGateAcquireResult::kError;
        }

        struct flock lock {};
        lock.l_type = F_WRLCK;
        lock.l_whence = SEEK_SET;
        lock.l_start = 0;
        lock.l_len = 0;
        if (::fcntl(fd, F_SETLK, &lock) == 0) {
            fd_ = fd;
            return RecycleGateAcquireResult::kAcquired;
        }

        const int saved_errno = errno;
        ::close(fd);
        errno = saved_errno;
        return saved_errno == EACCES || saved_errno == EAGAIN
            ? RecycleGateAcquireResult::kBusy
            : RecycleGateAcquireResult::kError;
    }

private:
    int fd_ = -1;
};

uint32_t HarnessFatalErrorCode(engine::HarnessFatalReason reason)
{
    switch (reason) {
    case engine::HarnessFatalReason::kOuterForkEagain:
        return ERR_HARNESS_OUTER_FORK_EAGAIN;
    case engine::HarnessFatalReason::kOuterForkFailed:
        return ERR_HARNESS_OUTER_FORK_FAILED;
    case engine::HarnessFatalReason::kMainChildReapFailed:
        return ERR_HARNESS_MAIN_REAP_FAILED;
    case engine::HarnessFatalReason::kStoppedDescendantReapTimeout:
        return ERR_HARNESS_STOPPED_REAP_TIMEOUT;
    case engine::HarnessFatalReason::kDomainWatchdogTimeout:
        return ERR_DOMAIN_WATCHDOG_TIMEOUT;
    case engine::HarnessFatalReason::kExecutionDomainCleanupFailed:
        return ERR_HARNESS_CLEANUP_FAILED;
    case engine::HarnessFatalReason::kKcovStateInvalid:
        return ERR_HARNESS_KCOV_STATE_INVALID;
    case engine::HarnessFatalReason::kForkServerProtocol:
    case engine::HarnessFatalReason::kNone:
        return ERR_HARNESS_FORK_SERVER_PROTOCOL;
    }
    return ERR_HARNESS_FORK_SERVER_PROTOCOL;
}

// syzkaller 对齐的 hang 判定：只有"程序可能仍在内核里"（kill/reap 未完成或
// 旧域可能还活着）才返回 COMP_STATUS_HUNG；程序从未创建（outer fork）或已证明
// 退出（post-exit 协议错 / KCOV 检查）是基础设施故障，返回 HARNESS_FATAL。
bool HarnessFatalIsHangTerminal(engine::HarnessFatalReason reason)
{
    switch (reason) {
    case engine::HarnessFatalReason::kDomainWatchdogTimeout:
    case engine::HarnessFatalReason::kMainChildReapFailed:
    case engine::HarnessFatalReason::kStoppedDescendantReapTimeout:
    case engine::HarnessFatalReason::kExecutionDomainCleanupFailed:
        return true;
    case engine::HarnessFatalReason::kOuterForkEagain:
    case engine::HarnessFatalReason::kOuterForkFailed:
    case engine::HarnessFatalReason::kForkServerProtocol:
    case engine::HarnessFatalReason::kKcovStateInvalid:
    case engine::HarnessFatalReason::kNone:
        return false;
    }
    return false;
}

uint32_t AddTimeouts(uint32_t first, uint32_t second,
                     uint32_t third, uint32_t fourth)
{
    const uint64_t sum = static_cast<uint64_t>(first) + second + third + fourth;
    return sum > std::numeric_limits<uint32_t>::max()
        ? std::numeric_limits<uint32_t>::max()
        : static_cast<uint32_t>(sum);
}

const char* DomainStartKindName(topology::DomainStartKind kind)
{
    switch (kind) {
    case topology::DomainStartKind::kReady: return "ready";
    case topology::DomainStartKind::kRejected: return "rejected";
    case topology::DomainStartKind::kExited: return "exited";
    case topology::DomainStartKind::kStalled: return "stalled";
    }
    return "unknown";
}

int DomainStartError(const topology::DomainStartResult& result)
{
    if (result.error_number != 0) {
        return result.error_number;
    }
    switch (result.kind) {
    case topology::DomainStartKind::kReady: return 0;
    case topology::DomainStartKind::kRejected: return EPROTO;
    case topology::DomainStartKind::kExited: return ECHILD;
    case topology::DomainStartKind::kStalled: return ETIMEDOUT;
    }
    return EPROTO;
}

} // namespace

const char* TransitionReasonName(TransitionReason reason)
{
    switch (reason) {
    case TransitionReason::kInitialStartup: return "initial-startup";
    case TransitionReason::kPeriodicRecycle: return "periodic-recycle";
    case TransitionReason::kTaskWatchdog: return "task-watchdog";
    case TransitionReason::kTaskCancelled: return "task-cancelled";
    case TransitionReason::kHarnessFailure: return "harness-failure";
    case TransitionReason::kProcRebind: return "proc-rebind";
    case TransitionReason::kShutdown: return "shutdown";
    }
    return "unknown";
}

DomainSupervisor::DomainSupervisor(
    IWorkerTaskChannel& task_channel,
    IExecutionDomainRegistry& domain_registry,
    DomainComponentBinding components,
    std::unique_ptr<topology::ProcessTopology> topology,
    EngineConfig config)
    : task_channel_(task_channel)
    , domain_registry_(domain_registry)
    , components_(std::move(components))
    , topology_(std::move(topology))
    , config_(std::move(config))
    , proc_lane_(config_.worker_id, domain_registry_.WorkerCount())
{
    topology_config_.sandbox_mode = config_.sandbox_mode;
    topology_config_.transport_mapped_bytes = config_.transport_mapped_bytes;
    topology_config_.recycle_after = config_.recycle_after;
    topology_config_.worker_id = config_.worker_id;
    topology_config_.exec_timeout_ms = config_.exec_timeout_ms;
    topology_config_.startup_timeout_ms = config_.domain_startup_timeout_ms;
    topology_config_.startup_cleanup_plan = MakeStopPlan(
        topology::DomainStopIntent::kStartupCleanup, false, false);
    topology_config_.transport_shm_base = config_.transport_shm_base;
    topology_config_.transport_shm_size = config_.transport_shm_size;
    topology_config_.program_mapping = config_.execution_transport.mapping;
    topology_config_.execution_backing_fd =
        config_.execution_transport.backing_fd;
    topology_config_.loop_boot_config = config_.loop_boot_config;
    topology_config_.executor_path = config_.executor_path;
}

void DomainSupervisor::RequestStop()
{
    stop_requested_.store(true, std::memory_order_release);
}

bool DomainSupervisor::IsRunning() const
{
    const DomainState state = State();
    return !stop_requested_.load(std::memory_order_acquire) &&
           state != DomainState::kFailed &&
           state != DomainState::kStopped;
}

DomainState DomainSupervisor::State() const
{
    return state_.load(std::memory_order_acquire);
}

uint64_t DomainSupervisor::PhaseDeadlineUs() const
{
    return phase_deadline_us_.load(std::memory_order_acquire);
}

void DomainSupervisor::EnterState(DomainState state,
                                  uint32_t timeout_ms)
{
    const bool next_domain_ready =
        state == DomainState::kReady || state == DomainState::kExecuting;
    const bool publish_domain_ready =
        !domain_ready_publication_initialized_ ||
        domain_ready_published_ != next_domain_ready;
    if (publish_domain_ready && !next_domain_ready) {
        task_channel_.SetDomainReady(false);
    }

    if (state_.load(std::memory_order_relaxed) != state) {
        state_.store(state, std::memory_order_release);
    }
    const uint64_t deadline_us = timeout_ms == 0
        ? 0
        : now_us() + static_cast<uint64_t>(timeout_ms) * 1000ULL;
    if (phase_deadline_us_.load(std::memory_order_relaxed) != deadline_us) {
        phase_deadline_us_.store(deadline_us, std::memory_order_release);
    }

    if (publish_domain_ready && next_domain_ready) {
        task_channel_.SetDomainReady(true);
    }
    if (publish_domain_ready) {
        domain_ready_published_ = next_domain_ready;
        domain_ready_publication_initialized_ = true;
    }
}

uint32_t DomainSupervisor::RemainingPhaseTimeoutMs() const
{
    const uint64_t deadline_us = PhaseDeadlineUs();
    const uint64_t current_us = now_us();
    if (deadline_us == 0 || deadline_us <= current_us) {
        return 0;
    }
    const uint64_t remaining_ms =
        (deadline_us - current_us + 999ULL) / 1000ULL;
    return remaining_ms > std::numeric_limits<uint32_t>::max()
        ? std::numeric_limits<uint32_t>::max()
        : static_cast<uint32_t>(remaining_ms);
}

uint32_t DomainSupervisor::EffectiveDaemonWatchdogMs() const
{
    if (config_.daemon_watchdog_ms != 0) {
        return config_.daemon_watchdog_ms;
    }
    const uint64_t derived =
        static_cast<uint64_t>(config_.exec_timeout_ms) * 3ULL;
    return derived > std::numeric_limits<uint32_t>::max()
        ? std::numeric_limits<uint32_t>::max()
        : static_cast<uint32_t>(derived);
}

topology::DomainStopPlan DomainSupervisor::MakeStopPlan(
    topology::DomainStopIntent intent,
    bool graceful,
    bool allow_abandon) const
{
    topology::DomainStopPlan plan{};
    plan.intent = intent;
    plan.graceful = graceful;
    plan.allow_abandon = allow_abandon;
    plan.graceful_timeout_ms = config_.domain_stop_grace_ms;
    plan.kill_timeout_ms = config_.domain_stop_kill_ms;
    plan.runner_timeout_ms = config_.domain_stop_runner_ms;
    plan.reap_timeout_ms = config_.domain_stop_reap_ms;
    return plan;
}

topology::DomainStopResult DomainSupervisor::StopDomain(
    topology::DomainStopIntent intent,
    bool graceful,
    bool allow_abandon)
{
    EnterState(
        DomainState::kStopping,
        AddTimeouts(graceful ? config_.domain_stop_grace_ms : 0u,
                    config_.domain_stop_kill_ms,
                    config_.domain_stop_runner_ms,
                    config_.domain_stop_reap_ms));
    topology::DomainStopPlan plan = MakeStopPlan(
        intent, graceful, allow_abandon);
    plan.absolute_deadline_us = PhaseDeadlineUs();
    const topology::DomainStopResult result =
        topology_->Stop(plan);
    if (topology::DomainStopAllowsReplacement(result)) {
        domain_active_ = false;
    }
    return result;
}

bool DomainSupervisor::ProcIdIsDirty(uint32_t proc_id) const
{
    return proc_lane_.IsDirty(proc_id, dirty_proc_mask_);
}

bool DomainSupervisor::MarkProcIdDirty(uint32_t proc_id)
{
    if (!proc_lane_.Owns(proc_id)) {
        LOG("domain supervisor refused dirty proc outside lane worker=%u proc=%u",
            config_.worker_id, proc_id);
        return false;
    }
    const uint32_t next_mask = dirty_proc_mask_ | (uint32_t{1} << proc_id);
    if (next_mask == dirty_proc_mask_) {
        return true;
    }
    if (!domain_registry_.PublishDirtyProcMask(next_mask)) {
        LOG("domain supervisor dirty proc persist failed worker=%u proc=%u mask=0x%x",
            config_.worker_id, proc_id, next_mask);
        return false;
    }
    dirty_proc_mask_ = next_mask;
    LOG("domain supervisor proc quarantined worker=%u proc=%u mask=0x%x",
        config_.worker_id, proc_id, dirty_proc_mask_);
    return true;
}

topology::DomainStartResult DomainSupervisor::StartAttempt(
    const topology::DomainIdentity& candidate,
    TransitionReason reason,
    uint32_t attempt,
    bool identity_already_published)
{
    if (!identity_already_published) {
        if (!domain_registry_.PublishProcState(candidate.proc_id,
                                               candidate.proc_epoch)) {
            LOG("domain supervisor persist failed reason=%s proc=%u epoch=%u "
                "attempt=%u",
                TransitionReasonName(reason), candidate.proc_id,
                candidate.proc_epoch, attempt);
            errno = EIO;
            return topology::MakeDomainStartRejected(
                candidate.proc_id,
                engine::LoopStartupStage::kUnknown,
                errno);
        }
        if (auto* inherited =
                std::get_if<InheritedDomainComponents>(&components_)) {
            inherited->backend.get().ConfigureProcId(candidate.proc_id);
            inherited->bus.get().ConfigureProcId(candidate.proc_id);
        }
    }

    topology_config_.identity = candidate;
    const uint32_t startup_timeout_ms =
        config_.domain_startup_timeout_ms == 0
            ? topology::kDefaultDomainStartupTimeoutMs
            : config_.domain_startup_timeout_ms;
    EnterState(DomainState::kStarting, startup_timeout_ms);
    topology_config_.startup_timeout_ms = startup_timeout_ms;
    topology_config_.startup_deadline_us = PhaseDeadlineUs();
    LOG("domain startup begin reason=%s worker=%u proc=%u epoch=%u "
        "attempt=%u timeout_ms=%u deadline_us=%llu",
        TransitionReasonName(reason), candidate.worker_id,
        candidate.proc_id, candidate.proc_epoch, attempt,
        startup_timeout_ms,
        static_cast<unsigned long long>(topology_config_.startup_deadline_us));
    const topology::DomainStartResult start_result =
        topology_->Setup(topology_config_);
    const int start_errno = DomainStartError(start_result);
    LOG("domain startup end reason=%s worker=%u proc=%u epoch=%u attempt=%u "
        "kind=%s stage=%u errno=%d exit=%d child_pid=%d generation=%llu",
        TransitionReasonName(reason), candidate.worker_id,
        candidate.proc_id, candidate.proc_epoch, attempt,
        DomainStartKindName(start_result.kind),
        static_cast<unsigned>(start_result.stage), start_errno,
        start_result.exit_status, topology_->CurrentChildPid(),
        static_cast<unsigned long long>(topology_->CurrentChildGeneration()));
    if (!start_result.IsReady()) {
        domain_active_ = topology_->CurrentChildPid() > 0;
        errno = start_errno;
        return start_result;
    }

    identity_ = candidate;
    domain_active_ = true;
    EnterState(DomainState::kReady);
    LOG("domain supervisor ready reason=%s worker=%u proc=%u epoch=%u "
        "generation=%llu attempt=%u startup_timeout_ms=%u",
        TransitionReasonName(reason), identity_.worker_id,
        identity_.proc_id, identity_.proc_epoch,
        static_cast<unsigned long long>(
            topology_->CurrentChildGeneration()),
        attempt, startup_timeout_ms);
    return start_result;
}

DomainSupervisor::RecoveryPolicy DomainSupervisor::RecoveryPolicyFor(
    TransitionReason reason) const
{
    RecoveryPolicy policy{};
    policy.startup_attempts =
        std::max<uint32_t>(1u, config_.domain_startup_attempts);

    switch (reason) {
    case TransitionReason::kInitialStartup:
        policy.identity_selection = IdentitySelection::kCurrentThenRotate;
        policy.stop_intent = topology::DomainStopIntent::kStartupCleanup;
        policy.count_against_streak = false;
        break;
    case TransitionReason::kTaskWatchdog:
        // A task watchdog already consumed the execution deadline. Give the
        // daemon one bounded replacement boot, then hand recovery to the host.
        policy.startup_attempts = 1;
        policy.allow_abandon = true;
        break;
    case TransitionReason::kTaskCancelled:
        // Cancellation is host intent, not evidence of domain illness.
        policy.stop_intent = topology::DomainStopIntent::kCancellation;
        policy.count_against_streak = false;
        break;
    case TransitionReason::kPeriodicRecycle:
        policy.stop_intent = topology::DomainStopIntent::kPeriodicRecycle;
        break;
    case TransitionReason::kProcRebind:
        policy.identity_selection = IdentitySelection::kExact;
        policy.stop_intent = topology::DomainStopIntent::kRequestedProcRebind;
        policy.graceful_stop = true;
        policy.count_against_streak = false;
        break;
    case TransitionReason::kHarnessFailure:
        break;
    case TransitionReason::kShutdown:
        policy.startup_attempts = 0;
        policy.count_against_streak = false;
        break;
    }
    return policy;
}

DomainRecoveryResult DomainSupervisor::Recover(TransitionReason reason)
{
    return Recover(reason, RecoveryContext{}, {});
}

DomainRecoveryResult DomainSupervisor::Recover(
    TransitionReason reason,
    const RecoveryContext& context)
{
    return Recover(reason, context, {});
}

DomainRecoveryResult DomainSupervisor::Recover(
    TransitionReason reason,
    const RecoveryContext& context,
    const std::function<void()>& on_stop_classified)
{
    DomainRecoveryResult result{};
    result.stop_result = context.prior_stop_result;
    const RecoveryPolicy policy = RecoveryPolicyFor(reason);
    const uint32_t max_startup_attempts = policy.startup_attempts;
    const uint32_t max_recovery_attempts =
        std::max<uint32_t>(1u, config_.domain_recovery_attempts);
    uint32_t recovery_streak =
        recovery_attempts_in_streak_.load(std::memory_order_relaxed);
    const bool recovery_budget_exhausted =
        policy.count_against_streak &&
        recovery_streak >= max_recovery_attempts;
    const uint32_t available_attempts = recovery_budget_exhausted
        ? 0u : max_startup_attempts;
    if (policy.count_against_streak && !recovery_budget_exhausted) {
        recovery_streak = recovery_attempts_in_streak_.fetch_add(
            1u, std::memory_order_relaxed) + 1u;
    }

    LOG("domain supervisor recover reason=%s proc=%u epoch=%u "
        "used=%u available=%u",
        TransitionReasonName(reason), identity_.proc_id,
        identity_.proc_epoch, recovery_streak,
        available_attempts);

    bool stopped = context.domain_already_stopped;
    topology::DomainIdentity candidate = identity_;
    bool candidate_selected = false;
    bool stop_classification_notified = false;

    auto notify_stop_classified = [&]() {
        if (!stop_classification_notified && on_stop_classified) {
            stop_classification_notified = true;
            on_stop_classified();
        }
    };
    if (stopped) {
        notify_stop_classified();
    }

    auto accept_stop_result = [this, &policy, reason](
                                  topology::DomainStopResult stop_result,
                                  uint32_t proc_id) {
        if (stop_result == topology::DomainStopResult::kAbandoned ||
            stop_result == topology::DomainStopResult::kFailed) {
            if (!MarkProcIdDirty(proc_id)) {
                return false;
            }
        }
        if (stop_result == topology::DomainStopResult::kAbandoned &&
            !policy.allow_abandon) {
            LOG("domain supervisor rejected unexpected abandonment reason=%s "
                "proc=%u",
                TransitionReasonName(reason), proc_id);
            return false;
        }
        return topology::DomainStopAllowsReplacement(stop_result);
    };

    for (uint32_t local_attempt = 1;
         local_attempt <= available_attempts;
         ++local_attempt) {
        result.attempts = local_attempt;
        if (!stopped) {
            const uint32_t stopped_proc_id = candidate_selected
                ? candidate.proc_id : identity_.proc_id;
            const topology::DomainStopResult stop_result = StopDomain(
                policy.stop_intent,
                policy.graceful_stop,
                policy.allow_abandon);
            result.stop_result = stop_result;
            const bool stop_accepted = accept_stop_result(
                stop_result, stopped_proc_id);
            notify_stop_classified();
            if (!stop_accepted) {
                result.failed_stage = RecoveryFailedStage::kStopCurrentDomain;
                LOG("domain supervisor stop failed reason=%s attempt=%u/%u",
                    TransitionReasonName(reason), local_attempt,
                    available_attempts);
                if (local_attempt > 3) {
                    ::usleep(static_cast<useconds_t>(local_attempt) * 100'000u);
                }
                continue;
            }
            stopped = true;
        }

        if (!candidate_selected) {
            std::optional<uint32_t> selected_proc_id;
            switch (policy.identity_selection) {
            case IdentitySelection::kCurrentThenRotate:
                candidate = identity_;
                if (!ProcIdIsDirty(candidate.proc_id)) {
                    selected_proc_id = candidate.proc_id;
                }
                break;
            case IdentitySelection::kRotate:
                candidate = identity_;
                candidate.proc_epoch += 1u;
                selected_proc_id = proc_lane_.NextClean(
                    identity_.proc_id, dirty_proc_mask_);
                break;
            case IdentitySelection::kExact:
                candidate = identity_;
                candidate.proc_epoch += 1u;
                if (proc_lane_.Owns(context.exact_proc_id) &&
                    !ProcIdIsDirty(context.exact_proc_id)) {
                    selected_proc_id = context.exact_proc_id;
                }
                break;
            }
            if (!selected_proc_id.has_value()) {
                LOG("domain supervisor clean proc lane exhausted reason=%s "
                    "worker=%u mask=0x%x",
                    TransitionReasonName(reason), config_.worker_id,
                    dirty_proc_mask_);
                result.failed_stage = RecoveryFailedStage::kBudgetExhausted;
                break;
            }
            candidate.proc_id = *selected_proc_id;
            candidate_selected = true;
        } else {
            candidate.proc_epoch += 1u;
            if (policy.identity_selection == IdentitySelection::kExact) {
                // The exact identity is the only acceptable candidate, so a
                // retry must not fall back to another proc id. It can,
                // however, have been marked dirty by a failed/abandoned
                // startup cleanup on a previous attempt; dirty ids must not be
                // reused until ClearProcIsolationState (VM reboot) clears the
                // mask, so re-validate before the next StartAttempt.
                if (ProcIdIsDirty(candidate.proc_id)) {
                    LOG("domain supervisor exact proc became dirty after "
                        "startup failure reason=%s worker=%u proc=%u "
                        "mask=0x%x",
                        TransitionReasonName(reason), config_.worker_id,
                        candidate.proc_id, dirty_proc_mask_);
                    result.failed_stage = RecoveryFailedStage::kBudgetExhausted;
                    break;
                }
            } else {
                const auto next_proc_id = proc_lane_.NextClean(
                    candidate.proc_id, dirty_proc_mask_);
                if (!next_proc_id.has_value()) {
                    LOG("domain supervisor clean proc lane exhausted after "
                        "startup failure reason=%s worker=%u mask=0x%x",
                        TransitionReasonName(reason), config_.worker_id,
                        dirty_proc_mask_);
                    result.failed_stage = RecoveryFailedStage::kBudgetExhausted;
                    break;
                }
                candidate.proc_id = *next_proc_id;
            }
        }

        const topology::DomainStartResult start_result =
            StartAttempt(candidate, reason, local_attempt, false);
        result.start_attempted = true;
        result.last_start_result = start_result;
        if (start_result.IsReady()) {
            reported_in_domain_ = 0;
            result.kind = DomainRecoveryKind::kRecovered;
            result.failed_stage = RecoveryFailedStage::kNone;
            return result;
        }
        result.failed_stage = RecoveryFailedStage::kStartReplacement;

        const int setup_errno = DomainStartError(start_result);
        LOG("domain supervisor startup failed reason=%s proc=%u epoch=%u "
            "attempt=%u/%u kind=%s stage=%u errno=%d exit=%d",
            TransitionReasonName(reason), candidate.proc_id,
            candidate.proc_epoch, local_attempt, available_attempts,
            DomainStartKindName(start_result.kind),
            static_cast<unsigned>(start_result.stage), setup_errno,
            start_result.exit_status);
        const topology::DomainStopResult cleanup_result = StopDomain(
            topology::DomainStopIntent::kStartupCleanup, false,
            policy.allow_abandon);
        result.stop_result = cleanup_result;
        stopped = accept_stop_result(cleanup_result, candidate.proc_id);
        if (!stopped) {
            result.failed_stage =
                RecoveryFailedStage::kStopPartialReplacement;
        }
        errno = setup_errno;

        if (local_attempt > 3 && local_attempt < available_attempts) {
            ::usleep(static_cast<useconds_t>(local_attempt) * 100'000u);
        }
    }

    if (!stopped || domain_active_) {
        const topology::DomainStopResult final_stop_result = StopDomain(
            policy.stop_intent, false, policy.allow_abandon);
        result.stop_result = final_stop_result;
        stopped = accept_stop_result(
            final_stop_result,
            candidate_selected ? candidate.proc_id : identity_.proc_id);
        notify_stop_classified();
    }
    const bool ownership_reclaimed = stopped && !domain_active_;
    if (ownership_reclaimed) {
        result.kind = DomainRecoveryKind::kReplacementStartFailed;
        result.failed_stage = result.start_attempted
            ? RecoveryFailedStage::kStartReplacement
            : RecoveryFailedStage::kBudgetExhausted;
    } else {
        result.kind = DomainRecoveryKind::kOwnershipUnreclaimed;
        result.failed_stage = result.start_attempted
            ? RecoveryFailedStage::kStopPartialReplacement
            : RecoveryFailedStage::kStopCurrentDomain;
    }
    EnterState(DomainState::kFailed);
    LOG("domain supervisor recovery failed reason=%s kind=%u stage=%u "
        "old_domain_isolated=%d stop_result=%u start_kind=%u "
        "start_stage=%u attempts=%u used=%u limit=%u",
        TransitionReasonName(reason),
        static_cast<unsigned>(result.kind),
        static_cast<unsigned>(result.failed_stage),
        result.OldDomainIsolated() ? 1 : 0,
        static_cast<unsigned>(result.stop_result),
        static_cast<unsigned>(result.last_start_result.kind),
        static_cast<unsigned>(result.last_start_result.stage),
        result.attempts, recovery_streak, max_recovery_attempts);
    return result;
}

void DomainSupervisor::ResetRecoveryStreak()
{
    recovery_attempts_in_streak_.store(0, std::memory_order_release);
}

bool DomainSupervisor::PeriodicRecycle()
{
    DomainRecycleGate recycle_gate;
    const RecycleGateAcquireResult gate_result =
        recycle_gate.TryAcquire(config_.recycle_gate_path);
    if (gate_result == RecycleGateAcquireResult::kBusy) {
        if (!periodic_recycle_deferred_) {
            LOG("periodic recycle deferred: another VM worker is rebuilding");
            periodic_recycle_deferred_ = true;
        }
        return true;
    }
    if (gate_result == RecycleGateAcquireResult::kError) {
        LOG("periodic recycle gate unavailable path=%s errno=%d; deferring",
            config_.recycle_gate_path.c_str(), errno);
        periodic_recycle_deferred_ = true;
        return true;
    }
    if (periodic_recycle_deferred_) {
        LOG("periodic recycle gate acquired after deferral");
        periodic_recycle_deferred_ = false;
    }

    LOG("periodic recycle after %llu reported programs threshold=%u",
        static_cast<unsigned long long>(reported_in_domain_),
        config_.recycle_after);
    const topology::DomainStopResult stop_result = StopDomain(
        topology::DomainStopIntent::kPeriodicRecycle, true);
    if (stop_result == topology::DomainStopResult::kClean) {
        const topology::DomainStartResult start_result =
            StartAttempt(identity_, TransitionReason::kPeriodicRecycle,
                         1, true);
        if (start_result.IsReady()) {
            reported_in_domain_ = 0;
            return true;
        }
        LOG("periodic recycle startup failed kind=%s stage=%u errno=%d exit=%d",
            DomainStartKindName(start_result.kind),
            static_cast<unsigned>(start_result.stage),
            DomainStartError(start_result), start_result.exit_status);
        return Recover(TransitionReason::kPeriodicRecycle).Recovered();
    }

    RecoveryContext context{};
    context.domain_already_stopped =
        stop_result == topology::DomainStopResult::kForced;
    context.prior_stop_result = stop_result;
    return Recover(TransitionReason::kPeriodicRecycle, context).Recovered();
}

bool DomainSupervisor::MaintainReadyDomain()
{
    if (topology_->ExecutionDomainExited()) {
        if (!Recover(TransitionReason::kHarnessFailure).Recovered()) {
            return false;
        }
    }

    if (config_.recycle_after > 0 && domain_registry_.InitialCorpusTriaged() &&
        reported_in_domain_ >= config_.recycle_after) {
        return PeriodicRecycle();
    }
    return true;
}

int DomainSupervisor::Run()
{
    LOG("domain supervisor run entered worker=%u", config_.worker_id);
    if (topology_ == nullptr || !proc_lane_.Valid()) {
        LOG("domain supervisor invalid configuration worker=%u workers=%u "
            "capacity=%u topology=%p",
            config_.worker_id, domain_registry_.WorkerCount(), proc_lane_.capacity(),
            static_cast<void*>(topology_.get()));
        EnterState(DomainState::kFailed);
        return 2;
    }

    identity_.worker_id = config_.worker_id;
    const PersistedProcState persisted = domain_registry_.LoadProcState();
    dirty_proc_mask_ = persisted.dirty_proc_mask;
    std::optional<uint32_t> initial_proc_id;
    if (persisted.valid && proc_lane_.Owns(persisted.proc_id)) {
        initial_proc_id = proc_lane_.NextClean(
            persisted.proc_id, dirty_proc_mask_);
        identity_.proc_epoch = persisted.epoch + 1u;
    } else {
        initial_proc_id = proc_lane_.FirstClean(dirty_proc_mask_);
        identity_.proc_epoch = 0;
    }
    if (!initial_proc_id.has_value()) {
        LOG("domain supervisor initial clean proc lane exhausted worker=%u mask=0x%x",
            config_.worker_id, dirty_proc_mask_);
        (void)domain_registry_.PublishMaintenanceError(
            ERR_DOMAIN_REPLACEMENT_START_FAILED);
        EnterState(DomainState::kFailed);
        return 1;
    }
    identity_.proc_id = *initial_proc_id;

    LOG("domain initial recovery begin worker=%u proc=%u epoch=%u",
        config_.worker_id, identity_.proc_id, identity_.proc_epoch);
    RecoveryContext initial{};
    initial.domain_already_stopped = true;
    const DomainRecoveryResult initial_recovery = Recover(
        TransitionReason::kInitialStartup, initial);
    if (!initial_recovery.Recovered()) {
        (void)domain_registry_.PublishMaintenanceError(
            initial_recovery.OldDomainIsolated()
                ? ERR_DOMAIN_REPLACEMENT_START_FAILED
                : ERR_DOMAIN_OWNERSHIP_UNRECLAIMED);
        return 1;
    }
    LOG("domain initial recovery complete worker=%u proc=%u epoch=%u",
        config_.worker_id, identity_.proc_id, identity_.proc_epoch);
    ResetRecoveryStreak();

    int exit_code = 0;
    const uint32_t daemon_watchdog_ms = EffectiveDaemonWatchdogMs();
    const bool collect_exec_timeline =
        ::refuzz::worker::perf::Enabled();
    // VM-global saturation is sampled by worker 0 only. Role CPU is sampled by
    // every daemon because analysis sums its per-worker cumulative deltas.
    uint64_t tl_last_cpu_sample_us = 0;
    uint64_t tl_last_role_cpu_sample_us = 0;
    uint64_t tl_role_completed = 0;
    while (g_running && !stop_requested_.load(std::memory_order_acquire)) {
        if (collect_exec_timeline) {
            const uint64_t tl_now_us = now_us();
            if (tl_now_us - tl_last_role_cpu_sample_us >= 5000000ULL) {
                tl_last_role_cpu_sample_us = tl_now_us;
                EmitRoleCpuLine(config_.worker_id, tl_role_completed);
            }
            if (config_.worker_id == 0 &&
                tl_now_us - tl_last_cpu_sample_us >= 5000000ULL) {
                tl_last_cpu_sample_us = tl_now_us;
                EmitCpuStatLine();
            }
        }
        if (!MaintainReadyDomain()) {
            exit_code = 1;
            break;
        }

        auto task = task_channel_.WaitTask(std::chrono::milliseconds(
            config_.poll_ms > 0 ? config_.poll_ms : 1));
        if (!task) {
            const AdapterLifecycleState adapter_state =
                task_channel_.LifecycleState();
            if (adapter_state == AdapterLifecycleState::kCleanShutdown) {
                break;
            }
            if (adapter_state == AdapterLifecycleState::kFailed) {
                exit_code = task_channel_.ExitCode() != 0
                    ? task_channel_.ExitCode() : 1;
                break;
            }
            continue;
        }
        // [ExecTL] A: task claimed from the shared-memory slot.
        const uint64_t tl_a_us = collect_exec_timeline ? now_us() : 0;

        if (task->cancel_requested) {
            EnterState(DomainState::kExecuting);
            TaskResult cancelled{};
            cancelled.executor_id = task->executor_id;
            cancelled.dispatch_gen = task->dispatch_gen;
            cancelled.status = -1;
            cancelled.completion_status = COMP_STATUS_CANCELLED;
            cancelled.error_code = ERR_TASK_CANCELLED;
            cancelled.proc_id = identity_.proc_id;
            cancelled.cancel_observed = true;
            task_channel_.ReportDone(cancelled);
            if (collect_exec_timeline) {
                ++tl_role_completed;
            }
            EnterState(DomainState::kReady);
            continue;
        }

        const ExecMode mode = ExecModeFromFlags(task->flags);
        if (!ExecFlagsAreSupported(task->flags)) {
            EnterState(DomainState::kExecuting);
            LOG("unsupported exec mode flags=0x%x intra=%u shape=%u",
                task->flags, static_cast<unsigned>(mode.intra),
                static_cast<unsigned>(mode.shape));
            TaskResult unsupported{};
            unsupported.executor_id = task->executor_id;
            unsupported.dispatch_gen = task->dispatch_gen;
            unsupported.status = -1;
            // host 下发了本 worker 不支持的 exec flags(如 thread_count=1 却要
            // threaded)—— 配置/协议错,程序无罪,且**确定性**:同一请求重试必然
            // 同样失败,所以下游要 hard_stop 而不是当成"这次没跑成"去重试。
            unsupported.completion_status = COMP_STATUS_INFRA_FAULT;
            unsupported.error_code = ERR_INVALID_INPUT;
            unsupported.proc_id = identity_.proc_id;
            task_channel_.ReportDone(unsupported);
            if (collect_exec_timeline) {
                ++tl_role_completed;
            }
            EnterState(DomainState::kReady);
            continue;
        }

        if (task->target_proc_id != PROC_ID_ANY) {
            if (!proc_lane_.Owns(task->target_proc_id)) {
                EnterState(DomainState::kExecuting);
                LOG("requested proc-id outside worker lane worker=%u proc=%u",
                    config_.worker_id, task->target_proc_id);
                TaskResult invalid_proc{};
                invalid_proc.executor_id = task->executor_id;
                invalid_proc.dispatch_gen = task->dispatch_gen;
                invalid_proc.status = -1;
                invalid_proc.completion_status = COMP_STATUS_HARNESS_FATAL;
                invalid_proc.error_code = ERR_HARNESS_FORK_SERVER_PROTOCOL;
                invalid_proc.proc_id = identity_.proc_id;
                task_channel_.ReportDone(invalid_proc);
                if (collect_exec_timeline) {
                    ++tl_role_completed;
                }
                EnterState(DomainState::kReady);
                continue;
            }
            if (task->target_proc_id != identity_.proc_id) {
                RecoveryContext rebind{};
                rebind.exact_proc_id = task->target_proc_id;
                const DomainRecoveryResult rebind_result = Recover(
                    TransitionReason::kProcRebind, rebind);
                if (!rebind_result.Recovered()) {
                    TaskResult failed{};
                    failed.executor_id = task->executor_id;
                    failed.dispatch_gen = task->dispatch_gen;
                    failed.status = -1;
                    failed.completion_status = COMP_STATUS_HARNESS_FATAL;
                    failed.error_code = rebind_result.OldDomainIsolated()
                        ? ERR_DOMAIN_REPLACEMENT_START_FAILED
                        : ERR_DOMAIN_OWNERSHIP_UNRECLAIMED;
                    failed.proc_id = PROC_ID_ANY;
                    task_channel_.ReportDone(failed);
                    if (collect_exec_timeline) {
                        ++tl_role_completed;
                    }
                    EnterState(DomainState::kFailed);
                    exit_code = 1;
                    break;
                }
            }
        }

        topology::ProgramRequest request{};
        request.input_len = task->input_len;
        request.output_cap = task->output_cap;
        request.flags = task->flags;
        request.executor_id = task->executor_id;
        request.dispatch_gen = task->dispatch_gen;
        request.buffers = task->buffers;

        uint32_t magic_probe = 0;
        if (task->input_len >= sizeof(magic_probe)) {
            __builtin_memcpy(&magic_probe, task->input_buf, sizeof(magic_probe));
        }

        task_channel_.ResetOutputLen();
        const uint32_t task_proc_id = identity_.proc_id;
        const int active_child_pid = topology_->CurrentChildPid();
        EnterState(DomainState::kExecuting, daemon_watchdog_ms);
        const topology::DispatchHandle handle = topology_->Dispatch(request);
        const uint32_t collect_timeout_ms = daemon_watchdog_ms == 0
            ? 0 : RemainingPhaseTimeoutMs();
        topology::CollectResult collected{};
        if (daemon_watchdog_ms != 0 && collect_timeout_ms == 0) {
            collected.kind = topology::CollectKind::kTimeout;
            collected.fatal_reason =
                engine::HarnessFatalReason::kDomainWatchdogTimeout;
        } else {
            collected = topology_->Collect(
                handle, collect_timeout_ms,
                &CancelFromAdapter, &task_channel_);
        }

        TaskResult result{};
        result.executor_id = task->executor_id;
        result.dispatch_gen = task->dispatch_gen;
        result.proc_id = task_proc_id;
        bool terminal_harness_failure = false;

        switch (collected.kind) {
        case topology::CollectKind::kDone:
            switch (collected.result_kind) {
            case engine::RuntimeResultKind::kNormal:
                result.output_len = collected.output_len;
                result.status = 0;
                result.completion_status = COMP_STATUS_OK;
                result.error_code = ERR_OK;
                break;
            case engine::RuntimeResultKind::kPartial:
                result.output_len = collected.output_len;
                result.status = 0;
                result.completion_status = COMP_STATUS_PARTIAL;
                result.error_code = ERR_OK;
                break;
            case engine::RuntimeResultKind::kCrash:
                result.output_len = collected.output_len;
                result.status = -1;
                result.completion_status = COMP_STATUS_CHILD_ABORTED;
                result.error_code = ERR_PROGRAM_CHILD_CRASHED;
                result.crash_signal = collected.crash_signal;
                break;
            case engine::RuntimeResultKind::kTimeout:
                // program watchdog 判的超时。事实层不压缩信息:超时前已发布的
                // progress 数据照常带出(与 kNormal/kPartial/kCrash 同样拷
                // output_len),由 channel 按 (COMP_STATUS_TIMEOUT, ERR_TIMEOUT)
                // 决定它走 Completion 侧。真正的 task hang 是下面
                // CollectKind::kTimeout(daemon watchdog),用独立的
                // COMP_STATUS_HUNG + ERR_DOMAIN_WATCHDOG_TIMEOUT 返回。
                result.output_len = collected.output_len;
                result.status = -1;
                result.completion_status = COMP_STATUS_TIMEOUT;
                result.error_code = ERR_TIMEOUT;
                break;
            case engine::RuntimeResultKind::kHarnessFatal:
                result.status = -1;
                result.completion_status =
                    HarnessFatalIsHangTerminal(collected.fatal_reason)
                        ? COMP_STATUS_HUNG
                        : COMP_STATUS_HARNESS_FATAL;
                result.error_code =
                    HarnessFatalErrorCode(collected.fatal_reason);
                terminal_harness_failure = true;
                break;
            case engine::RuntimeResultKind::kNoResult:
                // 真的没产出(零 progress)。不是错误 —— error_code 保持 ERR_OK;
                // 标签自己说清楚"没结果、别消费",下游不需要再判 output_len。
                result.status = -1;
                result.completion_status = COMP_STATUS_NO_RESULT;
                result.error_code = ERR_OK;
                break;
            // [基础设施故障 — 程序无罪] 同一个 status,两个 error_code 细分归属。
            case engine::RuntimeResultKind::kInfraFault:
                result.status = -1;
                result.completion_status = COMP_STATUS_INFRA_FAULT;
                result.error_code = ERR_EXECUTOR_ERROR;   // worker 运行时故障
                break;
            case engine::RuntimeResultKind::kInvalidInput:
                result.status = -1;
                result.completion_status = COMP_STATUS_INFRA_FAULT;
                result.error_code = ERR_INVALID_INPUT;    // 配置/协议错(确定性)
                break;
            case engine::RuntimeResultKind::kUnknown:
            default:
                // 兜底:不该走到的分支。如实上报,不伪装成常规错误。
                result.status = -1;
                result.completion_status = COMP_STATUS_UNKNOWN;
                result.error_code = ERR_UNKNOWN;
                break;
            }
            break;
        case topology::CollectKind::kTimeout:
            LOG("domain watchdog timeout ts_us=%llu timeout_ms=%u "
                "executor_id=%llu dispatch_gen=%u child_pid=%d input_len=%u "
                "magic=0x%x",
                static_cast<unsigned long long>(now_us()), daemon_watchdog_ms,
                static_cast<unsigned long long>(task->executor_id),
                task->dispatch_gen, active_child_pid, task->input_len,
                magic_probe);
            result.status = -1;
            result.completion_status = COMP_STATUS_HUNG;
            result.error_code = ERR_DOMAIN_WATCHDOG_TIMEOUT;
            break;
        case topology::CollectKind::kCancelled:
            result.status = -1;
            result.completion_status = COMP_STATUS_CANCELLED;
            result.error_code = ERR_TASK_CANCELLED;
            result.cancel_observed = true;
            break;
        case topology::CollectKind::kChildAborted:
            result.output_len = collected.output_len != 0
                ? collected.output_len : task_channel_.GetCrashOutputLen();
            result.status = -1;
            result.completion_status = COMP_STATUS_CHILD_ABORTED;
            result.error_code = ERR_PROGRAM_CHILD_CRASHED;
            result.crash_signal = collected.crash_signal;
            break;
        case topology::CollectKind::kHarnessFail:
        default:
            LOG("topology harness failure executor_id=%llu dispatch_gen=%u "
                "child_pid=%d reason=%u",
                static_cast<unsigned long long>(task->executor_id),
                task->dispatch_gen, active_child_pid,
                static_cast<unsigned>(collected.fatal_reason));
            result.status = -1;
            // worker 端显式判定：kill/reap 未完成（可能 D 态）→ HUNG；
            // 程序从未创建或已证明退出 → HARNESS_FATAL（infra）。
            result.completion_status =
                HarnessFatalIsHangTerminal(collected.fatal_reason)
                    ? COMP_STATUS_HUNG
                    : COMP_STATUS_HARNESS_FATAL;
            result.error_code =
                HarnessFatalErrorCode(collected.fatal_reason);
            terminal_harness_failure = true;
            break;
        }

        bool recovery_required = terminal_harness_failure ||
            collected.kind == topology::CollectKind::kTimeout ||
            collected.kind == topology::CollectKind::kCancelled ||
            collected.kind == topology::CollectKind::kChildAborted;
        DomainRecoveryResult recovery_result{};
        bool recovered = false;
        bool result_reported = false;
        auto report_result = [&]() {
            if (result_reported) {
                return;
            }
            task_channel_.ReportDone(result);
            result_reported = true;
            // [ExecTL] D: completion slot written + doorbell rung.
            if (ExecTimelineSampled(task->executor_id)) {
                EmitExecTimelineDaemonLine(
                    config_.worker_id, task->executor_id,
                    tl_a_us, now_us());
            }
            if (collect_exec_timeline) {
                ++tl_role_completed;
            }
        };
        if (recovery_required) {
            TransitionReason recovery_reason;
            if (terminal_harness_failure) {
                recovery_reason =
                    collected.fatal_reason ==
                        engine::HarnessFatalReason::kDomainWatchdogTimeout
                    ? TransitionReason::kTaskWatchdog
                    : TransitionReason::kHarnessFailure;
            } else if (collected.kind == topology::CollectKind::kTimeout) {
                recovery_reason = TransitionReason::kTaskWatchdog;
            } else if (collected.kind == topology::CollectKind::kCancelled) {
                recovery_reason = TransitionReason::kTaskCancelled;
            } else {
                recovery_reason = TransitionReason::kHarnessFailure;
            }
            const bool task_watchdog_recovery =
                recovery_reason == TransitionReason::kTaskWatchdog;
            if (task_watchdog_recovery) {
                // The task terminal is independent of domain maintenance. It
                // is published after the old stop disposition is known and
                // before any replacement startup attempt.
                result.output_len = 0;
                result.status = -1;
                result.completion_status = COMP_STATUS_HUNG;
                result.error_code = ERR_DOMAIN_WATCHDOG_TIMEOUT;
                result.crash_signal = 0;
                recovery_result = Recover(
                    recovery_reason, RecoveryContext{}, report_result);
            } else {
                recovery_result = Recover(recovery_reason);
            }
            recovered = recovery_result.Recovered();
            if (recovered && !task_watchdog_recovery) {
                // Replacement startup reached Ready, but this task still owns
                // the daemon until its completion is published.
                EnterState(DomainState::kExecuting);
            }
            if (task_watchdog_recovery) {
                if (!recovered) {
                    const uint32_t maintenance_error =
                        recovery_result.OldDomainIsolated()
                            ? ERR_DOMAIN_REPLACEMENT_START_FAILED
                            : ERR_DOMAIN_OWNERSHIP_UNRECLAIMED;
                    if (!domain_registry_.PublishMaintenanceError(
                            maintenance_error)) {
                        LOG("domain supervisor maintenance error publish failed "
                            "worker=%u error=%u",
                            config_.worker_id, maintenance_error);
                    }
                    LOG("domain maintenance terminal worker=%u error=%u "
                        "kind=%u stage=%u stop_result=%u",
                        config_.worker_id, maintenance_error,
                        static_cast<unsigned>(recovery_result.kind),
                        static_cast<unsigned>(recovery_result.failed_stage),
                        static_cast<unsigned>(recovery_result.stop_result));
                }
            } else if (recovered && terminal_harness_failure) {
                // hang-evidence（8/9/12）保持 HUNG：重建成功只说明执行域换新，
                // 旧程序可能仍以 D 态残留在旧 namespace（loop 死后 SIGKILL 只是
                // pending，要等它脱离 D 态才死），任务终态仍是"结果丢失、程序
                // 可能还活着"→ 保持 HUNG 进 hang 池。infra 类（6/7/10/13，
                // 程序已证明退出 / 从未创建）才报 HARNESS_RECOVERED。
                if (!HarnessFatalIsHangTerminal(collected.fatal_reason)) {
                    result.completion_status = COMP_STATUS_HARNESS_RECOVERED;
                }
            } else if (!recovered) {
                const uint32_t original_error_code = result.error_code;
                const uint32_t maintenance_error =
                    recovery_result.OldDomainIsolated()
                        ? ERR_DOMAIN_REPLACEMENT_START_FAILED
                        : ERR_DOMAIN_OWNERSHIP_UNRECLAIMED;
                if (terminal_harness_failure) {
                    // 执行阶段 harness 失败的终态已由 HarnessFatalIsHangTerminal
                    // 判定为 HUNG / HARNESS_FATAL，恢复失败只改 error_code
                    // （14/15），不改变 hang 分类。
                    result.output_len = 0;
                    result.status = -1;
                    result.error_code = maintenance_error;
                    result.crash_signal = 0;
                } else {
                    // child-abort / cancelled：任务终态在 collect 时已定且
                    // 数据有效 / 取消已确认，重建失败是域维护问题，不能把任务
                    // 压成 infra —— 保持 CHILD_ABORTED+16 / CANCELLED+17，
                    // 维护失败走 error_latch 独立上报（14/15 → host 恢复）。
                    if (!domain_registry_.PublishMaintenanceError(
                            maintenance_error)) {
                        LOG("domain supervisor maintenance error publish failed "
                            "worker=%u error=%u",
                            config_.worker_id, maintenance_error);
                    }
                    LOG("domain maintenance terminal worker=%u error=%u "
                        "kind=%u stage=%u stop_result=%u",
                        config_.worker_id, maintenance_error,
                        static_cast<unsigned>(recovery_result.kind),
                        static_cast<unsigned>(recovery_result.failed_stage),
                        static_cast<unsigned>(recovery_result.stop_result));
                }
                LOG("task recovery terminal executor_id=%llu reason=%s "
                    "original_error=%u recovery_error=%u kind=%u stage=%u "
                    "ownership_reclaimed=%d stop_result=%u",
                    static_cast<unsigned long long>(result.executor_id),
                    TransitionReasonName(recovery_reason),
                    original_error_code, result.error_code,
                    static_cast<unsigned>(recovery_result.kind),
                    static_cast<unsigned>(recovery_result.failed_stage),
                    recovery_result.OldDomainIsolated() ? 1 : 0,
                    static_cast<unsigned>(recovery_result.stop_result));
            }
        } else {
            ResetRecoveryStreak();
        }

        report_result();
        if (recovery_required) {
            reported_in_domain_ = 0;
        } else {
            ++reported_in_domain_;
        }
        if (!recovered && recovery_required) {
            EnterState(DomainState::kFailed);
            exit_code = 1;
            break;
        }
        EnterState(DomainState::kReady);
    }

    if (State() != DomainState::kFailed) {
        const topology::DomainStopResult stop_result = StopDomain(
            topology::DomainStopIntent::kDaemonShutdown, true);
        if (stop_result == topology::DomainStopResult::kFailed) {
            EnterState(DomainState::kFailed);
            exit_code = 1;
        } else {
            EnterState(DomainState::kStopped);
        }
    }
    return exit_code;
}

} // namespace refuzz::worker

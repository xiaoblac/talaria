#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "worker/topology/reusable_child_topology.hpp"
#include "worker/topology/double_fork_topology.hpp"
#include "worker/topology/recycle_child_topology.hpp"

#include "worker/backend/exec_backend.hpp"
#include "worker/engine/loop_runtime.hpp"
#include "worker/engine/program_runtime.hpp"
#include "worker/engine/runtime_messages.hpp"
#include "worker/log/log_macros.hpp"
#include "worker/observation/observation_bus.hpp"

#include "refuzz/proto_wire/ivshmem_protocol.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <limits>

#define LOG(fmt, ...) ::refuzz::worker::log::WorkerLog("[Worker] " fmt "\n", ##__VA_ARGS__)

namespace refuzz::worker::topology {
namespace {

namespace eng = ::refuzz::worker::engine;

int PidfdOpen(pid_t pid)
{
#ifdef SYS_pidfd_open
    return static_cast<int>(::syscall(SYS_pidfd_open, pid, 0u));
#else
    (void)pid;
    errno = ENOSYS;
    return -1;
#endif
}

uint32_t CrashSignalFromStatus(int wstatus)
{
    if (WIFSIGNALED(wstatus)) {
        return static_cast<uint32_t>(WTERMSIG(wstatus));
    }
    if (WIFEXITED(wstatus)) {
        const int exit_code = WEXITSTATUS(wstatus);
        return exit_code >= 128 ? static_cast<uint32_t>(exit_code - 128) : 0;
    }
    return 0;
}

} // namespace

ReusableChildTopology::ReusableChildTopology(
    ::refuzz::worker::IExecBackend& backend,
    ::refuzz::worker::IObservationBus& bus)
    : backend_(&backend), bus_(&bus)
{}

DomainStartResult ReusableChildTopology::Setup(const TopologyConfig& cfg)
{
    cfg_ = cfg;
    if (cfg_.identity.proc_id == kAnyProcId) {
        cfg_.identity.worker_id = cfg_.worker_id;
        cfg_.identity.proc_id = cfg_.worker_id;
    }
    if (cfg_.startup_timeout_ms == 0) {
        cfg_.startup_timeout_ms = kDefaultDomainStartupTimeoutMs;
    }
    if (cfg_.startup_deadline_us == 0) {
        const uint64_t timeout_us =
            static_cast<uint64_t>(cfg_.startup_timeout_ms) * 1000ULL;
        const uint64_t current_us = now_us();
        cfg_.startup_deadline_us =
            timeout_us > std::numeric_limits<uint64_t>::max() - current_us
                ? std::numeric_limits<uint64_t>::max()
                : current_us + timeout_us;
    }
    return ForkChild();
}

DomainStartResult ReusableChildTopology::ForkChild()
{
    if (backend_ == nullptr || bus_ == nullptr) {
        errno = EINVAL;
        return MakeDomainStartRejected(
            cfg_.identity.proc_id, eng::LoopStartupStage::kUnknown, errno);
    }
    int ready_fds[2] = {-1, -1};
    int done_fds[2] = {-1, -1};
    if (::pipe2(ready_fds, O_CLOEXEC) < 0) {
        return MakeDomainStartRejected(
            cfg_.identity.proc_id, eng::LoopStartupStage::kUnknown, errno);
    }
    if (::pipe2(done_fds, O_CLOEXEC) < 0) {
        const int saved_errno = errno;
        ::close(ready_fds[0]);
        ::close(ready_fds[1]);
        errno = saved_errno;
        return MakeDomainStartRejected(
            cfg_.identity.proc_id, eng::LoopStartupStage::kUnknown, errno);
    }

    const pid_t pid = ::fork();
    if (pid < 0) {
        const int saved_errno = errno;
        ::close(ready_fds[0]);
        ::close(ready_fds[1]);
        ::close(done_fds[0]);
        ::close(done_fds[1]);
        errno = saved_errno;
        return MakeDomainStartRejected(
            cfg_.identity.proc_id, eng::LoopStartupStage::kUnknown, errno);
    }

    if (pid == 0) {
        ::close(ready_fds[1]);
        ::close(done_fds[0]);
        if (::setsid() < 0) {
            _exit(126);
        }

        eng::InlineProgramExecutor executor(*backend_, *bus_,
                                            cfg_.identity.worker_id,
                                            cfg_.identity.proc_id);
        eng::LoopRuntimeRun(ready_fds[0], done_fds[1],
                            cfg_.identity.worker_id,
                            cfg_.identity.proc_id,
                            *backend_, *bus_, cfg_.sandbox_mode,
                            cfg_.allow_no_private_mount_namespace_for_tests,
                            cfg_.transport_mapped_bytes,
                            cfg_.transport_shm_base,
                            cfg_.transport_shm_size,
                            cfg_.program_mapping,
                            -1,
                            executor);
    }

    ::close(ready_fds[0]);
    ::close(done_fds[1]);

    ctx_.pid = pid;
    ctx_.loop_pid = pid;
    ctx_.loop_pidfd = PidfdOpen(pid);
    ctx_.ns_runner_pidfd = -1;
    ctx_.separate_runner = false;
    ctx_.ready_pipe_w = ready_fds[1];
    ctx_.done_pipe_r = done_fds[0];
    ctx_.direct_child_reaped = false;
    ctx_.direct_child_status_known = false;
    ctx_.direct_child_status = 0;
    ++ctx_.generation;
    dispatch_failed_ = false;
    LOG("child forked pid=%d loop_pidfd=%d gen=%lu",
        pid, ctx_.loop_pidfd, ctx_.generation);
    return MakeDomainStartReady(cfg_.identity.proc_id);
}

DispatchHandle ReusableChildTopology::Dispatch(const ProgramRequest& req)
{
    DispatchHandle handle{ctx_.generation};

    eng::ReadyMsg message{};
    message.input_len = req.input_len;
    message.output_cap = req.output_cap;
    message.flags = req.flags;
    message.dispatch_gen = req.dispatch_gen;
    message.executor_id = req.executor_id;
    message.buffers = req.buffers;

    ssize_t written;
    do {
        written = ::write(ctx_.ready_pipe_w, &message, sizeof(message));
    } while (written < 0 && errno == EINTR);
    if (written != static_cast<ssize_t>(sizeof(message))) {
        dispatch_failed_ = true;
    }
    return handle;
}

int ReusableChildTopology::WaitChild(eng::DoneMsg& done,
                                     uint32_t timeout_ms,
                                     CancelPredicate cancel,
                                     void* cancel_user,
                                     uint32_t* crash_signal)
{
    const uint64_t deadline_us = timeout_ms == 0
        ? 0
        : now_us() + static_cast<uint64_t>(timeout_ms) * 1000ULL;

    for (;;) {
        const uint64_t current_us = now_us();
        if (timeout_ms > 0 && current_us >= deadline_us) {
            return 1;
        }

        int wait_ms = 100;
        if (timeout_ms > 0) {
            const uint64_t remaining_us = deadline_us - current_us;
            wait_ms = static_cast<int>((remaining_us + 999ULL) / 1000ULL);
            if (wait_ms > 100) {
                wait_ms = 100;
            }
            if (wait_ms < 1) {
                wait_ms = 1;
            }
        }

        pollfd pfds[3]{};
        nfds_t count = 0;
        const nfds_t done_index = count;
        pfds[count].fd = ctx_.done_pipe_r;
        pfds[count].events = POLLIN;
        ++count;

        int loop_index = -1;
        if (ctx_.loop_pidfd >= 0) {
            loop_index = static_cast<int>(count);
            pfds[count].fd = ctx_.loop_pidfd;
            pfds[count].events = POLLIN;
            ++count;
        }

        int runner_index = -1;
        if (ctx_.ns_runner_pidfd >= 0 &&
            ctx_.ns_runner_pidfd != ctx_.loop_pidfd) {
            runner_index = static_cast<int>(count);
            pfds[count].fd = ctx_.ns_runner_pidfd;
            pfds[count].events = POLLIN;
            ++count;
        }

        const int poll_result = ::poll(pfds, count, wait_ms);
        if (poll_result < 0) {
            if (errno == EINTR) {
                continue;
            }
            return 4;
        }

        if (poll_result > 0) {
            const short done_events = pfds[done_index].revents;
            if ((done_events & POLLIN) != 0) {
                ssize_t received;
                do {
                    received = ::read(ctx_.done_pipe_r, &done, sizeof(done));
                } while (received < 0 && errno == EINTR);
                if (received == static_cast<ssize_t>(sizeof(done))) {
                    return 0;
                }
                return 4;
            }
            if ((done_events & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
                return 4;
            }

            if (loop_index >= 0 &&
                (pfds[loop_index].revents &
                 (POLLIN | POLLHUP | POLLERR | POLLNVAL)) != 0) {
                if (ctx_.ns_runner_pidfd < 0 && !ctx_.direct_child_reaped) {
                    int wstatus = 0;
                    pid_t reaped;
                    do {
                        reaped = ::waitpid(ctx_.pid, &wstatus, WNOHANG);
                    } while (reaped < 0 && errno == EINTR);
                    if (reaped == ctx_.pid) {
                        ctx_.direct_child_reaped = true;
                        ctx_.direct_child_status_known = true;
                        ctx_.direct_child_status = wstatus;
                        *crash_signal = CrashSignalFromStatus(wstatus);
                    }
                }
                return 2;
            }

            if (runner_index >= 0 &&
                (pfds[runner_index].revents &
                 (POLLIN | POLLHUP | POLLERR | POLLNVAL)) != 0) {
                if (!ctx_.direct_child_reaped) {
                    int wstatus = 0;
                    pid_t reaped;
                    do {
                        reaped = ::waitpid(ctx_.pid, &wstatus, WNOHANG);
                    } while (reaped < 0 && errno == EINTR);
                    if (reaped == ctx_.pid) {
                        ctx_.direct_child_reaped = true;
                        ctx_.direct_child_status_known = true;
                        ctx_.direct_child_status = wstatus;
                    } else if (reaped < 0 && errno == ECHILD) {
                        ctx_.direct_child_reaped = true;
                        ctx_.direct_child_status_known = false;
                        ctx_.direct_child_status = 0;
                    }
                }
                return 5;
            }
        }

        if (cancel != nullptr && cancel(cancel_user)) {
            return 3;
        }

        if (ctx_.loop_pidfd < 0 && ctx_.pid > 0 && !ctx_.direct_child_reaped) {
            int wstatus = 0;
            pid_t reaped;
            do {
                reaped = ::waitpid(ctx_.pid, &wstatus, WNOHANG);
            } while (reaped < 0 && errno == EINTR);
            if (reaped == ctx_.pid) {
                ctx_.direct_child_reaped = true;
                ctx_.direct_child_status_known = true;
                ctx_.direct_child_status = wstatus;
                *crash_signal = CrashSignalFromStatus(wstatus);
                return 2;
            }
        }
    }
}

CollectResult ReusableChildTopology::Collect(DispatchHandle handle,
                                             uint32_t timeout_ms,
                                             CancelPredicate cancel,
                                             void* cancel_user)
{
    CollectResult result{};
    if (handle.generation != ctx_.generation || dispatch_failed_) {
        result.kind = CollectKind::kHarnessFail;
        result.fatal_reason = eng::HarnessFatalReason::kForkServerProtocol;
        return result;
    }

    eng::DoneMsg done{};
    uint32_t crash_signal = 0;
    const int wait_result = WaitChild(done, timeout_ms, cancel, cancel_user,
                                      &crash_signal);
    switch (wait_result) {
    case 0:
        result.kind = CollectKind::kDone;
        result.output_len = done.output_len;
        result.status = done.status;
        result.flags = done.flags;
        result.result_kind = done.result_kind;
        result.crash_signal = done.crash_signal;
        result.fatal_reason = done.fatal_reason;
        break;
    case 1:
        result.fatal_reason = eng::HarnessFatalReason::kDomainWatchdogTimeout;
        result.kind = CollectKind::kTimeout;
        break;
    case 2:
    case 5: {
        const bool harness_fatal = UnexpectedChildExitIsHarnessFatal();
        if (!harness_fatal) {
            result.kind = CollectKind::kChildAborted;
            result.result_kind = eng::RuntimeResultKind::kCrash;
            result.crash_signal = crash_signal;
        } else {
            result.kind = CollectKind::kHarnessFail;
            result.fatal_reason = eng::HarnessFatalReason::kForkServerProtocol;
        }
        break;
    }
    case 3:
        result.kind = CollectKind::kCancelled;
        break;
    case 4:
    default:
        result.kind = CollectKind::kHarnessFail;
        result.fatal_reason = eng::HarnessFatalReason::kForkServerProtocol;
        break;
    }
    return result;
}

DomainStopResult ReusableChildTopology::StopChild(const DomainStopPlan& plan)
{
    const DomainStopResult result = StopDomainHandle(
        ctx_, DomainStopDeadlineUs(plan), plan);
    dispatch_failed_ = false;
    return result;
}

bool ReusableChildTopology::ExecutionDomainExited() const
{
    return DomainHandleExecutionExited(ctx_);
}

DomainStopResult ReusableChildTopology::Stop(const DomainStopPlan& plan)
{
    return StopChild(plan);
}

std::unique_ptr<ProcessTopology> MakeTopology(
    TopologyKind kind,
    ::refuzz::worker::IExecBackend& backend,
    ::refuzz::worker::IObservationBus& bus)
{
    switch (kind) {
    case TopologyKind::kReusableChild:
        return std::make_unique<ReusableChildTopology>(backend, bus);
    case TopologyKind::kRecycleChild:
        return std::make_unique<RecycleChildTopology>(backend, bus);
    case TopologyKind::kDoubleFork:
        return std::make_unique<DoubleForkTopology>(backend, bus);
    case TopologyKind::kExecDoubleFork:
        return std::make_unique<ExecDoubleForkTopology>();
    }
    return nullptr;
}

} // namespace refuzz::worker::topology

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "worker/topology/domain_handle.hpp"

#include "worker/log/log_macros.hpp"
#include "worker/sandbox/device_init/device_init.hpp"

#include "refuzz/proto_wire/ivshmem_protocol.h"

#include <algorithm>
#include <cerrno>
#include <climits>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <poll.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define LOG(fmt, ...) ::refuzz::worker::log::WorkerLog("[Worker] " fmt "\n", ##__VA_ARGS__)

namespace refuzz::worker::topology {
namespace {

int PidfdSendSignal(int pidfd, int signal_number)
{
#ifdef SYS_pidfd_send_signal
    return static_cast<int>(
        ::syscall(SYS_pidfd_send_signal, pidfd, signal_number, nullptr, 0u));
#else
    (void)pidfd;
    (void)signal_number;
    errno = ENOSYS;
    return -1;
#endif
}

// Resolve a pidfd's daemon-namespace PID for handles created before the
// explicit handoff field was added, or for partial-startup recovery. The
// kernel exposes the caller-namespace PID in /proc/self/fdinfo/<fd> ("Pid:"
// line). Returns -1 when the fd is not a pidfd or /proc is unavailable;
// callers keep the single-pid fallback in that case.
pid_t PidfdToPid(int pidfd)
{
    if (pidfd < 0) {
        return -1;
    }
    char path[64];
    const int path_len = ::snprintf(
        path, sizeof(path), "/proc/self/fdinfo/%d", pidfd);
    if (path_len <= 0 ||
        static_cast<std::size_t>(path_len) >= sizeof(path)) {
        return -1;
    }
    const int fd = ::open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    char buf[256];
    ssize_t read_size;
    do {
        read_size = ::read(fd, buf, sizeof(buf) - 1);
    } while (read_size < 0 && errno == EINTR);
    ::close(fd);
    if (read_size <= 0) {
        return -1;
    }
    buf[read_size] = '\0';
    char* pid_line = nullptr;
    if (::strncmp(buf, "Pid:", 4) == 0) {
        pid_line = buf;
    } else {
        pid_line = ::strstr(buf, "\nPid:");
        if (pid_line != nullptr) {
            ++pid_line;
        }
    }
    if (pid_line == nullptr) {
        return -1;
    }
    pid_line += 4;
    errno = 0;
    char* end = nullptr;
    const long parsed = ::strtol(pid_line, &end, 10);
    if (errno != 0 || end == pid_line || parsed <= 0 ||
        parsed > std::numeric_limits<pid_t>::max()) {
        return -1;
    }
    return static_cast<pid_t>(parsed);
}

void CloseFd(int* fd)
{
    if (*fd >= 0) {
        ::close(*fd);
        *fd = -1;
    }
}

uint64_t SaturatingAddUs(uint64_t base, uint64_t delta)
{
    return delta > std::numeric_limits<uint64_t>::max() - base
        ? std::numeric_limits<uint64_t>::max()
        : base + delta;
}

uint64_t StageDeadline(uint64_t absolute_deadline_us, uint32_t timeout_ms)
{
    return std::min(
        absolute_deadline_us,
        SaturatingAddUs(now_us(), static_cast<uint64_t>(timeout_ms) * 1000ULL));
}

int RemainingTimeoutMs(uint64_t absolute_deadline_us)
{
    const uint64_t now = now_us();
    if (absolute_deadline_us <= now) {
        return 0;
    }
    const uint64_t remaining_us = absolute_deadline_us - now;
    const uint64_t remaining_ms = (remaining_us + 999ULL) / 1000ULL;
    return remaining_ms > static_cast<uint64_t>(INT_MAX)
        ? INT_MAX : static_cast<int>(remaining_ms);
}

bool PidfdExited(int pidfd)
{
    if (pidfd < 0) {
        return false;
    }
    pollfd descriptor{};
    descriptor.fd = pidfd;
    descriptor.events = POLLIN;
    for (;;) {
        const int result = ::poll(&descriptor, 1, 0);
        if (result > 0) {
            return (descriptor.revents &
                    (POLLIN | POLLHUP | POLLERR | POLLNVAL)) != 0;
        }
        if (result == 0 || errno != EINTR) {
            return false;
        }
    }
}

bool WaitPidfdUntil(int pidfd, uint64_t absolute_deadline_us)
{
    if (pidfd < 0) {
        return false;
    }
    pollfd descriptor{};
    descriptor.fd = pidfd;
    descriptor.events = POLLIN;
    for (;;) {
        const int result = ::poll(
            &descriptor, 1, RemainingTimeoutMs(absolute_deadline_us));
        if (result > 0) {
            return (descriptor.revents &
                    (POLLIN | POLLHUP | POLLERR | POLLNVAL)) != 0;
        }
        if (result == 0) {
            return PidfdExited(pidfd);
        }
        if (errno != EINTR) {
            return false;
        }
    }
}

bool TryReapDirectChild(DomainHandle& handle)
{
    if (handle.direct_child_reaped || handle.pid <= 0) {
        return true;
    }

    int status = 0;
    pid_t result;
    do {
        result = ::waitpid(handle.pid, &status, WNOHANG);
    } while (result < 0 && errno == EINTR);
    if (result == handle.pid) {
        handle.direct_child_reaped = true;
        handle.direct_child_status_known = true;
        handle.direct_child_status = status;
        return true;
    }
    if (result < 0 && errno == ECHILD) {
        handle.direct_child_reaped = true;
        handle.direct_child_status_known = false;
        handle.direct_child_status = 0;
        return true;
    }
    return false;
}

bool WaitDirectChildUntil(DomainHandle& handle,
                          uint64_t absolute_deadline_us)
{
    for (;;) {
        if (TryReapDirectChild(handle)) {
            return true;
        }
        const uint64_t now = now_us();
        if (now >= absolute_deadline_us) {
            return TryReapDirectChild(handle);
        }
        if (handle.ns_runner_pidfd >= 0) {
            if (!WaitPidfdUntil(handle.ns_runner_pidfd,
                                absolute_deadline_us)) {
                return TryReapDirectChild(handle);
            }
            continue;
        }
        const uint64_t remaining_us = absolute_deadline_us - now;
        ::usleep(static_cast<useconds_t>(
            std::min<uint64_t>(remaining_us, 10'000ULL)));
    }
}

bool KillDirectChild(DomainHandle& handle, bool* forced)
{
    if (handle.pid <= 0 || handle.direct_child_reaped) {
        return true;
    }
    // Align with syzkaller kill_and_wait(): signal the whole process group
    // first, then single-kill the group leader as the setup-race fallback.
    // ns-runner calls setpgid(0,0) at spawn so its PGID == its own pid; a
    // group kill can never bleed into the daemon's group. Non-group-leader
    // test stubs make kill(-pid) fail with ESRCH, which falls through to the
    // single kill below.
    bool group_signaled = false;
    if (::kill(-handle.pid, SIGKILL) == 0) {
        group_signaled = true;
    } else if (errno != ESRCH) {
        LOG("stop handle: direct child group kill failed pid=%d errno=%d",
            handle.pid, errno);
    }
    if (::kill(handle.pid, SIGKILL) == 0) {
        *forced = true;
        return true;
    }
    if (errno == ESRCH) {
        *forced = *forced || group_signaled;
        return true;
    }
    return false;
}

enum class LoopKillOutcome : uint8_t {
    kExited,  // 目标已不存在（ESRCH），无需再等
    kSent,    // SIGKILL 已送达（进程组和/或 pidfd）
    kFailed,  // 所有信号路径都失败
};

// Kill the loop with the syzkaller pair: group kill (-pgid) first, then a
// single pidfd signal as the race fallback. The loop calls setsid() at
// startup, so its PGID equals its pid; the group covers transient children
// that have not yet setpgrp()'d into their own program group. loop_pid is sent
// in the startup handoff; PidfdToPid remains a fallback for older/partial
// handles.
LoopKillOutcome KillLoopWithGroup(const DomainHandle& handle, pid_t loop_pid)
{
    bool group_signaled = false;
    bool group_missing = false;
    if (loop_pid > 0) {
        if (::kill(-loop_pid, SIGKILL) == 0) {
            group_signaled = true;
        } else if (errno == ESRCH) {
            group_missing = true;
        } else {
            LOG("stop handle: loop group kill failed pid=%d errno=%d",
                loop_pid, errno);
        }
    }
    if (handle.loop_pidfd >= 0) {
        if (PidfdSendSignal(handle.loop_pidfd, SIGKILL) == 0) {
            return LoopKillOutcome::kSent;
        }
        if (errno == ESRCH) {
            return group_signaled ? LoopKillOutcome::kSent
                                  : LoopKillOutcome::kExited;
        }
        LOG("stop handle: loop pidfd kill failed pidfd=%d errno=%d",
            handle.loop_pidfd, errno);
    }
    if (group_signaled) {
        return LoopKillOutcome::kSent;
    }
    return group_missing ? LoopKillOutcome::kExited
                         : LoopKillOutcome::kFailed;
}

// Align with syzkaller kill_and_wait(): give a non-blocking 100 ms grace
// after SIGKILL, then abort every FUSE connection visible through the
// execution domain's fusectl mount. fusectl is mounted into the daemon's root
// mount namespace by worker 0 at startup, so both the daemon (here) and every
// loop (program-level timeout path) can see the connections. Aborting wakes
// tasks stuck in D-state on a FUSE request so their pending SIGKILL can land.
// The grace is clamped to the caller's absolute stop deadline, so this never
// extends the stop budget. At most one abort per StopDomainHandle call.
bool WaitLoopKillWithFuseEscalation(const DomainHandle& handle,
                                    uint64_t kill_deadline_us,
                                    bool* fuse_aborted)
{
    if (handle.loop_pidfd < 0) {
        return false;
    }
    const uint64_t grace_deadline_us = std::min(
        kill_deadline_us, SaturatingAddUs(now_us(), 100'000ULL));
    bool exited = WaitPidfdUntil(handle.loop_pidfd, grace_deadline_us);
    if (!exited && !*fuse_aborted && now_us() < kill_deadline_us) {
        *fuse_aborted = true;
        LOG("stop handle: loop alive after SIGKILL pid=%d — aborting fuse "
            "connections",
            handle.pid);
        (void)::refuzz::worker::sandbox::device_init::AbortFuseConnections(
            kill_deadline_us);
    }
    if (!exited) {
        exited = WaitPidfdUntil(handle.loop_pidfd, kill_deadline_us);
    }
    return exited;
}

void ClearConsumedHandle(DomainHandle& handle)
{
    CloseFd(&handle.ready_pipe_w);
    CloseFd(&handle.done_pipe_r);
    CloseFd(&handle.loop_pidfd);
    CloseFd(&handle.ns_runner_pidfd);
    handle.pid = -1;
    handle.loop_pid = -1;
    handle.separate_runner = false;
    handle.direct_child_reaped = false;
    handle.direct_child_status_known = false;
    handle.direct_child_status = 0;
}

} // namespace

uint64_t DomainStopDeadlineUs(const DomainStopPlan& plan)
{
    if (plan.absolute_deadline_us != 0) {
        return plan.absolute_deadline_us;
    }
    uint64_t timeout_ms = plan.kill_timeout_ms;
    timeout_ms += plan.runner_timeout_ms;
    timeout_ms += plan.reap_timeout_ms;
    if (plan.graceful) {
        timeout_ms += plan.graceful_timeout_ms;
    }
    return SaturatingAddUs(now_us(), timeout_ms * 1000ULL);
}

DomainStopResult StopDomainHandle(DomainHandle& handle,
                                  uint64_t absolute_deadline_us,
                                  const DomainStopPlan& plan)
{
    if (absolute_deadline_us == 0) {
        absolute_deadline_us = DomainStopDeadlineUs(plan);
    }

    const bool had_child = handle.pid > 0 || handle.direct_child_reaped;
    bool forced = false;
    bool loop_exited = handle.loop_pidfd >= 0
        ? PidfdExited(handle.loop_pidfd)
        : (!handle.separate_runner && handle.direct_child_reaped);
    const bool graceful_stop_requested =
        plan.graceful && had_child && !loop_exited;
    if (handle.loop_pid <= 0 && handle.loop_pidfd >= 0) {
        handle.loop_pid = PidfdToPid(handle.loop_pidfd);
    }

    // Closing the command pipe prevents any new dispatch and is the graceful
    // signal understood by LoopRuntime. Forced startup cleanup uses the same
    // irreversible ownership transition before escalation.
    CloseFd(&handle.ready_pipe_w);

    if (graceful_stop_requested) {
        const uint64_t graceful_deadline = StageDeadline(
            absolute_deadline_us, plan.graceful_timeout_ms);
        if (handle.loop_pidfd >= 0) {
            loop_exited = WaitPidfdUntil(handle.loop_pidfd,
                                         graceful_deadline);
        } else if (!handle.separate_runner) {
            loop_exited = WaitDirectChildUntil(handle, graceful_deadline);
        }
    }

    bool runner_killed = false;
    bool loop_signal_sent = false;
    bool fuse_aborted = false;
    if (!loop_exited) {
        if (handle.loop_pidfd >= 0) {
            const LoopKillOutcome outcome =
                KillLoopWithGroup(handle, handle.loop_pid);
            if (outcome == LoopKillOutcome::kExited) {
                loop_exited = true;
            } else if (outcome == LoopKillOutcome::kSent) {
                forced = true;
                loop_signal_sent = true;
            }
        }

        if (!loop_exited && !loop_signal_sent) {
            if (handle.separate_runner) {
                if (!KillDirectChild(handle, &forced)) {
                    LOG("stop handle: failed to kill ns-runner pid=%d errno=%d",
                        handle.pid, errno);
                    return DomainStopResult::kFailed;
                }
                runner_killed = true;
            } else if (!KillDirectChild(handle, &forced)) {
                LOG("stop handle: failed to kill child pid=%d errno=%d",
                    handle.pid, errno);
                return DomainStopResult::kFailed;
            }
        }

        if (handle.loop_pidfd >= 0 && !loop_exited) {
            loop_exited = WaitLoopKillWithFuseEscalation(
                handle,
                StageDeadline(absolute_deadline_us, plan.kill_timeout_ms),
                &fuse_aborted);
        }

        if (!loop_exited && handle.separate_runner && !runner_killed) {
            if (!KillDirectChild(handle, &forced)) {
                LOG("stop handle: loop stuck and ns-runner kill failed pid=%d errno=%d",
                    handle.pid, errno);
                return DomainStopResult::kFailed;
            }
            runner_killed = true;
        }
        if (!loop_exited && !handle.separate_runner &&
            handle.loop_pidfd >= 0) {
            LOG("stop handle: child did not exit pid=%d", handle.pid);
            return DomainStopResult::kFailed;
        }
    }

    if (handle.separate_runner && !handle.direct_child_reaped) {
        bool runner_exited = WaitDirectChildUntil(
            handle,
            StageDeadline(absolute_deadline_us, plan.runner_timeout_ms));
        if (!runner_exited) {
            if (!KillDirectChild(handle, &forced)) {
                LOG("stop handle: ns-runner escalation failed pid=%d errno=%d",
                    handle.pid, errno);
                return DomainStopResult::kFailed;
            }
            // ns-runner 死后 loop 若仍卡在 FUSE D-state，abort 才能让挂起的
            // SIGKILL 落地（loop_pidfd == -1 的 startup gap 也走这里）。
            if (!fuse_aborted && now_us() < absolute_deadline_us) {
                fuse_aborted = true;
                LOG("stop handle: ns-runner alive after kill pid=%d — aborting "
                    "fuse connections",
                    handle.pid);
                (void)::refuzz::worker::sandbox::device_init::
                    AbortFuseConnections(absolute_deadline_us);
            }
            runner_exited = WaitDirectChildUntil(
                handle,
                StageDeadline(absolute_deadline_us, plan.kill_timeout_ms));
        }
        if (!runner_exited) {
            LOG("stop handle: ns-runner did not exit pid=%d", handle.pid);
            return DomainStopResult::kFailed;
        }
    }

    if (!handle.direct_child_reaped &&
        !WaitDirectChildUntil(
            handle,
            StageDeadline(absolute_deadline_us, plan.reap_timeout_ms))) {
        LOG("stop handle: failed to reap direct child pid=%d errno=%d",
            handle.pid, errno);
        return DomainStopResult::kFailed;
    }

    if (handle.separate_runner && handle.loop_pidfd >= 0 && !loop_exited) {
        loop_exited = WaitPidfdUntil(handle.loop_pidfd,
                                     absolute_deadline_us);
        if (!loop_exited) {
            if (plan.allow_abandon && loop_signal_sent &&
                handle.direct_child_reaped) {
                LOG("stop handle: abandoning signaled loop after ns-runner reap pid=%d",
                    handle.pid);
                ClearConsumedHandle(handle);
                return DomainStopResult::kAbandoned;
            }
            LOG("stop handle: loop survived ns-runner pid=%d", handle.pid);
            return DomainStopResult::kFailed;
        }
    }

    // [partial-startup gap] separate-runner 域在 loop pidfd handoff 到达前被停：
    // loop_pidfd == -1 时 daemon 对 loop 既不能发信号也不能 wait。即使 exec
    // loop 已注册 PDEATHSIG，daemon 仍无法从这个半初始化句柄证明 loop 的实际
    // 归宿；若 ns-runner 是被杀或异常死亡（非 WIFEXITED），只能保守地保留
    // kFailed，不能把“物理回收已确认”的 kForced 发给上层。只有 ns-runner
    // 自行干净退出才允许 kForced：其失败路径保证 loop 已杀或从未 fork，正常
    // 路径 waitpid(loop) 后才退出。
    if (had_child && handle.separate_runner &&
        handle.loop_pidfd < 0 && !loop_exited) {
        const bool runner_self_exited =
            handle.direct_child_reaped && handle.direct_child_status_known &&
            WIFEXITED(handle.direct_child_status);
        if (!runner_self_exited) {
            LOG("stop handle: loop fate unknown without pidfd pid=%d",
                handle.pid);
            return DomainStopResult::kFailed;
        }
    }

    const bool clean_graceful_exit =
        !had_child ||
        (graceful_stop_requested && !forced &&
         handle.direct_child_reaped && handle.direct_child_status_known &&
         WIFEXITED(handle.direct_child_status) &&
         WEXITSTATUS(handle.direct_child_status) == 0);
    if (had_child && !clean_graceful_exit) {
        LOG("stop handle: execution domain exit untrusted graceful=%d forced=%d "
            "status_known=%d status=0x%x",
            graceful_stop_requested ? 1 : 0, forced ? 1 : 0,
            handle.direct_child_status_known ? 1 : 0,
            handle.direct_child_status);
    }

    ClearConsumedHandle(handle);
    return clean_graceful_exit ? DomainStopResult::kClean
                               : DomainStopResult::kForced;
}

bool DomainHandleExecutionExited(const DomainHandle& handle)
{
    return handle.direct_child_reaped ||
           PidfdExited(handle.loop_pidfd) ||
           PidfdExited(handle.ns_runner_pidfd);
}

} // namespace refuzz::worker::topology

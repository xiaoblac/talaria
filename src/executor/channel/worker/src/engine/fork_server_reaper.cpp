#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "worker/engine/fork_server_reaper.hpp"
#include "worker/perf/worker_perf.hpp"

#include <algorithm>
#include <cerrno>
#include <csignal>
#include <ctime>
#include <poll.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

namespace refuzz::worker::engine {

namespace {

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

void RemovePid(std::vector<pid_t>* pids, pid_t pid)
{
    if (pids == nullptr) {
        return;
    }
    const auto it = std::find(pids->begin(), pids->end(), pid);
    if (it != pids->end()) {
        pids->erase(it);
    }
}

bool ContainsPid(const std::vector<pid_t>& pids, pid_t pid)
{
    return std::find(pids.begin(), pids.end(), pid) != pids.end();
}

} // namespace

ForkServerReaper::ForkServerReaper(pid_t main_pid)
    : main_pid_(main_pid)
{
    if (main_pid_ > 0) {
        pidfd_ = PidfdOpen(main_pid_);
    } else {
        SetError(ForkServerReapError::kWaitFailed, EINVAL);
    }
}

ForkServerReaper::~ForkServerReaper()
{
    if (pidfd_ >= 0) {
        ::close(pidfd_);
    }
}

void ForkServerReaper::SetError(ForkServerReapError error, int error_number)
{
    if (error_ != ForkServerReapError::kNone) {
        return;
    }
    error_ = error;
    error_number_ = error_number;
}

void ForkServerReaper::RememberStoppedDescendant(pid_t pid)
{
    if (std::find(observed_stopped_descendants_.begin(),
                  observed_stopped_descendants_.end(), pid) ==
        observed_stopped_descendants_.end()) {
        observed_stopped_descendants_.push_back(pid);
    }
}

bool ForkServerReaper::KillStoppedDescendant(pid_t pid)
{
    if (::kill(pid, SIGKILL) != 0) {
        if (errno == ESRCH) {
            return true;
        }
        SetError(ForkServerReapError::kWaitFailed, errno);
        return false;
    }
    ++stats_.stopped_children_killed;
    return true;
}

bool ForkServerReaper::ConsumeStatus(pid_t pid, int status, const struct rusage* ru)
{
    const bool terminal = WIFEXITED(status) || WIFSIGNALED(status);
    if (pid == main_pid_) {
        if (terminal) {
            main_status_ = status;
            main_exited_ = true;
            if (::refuzz::worker::perf::Enabled()) {
                // Harvest the optional performance ledger at the exact reap
                // moment. Functional child status handling does not depend on
                // either field.
                if (ru != nullptr) {
                    main_rusage_ = *ru;
                    main_rusage_valid_ = true;
                }
                struct timespec ts;
                if (::clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
                    main_reap_ts_us_ =
                        static_cast<std::uint64_t>(ts.tv_sec) * 1000000ULL +
                        static_cast<std::uint64_t>(ts.tv_nsec) / 1000ULL;
                }
            }
        }
        return true;
    }

    if (terminal) {
        ++stats_.descendants_reaped;
        RemovePid(&observed_stopped_descendants_, pid);
        return true;
    }
    if (WIFSTOPPED(status)) {
        RememberStoppedDescendant(pid);
    }
    return true;
}

bool ForkServerReaper::Drain()
{
    return DrainReady();
}

bool ForkServerReaper::DrainReady()
{
    for (;;) {
        int status = 0;
        errno = 0;
        struct rusage ru {};
        struct rusage* ru_out = ::refuzz::worker::perf::Enabled()
            ? &ru : nullptr;
        const pid_t pid = ::wait4(-1, &status, WNOHANG | __WALL, ru_out);
        if (pid > 0) {
            if (!ConsumeStatus(pid, status, ru_out)) {
                return false;
            }
            continue;
        }
        if (pid == 0) {
            return true;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == ECHILD) {
            if (!main_exited_) {
                SetError(ForkServerReapError::kMainStatusLost, ECHILD);
                return false;
            }
            return true;
        }
        SetError(ForkServerReapError::kWaitFailed, errno);
        return false;
    }
}

bool ForkServerReaper::WaitForMainBlocking()
{
    if (error_ != ForkServerReapError::kNone) {
        return false;
    }
    while (!main_exited_) {
        int status = 0;
        errno = 0;
        struct rusage ru {};
        struct rusage* ru_out = ::refuzz::worker::perf::Enabled()
            ? &ru : nullptr;
        const pid_t pid = ::wait4(-1, &status, __WALL, ru_out);
        if (pid > 0) {
            if (!ConsumeStatus(pid, status, ru_out)) {
                return false;
            }
            continue;
        }
        if (pid < 0 && errno == EINTR) {
            continue;
        }
        if (pid < 0 && errno == ECHILD) {
            SetError(ForkServerReapError::kMainStatusLost, ECHILD);
        } else {
            SetError(ForkServerReapError::kWaitFailed, errno);
        }
        return false;
    }
    return true;
}

ForkServerWaitResult ForkServerReaper::WaitFor(std::uint32_t timeout_ms,
                                               int extra_fd,
                                               bool* extra_fd_ready)
{
    if (extra_fd_ready != nullptr) {
        *extra_fd_ready = false;
    }
    if (error_ != ForkServerReapError::kNone) {
        return ForkServerWaitResult::kError;
    }
    if (main_exited_) {
        return ForkServerWaitResult::kMainExited;
    }

    pollfd pfds[2]{};
    nfds_t n = 0;
    int extra_idx = -1;
    if (pidfd_ >= 0) {
        pfds[n].fd = pidfd_;
        pfds[n].events = POLLIN;
        ++n;
    }
    if (extra_fd >= 0) {
        extra_idx = static_cast<int>(n);
        pfds[n].fd = extra_fd;
        pfds[n].events = POLLIN;
        ++n;
    }
    int poll_result = 0;
    if (n > 0) {
        poll_result = ::poll(pfds, n, static_cast<int>(timeout_ms));
    } else {
        poll_result = ::poll(nullptr, 0, static_cast<int>(timeout_ms));
    }
    const int poll_error = (poll_result < 0) ? errno : 0;

    // [early-publish ordering] Check the extra fd BEFORE draining/reaping.
    // If it's ready, return immediately without touching DrainReady() at all
    // this call -- even if pidfd_ is ALSO ready in the same poll_result, the
    // reap is deferred to a later, explicit Drain() call the caller makes
    // after it has reacted to the extra-fd signal. This is what turns "publish
    // before reap" from an empirical timing margin into a structural
    // guarantee: the code never lets a reap happen ahead of the caller's
    // chance to observe the signal that woke it, regardless of how close
    // together (or simultaneous) the two underlying events actually were.
    if (extra_idx >= 0 && poll_result > 0 &&
        (pfds[extra_idx].revents &
         (POLLIN | POLLERR | POLLHUP | POLLNVAL)) != 0) {
        if (extra_fd_ready != nullptr) {
            *extra_fd_ready = true;
        }
        return ForkServerWaitResult::kExtraFdReady;
    }

    if (!DrainReady()) {
        return ForkServerWaitResult::kError;
    }
    if (main_exited_) {
        return ForkServerWaitResult::kMainExited;
    }
    if (poll_result < 0 && poll_error != EINTR) {
        SetError(ForkServerReapError::kWaitFailed, poll_error);
        return ForkServerWaitResult::kError;
    }
    return ForkServerWaitResult::kPending;
}

bool ForkServerReaper::ScanAndSignalStopped(std::vector<pid_t>* signaled)
{
    for (int safety = 0; safety < 64; ++safety) {
        int status = 0;
        errno = 0;
        const pid_t pid =
            ::waitpid(-1, &status, WNOHANG | WUNTRACED | __WALL);
        if (pid > 0) {
            if (pid == main_pid_) {
                SetError(ForkServerReapError::kMainStatusLost, ECHILD);
                return false;
            }
            if (WIFSTOPPED(status)) {
                if (ContainsPid(*signaled, pid)) {
                    return true;
                }
                if (!KillStoppedDescendant(pid)) {
                    return true;
                }
                signaled->push_back(pid);
            } else if (WIFEXITED(status) || WIFSIGNALED(status)) {
                ++stats_.descendants_reaped;
                RemovePid(&observed_stopped_descendants_, pid);
            }
            continue;
        }
        if (pid == 0) {
            return true;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == ECHILD) {
            return true;
        }
        SetError(ForkServerReapError::kWaitFailed, errno);
        return true;
    }
    return true;
}

bool ForkServerReaper::SignalStoppedDescendants()
{
    if (!main_exited_) {
        SetError(ForkServerReapError::kMainStatusLost, ECHILD);
        return false;
    }

    std::vector<pid_t> signaled;
    const auto observed_stopped = observed_stopped_descendants_;
    observed_stopped_descendants_.clear();
    for (pid_t pid : observed_stopped) {
        if (!KillStoppedDescendant(pid)) {
            return true;
        }
        signaled.push_back(pid);
    }
    return ScanAndSignalStopped(&signaled);
}

} // namespace refuzz::worker::engine

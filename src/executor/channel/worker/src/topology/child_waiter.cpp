// ChildWaiter 实现。

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "worker/topology/child_waiter.hpp"

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>

namespace refuzz::worker::topology {

namespace {

// glibc < 2.36 没有 pidfd_open wrapper;直接走 syscall 入口。
// Linux >= 5.3 才有 SYS_pidfd_open;更老 kernel ENOSYS,caller fallback。
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

} // namespace

ChildWaiter::~ChildWaiter() { Reset(); }

ChildWaiter::ChildWaiter(ChildWaiter&& other) noexcept
    : pid_(other.pid_)
    , pidfd_(other.pidfd_)
    , exit_status_(other.exit_status_)
    , exited_(other.exited_)
{
    other.pid_ = -1;
    other.pidfd_ = -1;
    other.exited_ = false;
    other.exit_status_ = 0;
}

ChildWaiter& ChildWaiter::operator=(ChildWaiter&& other) noexcept
{
    if (this != &other) {
        Reset();
        pid_ = other.pid_;
        pidfd_ = other.pidfd_;
        exit_status_ = other.exit_status_;
        exited_ = other.exited_;
        other.pid_ = -1;
        other.pidfd_ = -1;
        other.exited_ = false;
        other.exit_status_ = 0;
    }
    return *this;
}

void ChildWaiter::Reset()
{
    if (pidfd_ >= 0) {
        ::close(pidfd_);
        pidfd_ = -1;
    }
    pid_ = -1;
    exit_status_ = 0;
    exited_ = false;
}

int ChildWaiter::Watch(pid_t pid)
{
    if (pid <= 0) {
        return -EINVAL;
    }
    Reset();
    pid_ = pid;
    // Best-effort: 失败时 fallback 到 waitpid-only,Watch 仍算成功。
    pidfd_ = PidfdOpen(pid);
    return 0;
}

int ChildWaiter::ReleasePollFd()
{
    const int fd = pidfd_;
    pidfd_ = -1;
    return fd;
}

bool ChildWaiter::TryReap()
{
    if (exited_) return true;
    if (pid_ <= 0) return false;

    int wstatus = 0;
    const pid_t w = ::waitpid(pid_, &wstatus, WNOHANG);
    if (w == pid_) {
        exit_status_ = wstatus;
        exited_ = true;
        return true;
    }
    if (w < 0 && errno == ECHILD) {
        // 已被别人 reap 过(eg. signal handler);child 死了但我们拿不到 status。
        exited_ = true;
        exit_status_ = 0;
        return true;
    }
    return false;
}

bool ChildWaiter::HasExited()
{
    if (exited_) return true;

    if (pidfd_ >= 0) {
        // pidfd 路径:poll(POLLIN, 0) 等于查询是否已死。
        struct pollfd pfd{};
        pfd.fd = pidfd_;
        pfd.events = POLLIN;
        const int r = ::poll(&pfd, 1, 0);
        if (r > 0 && (pfd.revents & POLLIN)) {
            return TryReap();
        }
        // EINTR / 未 ready / 出错 — fall through 到 waitpid 再确认一次。
    }
    return TryReap();
}

bool ChildWaiter::WaitFor(uint32_t timeout_ms)
{
    if (exited_) return true;

    if (pidfd_ >= 0) {
        // pidfd 路径:阻塞 poll 直到 POLLIN 或超时。
        struct pollfd pfd{};
        pfd.fd = pidfd_;
        pfd.events = POLLIN;
        const int r = ::poll(&pfd, 1, static_cast<int>(timeout_ms));
        if (r > 0 && (pfd.revents & POLLIN)) {
            return TryReap();
        }
        if (r == 0) return false; // timeout
        // r < 0: fall through 到 fallback 一次性确认
    }

    // fallback 路径(或 pidfd poll 出错):waitpid WNOHANG + sleep 轮询。
    // 给定 timeout_ms 内每 10ms 查一次;不是低延迟路径,但简单可靠。
    constexpr uint32_t kPollIntervalMs = 10;
    const uint32_t steps = (timeout_ms + kPollIntervalMs - 1) / kPollIntervalMs;
    for (uint32_t i = 0; i < steps; ++i) {
        if (TryReap()) return true;
        if (i + 1 < steps) {
            ::usleep(kPollIntervalMs * 1000u);
        }
    }
    return TryReap();
}

} // namespace refuzz::worker::topology

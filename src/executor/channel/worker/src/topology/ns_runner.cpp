#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "worker/topology/ns_runner.hpp"

#include "worker/engine/exec_loop_entry.hpp"
#include "worker/log/log_macros.hpp"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <climits>
#include <limits>
#include <string>

#define LOG(fmt, ...) ::refuzz::worker::log::WorkerLog("[Worker] " fmt "\n", ##__VA_ARGS__)

#ifndef CLOSE_RANGE_CLOEXEC
#define CLOSE_RANGE_CLOEXEC (1U << 2)
#endif

namespace refuzz::worker::topology {
namespace {

constexpr uint32_t kHandoffVersion = 2;
constexpr uint32_t kHandoffAck = 0x4c504944U;
constexpr int kHandoffTimeoutMs = 5000;

struct LoopPidfdHandoff {
    uint32_t version = kHandoffVersion;
    int32_t status = -1;
    int32_t error_number = 0;
    int32_t loop_pid = -1;
};

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

bool PollReadable(int fd, int timeout_ms)
{
    if (fd < 0) {
        return false;
    }
    pollfd pfd{};
    pfd.fd = fd;
    pfd.events = POLLIN;
    for (;;) {
        const int rc = ::poll(&pfd, 1, timeout_ms);
        if (rc > 0) {
            return (pfd.revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)) != 0;
        }
        if (rc == 0 || errno != EINTR) {
            return false;
        }
    }
}

bool SendHandoff(int socket_fd, const LoopPidfdHandoff& payload, int pidfd)
{
    iovec iov{};
    iov.iov_base = const_cast<LoopPidfdHandoff*>(&payload);
    iov.iov_len = sizeof(payload);

    union {
        cmsghdr align;
        char bytes[CMSG_SPACE(sizeof(int))];
    } control{};
    msghdr message{};
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    if (pidfd >= 0) {
        message.msg_control = control.bytes;
        message.msg_controllen = sizeof(control.bytes);
        cmsghdr* cmsg = CMSG_FIRSTHDR(&message);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        ::memcpy(CMSG_DATA(cmsg), &pidfd, sizeof(pidfd));
    }

    ssize_t written;
    do {
        written = ::sendmsg(socket_fd, &message, MSG_NOSIGNAL);
    } while (written < 0 && errno == EINTR);
    return written == static_cast<ssize_t>(sizeof(payload));
}

int ReceiveHandoffMessage(int socket_fd,
                          LoopPidfdHandoff* payload,
                          bool* explicitly_rejected)
{
    if (explicitly_rejected != nullptr) {
        *explicitly_rejected = false;
    }
    iovec iov{};
    iov.iov_base = payload;
    iov.iov_len = sizeof(*payload);
    union {
        cmsghdr align;
        char bytes[CMSG_SPACE(sizeof(int))];
    } control{};
    msghdr message{};
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control.bytes;
    message.msg_controllen = sizeof(control.bytes);

    ssize_t received;
    do {
        received = ::recvmsg(socket_fd, &message, MSG_CMSG_CLOEXEC);
    } while (received < 0 && errno == EINTR);
    if (received != static_cast<ssize_t>(sizeof(*payload)) ||
        (message.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) != 0) {
        errno = EPROTO;
        return -1;
    }

    int received_fd = -1;
    int rights_messages = 0;
    for (cmsghdr* cmsg = CMSG_FIRSTHDR(&message); cmsg != nullptr;
         cmsg = CMSG_NXTHDR(&message, cmsg)) {
        if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS ||
            cmsg->cmsg_len != CMSG_LEN(sizeof(int))) {
            if (received_fd >= 0) {
                ::close(received_fd);
            }
            errno = EPROTO;
            return -1;
        }
        ++rights_messages;
        ::memcpy(&received_fd, CMSG_DATA(cmsg), sizeof(received_fd));
    }

    if (payload->version != kHandoffVersion) {
        if (received_fd >= 0) {
            ::close(received_fd);
        }
        errno = EPROTO;
        return -1;
    }
    if (payload->status != 0) {
        if (received_fd >= 0) {
            ::close(received_fd);
        }
        if (explicitly_rejected != nullptr) {
            *explicitly_rejected = true;
        }
        errno = payload->error_number != 0 ? payload->error_number : EPROTO;
        return -1;
    }
    if (rights_messages != 1 || received_fd < 0) {
        if (received_fd >= 0) {
            ::close(received_fd);
        }
        errno = EPROTO;
        return -1;
    }
    if (payload->loop_pid <= 0) {
        ::close(received_fd);
        errno = EPROTO;
        return -1;
    }
    return received_fd;
}

int ReceiveHandoff(int socket_fd,
                   LoopPidfdHandoff* payload,
                   int timeout_ms = kHandoffTimeoutMs)
{
    if (!PollReadable(socket_fd, timeout_ms)) {
        errno = ETIMEDOUT;
        return -1;
    }
    return ReceiveHandoffMessage(socket_fd, payload, nullptr);
}

bool SendAck(int socket_fd)
{
    const uint32_t ack = kHandoffAck;
    ssize_t written;
    do {
        written = ::send(socket_fd, &ack, sizeof(ack), MSG_NOSIGNAL);
    } while (written < 0 && errno == EINTR);
    if (written != static_cast<ssize_t>(sizeof(ack))) {
        LOG("NsRunner: SendAck fd=%d written=%zd errno=%d", socket_fd,
            written, errno);
    }
    return written == static_cast<ssize_t>(sizeof(ack));
}

bool ReceiveAck(int socket_fd)
{
    if (!PollReadable(socket_fd, kHandoffTimeoutMs)) {
        return false;
    }
    uint32_t ack = 0;
    ssize_t received;
    do {
        received = ::recv(socket_fd, &ack, sizeof(ack), 0);
    } while (received < 0 && errno == EINTR);
    return received == static_cast<ssize_t>(sizeof(ack)) && ack == kHandoffAck;
}

void ClosePair(int fds[2])
{
    if (fds[0] >= 0) {
        ::close(fds[0]);
        fds[0] = -1;
    }
    if (fds[1] >= 0) {
        ::close(fds[1]);
        fds[1] = -1;
    }
}

} // namespace

NsRunnerSupervisor::~NsRunnerSupervisor()
{
    Stop();
}

int NsRunnerSupervisor::Spawn(
    LoopChildEntry entry, void* user,
    const DomainStopPlan& startup_cleanup_plan,
    uint64_t startup_deadline_us)
{
    if (entry == nullptr || handle_.pid > 0) {
        LOG("NsRunner::Spawn invalid entry=%s existing_pid=%d",
            entry == nullptr ? "null" : "set", handle_.pid);
        return -1;
    }

    int ready_fds[2] = {-1, -1};
    int done_fds[2] = {-1, -1};
    int handoff_fds[2] = {-1, -1};
    int start_fds[2] = {-1, -1};
    if (::pipe2(ready_fds, O_CLOEXEC) < 0 ||
        ::pipe2(done_fds, O_CLOEXEC) < 0 ||
        ::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, handoff_fds) < 0 ||
        ::pipe2(start_fds, O_CLOEXEC) < 0) {
        const int saved_errno = errno;
        ClosePair(ready_fds);
        ClosePair(done_fds);
        ClosePair(handoff_fds);
        ClosePair(start_fds);
        errno = saved_errno;
        LOG("NsRunner: spawn fd setup errno=%d", errno);
        return -1;
    }

    const pid_t pid = ::fork();
    if (pid < 0) {
        const int saved_errno = errno;
        ClosePair(ready_fds);
        ClosePair(done_fds);
        ClosePair(handoff_fds);
        ClosePair(start_fds);
        errno = saved_errno;
        LOG("NsRunner: fork(ns-runner) errno=%d", errno);
        return -1;
    }

    if (pid == 0) {
        ::close(handoff_fds[0]);

        const pid_t expected_parent = ::getppid();
        if (::prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 ||
            ::getppid() != expected_parent) {
            _exit(123);
        }

        const int devnull = ::open("/dev/null", O_RDWR | O_CLOEXEC);
        if (devnull >= 0) {
            ::dup2(devnull, 0);
            ::dup2(devnull, 1);
            if (devnull > 2) {
                ::close(devnull);
            }
        }

        // [kill-alignment 2026-08-08] ns-runner 成 process group leader
        // (PGID = 自身 pid)。daemon 侧 StopDomainHandle 用 kill(-pid) 杀
        // 整个组（对齐 syzkaller kill_and_wait），没有这一步 ns-runner 会留
        // 在 daemon 的进程组里，组 kill 会误伤 daemon 及其它 worker。
        if (::setpgid(0, 0) != 0) {
            LoopPidfdHandoff failure{};
            failure.error_number = errno;
            (void)SendHandoff(handoff_fds[1], failure, -1);
            _exit(126);
        }

        if (::unshare(CLONE_NEWPID) != 0) {
            ::fprintf(stderr,
                      "[Worker] NsRunner: unshare(NEWPID) errno=%d "
                      "(host fallback)\n",
                      errno);
        }

        const pid_t loop_pid = ::fork();
        if (loop_pid < 0) {
            LoopPidfdHandoff failure{};
            failure.error_number = errno;
            (void)SendHandoff(handoff_fds[1], failure, -1);
            _exit(2);
        }

        if (loop_pid == 0) {
            ::close(ready_fds[1]);
            ::close(done_fds[0]);
            ::close(handoff_fds[1]);
            ::close(start_fds[1]);

            const pid_t expected_loop_parent = ::getppid();
            if (::prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 ||
                ::getppid() != expected_loop_parent) {
                _exit(124);
            }

            uint8_t start_token = 0;
            ssize_t gate_read;
            do {
                gate_read = ::read(start_fds[0], &start_token, sizeof(start_token));
            } while (gate_read < 0 && errno == EINTR);
            ::close(start_fds[0]);
            if (gate_read != static_cast<ssize_t>(sizeof(start_token)) ||
                start_token != 1) {
                _exit(125);
            }

            if (::setsid() < 0) {
                _exit(126);
            }
            entry(ready_fds[0], done_fds[1], user);
            _exit(0);
        }

        ClosePair(ready_fds);
        ClosePair(done_fds);
        ::close(start_fds[0]);

        const int loop_pidfd = PidfdOpen(loop_pid);
        if (loop_pidfd < 0) {
            LoopPidfdHandoff failure{};
            failure.error_number = errno;
            (void)SendHandoff(handoff_fds[1], failure, -1);
            ::close(handoff_fds[1]);
            ::close(start_fds[1]);
            ::kill(loop_pid, SIGKILL);
            (void)::waitpid(loop_pid, nullptr, 0);
            _exit(4);
        }

        LoopPidfdHandoff success{};
        success.status = 0;
        success.loop_pid = static_cast<int32_t>(loop_pid);
        const bool handoff_ok = SendHandoff(handoff_fds[1], success, loop_pidfd);
        ::close(loop_pidfd);
        if (!handoff_ok || !ReceiveAck(handoff_fds[1])) {
            ::close(handoff_fds[1]);
            ::close(start_fds[1]);
            ::kill(loop_pid, SIGKILL);
            (void)::waitpid(loop_pid, nullptr, 0);
            _exit(5);
        }
        ::close(handoff_fds[1]);

        const uint8_t start_token = 1;
        ssize_t gate_written;
        do {
            gate_written = ::write(start_fds[1], &start_token, sizeof(start_token));
        } while (gate_written < 0 && errno == EINTR);
        ::close(start_fds[1]);
        if (gate_written != static_cast<ssize_t>(sizeof(start_token))) {
            ::kill(loop_pid, SIGKILL);
        }

        int wstatus = 0;
        while (::waitpid(loop_pid, &wstatus, 0) < 0) {
            if (errno != EINTR) {
                _exit(3);
            }
        }
        if (WIFEXITED(wstatus)) {
            _exit(WEXITSTATUS(wstatus));
        }
        if (WIFSIGNALED(wstatus)) {
            _exit(128 + WTERMSIG(wstatus));
        }
        _exit(0);
    }

    ::close(ready_fds[0]);
    ::close(done_fds[1]);
    ::close(handoff_fds[1]);
    ClosePair(start_fds);

    handle_.pid = pid;
    handle_.ready_pipe_w = ready_fds[1];
    handle_.done_pipe_r = done_fds[0];
    handle_.separate_runner = true;

    if (waiter_.Watch(pid) != 0) {
        const int saved_errno = errno != 0 ? errno : ENOSYS;
        LOG("NsRunner: pidfd_open(ns-runner=%d) failed errno=%d", pid, saved_errno);
        ::close(handoff_fds[0]);
        (void)Stop(startup_cleanup_plan);
        errno = saved_errno;
        return -1;
    }

    int handoff_timeout_ms = kHandoffTimeoutMs;
    if (startup_deadline_us != 0) {
        const uint64_t current_us = now_us();
        if (startup_deadline_us <= current_us) {
            handoff_timeout_ms = 0;
        } else {
            const uint64_t remaining_ms =
                (startup_deadline_us - current_us + 999ULL) / 1000ULL;
            handoff_timeout_ms = remaining_ms > static_cast<uint64_t>(INT_MAX)
                ? INT_MAX : static_cast<int>(remaining_ms);
        }
    }
    LoopPidfdHandoff handoff{};
    handle_.loop_pidfd = ReceiveHandoff(
        handoff_fds[0], &handoff, handoff_timeout_ms);
    if (handle_.loop_pidfd >= 0) {
        handle_.loop_pid = static_cast<pid_t>(handoff.loop_pid);
    }
    if (handle_.loop_pidfd < 0 || PollReadable(handle_.loop_pidfd, 0) ||
        !SendAck(handoff_fds[0])) {
        const int saved_errno = errno != 0 ? errno : EPROTO;
        LOG("ExecNsRunner: loop pidfd handoff failed errno=%d", saved_errno);
        LOG("NsRunner: loop pidfd handoff failed errno=%d", saved_errno);
        ::close(handoff_fds[0]);
        (void)Stop(startup_cleanup_plan);
        errno = saved_errno;
        return -1;
    }
    ::close(handoff_fds[0]);

    LOG("NsRunner: spawned ns_runner_pid=%d ns_pidfd=%d loop_pidfd=%d",
        pid, waiter_.PollFd(), handle_.loop_pidfd);
    return 0;
}

void NsRunnerSupervisor::ReleaseWaiterToHandle()
{
    if (waiter_.Pid() > 0 && waiter_.HasExited()) {
        handle_.direct_child_reaped = true;
        handle_.direct_child_status_known = true;
        handle_.direct_child_status = waiter_.ExitStatus();
    }
    if (handle_.ns_runner_pidfd < 0) {
        handle_.ns_runner_pidfd = waiter_.ReleasePollFd();
    }
    waiter_.Reset();
}

DomainStopResult NsRunnerSupervisor::Stop(
    const DomainStopPlan& plan,
    uint64_t absolute_deadline_us)
{
    ReleaseWaiterToHandle();
    return StopDomainHandle(
        handle_,
        absolute_deadline_us != 0
            ? absolute_deadline_us : DomainStopDeadlineUs(plan),
        plan);
}

int NsRunnerSupervisor::Respawn(
    LoopChildEntry entry, void* user,
    const DomainStopPlan& startup_cleanup_plan,
    uint64_t startup_deadline_us)
{
    if (Stop(startup_cleanup_plan) == DomainStopResult::kFailed) {
        errno = ETIMEDOUT;
        return -1;
    }
    return Spawn(entry, user, startup_cleanup_plan, startup_deadline_us);
}

NsRunnerSupervisor::DetachedState NsRunnerSupervisor::Detach()
{
    ReleaseWaiterToHandle();
    DetachedState detached = handle_;
    handle_ = DomainHandle{};
    return detached;
}

bool NsRunnerSupervisor::LoopHasExited() const
{
    return PollReadable(handle_.loop_pidfd, 0);
}

bool NsRunnerSupervisor::HasExited()
{
    return waiter_.Pid() > 0
        ? waiter_.HasExited()
        : DomainHandleExecutionExited(handle_);
}

int NsRunnerSupervisor::ExitStatus() const
{
    return waiter_.Pid() > 0
        ? waiter_.ExitStatus() : handle_.direct_child_status;
}

namespace {

constexpr int kExecBootFd = 10;
constexpr int kExecBackingFd = 11;
constexpr int kExecReadyFd = 12;
constexpr int kExecDoneFd = 13;
constexpr int kExecStartupAckFd = 14;
constexpr int kExecHandoffFd = 15;

bool WriteExact(int fd, const void* data, size_t size)
{
    const auto* bytes = static_cast<const uint8_t*>(data);
    size_t offset = 0;
    while (offset < size) {
        const ssize_t written = ::write(fd, bytes + offset, size - offset);
        if (written > 0) {
            offset += static_cast<size_t>(written);
        } else if (written < 0 && errno == EINTR) {
            continue;
        } else {
            return false;
        }
    }
    return true;
}

bool ReadExact(int fd, void* data, size_t size)
{
    auto* bytes = static_cast<uint8_t*>(data);
    size_t offset = 0;
    while (offset < size) {
        const ssize_t received = ::read(fd, bytes + offset, size - offset);
        if (received > 0) {
            offset += static_cast<size_t>(received);
        } else if (received < 0 && errno == EINTR) {
            continue;
        } else {
            return false;
        }
    }
    return true;
}

uint64_t ResolveStartupDeadline(uint64_t configured_deadline_us)
{
    if (configured_deadline_us != 0) {
        return configured_deadline_us;
    }
    const uint64_t current_us = now_us();
    const uint64_t timeout_us =
        static_cast<uint64_t>(kDefaultDomainStartupTimeoutMs) * 1000ULL;
    return timeout_us > std::numeric_limits<uint64_t>::max() - current_us
        ? std::numeric_limits<uint64_t>::max()
        : current_us + timeout_us;
}

int RemainingStartupTimeoutMs(uint64_t absolute_deadline_us)
{
    const uint64_t current_us = now_us();
    if (absolute_deadline_us <= current_us) {
        return 0;
    }
    const uint64_t remaining_us = absolute_deadline_us - current_us;
    const uint64_t remaining_ms = (remaining_us + 999ULL) / 1000ULL;
    return remaining_ms > static_cast<uint64_t>(INT_MAX)
        ? INT_MAX : static_cast<int>(remaining_ms);
}

bool StartupFailureStageValid(
    ::refuzz::worker::engine::LoopStartupStage stage)
{
    using Stage = ::refuzz::worker::engine::LoopStartupStage;
    return stage > Stage::kUnknown && stage < Stage::kReady;
}

DomainStartResult ClassifyStartupStatus(
    const ::refuzz::worker::engine::LoopStartupStatus& status,
    uint32_t expected_proc_id,
    bool handoff_complete)
{
    using namespace ::refuzz::worker::engine;
    const bool envelope_valid =
        status.magic == kLoopWorkerBootMagic &&
        status.version == kLoopWorkerBootVersion &&
        status.size == sizeof(status) &&
        status.proc_id == expected_proc_id;
    if (!envelope_valid) {
        return MakeDomainStartRejected(
            expected_proc_id, LoopStartupStage::kUnknown, EPROTO);
    }
    if (status.ready == 0u && StartupFailureStageValid(status.stage)) {
        return MakeDomainStartRejected(
            status.proc_id, status.stage,
            status.error_number != 0 ? status.error_number : EPROTO);
    }
    if (status.ready == 1u &&
        status.stage == LoopStartupStage::kReady &&
        status.error_number == 0 && handoff_complete) {
        return MakeDomainStartReady(status.proc_id);
    }
    return MakeDomainStartRejected(
        expected_proc_id, LoopStartupStage::kUnknown, EPROTO);
}

DomainStartResult ObserveStartupExit(ChildWaiter& waiter, uint32_t proc_id)
{
    int exit_status = 0;
    if (waiter.HasExited()) {
        exit_status = waiter.ExitStatus();
    }
    return MakeDomainStartExited(proc_id, exit_status, ECHILD);
}

bool DupForExec(int source_fd, int target_fd)
{
    if (source_fd < 0) {
        return false;
    }
    if (source_fd != target_fd) {
        return ::dup3(source_fd, target_fd, 0) == target_fd;
    }
    const int flags = ::fcntl(target_fd, F_GETFD);
    return flags >= 0 && ::fcntl(target_fd, F_SETFD, flags & ~FD_CLOEXEC) == 0;
}

void MarkNonStandardFdsCloseOnExec()
{
#ifdef SYS_close_range
    if (::syscall(SYS_close_range, 3u, ~0u, CLOSE_RANGE_CLOEXEC) == 0) {
        return;
    }
#endif
    for (int fd = 3; fd < 65536; ++fd) {
        const int flags = ::fcntl(fd, F_GETFD);
        if (flags >= 0) {
            (void)::fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
        }
    }
}

std::string ResolveExecutorPath(const std::string& configured)
{
    if (!configured.empty()) {
        return configured;
    }
    char path[PATH_MAX];
    const ssize_t length = ::readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (length <= 0) {
        return {};
    }
    path[length] = '\0';
    std::string resolved(path);
    const size_t slash = resolved.find_last_of('/');
    if (slash == std::string::npos) {
        return {};
    }
    resolved.resize(slash + 1);
    resolved += "refuzz_executor";
    return resolved;
}

void WriteRoleStartupFailure(uint32_t proc_id,
                             ::refuzz::worker::engine::LoopStartupStage stage,
                             int error_number)
{
    auto status = ::refuzz::worker::engine::MakeLoopStartupStatus();
    status.ready = 0;
    status.proc_id = proc_id;
    status.stage = stage;
    status.error_number = error_number;
    (void)WriteExact(kExecStartupAckFd, &status, sizeof(status));
}

} // namespace

ExecNsRunnerSupervisor::~ExecNsRunnerSupervisor()
{
    Stop();
}

DomainStartResult ExecNsRunnerSupervisor::Spawn(
    const ExecNsRunnerSpawnConfig& config)
{
    using Stage = ::refuzz::worker::engine::LoopStartupStage;
    const uint32_t proc_id = config.boot.proc_id;
    if (handle_.pid > 0 || config.backing_fd < 0 ||
        !::refuzz::worker::engine::LoopWorkerBootConfigValid(config.boot)) {
        errno = EPROTO;
        LOG("ExecNsRunner: spawn rejected proc=%u existing_pid=%d backing_fd=%d "
            "boot_valid=%u",
            proc_id, handle_.pid, config.backing_fd,
            ::refuzz::worker::engine::LoopWorkerBootConfigValid(config.boot)
                ? 1u : 0u);
        return MakeDomainStartRejected(proc_id, Stage::kBootRead, errno);
    }
    const std::string executor_path = ResolveExecutorPath(config.executor_path);
    if (executor_path.empty() || ::access(executor_path.c_str(), X_OK) != 0) {
        if (errno == 0) {
            errno = ENOENT;
        }
        LOG("ExecNsRunner: executor unavailable path=%s errno=%d",
            executor_path.c_str(), errno);
        return MakeDomainStartRejected(proc_id, Stage::kBootRead, errno);
    }

    int ready_fds[2] = {-1, -1};
    int done_fds[2] = {-1, -1};
    int startup_fds[2] = {-1, -1};
    int boot_fds[2] = {-1, -1};
    int handoff_fds[2] = {-1, -1};
    if (::pipe2(ready_fds, O_CLOEXEC) != 0 ||
        ::pipe2(done_fds, O_CLOEXEC) != 0 ||
        ::pipe2(startup_fds, O_CLOEXEC) != 0 ||
        ::pipe2(boot_fds, O_CLOEXEC) != 0 ||
        ::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0,
                     handoff_fds) != 0) {
        const int saved_errno = errno;
        ClosePair(ready_fds);
        ClosePair(done_fds);
        ClosePair(startup_fds);
        ClosePair(boot_fds);
        ClosePair(handoff_fds);
        errno = saved_errno;
        LOG("ExecNsRunner: startup IPC creation failed proc=%u errno=%d",
            proc_id, saved_errno);
        return MakeDomainStartRejected(
            proc_id, Stage::kUnknown, saved_errno);
    }

    const pid_t pid = ::fork();
    if (pid < 0) {
        const int saved_errno = errno;
        ClosePair(ready_fds);
        ClosePair(done_fds);
        ClosePair(startup_fds);
        ClosePair(boot_fds);
        ClosePair(handoff_fds);
        errno = saved_errno;
        LOG("ExecNsRunner: fork failed proc=%u errno=%d", proc_id,
            saved_errno);
        return MakeDomainStartRejected(
            proc_id, Stage::kUnknown, saved_errno);
    }
    if (pid == 0) {
        MarkNonStandardFdsCloseOnExec();
        const int original_fds[] = {
            boot_fds[0], config.backing_fd, ready_fds[0], done_fds[1],
            startup_fds[1], handoff_fds[1]};
        const int target_fds[] = {
            kExecBootFd, kExecBackingFd, kExecReadyFd, kExecDoneFd,
            kExecStartupAckFd, kExecHandoffFd};
        int temporary_fds[6] = {-1, -1, -1, -1, -1, -1};
        bool fd_setup_ok = true;
        for (size_t index = 0; index < 6; ++index) {
            temporary_fds[index] =
                ::fcntl(original_fds[index], F_DUPFD_CLOEXEC,
                        100 + static_cast<int>(index));
            if (temporary_fds[index] < 0) {
                fd_setup_ok = false;
                break;
            }
        }
        for (size_t index = 0; fd_setup_ok && index < 6; ++index) {
            fd_setup_ok = DupForExec(temporary_fds[index], target_fds[index]);
        }
        if (!fd_setup_ok) {
            _exit(126);
        }
        if (::prctl(PR_SET_PDEATHSIG, SIGKILL) != 0) {
            _exit(126);
        }
        char role_arg[] = "--role=ns-runner";
        char* const argv[] = {
            const_cast<char*>(executor_path.c_str()), role_arg, nullptr};
        ::execv(executor_path.c_str(), argv);
        _exit(127);
    }

    ::close(ready_fds[0]);
    ::close(done_fds[1]);
    ::close(startup_fds[1]);
    ::close(boot_fds[0]);
    ::close(handoff_fds[1]);

    handle_.pid = pid;
    handle_.ready_pipe_w = ready_fds[1];
    handle_.done_pipe_r = done_fds[0];
    handle_.separate_runner = true;
    if (waiter_.Watch(pid) != 0) {
        const int saved_errno = errno != 0 ? errno : ECHILD;
        ::close(startup_fds[0]);
        ::close(boot_fds[1]);
        ::close(handoff_fds[0]);
        errno = saved_errno;
        LOG("ExecNsRunner: waiter watch failed runner_pid=%d proc=%u errno=%d",
            pid, proc_id, saved_errno);
        return MakeDomainStartRejected(
            proc_id, Stage::kUnknown, saved_errno);
    }

    const bool boot_written = WriteExact(boot_fds[1], &config.boot,
                                         sizeof(config.boot));
    ::close(boot_fds[1]);
    if (!boot_written) {
        const int saved_errno = errno != 0 ? errno : EPIPE;
        ::close(startup_fds[0]);
        ::close(handoff_fds[0]);
        errno = saved_errno;
        LOG("ExecNsRunner: boot write failed runner_pid=%d proc=%u errno=%d",
            pid, proc_id, saved_errno);
        return MakeDomainStartRejected(
            proc_id, Stage::kBootRead, saved_errno);
    }

    const uint64_t startup_deadline_us =
        ResolveStartupDeadline(config.startup_deadline_us);
    bool handoff_complete = false;
    DomainStartResult start_result = MakeDomainStartRejected(
        proc_id, Stage::kUnknown, EPROTO);
    bool terminal = false;
    while (!terminal) {
        pollfd descriptors[4]{};
        nfds_t descriptor_count = 0;

        const nfds_t startup_index = descriptor_count++;
        descriptors[startup_index].fd = startup_fds[0];
        descriptors[startup_index].events = POLLIN;

        int handoff_index = -1;
        if (!handoff_complete && handoff_fds[0] >= 0) {
            handoff_index = static_cast<int>(descriptor_count);
            descriptors[descriptor_count].fd = handoff_fds[0];
            descriptors[descriptor_count].events = POLLIN;
            ++descriptor_count;
        }

        int runner_index = -1;
        if (waiter_.PollFd() >= 0) {
            runner_index = static_cast<int>(descriptor_count);
            descriptors[descriptor_count].fd = waiter_.PollFd();
            descriptors[descriptor_count].events = POLLIN;
            ++descriptor_count;
        }

        int loop_index = -1;
        if (handle_.loop_pidfd >= 0) {
            loop_index = static_cast<int>(descriptor_count);
            descriptors[descriptor_count].fd = handle_.loop_pidfd;
            descriptors[descriptor_count].events = POLLIN;
            ++descriptor_count;
        }

        const int poll_result = ::poll(
            descriptors, descriptor_count,
            RemainingStartupTimeoutMs(startup_deadline_us));
        if (poll_result < 0) {
            if (errno == EINTR) {
                continue;
            }
            start_result = MakeDomainStartRejected(
                proc_id, Stage::kUnknown, errno);
            break;
        }
        if (poll_result == 0) {
            LOG("ExecNsRunner: startup poll timeout runner_pid=%d proc=%u "
                "handoff=%u loop_pidfd=%d",
                pid, proc_id, handoff_complete ? 1u : 0u,
                handle_.loop_pidfd);
            start_result = MakeDomainStartStalled(
                proc_id, ETIMEDOUT);
            break;
        }

        const short startup_events = descriptors[startup_index].revents;
        if ((startup_events & POLLIN) != 0) {
            ::refuzz::worker::engine::LoopStartupStatus startup{};
            if (ReadExact(startup_fds[0], &startup, sizeof(startup))) {
                start_result = ClassifyStartupStatus(
                    startup, proc_id, handoff_complete);
            } else if (waiter_.HasExited() ||
                       (handle_.loop_pidfd >= 0 &&
                        PollReadable(handle_.loop_pidfd, 0))) {
                start_result = ObserveStartupExit(waiter_, proc_id);
            } else {
                start_result = MakeDomainStartRejected(
                    proc_id, Stage::kUnknown, EPROTO);
            }
            terminal = true;
            continue;
        }

        if (handoff_index >= 0 &&
            (descriptors[handoff_index].revents &
             (POLLIN | POLLHUP | POLLERR | POLLNVAL)) != 0) {
            LoopPidfdHandoff handoff{};
            bool explicitly_rejected = false;
            const int loop_pidfd = ReceiveHandoffMessage(
                handoff_fds[0], &handoff, &explicitly_rejected);
            if (loop_pidfd < 0) {
                const int handoff_errno = errno != 0 ? errno : EPROTO;
                LOG("ExecNsRunner: loop handoff failed runner_pid=%d proc=%u "
                    "errno=%d explicit=%u",
                    pid, proc_id, handoff_errno,
                    explicitly_rejected ? 1u : 0u);
                start_result = explicitly_rejected
                    ? MakeDomainStartRejected(
                        proc_id, Stage::kNamespace, handoff_errno)
                    : (waiter_.HasExited()
                        ? ObserveStartupExit(waiter_, proc_id)
                        : MakeDomainStartRejected(
                            proc_id, Stage::kUnknown, handoff_errno));
                terminal = true;
                continue;
            }
            handle_.loop_pidfd = loop_pidfd;
            handoff_complete = true;
            ::close(handoff_fds[0]);
            handoff_fds[0] = -1;
            if (PollReadable(handle_.loop_pidfd, 0)) {
                start_result = ObserveStartupExit(waiter_, proc_id);
                terminal = true;
            }
            continue;
        }

        if ((loop_index >= 0 &&
             (descriptors[loop_index].revents &
              (POLLIN | POLLHUP | POLLERR | POLLNVAL)) != 0) ||
            (runner_index >= 0 &&
             (descriptors[runner_index].revents &
              (POLLIN | POLLHUP | POLLERR | POLLNVAL)) != 0)) {
            LOG("ExecNsRunner: startup process exit event runner_pid=%d proc=%u "
                "runner_revents=0x%x loop_revents=0x%x",
                pid, proc_id,
                runner_index >= 0 ? descriptors[runner_index].revents : 0,
                loop_index >= 0 ? descriptors[loop_index].revents : 0);
            start_result = ObserveStartupExit(waiter_, proc_id);
            break;
        }

        if ((startup_events & (POLLHUP | POLLERR | POLLNVAL)) != 0) {
            LOG("ExecNsRunner: startup ACK pipe closed runner_pid=%d proc=%u "
                "revents=0x%x",
                pid, proc_id, startup_events);
            start_result = ObserveStartupExit(waiter_, proc_id);
            break;
        }
    }

    ::close(startup_fds[0]);
    if (handoff_fds[0] >= 0) {
        ::close(handoff_fds[0]);
    }
    errno = start_result.error_number;
    if (!start_result.IsReady()) {
        LOG("ExecNsRunner: startup failed kind=%u proc=%u stage=%u errno=%d exit=%d",
            static_cast<unsigned>(start_result.kind), proc_id,
            static_cast<unsigned>(start_result.stage),
            start_result.error_number, start_result.exit_status);
        return start_result;
    }

    return start_result;
}

void ExecNsRunnerSupervisor::ReleaseWaiterToHandle()
{
    if (waiter_.Pid() > 0 && waiter_.HasExited()) {
        handle_.direct_child_reaped = true;
        handle_.direct_child_status_known = true;
        handle_.direct_child_status = waiter_.ExitStatus();
    }
    if (handle_.ns_runner_pidfd < 0) {
        handle_.ns_runner_pidfd = waiter_.ReleasePollFd();
    }
    waiter_.Reset();
}

DomainStopResult ExecNsRunnerSupervisor::Stop(
    const DomainStopPlan& plan,
    uint64_t absolute_deadline_us)
{
    ReleaseWaiterToHandle();
    return StopDomainHandle(
        handle_,
        absolute_deadline_us != 0
            ? absolute_deadline_us : DomainStopDeadlineUs(plan),
        plan);
}

NsRunnerSupervisor::DetachedState ExecNsRunnerSupervisor::Detach()
{
    ReleaseWaiterToHandle();
    NsRunnerSupervisor::DetachedState detached = handle_;
    handle_ = DomainHandle{};
    return detached;
}

int RunExecNsRunnerRole()
{
    ::refuzz::worker::engine::LoopWorkerBootConfig config{};
    if (!ReadExact(kExecBootFd, &config, sizeof(config)) ||
        !::refuzz::worker::engine::LoopWorkerBootConfigValid(config)) {
        WriteRoleStartupFailure(config.proc_id,
                                ::refuzz::worker::engine::LoopStartupStage::kBootRead,
                                EPROTO);
        return 2;
    }
    ::close(kExecBootFd);
    if ((config.flags &
         ::refuzz::worker::engine::kLoopBootEnableWorkerLog) != 0) {
        ::refuzz::worker::log::EnableWorkerLog();
    }

    const pid_t expected_parent = ::getppid();
    if (::prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 ||
        ::getppid() != expected_parent) {
        return 3;
    }
    const int devnull = ::open("/dev/null", O_RDWR | O_CLOEXEC);
    if (devnull >= 0) {
        (void)::dup2(devnull, STDIN_FILENO);
        (void)::dup2(devnull, STDOUT_FILENO);
        if (devnull > STDERR_FILENO) {
            ::close(devnull);
        }
    }

    // [kill-alignment 2026-08-08] exec 路径同样成组 leader，daemon 才能
    // kill(-pid) 覆盖 ns-runner 及其尚未脱离组的子进程。
    if (::setpgid(0, 0) != 0) {
        const int saved_errno = errno;
        WriteRoleStartupFailure(
            config.proc_id,
            ::refuzz::worker::engine::LoopStartupStage::kNamespace,
            saved_errno);
        return 4;
    }

    if (::unshare(CLONE_NEWPID) != 0) {
        LOG("ExecNsRunner: unshare(CLONE_NEWPID) errno=%d (host fallback)", errno);
    }

    int start_fds[2] = {-1, -1};
    if (::pipe2(start_fds, O_CLOEXEC) != 0) {
        WriteRoleStartupFailure(config.proc_id,
                                ::refuzz::worker::engine::LoopStartupStage::kNamespace,
                                errno);
        return 4;
    }
    const pid_t loop_pid = ::fork();
    if (loop_pid < 0) {
        LoopPidfdHandoff failure{};
        failure.error_number = errno;
        (void)SendHandoff(kExecHandoffFd, failure, -1);
        return 5;
    }
    if (loop_pid == 0) {
        ::close(start_fds[1]);
        ::close(kExecHandoffFd);
        // exec 路径的 loop 同样是 ns-runner 的直接子进程：fork 会清掉子进程的
        // PDEATHSIG，必须在 loop 自己这里重新注册 + 父死竞态检查，否则杀 ns-runner
        // 时 loop 会存活（非 exec 路径在 Spawn 里同款注册，见上方 loop_pid==0）。
        const pid_t expected_loop_parent = ::getppid();
        if (::prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 ||
            ::getppid() != expected_loop_parent) {
            _exit(124);
        }
        uint8_t token = 0;
        if (!ReadExact(start_fds[0], &token, sizeof(token)) || token != 1) {
            _exit(125);
        }
        ::close(start_fds[0]);
        if (::setsid() < 0) {
            _exit(126);
        }
        ::refuzz::worker::engine::RunExecLoop(config,
                                               kExecBackingFd,
                                               kExecReadyFd,
                                               kExecDoneFd,
                                               kExecStartupAckFd);
    }

    ::close(start_fds[0]);
    ::close(kExecBackingFd);
    ::close(kExecReadyFd);
    ::close(kExecDoneFd);
    ::close(kExecStartupAckFd);

    const int loop_pidfd = PidfdOpen(loop_pid);
    if (loop_pidfd < 0) {
        LOG("ExecNsRunner role: pidfd_open loop=%d errno=%d", loop_pid, errno);
        LoopPidfdHandoff failure{};
        failure.error_number = errno;
        (void)SendHandoff(kExecHandoffFd, failure, -1);
        ::kill(loop_pid, SIGKILL);
        (void)::waitpid(loop_pid, nullptr, 0);
        return 6;
    }
    LoopPidfdHandoff success{};
    success.status = 0;
    success.loop_pid = static_cast<int32_t>(loop_pid);
    const bool handed_off = SendHandoff(kExecHandoffFd, success, loop_pidfd);
    ::close(loop_pidfd);
    if (!handed_off) {
        ::kill(loop_pid, SIGKILL);
        (void)::waitpid(loop_pid, nullptr, 0);
        return 7;
    }
    ::close(kExecHandoffFd);
    const uint8_t token = 1;
    if (!WriteExact(start_fds[1], &token, sizeof(token))) {
        LOG("ExecNsRunner role: loop release failed pid=%d proc=%u errno=%d",
            loop_pid, config.proc_id, errno);
        ::kill(loop_pid, SIGKILL);
    }
    ::close(start_fds[1]);

    int status = 0;
    while (::waitpid(loop_pid, &status, 0) < 0) {
        if (errno != EINTR) {
            return 8;
        }
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        return 128 + WTERMSIG(status);
    }
    return 0;
}

} // namespace refuzz::worker::topology

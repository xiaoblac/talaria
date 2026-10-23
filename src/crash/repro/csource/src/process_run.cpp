// Copyright 2026 reFuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.

#include "refuzz/crash/repro/csource/internal/process_run.hpp"

#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <format>
#include <poll.h>
#include <span>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace refuzz::crash::repro::csource::internal {

namespace {

// Drain bytes from a non-blocking pipe fd into `dst`. Returns true
// when EOF was observed; on EAGAIN returns false (caller polls
// again).
bool drain_fd(int fd, std::string& dst) {
    char buf[4096];
    while (true) {
        ssize_t n = ::read(fd, buf, sizeof(buf));
        if (n > 0) {
            dst.append(buf, static_cast<std::size_t>(n));
            continue;
        }
        if (n == 0) return true;          // EOF
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return false;
        return true;                       // treat other errors as EOF
    }
}

void set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
}

} // namespace

std::expected<ProcessResult, std::string>
run_process(std::span<const std::string_view> argv,
            std::string_view stdin_bytes,
            std::chrono::seconds timeout) {
    if (argv.empty()) {
        return std::unexpected("argv empty");
    }

    // pipes: parent writes stdin via stdin_pipe[1]; reads child stdout
    // via stdout_pipe[0] and stderr via stderr_pipe[0].
    int stdin_pipe[2]  = { -1, -1 };
    int stdout_pipe[2] = { -1, -1 };
    int stderr_pipe[2] = { -1, -1 };
    auto close_all = [&]() {
        for (int* p : { stdin_pipe, stdout_pipe, stderr_pipe }) {
            if (p[0] >= 0) ::close(p[0]);
            if (p[1] >= 0) ::close(p[1]);
        }
    };
    if (::pipe(stdin_pipe)  < 0 ||
        ::pipe(stdout_pipe) < 0 ||
        ::pipe(stderr_pipe) < 0) {
        close_all();
        return std::unexpected(std::format("pipe: {}", std::strerror(errno)));
    }

    pid_t pid = ::fork();
    if (pid < 0) {
        close_all();
        return std::unexpected(std::format("fork: {}", std::strerror(errno)));
    }
    if (pid == 0) {
        // Child.
        if (::dup2(stdin_pipe[0], 0)  < 0) ::_exit(127);
        if (::dup2(stdout_pipe[1], 1) < 0) ::_exit(127);
        if (::dup2(stderr_pipe[1], 2) < 0) ::_exit(127);
        ::close(stdin_pipe[0]); ::close(stdin_pipe[1]);
        ::close(stdout_pipe[0]); ::close(stdout_pipe[1]);
        ::close(stderr_pipe[0]); ::close(stderr_pipe[1]);

        // Build argv as a C array of mutable strings.
        std::vector<std::string> owned;
        owned.reserve(argv.size());
        for (auto& a : argv) owned.emplace_back(a);
        std::vector<char*> cargv;
        cargv.reserve(owned.size() + 1);
        for (auto& s : owned) cargv.push_back(s.data());
        cargv.push_back(nullptr);
        ::execvp(cargv[0], cargv.data());
        ::_exit(127);
    }

    // Parent.
    ::close(stdin_pipe[0]);  stdin_pipe[0]  = -1;
    ::close(stdout_pipe[1]); stdout_pipe[1] = -1;
    ::close(stderr_pipe[1]); stderr_pipe[1] = -1;

    // H2 fix: ALL three pipes non-blocking and interleaved via poll().
    // Pre-PR-4-B-rev2 the parent wrote the entire stdin payload first
    // before reading stdout/stderr — when the child's stderr (or
    // stdout) pipe filled (~64KB on Linux) the child blocked on
    // writev(stderr) and the parent blocked on write(stdin) →
    // deadlock. cpp -nostdinc emits diagnostics that easily fill
    // 64KB on a 580KB common-header input.
    set_nonblock(stdin_pipe[1]);
    set_nonblock(stdout_pipe[0]);
    set_nonblock(stderr_pipe[0]);

    ProcessResult result;
    bool stdout_eof = false;
    bool stderr_eof = false;
    std::size_t stdin_off = 0;
    const auto start = std::chrono::steady_clock::now();

    while (!(stdout_eof && stderr_eof)) {
        struct pollfd pfds[3];
        int nfds = 0;
        if (stdin_pipe[1] >= 0) {
            pfds[nfds].fd     = stdin_pipe[1];
            pfds[nfds].events = POLLOUT;
            ++nfds;
        }
        if (!stdout_eof) {
            pfds[nfds].fd     = stdout_pipe[0];
            pfds[nfds].events = POLLIN;
            ++nfds;
        }
        if (!stderr_eof) {
            pfds[nfds].fd     = stderr_pipe[0];
            pfds[nfds].events = POLLIN;
            ++nfds;
        }
        if (nfds == 0) break;

        int poll_ms = -1;
        if (timeout.count() > 0) {
            const auto elapsed = std::chrono::steady_clock::now() - start;
            const auto rem =
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    timeout - elapsed);
            if (rem.count() <= 0) {
                result.timed_out = true;
                ::kill(pid, SIGKILL);
                break;
            }
            poll_ms = static_cast<int>(rem.count());
        }
        int p = ::poll(pfds, static_cast<nfds_t>(nfds), poll_ms);
        if (p < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (p == 0 && timeout.count() > 0) {
            result.timed_out = true;
            ::kill(pid, SIGKILL);
            break;
        }
        for (int i = 0; i < nfds; ++i) {
            const int fd = pfds[i].fd;
            const auto rev = pfds[i].revents;
            if (fd == stdin_pipe[1] && (rev & POLLOUT)) {
                if (stdin_off < stdin_bytes.size()) {
                    ssize_t n = ::write(fd, stdin_bytes.data() + stdin_off,
                                        stdin_bytes.size() - stdin_off);
                    if (n > 0) {
                        stdin_off += static_cast<std::size_t>(n);
                    } else if (n < 0 && errno != EAGAIN && errno != EINTR) {
                        ::close(stdin_pipe[1]); stdin_pipe[1] = -1;
                    }
                }
                if (stdin_off >= stdin_bytes.size()) {
                    ::close(stdin_pipe[1]); stdin_pipe[1] = -1;
                }
                continue;
            }
            if (fd == stdin_pipe[1] && (rev & (POLLERR | POLLHUP))) {
                ::close(stdin_pipe[1]); stdin_pipe[1] = -1;
                continue;
            }
            if ((rev & (POLLIN | POLLHUP)) == 0) continue;
            const bool is_stdout = fd == stdout_pipe[0];
            std::string& dst = is_stdout ? result.stdout_ : result.stderr_;
            if (drain_fd(fd, dst)) {
                if (is_stdout) stdout_eof = true;
                else           stderr_eof = true;
            }
        }
    }
    if (stdin_pipe[1] >= 0) {
        ::close(stdin_pipe[1]);
        stdin_pipe[1] = -1;
    }

    int status = 0;
    while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    if (WIFEXITED(status)) {
        result.exit_code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        result.exit_code = -WTERMSIG(status);
    }
    close_all();
    return result;
}

} // namespace refuzz::crash::repro::csource::internal

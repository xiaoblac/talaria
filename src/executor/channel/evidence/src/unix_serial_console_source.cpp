// UnixSerialConsoleSource 实现
//
// 封装 AF_UNIX / SOCK_STREAM 的 socket + poll + line-split 主干，按
// IConsoleSource 合同对外暴露。
//
// 约束：
//   - 本类不持有线程；ReadLine() 是阻塞 call，由上层（ConsoleSensor）决定是否开线程
//   - 不做 crash pattern match（对应 Evidence 层的 IConsoleSource 合同）
//   - 不直接 report 给 HealthMonitor（上层 Sensor 负责）
//
// 设计来源：docs/channel-redesign/v3/40_evidence.md §2.1

#include "refuzz/channel/evidence/unix_serial_console_source.hpp"

#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <utility>

namespace refuzz::channel::evidence {

namespace {

inline void CloseFd(int& fd) noexcept {
    if (fd != -1) {
        ::close(fd);
        fd = -1;
    }
}

} // namespace

UnixSerialConsoleSource::~UnixSerialConsoleSource()
{
    Close();
}

Result<void> UnixSerialConsoleSource::Open(const ConsoleEndpoint& endpoint)
{
    if (state_.load(std::memory_order_acquire) == State::kOpen) {
        return Error{ErrorKind::kConnection,
                     "UnixSerialConsoleSource::Open() called while already open"};
    }

    if (::pipe(wakeup_pipe_) != 0) {
        last_error_ = std::string("pipe() failed: ") + std::strerror(errno);
        return Error{ErrorKind::kConnection, last_error_};
    }

    switch (endpoint.kind) {
    case ConsoleEndpoint::Kind::kUnixSocket: {
        auto r = ConnectUnixSocket(endpoint.path);
        if (!r.ok()) {
            CloseFd(wakeup_pipe_[0]);
            CloseFd(wakeup_pipe_[1]);
            return r;
        }
        socket_owned_ = true;
        break;
    }
    case ConsoleEndpoint::Kind::kFdBorrow: {
        if (endpoint.fd < 0) {
            CloseFd(wakeup_pipe_[0]);
            CloseFd(wakeup_pipe_[1]);
            last_error_ = "UnixSerialConsoleSource: kFdBorrow with negative fd";
            return Error{ErrorKind::kConnection, last_error_};
        }
        socket_fd_    = endpoint.fd;
        socket_owned_ = false;
        break;
    }
    default:
        CloseFd(wakeup_pipe_[0]);
        CloseFd(wakeup_pipe_[1]);
        last_error_ = "UnixSerialConsoleSource: unsupported ConsoleEndpoint::Kind";
        return Error{ErrorKind::kConnection, last_error_};
    }

    line_buffer_.clear();
    last_error_.clear();
    state_.store(State::kOpen, std::memory_order_release);
    return Result<void>::Ok();
}

Result<void> UnixSerialConsoleSource::ConnectUnixSocket(const std::string& path)
{
    if (path.empty()) {
        last_error_ = "UnixSerialConsoleSource: socket path is empty";
        return Error{ErrorKind::kConnection, last_error_};
    }

    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        last_error_ = std::string("socket() failed: ") + std::strerror(errno);
        return Error{ErrorKind::kConnection, last_error_};
    }

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);

    if (::connect(fd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0) {
        last_error_ = std::string("connect() failed: ") + std::strerror(errno);
        ::close(fd);
        return Error{ErrorKind::kConnection, last_error_};
    }

    socket_fd_ = fd;
    return Result<void>::Ok();
}

bool UnixSerialConsoleSource::TryConsumeFromBuffer(std::string& out_line)
{
    const auto pos = line_buffer_.find('\n');
    if (pos == std::string::npos) return false;
    out_line.assign(line_buffer_, 0, pos);
    line_buffer_.erase(0, pos + 1);
    return true;
}

bool UnixSerialConsoleSource::PumpOnce()
{
    char read_buf[4096];
    ssize_t n = ::read(socket_fd_, read_buf, sizeof(read_buf));
    if (n > 0) {
        line_buffer_.append(read_buf, static_cast<size_t>(n));
        return true;
    }
    if (n == 0) {
        // EOF
        state_.store(State::kEof, std::memory_order_release);
        return false;
    }
    if (errno == EINTR) {
        return true; // 再试一轮 poll
    }
    last_error_ = std::string("read() failed: ") + std::strerror(errno);
    state_.store(State::kError, std::memory_order_release);
    return false;
}

std::optional<std::string>
UnixSerialConsoleSource::ReadLine(std::chrono::milliseconds timeout)
{
    const State s = state_.load(std::memory_order_acquire);
    if (s != State::kOpen) return std::nullopt;

    // 先从缓冲消费一行（兼顾多行粘包）
    std::string line;
    if (TryConsumeFromBuffer(line)) return line;

    // 使用单调时钟减去已用时间；-1 等价无限等
    using Clock = std::chrono::steady_clock;
    const auto deadline =
        (timeout.count() < 0)
            ? Clock::time_point::max()
            : Clock::now() + timeout;

    while (true) {
        pollfd fds[2];
        fds[0].fd = socket_fd_;      fds[0].events = POLLIN; fds[0].revents = 0;
        fds[1].fd = wakeup_pipe_[0]; fds[1].events = POLLIN; fds[1].revents = 0;

        int timeout_ms;
        if (deadline == Clock::time_point::max()) {
            timeout_ms = -1;
        } else {
            const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - Clock::now());
            if (left.count() <= 0) return std::nullopt;
            timeout_ms = static_cast<int>(left.count());
        }

        int ret = ::poll(fds, 2, timeout_ms);
        if (ret < 0) {
            if (errno == EINTR) continue;
            last_error_ = std::string("poll() failed: ") + std::strerror(errno);
            state_.store(State::kError, std::memory_order_release);
            return std::nullopt;
        }
        if (ret == 0) {
            return std::nullopt; // 超时，状态保持 kOpen
        }

        if (fds[1].revents & POLLIN) {
            char discard[16];
            const ssize_t w = ::read(wakeup_pipe_[0], discard, sizeof(discard));
            (void)w;
            // Wakeup 返回 nullopt，让上层检查 stop 条件后再决定是否重入
            return std::nullopt;
        }

        if (fds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            if (!PumpOnce()) return std::nullopt;
            if (TryConsumeFromBuffer(line)) return line;
            // 无完整行 → 继续下一轮 poll
            continue;
        }

        // 兜底：revents 未标注 POLLIN 类且非超时 → 视为异常
        last_error_ = "poll() returned unexpected revents";
        state_.store(State::kError, std::memory_order_release);
        return std::nullopt;
    }
}

void UnixSerialConsoleSource::Wakeup()
{
    if (wakeup_pipe_[1] == -1) return;
    const char byte = 1;
    const ssize_t n = ::write(wakeup_pipe_[1], &byte, 1);
    (void)n; // 管道可能满/已关，状态由 ReadLine 兜底
}

void UnixSerialConsoleSource::ReleaseFds() noexcept
{
    if (socket_owned_) {
        CloseFd(socket_fd_);
    } else {
        socket_fd_ = -1;
    }
    socket_owned_ = false;
    CloseFd(wakeup_pipe_[0]);
    CloseFd(wakeup_pipe_[1]);
}

void UnixSerialConsoleSource::Close()
{
    ReleaseFds();
    line_buffer_.clear();
    // kError / kEof 保留（供上层读 CurrentState() 决策）；否则回落 kIdle
    State cur = state_.load(std::memory_order_acquire);
    if (cur == State::kOpen) {
        state_.store(State::kIdle, std::memory_order_release);
    }
}

std::string UnixSerialConsoleSource::LastError() const
{
    return last_error_;
}

} // namespace refuzz::channel::evidence

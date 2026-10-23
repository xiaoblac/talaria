#include "refuzz/channel/infra/xiuos_uart_backbone.hpp"

#include "refuzz/proto_wire/xiuos_uart_codec.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <termios.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <thread>
#include <utility>
#include <vector>

namespace refuzz::channel::infra {

namespace {

using refuzz::channel::Error;
using refuzz::channel::ErrorKind;
using refuzz::channel::Result;

std::string StrErrno(int err) {
    return std::strerror(err);
}

Result<int> CreateSocket() {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return Error{ErrorKind::kInfra, "socket(): " + StrErrno(errno)};
    }
    return Result<int>::Ok(fd);
}

bool FrameMatches(const XiuosFrameMessage& m,
                  XiuosFrameType want_type,
                  std::optional<std::uint16_t> want_seq) {
    if (m.type != want_type) return false;
    if (want_seq.has_value() && m.seq != *want_seq) return false;
    return true;
}

XiuosFrameMessage MessageFromView(const XiuosFrameView& v) {
    XiuosFrameMessage m;
    m.type = static_cast<XiuosFrameType>(v.type);
    m.seq = v.seq;
    if (v.payload_len > 0 && v.payload != nullptr) {
        m.payload.assign(v.payload, v.payload + v.payload_len);
    }
    return m;
}

}  // namespace

XiuosUartBackbone::XiuosUartBackbone(const Config& cfg)
    : config_(cfg) {
    XiuosDecodeInit(&decode_);
}

XiuosUartBackbone::~XiuosUartBackbone() {
    const int fd = fd_.exchange(-1);
    if (fd >= 0) {
        ::shutdown(fd, SHUT_RDWR);
        ::close(fd);
    }
}

Result<std::shared_ptr<XiuosUartBackbone>>
XiuosUartBackbone::Create(const Config& cfg) {
    if (cfg.transport == Config::Transport::kSerial) {
        if (cfg.serial_device.empty()) {
            return Error{ErrorKind::kConfig,
                         "XiuosUartBackbone: serial_device must be non-empty (kSerial)"};
        }
    } else {
        if (cfg.port == 0) {
            return Error{ErrorKind::kConfig,
                         "XiuosUartBackbone: port must be non-zero (kTcp)"};
        }
        if (cfg.host.empty()) {
            return Error{ErrorKind::kConfig,
                         "XiuosUartBackbone: host must be non-empty (kTcp)"};
        }
    }
    if (cfg.max_queued_frames == 0) {
        return Error{ErrorKind::kConfig,
                     "XiuosUartBackbone: max_queued_frames must be non-zero"};
    }
    return Result<std::shared_ptr<XiuosUartBackbone>>::Ok(
        std::shared_ptr<XiuosUartBackbone>(new XiuosUartBackbone(cfg)));
}

bool XiuosUartBackbone::IsConnected() const noexcept {
    return fd_.load() >= 0;
}

std::size_t XiuosUartBackbone::BufferedFrameQueueSize() const noexcept {
    return queued_frames_.size();
}

Result<void> XiuosUartBackbone::Connect() {
    return config_.transport == Config::Transport::kSerial ? ConnectSerial()
                                                           : ConnectTcp();
}

Result<void> XiuosUartBackbone::ConnectTcp() {
    // [Stage 3 reboot reconnect] A lingering fd means we're on the recovery
    // reboot path (RecoveryExe::ExecuteRebootInstance → RebootVM relaunched QEMU,
    // then DP.Prepare → here): the old TCP connection points at the now-dead
    // QEMU, so close it and connect fresh to the relaunched QEMU. At first boot
    // fd_ == -1 so this is a no-op. Safe because the Channel recovery sequence
    // pauses the data plane + suspends health before reboot, so no other thread
    // is touching the backbone here.
    {
        const int stale = fd_.exchange(-1);
        if (stale >= 0) {
            ::shutdown(stale, SHUT_RDWR);
            ::close(stale);
        }
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(config_.port);
    if (::inet_pton(AF_INET, config_.host.c_str(), &addr.sin_addr) != 1) {
        return Error{ErrorKind::kConfig,
                     "XiuosUartBackbone::Connect: invalid host '" + config_.host + "'"};
    }

    const auto deadline = std::chrono::steady_clock::now() + config_.connect_timeout;
    for (;;) {
        auto fd_result = CreateSocket();
        if (!fd_result.ok()) return fd_result.error();
        const int fd = fd_result.value();

        if (::connect(fd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == 0) {
            int expected = -1;
            if (!fd_.compare_exchange_strong(expected, fd)) {
                ::shutdown(fd, SHUT_RDWR);
                ::close(fd);
                return Error{ErrorKind::kConnection,
                             "XiuosUartBackbone::Connect: closed concurrently"};
            }
            XiuosDecodeInit(&decode_);
            queued_frames_.clear();
            return Result<void>::Ok();
        }
        const int err = errno;
        ::close(fd);

        if (std::chrono::steady_clock::now() >= deadline) {
            return Error{ErrorKind::kTimeout,
                         "XiuosUartBackbone::Connect: timed out connecting to " +
                             config_.host + ":" + std::to_string(config_.port) +
                             ": " + StrErrno(err)};
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

Result<void> XiuosUartBackbone::ConnectSerial() {
    // recovery reboot 复用同一 backbone:旧 fd 指向 reset 前的串口句柄,关掉重开。
    // 物理板(WCH-Link CDC)在板 reset 时 host 侧 /dev/ttyACM* 持续存在;若设备正在
    // 重枚举,open 失败则在 connect_timeout 内重试(镜像 TCP connect 的重试)。
    {
        const int stale = fd_.exchange(-1);
        if (stale >= 0) {
            ::close(stale);  // serial fd:无 shutdown(),直接 close
        }
    }

    speed_t spd;
    switch (config_.baud) {
        case 9600:   spd = B9600;   break;
        case 19200:  spd = B19200;  break;
        case 38400:  spd = B38400;  break;
        case 57600:  spd = B57600;  break;
        case 115200: spd = B115200; break;
        case 230400: spd = B230400; break;
        case 460800: spd = B460800; break;
        case 921600: spd = B921600; break;
        default:     spd = B115200; break;  // 未知波特率回退 115200(物理板默认)
    }

    const auto deadline = std::chrono::steady_clock::now() + config_.connect_timeout;
    for (;;) {
        const int fd =
            ::open(config_.serial_device.c_str(),
                   O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
        if (fd >= 0) {
            struct termios tio{};
            if (::tcgetattr(fd, &tio) != 0) {
                const int err = errno;
                ::close(fd);
                return Error{ErrorKind::kConnection,
                             "XiuosUartBackbone::ConnectSerial: tcgetattr('" +
                                 config_.serial_device + "'): " + StrErrno(err)};
            }
            ::cfmakeraw(&tio);
            ::cfsetispeed(&tio, spd);
            ::cfsetospeed(&tio, spd);
            tio.c_cflag |= (CLOCAL | CREAD);   // ignore modem ctrl lines, enable receiver
            tio.c_cflag &= ~CRTSCTS;           // no hardware flow control
            tio.c_cflag &= ~CSTOPB;            // 1 stop bit
            tio.c_cflag &= ~PARENB;            // no parity
            tio.c_cflag &= ~CSIZE;
            tio.c_cflag |= CS8;                // 8 data bits
            tio.c_cc[VMIN]  = 0;               // non-blocking; reads are poll()-gated
            tio.c_cc[VTIME] = 0;
            if (::tcsetattr(fd, TCSANOW, &tio) != 0) {
                const int err = errno;
                ::close(fd);
                return Error{ErrorKind::kConnection,
                             "XiuosUartBackbone::ConnectSerial: tcsetattr('" +
                                 config_.serial_device + "'): " + StrErrno(err)};
            }
            ::tcflush(fd, TCIOFLUSH);

            int expected = -1;
            if (!fd_.compare_exchange_strong(expected, fd)) {
                ::close(fd);
                return Error{ErrorKind::kConnection,
                             "XiuosUartBackbone::ConnectSerial: closed concurrently"};
            }
            XiuosDecodeInit(&decode_);
            queued_frames_.clear();
            return Result<void>::Ok();
        }
        const int err = errno;

        if (std::chrono::steady_clock::now() >= deadline) {
            return Error{ErrorKind::kTimeout,
                         "XiuosUartBackbone::ConnectSerial: timed out opening " +
                             config_.serial_device + ": " + StrErrno(err)};
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

Result<void> XiuosUartBackbone::WriteAll(int fd, const std::uint8_t* data, std::size_t len) {
    while (len > 0) {
        // 串口 fd 用 write();socket fd 用 send(MSG_NOSIGNAL)(防 SIGPIPE)。
        const ssize_t n =
            (config_.transport == Config::Transport::kSerial)
                ? ::write(fd, data, len)
                : ::send(fd, data, len, MSG_NOSIGNAL);
        if (n > 0) {
            data += n;
            len -= static_cast<std::size_t>(n);
            continue;
        }
        if (n < 0 && (errno == EINTR || errno == EAGAIN)) {
            continue;
        }
        return Error{ErrorKind::kConnection,
                     "XiuosUartBackbone::WriteAll: send(): " + StrErrno(errno)};
    }
    return Result<void>::Ok();
}

Result<void> XiuosUartBackbone::SendFrame(XiuosFrameType type,
                                          std::uint16_t seq,
                                          std::span<const std::uint8_t> payload) {
    const int fd = fd_.load();
    if (fd < 0) {
        return Error{ErrorKind::kConnection, "XiuosUartBackbone::SendFrame: not connected"};
    }
    if (payload.size() > XIUOS_MAX_PAYLOAD) {
        return Error{ErrorKind::kProtocol,
                     "XiuosUartBackbone::SendFrame: payload exceeds XIUOS_MAX_PAYLOAD"};
    }

    std::uint8_t buf[XIUOS_HEADER_SIZE + XIUOS_MAX_PAYLOAD + 2];
    const std::size_t total = XiuosBuildFrame(
        buf, sizeof(buf),
        static_cast<std::uint8_t>(type), seq,
        payload.empty() ? nullptr : payload.data(),
        static_cast<std::uint16_t>(payload.size()));
    if (total == 0) {
        return Error{ErrorKind::kProtocol,
                     "XiuosUartBackbone::SendFrame: XiuosBuildFrame failed"};
    }
    return WriteAll(fd, buf, total);
}

Result<bool>
XiuosUartBackbone::PollReadable(int fd, std::chrono::milliseconds remaining) {
    pollfd pfd{};
    pfd.fd = fd;
    pfd.events = POLLIN;

    const int timeout_ms =
        remaining.count() < 0 ? 0 : static_cast<int>(remaining.count());

    const int rc = ::poll(&pfd, 1, timeout_ms);
    if (rc < 0) {
        if (errno == EINTR) {
            return Result<bool>::Ok(false);
        }
        return Error{ErrorKind::kConnection,
                     "XiuosUartBackbone::PollReadable: poll(): " + StrErrno(errno)};
    }
    if (rc == 0) {
        return Result<bool>::Ok(false);
    }
    if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
        return Error{ErrorKind::kConnection,
                     "XiuosUartBackbone::PollReadable: socket closed by peer"};
    }
    return Result<bool>::Ok((pfd.revents & POLLIN) != 0);
}

Result<XiuosFrameMessage>
XiuosUartBackbone::WaitFrame(XiuosFrameType want_type,
                             std::optional<std::uint16_t> want_seq,
                             std::chrono::milliseconds timeout) {
    if (fd_.load() < 0) {
        return Error{ErrorKind::kConnection, "XiuosUartBackbone::WaitFrame: not connected"};
    }

    const auto deadline = std::chrono::steady_clock::now() + timeout;
    std::vector<std::uint8_t> chunk(config_.read_chunk);

    for (;;) {
        // 1. Already-buffered frames take priority. CP heartbeat and DP
        //    PROGRAM/RESULT share this backbone; a frame received earlier
        //    while waiting for a different (type, seq) stays here.
        for (auto it = queued_frames_.begin(); it != queued_frames_.end(); ++it) {
            if (FrameMatches(*it, want_type, want_seq)) {
                XiuosFrameMessage matched = std::move(*it);
                queued_frames_.erase(it);
                return Result<XiuosFrameMessage>::Ok(std::move(matched));
            }
        }

        // 2. Try to read bytes from the socket and push them through the
        //    pure-C state machine. On FRAME_READY we either return (match)
        //    or push into the pending queue (mismatch).
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            return Error{ErrorKind::kTimeout,
                         "XiuosUartBackbone::WaitFrame: timed out waiting for type=" +
                             std::to_string(static_cast<int>(want_type))};
        }
        const int fd = fd_.load();
        if (fd < 0) {
            return Error{ErrorKind::kConnection,
                         "XiuosUartBackbone::WaitFrame: closed mid-wait"};
        }
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - now);

        auto ready = PollReadable(fd, remaining);
        if (!ready.ok()) return ready.error();
        if (!ready.value()) continue;

        // 串口 fd 用 read();socket fd 用 recv()。poll() 已报可读,O_NONBLOCK 下
        // read 返回可用字节(>0)。
        const ssize_t n =
            (config_.transport == Config::Transport::kSerial)
                ? ::read(fd, chunk.data(), chunk.size())
                : ::recv(fd, chunk.data(), chunk.size(), 0);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            return Error{ErrorKind::kConnection,
                         "XiuosUartBackbone::WaitFrame: recv(): " + StrErrno(errno)};
        }
        if (n == 0) {
            return Error{ErrorKind::kConnection,
                         "XiuosUartBackbone::WaitFrame: peer closed connection"};
        }

        for (ssize_t i = 0; i < n; ++i) {
            XiuosFrameView view{};
            const XiuosDecodeStatus s =
                XiuosDecodePush(&decode_, chunk[static_cast<std::size_t>(i)], &view);
            if (s != XIUOS_DECODE_FRAME_READY) continue;

            XiuosFrameMessage msg = MessageFromView(view);
            if (FrameMatches(msg, want_type, want_seq)) {
                return Result<XiuosFrameMessage>::Ok(std::move(msg));
            }
            if (queued_frames_.size() >= config_.max_queued_frames) {
                queued_frames_.pop_front();
            }
            queued_frames_.push_back(std::move(msg));
        }
    }
}

Result<void> XiuosUartBackbone::Close() {
    const int fd = fd_.exchange(-1);
    if (fd >= 0) {
        ::shutdown(fd, SHUT_RDWR);
        ::close(fd);
    }
    return Result<void>::Ok();
}

}  // namespace refuzz::channel::infra

// xiuos_uart_control_plane_test.cpp
//
// Phase 2 §B v1 review fixes — XiuosUartControlPlane behaviour tests
// without QEMU (loopback TCP peer that never sends READY).
//
// Covers two issues from the v1 review:
//   - HIGH: WaitAllWorkersReady(0 ms) must fall back to Config::ready_timeout
//     (Channel::Boot passes 0; ivshmem CP defaults the same way).
//   - MEDIUM: BeginSession must reject from Closing/Closed/Faulted instead
//     of silently returning OK; ResetSession brings state back to Idle so
//     recovery / reboot can begin a fresh session.
//
// LoopbackPeer mirrors the one in xiuos_uart_backbone_test.cpp — kept
// duplicated to keep each test file self-contained, consistent with the
// rest of the tests/ directory.

#include "refuzz/channel/control/xiuos_uart_control_plane.hpp"
#include "refuzz/channel/infra/xiuos_uart_backbone.hpp"
#include "refuzz/proto_wire/xiuos_uart_codec.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <memory>
#include <span>
#include <thread>
#include <vector>

namespace control = refuzz::channel::control;
namespace infra   = refuzz::channel::infra;

#define CHECK(cond)                                                                \
    do {                                                                           \
        if (!(cond)) {                                                             \
            std::fprintf(stderr, "CHECK failed: %s (line %d)\n", #cond, __LINE__); \
            return 1;                                                              \
        }                                                                          \
    } while (0)

namespace {

// Self-contained TCP loopback peer. Bind on 127.0.0.1:0, accept one
// connection, drive bytes via Send().
class LoopbackPeer {
public:
    bool Listen() {
        listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (listen_fd_ < 0) return false;
        int one = 1;
        ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (::bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            ::close(listen_fd_); listen_fd_ = -1; return false;
        }
        if (::listen(listen_fd_, 1) != 0) {
            ::close(listen_fd_); listen_fd_ = -1; return false;
        }
        sockaddr_in bound{};
        socklen_t len = sizeof(bound);
        if (::getsockname(listen_fd_, reinterpret_cast<sockaddr*>(&bound), &len) != 0) {
            ::close(listen_fd_); listen_fd_ = -1; return false;
        }
        port_ = ntohs(bound.sin_port);
        return true;
    }

    bool AcceptIn(std::chrono::milliseconds timeout) {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline) {
            sockaddr_in peer{};
            socklen_t len = sizeof(peer);
            const int fd = ::accept4(listen_fd_, reinterpret_cast<sockaddr*>(&peer),
                                     &len, SOCK_NONBLOCK);
            if (fd >= 0) {
                const int flags = ::fcntl(fd, F_GETFL, 0);
                ::fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
                peer_fd_ = fd;
                return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        return false;
    }

    bool Send(std::span<const std::uint8_t> bytes) {
        if (peer_fd_ < 0) return false;
        std::size_t off = 0;
        while (off < bytes.size()) {
            const ssize_t n = ::send(peer_fd_, bytes.data() + off,
                                     bytes.size() - off, MSG_NOSIGNAL);
            if (n <= 0) return false;
            off += static_cast<std::size_t>(n);
        }
        return true;
    }

    std::uint16_t port() const { return port_; }

    ~LoopbackPeer() {
        if (peer_fd_   >= 0) ::close(peer_fd_);
        if (listen_fd_ >= 0) ::close(listen_fd_);
    }

private:
    int           listen_fd_{-1};
    int           peer_fd_{-1};
    std::uint16_t port_{0};
};

std::shared_ptr<infra::XiuosUartBackbone>
ConnectBackbone(LoopbackPeer& peer, std::chrono::milliseconds frame_timeout) {
    infra::XiuosUartBackbone::Config cfg;
    cfg.host = "127.0.0.1";
    cfg.port = peer.port();
    cfg.connect_timeout = std::chrono::seconds(2);
    cfg.frame_timeout = frame_timeout;
    auto bb_r = infra::XiuosUartBackbone::Create(cfg);
    if (!bb_r.ok()) return nullptr;
    auto bb = bb_r.value();
    std::atomic<bool> connect_ok{false};
    std::thread connect_thread([&] { connect_ok.store(bb->Connect().ok()); });
    if (!peer.AcceptIn(std::chrono::seconds(2))) {
        connect_thread.join();
        return nullptr;
    }
    connect_thread.join();
    if (!connect_ok.load()) return nullptr;
    return bb;
}

// HIGH: WaitAllWorkersReady(0 ms) must wait Config::ready_timeout, not
// time out immediately. ivshmem CP behaves the same way and Channel::Boot
// passes 0 ms verbatim (executor/channel/orchestration/src/channel.cpp).
int TestWaitAllWorkersReadyFallsBackToConfigTimeout() {
    LoopbackPeer peer; CHECK(peer.Listen());
    auto bb = ConnectBackbone(peer, std::chrono::seconds(2));
    CHECK(bb != nullptr);

    control::XiuosUartControlPlane::Config cfg;
    cfg.backbone = bb;
    cfg.ready_timeout = std::chrono::milliseconds(200);
    control::XiuosUartControlPlane cp(cfg);

    const auto t0 = std::chrono::steady_clock::now();
    auto r = cp.WaitAllWorkersReady(std::chrono::milliseconds(0));
    const auto elapsed = std::chrono::steady_clock::now() - t0;

    CHECK(!r.ok());
    CHECK(r.error().kind == refuzz::channel::ErrorKind::kTimeout);
    // Must wait at least roughly the configured ready_timeout. 100 ms is a
    // generous lower bound; 1 s is a generous upper bound to keep the test
    // fast.
    CHECK(elapsed >= std::chrono::milliseconds(100));
    CHECK(elapsed <  std::chrono::seconds(1));

    // State should be kFaulted after a failed handshake.
    CHECK(cp.CurrentState() == control::SessionState::kFaulted);
    return 0;
}

// Explicit non-zero timeout must be honored (config_.ready_timeout is only
// the fallback path).
int TestWaitAllWorkersReadyHonorsExplicitTimeout() {
    LoopbackPeer peer; CHECK(peer.Listen());
    auto bb = ConnectBackbone(peer, std::chrono::seconds(2));
    CHECK(bb != nullptr);

    control::XiuosUartControlPlane::Config cfg;
    cfg.backbone = bb;
    cfg.ready_timeout = std::chrono::seconds(60);  // would otherwise mask the bug
    control::XiuosUartControlPlane cp(cfg);

    const auto t0 = std::chrono::steady_clock::now();
    auto r = cp.WaitAllWorkersReady(std::chrono::milliseconds(150));
    const auto elapsed = std::chrono::steady_clock::now() - t0;

    CHECK(!r.ok());
    CHECK(r.error().kind == refuzz::channel::ErrorKind::kTimeout);
    CHECK(elapsed >= std::chrono::milliseconds(80));
    CHECK(elapsed <  std::chrono::milliseconds(800));
    return 0;
}

// When READY actually arrives, WaitAllWorkersReady completes promptly and
// state transitions to kReady (even with the fallback path: 0 ms passed in).
int TestWaitAllWorkersReadySucceedsOnReadyFrame() {
    LoopbackPeer peer; CHECK(peer.Listen());
    auto bb = ConnectBackbone(peer, std::chrono::seconds(5));
    CHECK(bb != nullptr);

    control::XiuosUartControlPlane::Config cfg;
    cfg.backbone = bb;
    cfg.ready_timeout = std::chrono::seconds(2);
    control::XiuosUartControlPlane cp(cfg);

    std::uint8_t ready_buf[XIUOS_HEADER_SIZE + 2];
    const std::size_t ready_len = XiuosBuildFrame(
        ready_buf, sizeof(ready_buf), XIUOS_FRAME_READY, 0, nullptr, 0);
    CHECK(peer.Send(std::span<const std::uint8_t>(ready_buf, ready_len)));

    auto r = cp.WaitAllWorkersReady(std::chrono::milliseconds(0));
    CHECK(r.ok());
    CHECK(cp.CurrentState() == control::SessionState::kReady);
    CHECK(cp.IsWorkerRegistered(0));
    return 0;
}

// MEDIUM: BeginSession from Closed must return Error.
int TestBeginSessionRejectsFromClosed() {
    LoopbackPeer peer; CHECK(peer.Listen());
    auto bb = ConnectBackbone(peer, std::chrono::seconds(2));
    CHECK(bb != nullptr);

    control::XiuosUartControlPlane::Config cfg;
    cfg.backbone = bb;
    cfg.ready_timeout = std::chrono::milliseconds(100);
    control::XiuosUartControlPlane cp(cfg);

    CHECK(cp.BeginSession().ok());
    CHECK(cp.CurrentState() == control::SessionState::kHandshaking);

    // Driving into Closed.
    CHECK(cp.EndSession().ok());
    CHECK(cp.CurrentState() == control::SessionState::kClosed);

    auto r = cp.BeginSession();
    CHECK(!r.ok());
    CHECK(r.error().kind == refuzz::channel::ErrorKind::kProtocol);

    // ResetSession should bring the state back to a beginnable place.
    CHECK(cp.ResetSession().ok());
    CHECK(cp.CurrentState() == control::SessionState::kIdle);
    CHECK(cp.BeginSession().ok());
    CHECK(cp.CurrentState() == control::SessionState::kHandshaking);
    return 0;
}

// BeginSession from Handshaking / Ready must be idempotent (return OK,
// no state change).
int TestBeginSessionIdempotentFromActive() {
    LoopbackPeer peer; CHECK(peer.Listen());
    auto bb = ConnectBackbone(peer, std::chrono::seconds(5));
    CHECK(bb != nullptr);

    control::XiuosUartControlPlane::Config cfg;
    cfg.backbone = bb;
    cfg.ready_timeout = std::chrono::seconds(2);
    control::XiuosUartControlPlane cp(cfg);

    CHECK(cp.BeginSession().ok());
    CHECK(cp.BeginSession().ok());  // idempotent from Handshaking
    CHECK(cp.CurrentState() == control::SessionState::kHandshaking);

    std::uint8_t ready_buf[XIUOS_HEADER_SIZE + 2];
    const std::size_t ready_len = XiuosBuildFrame(
        ready_buf, sizeof(ready_buf), XIUOS_FRAME_READY, 0, nullptr, 0);
    CHECK(peer.Send(std::span<const std::uint8_t>(ready_buf, ready_len)));
    CHECK(cp.WaitAllWorkersReady(std::chrono::milliseconds(0)).ok());
    CHECK(cp.CurrentState() == control::SessionState::kReady);

    CHECK(cp.BeginSession().ok());  // idempotent from Ready
    CHECK(cp.CurrentState() == control::SessionState::kReady);
    return 0;
}

// ResetSession from Ready must discard stale readiness. Reboot recovery enters
// this path while the old QEMU was Ready; the next WaitAllWorkersReady must wait
// for a new READY frame from the relaunched VM.
int TestResetSessionFromReadyRequiresNewReady() {
    LoopbackPeer peer; CHECK(peer.Listen());
    auto bb = ConnectBackbone(peer, std::chrono::seconds(2));
    CHECK(bb != nullptr);

    control::XiuosUartControlPlane::Config cfg;
    cfg.backbone = bb;
    cfg.ready_timeout = std::chrono::milliseconds(50);
    control::XiuosUartControlPlane cp(cfg);

    CHECK(cp.BeginSession().ok());
    std::uint8_t ready_buf[XIUOS_HEADER_SIZE + 2];
    const std::size_t ready_len = XiuosBuildFrame(
        ready_buf, sizeof(ready_buf), XIUOS_FRAME_READY, 0, nullptr, 0);
    CHECK(peer.Send(std::span<const std::uint8_t>(ready_buf, ready_len)));
    CHECK(cp.WaitAllWorkersReady(std::chrono::milliseconds(0)).ok());
    CHECK(cp.CurrentState() == control::SessionState::kReady);
    CHECK(cp.RegisteredWorkerCount() == 1);

    CHECK(cp.ResetSession().ok());
    CHECK(cp.CurrentState() == control::SessionState::kIdle);
    CHECK(cp.RegisteredWorkerCount() == 0);

    CHECK(cp.BeginSession().ok());
    auto r = cp.WaitAllWorkersReady(std::chrono::milliseconds(20));
    CHECK(!r.ok());
    CHECK(cp.CurrentState() == control::SessionState::kFaulted);
    return 0;
}

// BeginSession from Faulted must reject; ResetSession is required.
int TestBeginSessionRejectsFromFaulted() {
    LoopbackPeer peer; CHECK(peer.Listen());
    auto bb = ConnectBackbone(peer, std::chrono::seconds(2));
    CHECK(bb != nullptr);

    control::XiuosUartControlPlane::Config cfg;
    cfg.backbone = bb;
    cfg.ready_timeout = std::chrono::milliseconds(100);
    control::XiuosUartControlPlane cp(cfg);

    // Force a Fault by failing the ready handshake (no READY ever sent).
    CHECK(!cp.WaitAllWorkersReady(std::chrono::milliseconds(0)).ok());
    CHECK(cp.CurrentState() == control::SessionState::kFaulted);

    auto r = cp.BeginSession();
    CHECK(!r.ok());
    CHECK(r.error().kind == refuzz::channel::ErrorKind::kProtocol);

    CHECK(cp.ResetSession().ok());
    CHECK(cp.CurrentState() == control::SessionState::kIdle);
    CHECK(cp.BeginSession().ok());
    return 0;
}

}  // namespace

int main() {
    std::fprintf(stdout, "Running xiuos_uart_control_plane_test...\n");
    int run = 0, ok = 0;
    auto exec = [&](auto fn, const char* name) {
        ++run;
        std::fprintf(stderr, "  [RUN] %s\n", name);
        if (fn() == 0) { ++ok; std::fprintf(stderr, "  [PASS] %s\n", name); }
        else            { std::fprintf(stderr, "  [FAIL] %s\n", name); }
    };

    exec(TestWaitAllWorkersReadyFallsBackToConfigTimeout,
         "WaitAllWorkersReadyFallsBackToConfigTimeout");
    exec(TestWaitAllWorkersReadyHonorsExplicitTimeout,
         "WaitAllWorkersReadyHonorsExplicitTimeout");
    exec(TestWaitAllWorkersReadySucceedsOnReadyFrame,
         "WaitAllWorkersReadySucceedsOnReadyFrame");
    exec(TestBeginSessionRejectsFromClosed,
         "BeginSessionRejectsFromClosed");
    exec(TestBeginSessionIdempotentFromActive,
         "BeginSessionIdempotentFromActive");
    exec(TestResetSessionFromReadyRequiresNewReady,
         "ResetSessionFromReadyRequiresNewReady");
    exec(TestBeginSessionRejectsFromFaulted,
         "BeginSessionRejectsFromFaulted");

    std::fprintf(stdout, "\nPassed %d/%d tests\n", ok, run);
    return (run == ok) ? 0 : 1;
}

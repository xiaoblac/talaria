// xiuos_uart_backbone_test.cpp
//
// Phase 2 §B v1 — unit tests for XiuosUartBackbone behaviour that does NOT
// require QEMU. Uses a 127.0.0.1 TCP listener as the peer.
//
// Covers the two findings landed alongside the v1 codec/backbone slice:
//   - HIGH: WaitFrame must buffer non-matching frames (CP heartbeat ↔ DP
//     PROGRAM/RESULT share the backbone), not silently discard them.
//   - MEDIUM: Close() called from another thread must unblock an in-flight
//     WaitFrame promptly via shutdown(SHUT_RDWR).

#include "refuzz/channel/infra/xiuos_uart_backbone.hpp"
#include "refuzz/proto_wire/xiuos_uart_codec.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <thread>
#include <vector>

namespace infra = refuzz::channel::infra;

#define CHECK(cond)                                                                \
    do {                                                                           \
        if (!(cond)) {                                                             \
            std::fprintf(stderr, "CHECK failed: %s (line %d)\n", #cond, __LINE__); \
            return 1;                                                              \
        }                                                                          \
    } while (0)

namespace {

// Minimal TCP loopback peer. Bind on 127.0.0.1:0, accept one connection, then
// the test drives bytes through `peer_fd_`.
class LoopbackPeer {
public:
    bool Listen() {
        listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (listen_fd_ < 0) return false;

        int one = 1;
        ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = 0;  // kernel picks
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
                // Switch back to blocking for ease of use in test.
                int flags = ::fcntl(fd, F_GETFL, 0);
                ::fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
                if (peer_fd_ >= 0) ::close(peer_fd_);
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

// Test-local helper around the pure-C XiuosBuildFrame so individual cases
// can keep building frames as `std::vector<uint8_t>` without resurrecting
// a wider C++ codec wrapper.
std::vector<std::uint8_t> MakeFrame(std::uint8_t type, std::uint16_t seq,
                                    std::span<const std::uint8_t> payload = {}) {
    std::vector<std::uint8_t> out(XIUOS_HEADER_SIZE + payload.size() + 2);
    const std::size_t n = XiuosBuildFrame(
        out.data(), out.size(), type, seq,
        payload.empty() ? nullptr : payload.data(),
        static_cast<std::uint16_t>(payload.size()));
    out.resize(n);
    return out;
}

infra::XiuosUartBackbone::Config MakeConfig(std::uint16_t port) {
    infra::XiuosUartBackbone::Config cfg;
    cfg.host = "127.0.0.1";
    cfg.port = port;
    cfg.connect_timeout = std::chrono::milliseconds(2000);
    cfg.frame_timeout = std::chrono::milliseconds(2000);
    cfg.max_queued_frames = 8;
    return cfg;
}

// HIGH fix: cross-type frames received while WaitFrame waits for a specific
// (type, seq) must be queued, not discarded, so a later WaitFrame on the
// same backbone can pick them up.
int TestWaitFrameBuffersOutOfOrder() {
    LoopbackPeer peer;
    CHECK(peer.Listen());

    auto bb_result = infra::XiuosUartBackbone::Create(MakeConfig(peer.port()));
    CHECK(bb_result.ok());
    auto bb = bb_result.value();

    // Connect from a helper thread because Listen+Connect handshake otherwise
    // requires two threads.
    std::atomic<bool> connect_ok{false};
    std::thread connect_thread([&] {
        auto r = bb->Connect();
        connect_ok.store(r.ok());
    });

    CHECK(peer.AcceptIn(std::chrono::seconds(2)));
    connect_thread.join();
    CHECK(connect_ok.load());

    // Push READY + RESULT(empty) + PONG(seq=7) in one peer write. WaitFrame
    // for PONG should buffer READY and RESULT into the pending queue.
    const auto frame_ready =
        MakeFrame(XIUOS_FRAME_READY, 0);
    const auto frame_result_payload = std::vector<std::uint8_t>{
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};  // result_version=1, status=OK, coverage_size=0
    const auto frame_result =
        MakeFrame(XIUOS_FRAME_RESULT, 3,
                  std::span<const std::uint8_t>(frame_result_payload.data(),
                                                frame_result_payload.size()));
    const auto frame_pong =
        MakeFrame(XIUOS_FRAME_PONG, 7);

    std::vector<std::uint8_t> all;
    all.insert(all.end(), frame_ready.begin(),  frame_ready.end());
    all.insert(all.end(), frame_result.begin(), frame_result.end());
    all.insert(all.end(), frame_pong.begin(),   frame_pong.end());
    CHECK(peer.Send(std::span<const std::uint8_t>(all.data(), all.size())));

    auto pong = bb->WaitFrame(infra::XiuosFrameType::Pong, 7,
                              std::chrono::seconds(2));
    CHECK(pong.ok());
    CHECK(pong.value().type == infra::XiuosFrameType::Pong);
    CHECK(pong.value().seq == 7);
    CHECK(bb->BufferedFrameQueueSize() == 2);

    // Now drain the buffered READY and RESULT in either order.
    auto result = bb->WaitFrame(infra::XiuosFrameType::Result, 3,
                                std::chrono::seconds(1));
    CHECK(result.ok());
    CHECK(result.value().seq == 3);
    CHECK(bb->BufferedFrameQueueSize() == 1);

    auto ready = bb->WaitFrame(infra::XiuosFrameType::Ready, std::nullopt,
                               std::chrono::seconds(1));
    CHECK(ready.ok());
    CHECK(ready.value().type == infra::XiuosFrameType::Ready);
    CHECK(bb->BufferedFrameQueueSize() == 0);

    CHECK(bb->Close().ok());
    return 0;
}

// Bounded queue: when more than max_queued_frames non-matching frames pile
// up, the oldest gets dropped (drop-front).
int TestWaitFrameBoundedQueueDropsOldest() {
    LoopbackPeer peer;
    CHECK(peer.Listen());

    auto cfg = MakeConfig(peer.port());
    cfg.max_queued_frames = 3;
    auto bb_result = infra::XiuosUartBackbone::Create(cfg);
    CHECK(bb_result.ok());
    auto bb = bb_result.value();

    std::atomic<bool> connect_ok{false};
    std::thread connect_thread([&] {
        connect_ok.store(bb->Connect().ok());
    });
    CHECK(peer.AcceptIn(std::chrono::seconds(2)));
    connect_thread.join();
    CHECK(connect_ok.load());

    // Send 5 PONG(seq=0..4) then 1 ACK(seq=99) — the ACK is what we're
    // waiting for; the 5 PONGs overflow a queue of size 3 and the oldest 2
    // (seq=0, seq=1) must be dropped.
    std::vector<std::uint8_t> all;
    for (int s = 0; s < 5; ++s) {
        const auto f = MakeFrame(XIUOS_FRAME_PONG, static_cast<std::uint16_t>(s));
        all.insert(all.end(), f.begin(), f.end());
    }
    const auto ack = MakeFrame(XIUOS_FRAME_ACK, 99);
    all.insert(all.end(), ack.begin(), ack.end());
    CHECK(peer.Send(std::span<const std::uint8_t>(all.data(), all.size())));

    auto ack_got = bb->WaitFrame(infra::XiuosFrameType::Ack, 99,
                                 std::chrono::seconds(2));
    CHECK(ack_got.ok());
    CHECK(ack_got.value().seq == 99);

    // Queue should have exactly cfg.max_queued_frames PONGs left, and they
    // should be the most-recent ones (seq=2, 3, 4).
    CHECK(bb->BufferedFrameQueueSize() == 3);

    auto seq2 = bb->WaitFrame(infra::XiuosFrameType::Pong, std::nullopt,
                              std::chrono::seconds(1));
    CHECK(seq2.ok());
    CHECK(seq2.value().seq == 2);

    auto seq3 = bb->WaitFrame(infra::XiuosFrameType::Pong, std::nullopt,
                              std::chrono::seconds(1));
    CHECK(seq3.ok());
    CHECK(seq3.value().seq == 3);

    auto seq4 = bb->WaitFrame(infra::XiuosFrameType::Pong, std::nullopt,
                              std::chrono::seconds(1));
    CHECK(seq4.ok());
    CHECK(seq4.value().seq == 4);

    CHECK(bb->BufferedFrameQueueSize() == 0);
    CHECK(bb->Close().ok());
    return 0;
}

// MEDIUM fix: Close() from another thread must unblock an in-flight
// WaitFrame promptly. The blocked thread should see kConnection (not a
// hang and not silent success).
int TestCloseFromAnotherThreadUnblocksWaitFrame() {
    LoopbackPeer peer;
    CHECK(peer.Listen());

    auto cfg = MakeConfig(peer.port());
    cfg.frame_timeout = std::chrono::seconds(30);  // would otherwise mask the bug
    auto bb_result = infra::XiuosUartBackbone::Create(cfg);
    CHECK(bb_result.ok());
    auto bb = bb_result.value();

    std::atomic<bool> connect_ok{false};
    std::thread connect_thread([&] { connect_ok.store(bb->Connect().ok()); });
    CHECK(peer.AcceptIn(std::chrono::seconds(2)));
    connect_thread.join();
    CHECK(connect_ok.load());

    // Helper thread closes after a short delay; main thread waits 30s for
    // a frame that never arrives. Without shutdown() the close would NOT
    // wake the blocked poll/recv, the test would hang for 30s.
    std::thread closer([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        bb->Close();
    });

    const auto t0 = std::chrono::steady_clock::now();
    auto rc = bb->WaitFrame(infra::XiuosFrameType::Pong, std::nullopt,
                            std::chrono::seconds(30));
    const auto elapsed = std::chrono::steady_clock::now() - t0;

    closer.join();

    CHECK(!rc.ok());
    CHECK(rc.error().kind == refuzz::channel::ErrorKind::kConnection);
    // Should unblock well under the 30s timeout — pick a generous 5s bound.
    CHECK(elapsed < std::chrono::seconds(5));

    return 0;
}

// After Close(), every method should return kConnection (no hanging, no
// stale fd reuse).
int TestPostCloseMethodsReturnConnectionError() {
    LoopbackPeer peer;
    CHECK(peer.Listen());

    auto bb_result = infra::XiuosUartBackbone::Create(MakeConfig(peer.port()));
    CHECK(bb_result.ok());
    auto bb = bb_result.value();

    std::atomic<bool> connect_ok{false};
    std::thread connect_thread([&] { connect_ok.store(bb->Connect().ok()); });
    CHECK(peer.AcceptIn(std::chrono::seconds(2)));
    connect_thread.join();
    CHECK(connect_ok.load());

    CHECK(bb->Close().ok());
    CHECK(!bb->IsConnected());

    auto send_rc = bb->SendFrame(infra::XiuosFrameType::Ping, 1, {});
    CHECK(!send_rc.ok());
    CHECK(send_rc.error().kind == refuzz::channel::ErrorKind::kConnection);

    auto wait_rc = bb->WaitFrame(infra::XiuosFrameType::Pong, std::nullopt,
                                 std::chrono::milliseconds(50));
    CHECK(!wait_rc.ok());
    CHECK(wait_rc.error().kind == refuzz::channel::ErrorKind::kConnection);

    // Calling Close() again is idempotent.
    CHECK(bb->Close().ok());
    return 0;
}

// Recovery calls DP.Prepare() after reboot while the backbone may still hold
// the fd from the old QEMU. Connect() must replace that stale connection
// instead of rejecting "already connected".
int TestConnectAgainReplacesExistingConnection() {
    LoopbackPeer peer;
    CHECK(peer.Listen());

    auto bb_result = infra::XiuosUartBackbone::Create(MakeConfig(peer.port()));
    CHECK(bb_result.ok());
    auto bb = bb_result.value();

    std::atomic<bool> first_ok{false};
    std::thread first_thread([&] { first_ok.store(bb->Connect().ok()); });
    CHECK(peer.AcceptIn(std::chrono::seconds(2)));
    first_thread.join();
    CHECK(first_ok.load());
    CHECK(bb->IsConnected());

    std::atomic<bool> second_ok{false};
    std::thread second_thread([&] { second_ok.store(bb->Connect().ok()); });
    CHECK(peer.AcceptIn(std::chrono::seconds(2)));
    second_thread.join();
    CHECK(second_ok.load());
    CHECK(bb->IsConnected());

    CHECK(bb->Close().ok());
    return 0;
}

}  // namespace

int main() {
    std::fprintf(stdout, "Running xiuos_uart_backbone_test...\n");
    int run = 0, ok = 0;
    auto exec = [&](auto fn, const char* name) {
        ++run;
        std::fprintf(stderr, "  [RUN] %s\n", name);
        if (fn() == 0) { ++ok; std::fprintf(stderr, "  [PASS] %s\n", name); }
        else            { std::fprintf(stderr, "  [FAIL] %s\n", name); }
    };

    exec(TestWaitFrameBuffersOutOfOrder,
         "WaitFrameBuffersOutOfOrder");
    exec(TestWaitFrameBoundedQueueDropsOldest,
         "WaitFrameBoundedQueueDropsOldest");
    exec(TestCloseFromAnotherThreadUnblocksWaitFrame,
         "CloseFromAnotherThreadUnblocksWaitFrame");
    exec(TestPostCloseMethodsReturnConnectionError,
         "PostCloseMethodsReturnConnectionError");
    exec(TestConnectAgainReplacesExistingConnection,
         "ConnectAgainReplacesExistingConnection");

    std::fprintf(stdout, "\nPassed %d/%d tests\n", ok, run);
    return (run == ok) ? 0 : 1;
}

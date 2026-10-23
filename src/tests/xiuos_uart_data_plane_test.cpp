// xiuos_uart_data_plane_test.cpp
//
// Unit tests for the XiUOS UART data plane that do not require QEMU. A local
// TCP peer accepts the backbone connection but intentionally never sends RESULT
// frames, allowing the per-program timeout path to be tested directly.

#include "refuzz/channel/data/xiuos_uart_data_plane.hpp"
#include "refuzz/channel/infra/xiuos_uart_backbone.hpp"

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
#include <thread>
#include <vector>

namespace data  = refuzz::channel::data;
namespace infra = refuzz::channel::infra;

#define CHECK(cond)                                                                \
    do {                                                                           \
        if (!(cond)) {                                                             \
            std::fprintf(stderr, "CHECK failed: %s (line %d)\n", #cond, __LINE__); \
            return 1;                                                              \
        }                                                                          \
    } while (0)

namespace {

class LoopbackPeer {
public:
    bool Listen() {
        listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (listen_fd_ < 0) return false;

        int one = 1;
        ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = 0;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (::bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            ::close(listen_fd_);
            listen_fd_ = -1;
            return false;
        }
        if (::listen(listen_fd_, 1) != 0) {
            ::close(listen_fd_);
            listen_fd_ = -1;
            return false;
        }
        sockaddr_in bound{};
        socklen_t len = sizeof(bound);
        if (::getsockname(listen_fd_, reinterpret_cast<sockaddr*>(&bound), &len) != 0) {
            ::close(listen_fd_);
            listen_fd_ = -1;
            return false;
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
                if (peer_fd_ >= 0) ::close(peer_fd_);
                peer_fd_ = fd;
                return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        return false;
    }

    std::uint16_t port() const { return port_; }

    ~LoopbackPeer() {
        if (peer_fd_ >= 0) ::close(peer_fd_);
        if (listen_fd_ >= 0) ::close(listen_fd_);
    }

private:
    int listen_fd_{-1};
    int peer_fd_{-1};
    std::uint16_t port_{0};
};

std::shared_ptr<infra::XiuosUartBackbone>
MakeBackbone(std::uint16_t port) {
    infra::XiuosUartBackbone::Config cfg;
    cfg.host = "127.0.0.1";
    cfg.port = port;
    cfg.connect_timeout = std::chrono::seconds(2);
    cfg.frame_timeout = std::chrono::seconds(2);
    cfg.max_queued_frames = 8;
    auto bb_r = infra::XiuosUartBackbone::Create(cfg);
    if (!bb_r.ok()) return nullptr;
    return bb_r.value();
}

int Prepare(data::XiuosUartDataPlane& dp, LoopbackPeer& peer) {
    std::atomic<bool> prepare_ok{false};
    std::thread prepare_thread([&] {
        prepare_ok.store(dp.Prepare().ok());
    });
    CHECK(peer.AcceptIn(std::chrono::seconds(2)));
    prepare_thread.join();
    CHECK(prepare_ok.load());
    return 0;
}

int SubmitProgram(data::XiuosUartDataPlane& dp, std::uint64_t executor_id) {
    const std::vector<std::uint8_t> payload{0x01, 0x02, 0x03};
    data::IDataPlane::SubmitInput req;
    req.worker_id = 0;
    req.executor_id = executor_id;
    req.dispatch_gen = 7;
    req.payload_data = payload.data();
    req.payload_size = payload.size();
    CHECK(dp.Submit(req) == data::SubmitOutcome::kSent);
    return 0;
}

int TestProgramTimeoutReleasesSlotAndLatchesWedge() {
    LoopbackPeer peer;
    CHECK(peer.Listen());

    auto backbone = MakeBackbone(peer.port());
    CHECK(backbone != nullptr);

    data::XiuosUartDataPlane::Config cfg;
    cfg.backbone = backbone;
    cfg.poll_slice = std::chrono::milliseconds(1);
    cfg.program_timeout = std::chrono::milliseconds(20);
    data::XiuosUartDataPlane dp(cfg);

    CHECK(Prepare(dp, peer) == 0);

    CHECK(SubmitProgram(dp, 0x12345678ull) == 0);
    CHECK(!dp.IsWorkerSendable(0));

    std::this_thread::sleep_for(std::chrono::milliseconds(30));

    std::vector<data::DispatchOutcome> out;
    dp.Poll(out, std::chrono::microseconds{0});

    CHECK(out.size() == 1);
    CHECK(out[0].worker_id == 0);
    CHECK(out[0].executor_id == 0x12345678ull);
    CHECK(out[0].dispatch_gen == 7);
    CHECK(out[0].kind == data::DispatchOutcomeKind::kTimeout);
    CHECK(out[0].worker_start_ts_us != 0);
    CHECK(out[0].worker_done_ts_us >= out[0].worker_start_ts_us);
    CHECK(dp.IsWorkerSendable(0));
    CHECK(dp.SnapshotInflight().empty());

    CHECK(dp.ConsumeWedgePending());
    CHECK(!dp.ConsumeWedgePending());

    CHECK(SubmitProgram(dp, 0x12345679ull) == 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(30));
    out.clear();
    dp.Poll(out, std::chrono::microseconds{0});
    CHECK(out.size() == 1);
    CHECK(dp.ConsumeWedgePending());

    CHECK(SubmitProgram(dp, 0x1234567aull) == 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(30));
    out.clear();
    dp.Poll(out, std::chrono::microseconds{0});
    CHECK(out.size() == 1);
    dp.ResetAll();
    CHECK(!dp.ConsumeWedgePending());

    dp.Close();
    return 0;
}

}  // namespace

int main() {
    std::fprintf(stdout, "Running xiuos_uart_data_plane_test...\n");
    int run = 0;
    int ok = 0;
    auto exec = [&](auto fn, const char* name) {
        ++run;
        std::fprintf(stderr, "  [RUN] %s\n", name);
        if (fn() == 0) {
            ++ok;
            std::fprintf(stderr, "  [PASS] %s\n", name);
        } else {
            std::fprintf(stderr, "  [FAIL] %s\n", name);
        }
    };

    exec(TestProgramTimeoutReleasesSlotAndLatchesWedge,
         "ProgramTimeoutReleasesSlotAndLatchesWedge");

    std::fprintf(stdout, "\nPassed %d/%d tests\n", ok, run);
    return (run == ok) ? 0 : 1;
}

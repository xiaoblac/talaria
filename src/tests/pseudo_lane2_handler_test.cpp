// PR-C0 + PR-B1 + PR-B2 + PR-B4 — Lane 2 net-stack handler tests.
//
// Test layers:
//   PR-C0 lazy infra: tun_fd() / vhci_fd() / init_net_socket() lazy + degrade.
//     - tun_fd graceful: open or -1 (CAP_NET_ADMIN dependent, both OK).
//     - init_net_socket fallback: when init_netns_fd_for_pseudo==-1,
//       falls through to current-ns socket(); valid family creates fd.
//     - vhci_fd graceful: -1 if /dev/vhci absent (CI default).
//   PR-B1: emit_ethernet writev semantics (with mock TUN via socketpair);
//          extract_tcp_res reads + parses ETH+IP+TCP from mock TUN.
//   PR-B2: SyzInitNetSocket dispatches valid (dom, type, proto) tuples.
//   PR-B4: SyzEmitVhci writes to caller-overridden vhci fd.

#include "worker/backend/pseudo/pseudo_runtime.hpp"
#include "worker/backend/pseudo/pseudo_dispatcher.hpp"
#include "refuzz/program/syz/pseudo/target_view.hpp"

#include <arpa/inet.h>
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

// pseudo_dispatcher.hpp does not export per-domain entry points; forward
// declare DispatchNetPseudo so the test can drive it directly without
// going through the public DispatchPseudo (which would require building
// a full PseudoContext + cap mask).
namespace refuzz::worker::pseudo {
::refuzz::worker::PseudoResult DispatchNetPseudo(
    const ::refuzz::worker::PseudoContext& ctx,
    const ::refuzz::fuzzer::syz::PseudoMeta& meta,
    const intptr_t* args,
    uint32_t argc);
}

namespace {

namespace fzs = refuzz::fuzzer::syz;

const fzs::PseudoMeta& FindPseudo(const char* name)
{
    const auto& tbl = fzs::kDefaultSyzTarget.pseudos;
    for (std::size_t i = 0; i < tbl.size; ++i) {
        if (std::strcmp(tbl.entries[i].name, name) == 0) {
            return tbl.entries[i];
        }
    }
    assert(false && "pseudo not found");
    return tbl.entries[0];
}

// ---- PR-C0 lazy infra direct tests ----------------------------------

void TestTunFdLazyDegrades()
{
    refuzz::worker::PseudoRuntimeContext ctx;
    int fd1 = ctx.tun_fd();
    int fd2 = ctx.tun_fd();
    // Cached: same fd (or both -1).
    assert(fd1 == fd2);
    if (fd1 >= 0) {
        // /dev/net/tun opened + IFF_TAP — best effort, accept either way.
    } else {
        assert(fd1 == -1);  // tried-and-failed sentinel
    }
}

void TestInitNetSocketFallbackToCurrentNs()
{
    refuzz::worker::PseudoRuntimeContext ctx;
    // No operator-supplied init_netns_fd → should fall through to
    // current-ns socket creation. AF_UNIX is universally available.
    int fd = ctx.init_net_socket(AF_UNIX, SOCK_STREAM, 0);
    assert(fd >= 0);
    ::close(fd);
}

// [E13 review fix 2026-05-06] Exercise the operator-injected setns
// roundtrip path. Inject `dup(/proc/self/ns/net)` so the worker setns'es
// to its own netns (functionally a no-op but exercises both setns calls
// + socket() in between). Without this, the most dangerous PR-C0 path
// (B4 critical fix) had zero test coverage.
void TestInitNetSocketWithInjectedNetns()
{
    int my_netns = ::open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
    if (my_netns < 0) {
        // Permissions or non-Linux container: skip.
        return;
    }
    refuzz::worker::PseudoRuntimeContext ctx;
    ctx.set_init_netns_fd_for_pseudo(my_netns);
    int fd = ctx.init_net_socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd >= 0) {
        ::close(fd);
    } else {
        // setns may EPERM in some sandboxes; -1 with errno is acceptable.
        assert(errno != 0);
    }
    ::close(my_netns);
}

void TestVhciFdLazyDegrades()
{
    refuzz::worker::PseudoRuntimeContext ctx;
    int fd1 = ctx.vhci_fd();
    int fd2 = ctx.vhci_fd();
    assert(fd1 == fd2);
    if (fd1 < 0) {
        assert(fd1 == -1);
    }
}

// ---- Test PseudoContext that injects mock fds ----------------------

class FakePseudoContext : public refuzz::worker::PseudoContext {
public:
    int fake_tun_fd  = -1;
    int fake_vhci_fd = -1;
    int tun_fd()  const override { return fake_tun_fd; }
    int vhci_fd() const override { return fake_vhci_fd; }
    int init_net_socket(int dom, int type, int proto) const override {
        return ::socket(dom, type | SOCK_CLOEXEC, proto);
    }
};

// ---- PR-B1 emit_ethernet ---------------------------------------------

void TestEmitEthernetTunMissing()
{
    FakePseudoContext ctx;
    // fake_tun_fd = -1 → handler returns -1 cleanly
    char data[16] = {};
    intptr_t args[3] = {16, reinterpret_cast<intptr_t>(data), 0};
    auto& meta = FindPseudo("syz_emit_ethernet");
    auto r = refuzz::worker::pseudo::DispatchNetPseudo(ctx, meta, args, 3);
    assert(r.ret == -1);
    assert(r.err == 0);
}

void TestEmitEthernetWritesViaMockTun()
{
    int sv[2];
    assert(::socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
    FakePseudoContext ctx;
    ctx.fake_tun_fd = sv[0];

    std::uint8_t frame[64];
    for (std::size_t i = 0; i < sizeof(frame); ++i) frame[i] = static_cast<std::uint8_t>(i);
    intptr_t args[3] = {sizeof(frame), reinterpret_cast<intptr_t>(frame), 0};
    auto& meta = FindPseudo("syz_emit_ethernet");
    auto r = refuzz::worker::pseudo::DispatchNetPseudo(ctx, meta, args, 3);
    assert(r.ret == static_cast<intptr_t>(sizeof(frame)));

    char buf[128];
    ssize_t n = ::recv(sv[1], buf, sizeof(buf), 0);
    assert(n == static_cast<ssize_t>(sizeof(frame)));
    assert(std::memcmp(buf, frame, sizeof(frame)) == 0);
    ::close(sv[0]);
    ::close(sv[1]);
}

// ---- PR-B1 extract_tcp_res -----------------------------------------

void TestExtractTcpResParsesIpv4()
{
    int sv[2];
    assert(::socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
    FakePseudoContext ctx;
    ctx.fake_tun_fd = sv[0];

    // Build a synthetic ETH+IPv4+TCP frame.
    char frame[sizeof(::ethhdr) + sizeof(::iphdr) + sizeof(::tcphdr)] = {};
    auto* eh = reinterpret_cast<::ethhdr*>(frame);
    eh->h_proto = htons(ETH_P_IP);
    auto* ih = reinterpret_cast<::iphdr*>(frame + sizeof(::ethhdr));
    ih->ihl = sizeof(::iphdr) / 4;
    ih->protocol = IPPROTO_TCP;
    auto* th = reinterpret_cast<::tcphdr*>(
        frame + sizeof(::ethhdr) + sizeof(::iphdr));
    th->seq     = htonl(1000);
    th->ack_seq = htonl(2000);

    // Send the frame via socketpair; handler will read from fake_tun_fd.
    ssize_t sent = ::send(sv[1], frame, sizeof(frame), 0);
    assert(sent == static_cast<ssize_t>(sizeof(frame)));

    struct TcpResources { std::uint32_t seq; std::uint32_t ack; } res{};
    intptr_t args[3] = {reinterpret_cast<intptr_t>(&res), 5, 7};
    auto& meta = FindPseudo("syz_extract_tcp_res");
    auto r = refuzz::worker::pseudo::DispatchNetPseudo(ctx, meta, args, 3);
    assert(r.ret == 0);
    // Expected: seq = 1000+5, ack = 2000+7 (both htonl-ed by handler)
    assert(ntohl(res.seq) == 1005);
    assert(ntohl(res.ack) == 2007);
    ::close(sv[0]);
    ::close(sv[1]);
}

void TestExtractTcpResRejectsNonTcp()
{
    int sv[2];
    assert(::socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
    FakePseudoContext ctx;
    ctx.fake_tun_fd = sv[0];

    // Send eth+ip but with non-TCP protocol
    char frame[sizeof(::ethhdr) + sizeof(::iphdr)] = {};
    auto* eh = reinterpret_cast<::ethhdr*>(frame);
    eh->h_proto = htons(ETH_P_IP);
    auto* ih = reinterpret_cast<::iphdr*>(frame + sizeof(::ethhdr));
    ih->ihl = sizeof(::iphdr) / 4;
    ih->protocol = IPPROTO_UDP;  // not TCP
    ::send(sv[1], frame, sizeof(frame), 0);

    struct TcpResources { std::uint32_t seq; std::uint32_t ack; } res{};
    intptr_t args[3] = {reinterpret_cast<intptr_t>(&res), 0, 0};
    auto& meta = FindPseudo("syz_extract_tcp_res");
    auto r = refuzz::worker::pseudo::DispatchNetPseudo(ctx, meta, args, 3);
    assert(r.ret == -1);
    ::close(sv[0]);
    ::close(sv[1]);
}

// ---- PR-B2 init_net_socket -----------------------------------------

void TestInitNetSocketViaDispatcher()
{
    refuzz::worker::PseudoRuntimeContext ctx;
    intptr_t args[3] = {AF_UNIX, SOCK_STREAM, 0};
    auto& meta = FindPseudo("syz_init_net_socket$ax25");
    auto r = refuzz::worker::pseudo::DispatchNetPseudo(ctx, meta, args, 3);
    if (r.ret >= 0) {
        ::close(static_cast<int>(r.ret));
    }
    // AF_UNIX always succeeds in any ns; AX.25 family won't (no module).
    // Either path is acceptable — just don't crash. Args correct.
}

void TestInitNetSocketRejectsTooFewArgs()
{
    refuzz::worker::PseudoRuntimeContext ctx;
    intptr_t args[2] = {AF_UNIX, SOCK_STREAM};
    auto& meta = FindPseudo("syz_init_net_socket$ax25");
    auto r = refuzz::worker::pseudo::DispatchNetPseudo(ctx, meta, args, 2);
    assert(r.ret == -1);
    assert(r.err == EINVAL);
}

// ---- PR-B4 emit_vhci ------------------------------------------------

void TestEmitVhciVhciMissing()
{
    FakePseudoContext ctx;
    // fake_vhci_fd = -1 → handler returns -1 cleanly
    char data[8] = {'\xAA', '\xBB'};
    intptr_t args[2] = {reinterpret_cast<intptr_t>(data), 8};
    auto& meta = FindPseudo("syz_emit_vhci");
    auto r = refuzz::worker::pseudo::DispatchNetPseudo(ctx, meta, args, 2);
    assert(r.ret == -1);
    assert(r.err == 0);
}

void TestEmitVhciWritesViaMockFd()
{
    int sv[2];
    assert(::socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
    FakePseudoContext ctx;
    ctx.fake_vhci_fd = sv[0];

    char data[16];
    for (std::size_t i = 0; i < sizeof(data); ++i) data[i] = static_cast<char>(0xC0 + i);
    intptr_t args[2] = {reinterpret_cast<intptr_t>(data), sizeof(data)};
    auto& meta = FindPseudo("syz_emit_vhci");
    auto r = refuzz::worker::pseudo::DispatchNetPseudo(ctx, meta, args, 2);
    assert(r.ret == static_cast<intptr_t>(sizeof(data)));

    char buf[32];
    ssize_t n = ::recv(sv[1], buf, sizeof(buf), 0);
    assert(n == static_cast<ssize_t>(sizeof(data)));
    assert(std::memcmp(buf, data, sizeof(data)) == 0);
    ::close(sv[0]);
    ::close(sv[1]);
}

// [已删] TestEmitVhciRejectsNullData —— emit_vhci 的 null-data EINVAL guard 已有意移除
// (对齐上游 syz:只 guard vhci_fd<0 后直接 write,见 pseudo_net.cpp:386)。"rejects null
// data" 这个测试意图随之作废,故删除该用例(而非改断言测已不存在的行为)。

} // namespace

int main()
{
    TestTunFdLazyDegrades();
    TestInitNetSocketFallbackToCurrentNs();
    TestInitNetSocketWithInjectedNetns();
    TestVhciFdLazyDegrades();
    TestEmitEthernetTunMissing();
    TestEmitEthernetWritesViaMockTun();
    TestExtractTcpResParsesIpv4();
    TestExtractTcpResRejectsNonTcp();
    TestInitNetSocketViaDispatcher();
    TestInitNetSocketRejectsTooFewArgs();
    TestEmitVhciVhciMissing();
    TestEmitVhciWritesViaMockFd();
    return 0;
}

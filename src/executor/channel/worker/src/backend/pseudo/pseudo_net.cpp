#include "worker/backend/pseudo/pseudo_context.hpp"
#include "worker/backend/pseudo/pseudo_result.hpp"
#include "worker/log/log_macros.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <linux/genetlink.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/netlink.h>
#include <linux/tcp.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

namespace refuzz::worker::pseudo {
namespace {

bool HasBaseName(const char* name, const char* base)
{
    if (name == nullptr) {
        return false;
    }
    const size_t n = std::strlen(base);
    return std::strncmp(name, base, n) == 0 &&
           (name[n] == '\0' || name[n] == '$');
}

PseudoResult Error(int err)
{
    return PseudoResult{-1, err};
}

void AddAttr(char*& pos, int type, const void* data, size_t size)
{
    auto* attr = reinterpret_cast<nlattr*>(pos);
    attr->nla_type = static_cast<uint16_t>(type);
    attr->nla_len = static_cast<uint16_t>(sizeof(nlattr) + size);
    std::memcpy(attr + 1, data, size);
    pos += NLA_ALIGN(attr->nla_len);
}

PseudoResult QueryGenericNetlinkFamilyId(const char* family_name, int fd)
{
    if (family_name == nullptr) {
        return Error(EINVAL);
    }

    int sock = fd;
    const bool owned_socket = sock < 0;
    if (owned_socket) {
        sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
        if (sock < 0) {
            return Error(errno);
        }
    }

    char request[4096] = {};
    auto* nlh = reinterpret_cast<nlmsghdr*>(request);
    nlh->nlmsg_type = GENL_ID_CTRL;
    // [当前版本 upstream-parity: NLM_F_ACK] Upstream netlink_init sets
    // NLM_F_REQUEST | NLM_F_ACK (common_linux.h), so the kernel sends a
    // trailing NLMSG_ERROR ack after the GETFAMILY reply — exercising the
    // netlink_ack / netlink_ack_tlv_len / __nlmsg_put path. Without ACK the
    // kernel skips that path (syz_only PC divergence). Match upstream.
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = 1;

    auto* genlh = reinterpret_cast<genlmsghdr*>(nlh + 1);
    genlh->cmd = CTRL_CMD_GETFAMILY;
    genlh->version = 1;

    char* pos = reinterpret_cast<char*>(genlh + 1);
    const size_t name_len = strnlen(family_name, GENL_NAMSIZ - 1) + 1;
    AddAttr(pos, CTRL_ATTR_FAMILY_NAME, family_name, name_len);
    nlh->nlmsg_len = static_cast<uint32_t>(pos - request);

    sockaddr_nl addr{};
    addr.nl_family = AF_NETLINK;
    errno = 0;
    const ssize_t sent = sendto(sock, request, nlh->nlmsg_len, 0,
                                reinterpret_cast<const sockaddr*>(&addr),
                                sizeof(addr));
    if (sent < 0) {
        const int err = errno;
        if (owned_socket) {
            close(sock);
        }
        return Error(err);
    }

    char reply[4096] = {};
    errno = 0;
    const ssize_t received = recv(sock, reply, sizeof(reply), 0);
    if (received < 0) {
        const int err = errno;
        if (owned_socket) {
            close(sock);
        }
        return Error(err);
    }
    if (received < static_cast<ssize_t>(sizeof(nlmsghdr))) {
        if (owned_socket) {
            close(sock);
        }
        return Error(EINVAL);
    }

    const auto* reply_nlh = reinterpret_cast<const nlmsghdr*>(reply);
    if (reply_nlh->nlmsg_type == NLMSG_ERROR) {
        if (received < static_cast<ssize_t>(sizeof(nlmsghdr) + sizeof(nlmsgerr))) {
            if (owned_socket) {
                close(sock);
            }
            return Error(EINVAL);
        }
        const auto* err_msg = reinterpret_cast<const nlmsgerr*>(reply_nlh + 1);
        const int err = err_msg->error == 0 ? EINVAL : -err_msg->error;
        if (owned_socket) {
            close(sock);
        }
        return Error(err);
    }
    if (reply_nlh->nlmsg_type != GENL_ID_CTRL ||
        received < static_cast<ssize_t>(NLMSG_HDRLEN + GENL_HDRLEN)) {
        if (owned_socket) {
            close(sock);
        }
        return Error(EINVAL);
    }

    const char* attr_pos = reply + NLMSG_HDRLEN + GENL_HDRLEN;
    const char* end = reply + received;
    while (attr_pos + sizeof(nlattr) <= end) {
        const auto* attr = reinterpret_cast<const nlattr*>(attr_pos);
        if (attr->nla_len < sizeof(nlattr) || attr_pos + attr->nla_len > end) {
            if (owned_socket) {
                close(sock);
            }
            return Error(EINVAL);
        }
        if (attr->nla_type == CTRL_ATTR_FAMILY_ID &&
            attr->nla_len >= sizeof(nlattr) + sizeof(uint16_t)) {
            uint16_t id = 0;
            std::memcpy(&id, attr + 1, sizeof(id));
            // [当前版本 upstream-parity: recv ack] Upstream netlink_query_family_id
            // does a second recv() after parsing the family id to consume the
            // NLM_F_ACK reply. Drain it here too (best-effort; ignore result).
            char ack[256];
            (void)recv(sock, ack, sizeof(ack), MSG_DONTWAIT);
            if (owned_socket) {
                close(sock);
            }
            return PseudoResult{id, 0};
        }
        attr_pos += NLA_ALIGN(attr->nla_len);
    }

    if (owned_socket) {
        close(sock);
    }
    return Error(EINVAL);
}

} // namespace

// [当前版本 byte-equal upstream — 2026-05-22]
// 实装上游 syz_socket_connect_nvme_tcp (common_linux.h:2532) 完整版:
//   1. ctx.init_net_socket(AF_INET, SOCK_STREAM, 0) → setns(init_net) → socket
//      → setns back (基础设施 pseudo_runtime.cpp:168 已实装)
//   2. syscall(connect, sock, 127.0.0.1:4420, ...)
//   3. connect fail → close + return -1
//
// 旧版用 socket(-1,0,0) fail-fast 早返 EAFNOSUPPORT,kernel socket layer 早就
// 拒,**0 个 tcp/inet/network PC 被收集**。upstream 跑完整 TCP connect 路径:
// __inet_stream_connect → tcp_v4_connect → tcp_transmit_skb,返
// ECONNREFUSED (127.0.0.1:4420 没 NVMe-oF/TCP server)。8 个 actionable
// mismatch (syz=111 ECONNREFUSED, ref=97 EAFNOSUPPORT) 的根因。
PseudoResult SyzSocketConnectNvmeTcp(const PseudoContext& ctx)
{
    const int sock = ctx.init_net_socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return Error(errno);
    }
    struct sockaddr_in addr {};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htobe16(4420);
    addr.sin_addr.s_addr = htobe32(0x7f000001);  // 127.0.0.1
    errno = 0;
    const long rc = syscall(SYS_connect, sock, &addr, sizeof(addr));
    if (rc != 0) {
        const int saved = errno;
        ::close(sock);
        return PseudoResult{-1, saved};
    }
    return PseudoResult{static_cast<intptr_t>(sock), 0};
}

// ============================================================
// PR-B1 — ethernet injection / TCP-resource extraction.
// ============================================================

// syz_emit_ethernet(len, packet, frags) — upstream common_linux.h:1775
// Writes a raw ethernet frame to the worker's TUN tap interface.
//
// `frags` (vnet_fragmentation) handling differs from upstream by
// design:
//   - Upstream gates the iovec branch on compile-time
//     `ENABLE_NAPI_FRAGS` AND runtime `tun_frags_enabled` (set when
//     IFF_NAPI_FRAGS ioctl succeeded at TUN setup); otherwise a plain
//     `write(tunfd, data, length)` is used regardless of frags.
//   - reFuzz's PR-C0 lazy TUN setup uses IFF_TAP|IFF_NO_PI WITHOUT
//     IFF_NAPI_FRAGS, so the upstream gate would always fall through to
//     plain write. We honor `frags` (when non-null) anyway because
//     `writev` with a single iovec is identical to `write` for the
//     kernel observation, and the per-frag iovec construction is a
//     harmless layout the upstream NAPI-frags path would also use.
//     Net effect: kernel-observable single packet, regardless of frags
//     argument. (A3 review note 2026-05-06.)
struct VnetFragmentation {
    std::uint32_t full;
    std::uint32_t count;
    std::uint32_t frags[4];
};
constexpr std::uint32_t kMaxFrags = 4;

PseudoResult SyzEmitEthernet(const PseudoContext& ctx,
                             const intptr_t* args, uint32_t argc)
{
    if (args == nullptr || argc < 2) return Error(EINVAL);
    const int fd = ctx.tun_fd();
    if (fd < 0) {
        // Mirror upstream: tunfd<0 → return -1.
        return PseudoResult{-1, 0};
    }
    auto length = static_cast<std::uint32_t>(args[0]);
    auto* data  = reinterpret_cast<char*>(args[1]);
    auto* frags = (argc >= 3)
                  ? reinterpret_cast<VnetFragmentation*>(args[2])
                  : nullptr;
    // [当前版本 upstream-parity: no data==null guard] Upstream syz_emit_ethernet
    // (common_linux.h) only guards tunfd<0, then writes unconditionally. A
    // degenerate program syz_emit_ethernet(len=0, packet=NULL special ptr,
    // frags=NULL) resolves the packet ptr to 0 here; the old `data==null →
    // EINVAL` short-circuit skipped the real write() and diverged from syz,
    // which does write(fd, <null/zero>, 0) → tun rejects the 0-len frame
    // (EINVAL) via the vfs_write path. write(fd, 0, 0) does not deref; a
    // null+len>0 write would EFAULT, matching whatever syz gets. Drop the
    // guard so the kernel write path runs on both sides.

    if (frags == nullptr) {
        errno = 0;
        ssize_t n = ::write(fd, data, length);
        return PseudoResult{static_cast<intptr_t>(n), errno};
    }
    // With frags struct: build iovec slices honoring frag sizes (no
    // IFF_NAPI_FRAGS in PR-C0 default; this still works as a single
    // writev, kernel sees one packet — semantically OK).
    iovec vecs[kMaxFrags + 1] = {};
    std::uint32_t nfrags = 0;
    std::uint32_t count = frags->count;
    if (count > kMaxFrags) count = kMaxFrags;
    char* d = data;
    for (std::uint32_t i = 0; i < count && length != 0; ++i) {
        std::uint32_t size = frags->frags[i];
        if (size > length) size = length;
        vecs[nfrags].iov_base = d;
        vecs[nfrags].iov_len  = size;
        ++nfrags;
        d      += size;
        length -= size;
    }
    if (length != 0 && (frags->full || nfrags == 0)) {
        vecs[nfrags].iov_base = d;
        vecs[nfrags].iov_len  = length;
        ++nfrags;
    }
    errno = 0;
    ssize_t n = ::writev(fd, vecs, static_cast<int>(nfrags));
    return PseudoResult{static_cast<intptr_t>(n), errno};
}

// `tcp_resources` mirrors upstream (`common_linux.h:2332`).
struct TcpResources {
    std::uint32_t seq;
    std::uint32_t ack;
};

// syz_extract_tcp_res(res_out, seq_inc, ack_inc) — upstream common_linux.h:2337
// Reads one frame from the TUN, parses ETH+IP/IP6+TCP, writes
// (seq+seq_inc, ack+ack_inc) into the caller's tcp_resources struct.
PseudoResult SyzExtractTcpRes(const PseudoContext& ctx,
                              const intptr_t* args, uint32_t argc)
{
    if (args == nullptr || argc < 3) return Error(EINVAL);
    const int fd = ctx.tun_fd();
    if (fd < 0) {
        return PseudoResult{-1, 0};
    }
    auto* res = reinterpret_cast<TcpResources*>(args[0]);
    if (res == nullptr) return Error(EINVAL);
    const auto seq_inc = static_cast<std::uint32_t>(args[1]);
    const auto ack_inc = static_cast<std::uint32_t>(args[2]);

    char buf[1000];
    errno = 0;
    ssize_t rv = ::read(fd, buf, sizeof(buf));
    if (rv < 0) return PseudoResult{-1, errno};
    auto length = static_cast<std::size_t>(rv);
    if (length < sizeof(ethhdr)) return PseudoResult{-1, 0};

    const auto* eh = reinterpret_cast<const ethhdr*>(buf);
    const tcphdr* th = nullptr;
    if (eh->h_proto == htons(ETH_P_IP)) {
        if (length < sizeof(ethhdr) + sizeof(iphdr)) {
            return PseudoResult{-1, 0};
        }
        const auto* ih = reinterpret_cast<const iphdr*>(buf + sizeof(ethhdr));
        if (ih->protocol != IPPROTO_TCP) return PseudoResult{-1, 0};
        const std::size_t ip_len = static_cast<std::size_t>(ih->ihl) * 4;
        if (length < sizeof(ethhdr) + ip_len + sizeof(tcphdr)) {
            return PseudoResult{-1, 0};
        }
        th = reinterpret_cast<const tcphdr*>(buf + sizeof(ethhdr) + ip_len);
    } else {
        if (length < sizeof(ethhdr) + sizeof(ipv6hdr)) {
            return PseudoResult{-1, 0};
        }
        const auto* ih6 = reinterpret_cast<const ipv6hdr*>(buf + sizeof(ethhdr));
        // No extension-header walk — mirror upstream (TODO note at common_linux.h:2371).
        if (ih6->nexthdr != IPPROTO_TCP) return PseudoResult{-1, 0};
        if (length < sizeof(ethhdr) + sizeof(ipv6hdr) + sizeof(tcphdr)) {
            return PseudoResult{-1, 0};
        }
        th = reinterpret_cast<const tcphdr*>(buf + sizeof(ethhdr) + sizeof(ipv6hdr));
    }
    res->seq = htonl(ntohl(th->seq) + seq_inc);
    res->ack = htonl(ntohl(th->ack_seq) + ack_inc);
    return PseudoResult{0, 0};
}

// ============================================================
// PR-B2 — init-netns socket family (17 syz_init_net_socket$* variants).
// ============================================================

// syz_init_net_socket(dom, type, proto) — upstream common_linux.h:2495
// Single handler covers all 17 syz_init_net_socket$* variants; the
// variant suffix only constrains the (dom, type, proto) tuple at
// generation time, not at handler dispatch time.
PseudoResult SyzInitNetSocket(const PseudoContext& ctx,
                              const intptr_t* args, uint32_t argc)
{
    if (args == nullptr || argc < 3) return Error(EINVAL);
    const int domain   = static_cast<int>(args[0]);
    const int type     = static_cast<int>(args[1]);
    const int protocol = static_cast<int>(args[2]);
    errno = 0;
    int fd = ctx.init_net_socket(domain, type, protocol);
    if (fd < 0) {
        return Error(errno != 0 ? errno : EAFNOSUPPORT);
    }
    return PseudoResult{static_cast<intptr_t>(fd), 0};
}

// ============================================================
// PR-B4 — Bluetooth HCI injection via /dev/vhci (single pseudo).
// ============================================================

// syz_emit_vhci(data, length) — upstream common_linux.h:2927
PseudoResult SyzEmitVhci(const PseudoContext& ctx,
                         const intptr_t* args, uint32_t argc)
{
    if (args == nullptr || argc < 2) return Error(EINVAL);
    const int fd = ctx.vhci_fd();
    if (fd < 0) {
        return PseudoResult{-1, 0};  // hci_vhci module absent — graceful
    }
    auto* data   = reinterpret_cast<const void*>(args[0]);
    auto length  = static_cast<std::size_t>(args[1]);
    // [当前版本 upstream-parity: no data==null guard] Same fix as SyzEmitEthernet:
    // upstream syz_emit_vhci only guards vhci_fd<0 then write(fd, data, length).
    // A NULL special-ptr data arg resolves to 0 here; the old guard short-
    // circuited EINVAL instead of doing the real write() that syz does.
    errno = 0;
    ssize_t n = ::write(fd, data, length);
    return PseudoResult{static_cast<intptr_t>(n), errno};
}

// ============================================================
// PR-B3 — 802.11 inject / IBSS join. Forward-declared; defined in
// pseudo_wifi.cpp because the netlink-message-builder + hwsim genl
// helpers are large enough to deserve their own translation unit.
// ============================================================
PseudoResult SyzWifi80211InjectFrame(const PseudoContext& ctx,
                                     const intptr_t* args, uint32_t argc);
PseudoResult SyzWifi80211JoinIbss(const PseudoContext& ctx,
                                  const intptr_t* args, uint32_t argc);

PseudoResult DispatchNetPseudo(const PseudoContext& ctx,
                               const refuzz::fuzzer::syz::PseudoMeta& meta,
                               const intptr_t* args,
                               uint32_t argc)
{
    (void)ctx;
    if (HasBaseName(meta.name, "syz_genetlink_get_family_id")) {
        if (args == nullptr || argc < 2 || args[0] == 0) {
            return Error(EINVAL);
        }
        return QueryGenericNetlinkFamilyId(
            reinterpret_cast<const char*>(args[0]),
            static_cast<int>(args[1]));
    }
    if (std::strcmp(meta.name, "syz_init_net_socket$nl_generic") == 0) {
        if (args == nullptr || argc < 3) {
            return Error(EINVAL);
        }
        // [当前版本 byte-equal upstream — 2026-05-22]
        // upstream syz_init_net_socket (common_linux.h:2495) 走
        // setns(init_net) → socket → setns back,保证 socket 在 init netns
        // 创建。NFC / 一些 genetlink family 只在 init netns 注册响应,worker
        // netns 中的 socket 查询返 -ENOENT。直接 socket() 是 fail-fast 兜底。
        // 4 个 syz_genetlink_get_family_id$nfc actionable (syz=0, ref=2) 根因。
        const int fd = ctx.init_net_socket(static_cast<int>(args[0]),
                                            static_cast<int>(args[1]),
                                            static_cast<int>(args[2]));
        if (fd < 0) {
            return Error(errno);
        }
        return PseudoResult{fd, 0};
    }
    if (HasBaseName(meta.name, "syz_socket_connect_nvme_tcp")) {
        // 0-arg pseudo; argc/args ignored.
        return SyzSocketConnectNvmeTcp(ctx);
    }
    // PR-B1
    if (HasBaseName(meta.name, "syz_emit_ethernet")) {
        return SyzEmitEthernet(ctx, args, argc);
    }
    if (HasBaseName(meta.name, "syz_extract_tcp_res")) {
        return SyzExtractTcpRes(ctx, args, argc);
    }
    // PR-B2 — all `syz_init_net_socket$*` variants except $nl_generic
    // (already kNative pre-PR-B2 above) share one handler.
    if (HasBaseName(meta.name, "syz_init_net_socket")) {
        return SyzInitNetSocket(ctx, args, argc);
    }
    // PR-B4
    if (HasBaseName(meta.name, "syz_emit_vhci")) {
        return SyzEmitVhci(ctx, args, argc);
    }
    // PR-B3 — defined in pseudo_wifi.cpp.
    if (std::strcmp(meta.name, "syz_80211_inject_frame") == 0) {
        return SyzWifi80211InjectFrame(ctx, args, argc);
    }
    if (std::strcmp(meta.name, "syz_80211_join_ibss") == 0) {
        return SyzWifi80211JoinIbss(ctx, args, argc);
    }
    return PseudoResult{-1, ENOSYS};
}

} // namespace refuzz::worker::pseudo

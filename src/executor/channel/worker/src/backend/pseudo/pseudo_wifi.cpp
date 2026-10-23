// PR-B3 — 802.11 frame injection / IBSS join via mac80211_hwsim + nl80211.
//
// Both handlers do real generic-netlink dialogs:
//   syz_80211_inject_frame  → MAC80211_HWSIM family → CMD_REGISTER + CMD_FRAME
//   syz_80211_join_ibss     → nl80211 family → CMD_GET_INTERFACE + CMD_JOIN_IBSS
//
// When the kernel modules are not loaded (operator-preload absent — plan
// §10 Q6), `QueryGenericNetlinkFamilyId` returns ≤0 and the handler
// returns -1 cheaply. With modules loaded + sufficient capabilities, the
// handler exercises the real netlink path. Mirrors upstream semantics
// from `executor/common_linux.h:5603-5750`.
//
// Note: handler does NOT register socket per-call efficiently — it opens
// + registers + sends + closes per call (mirroring upstream's "we cannot
// keep socket registered across a proc" comment at common_linux.h:5673).

#include "worker/backend/pseudo/pseudo_context.hpp"
#include "worker/backend/pseudo/pseudo_result.hpp"
#include "worker/sandbox/device_init/device_init.hpp"

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <sys/socket.h>
#include <unistd.h>

namespace refuzz::worker::pseudo {
namespace {

PseudoResult Error(int err) { return PseudoResult{-1, err}; }

constexpr std::size_t kNlmsgBufSize     = 4096;
constexpr int         kWifiMaxInjectLen = 2048;
constexpr int         kWifiMaxSsidLen   = 32;
// WIFI_JOIN_IBSS_* mode upper bound — mirror upstream common_linux.h:5650-5652.
// 0=foreground no scan, 1=bg scan, 2=bg no scan;ssid/freq fixed 由
// device_init::WifiJoinIbssFuzzTime 内部按 mode 决定。pseudo handler 只校验
// mode 是否在 [0, 2] 范围。
constexpr int kWifiJoinIbssBgNoScan  = 2;

// MAC80211_HWSIM netlink constants (mirror upstream
// sys/linux/mac80211_hwsim.txt, also `<linux/mac80211_hwsim_user.h>`
// when present). Define locally for portability.
constexpr int   kHwsimCmdRegister      = 1;
constexpr int   kHwsimCmdFrame         = 2;
// [当前版本 byte-equal HWSIM attrs — 2026-05-22]
// 上游 common_linux.h:5563-5566 真值:
//   HWSIM_ATTR_ADDR_RECEIVER = 1
//   HWSIM_ATTR_FRAME         = 3
//   HWSIM_ATTR_RX_RATE       = 5
//   HWSIM_ATTR_SIGNAL        = 6
// reFuzz 之前写 5/7/13 → 错把 frame 数据当 RxRate u32 → kernel validate_nla
// 返 -ERANGE(u32 expected,frame len bytes mismatch)。16 个 syz_80211_inject_
// frame mismatch (syz=22/0, ref=34) 全在这。
// AddrTrans 名字写成 "transmitter" 但值正确(= ADDR_RECEIVER 1),保留。
constexpr int   kHwsimAttrAddrTrans    = 1;   // = HWSIM_ATTR_ADDR_RECEIVER
constexpr int   kHwsimAttrFrame        = 3;
constexpr int   kHwsimAttrRxRate       = 5;
constexpr int   kHwsimAttrSignal       = 6;
// [当前版本 byte-equal HWSIM defaults — 2026-05-22]
// 上游 common_linux.h:898-899 + :5586-5587 用 uint32 类型:
//   WIFI_DEFAULT_RX_RATE = 1   (uint32, sizeof=4)
//   WIFI_DEFAULT_SIGNAL  = 0   (uint32, sizeof=4)
// reFuzz 之前 RxRate 是 uint8_t(sizeof=1)→ kernel HWSIM nla_policy
// 期 NLA_U32(4 bytes)→ validate_nla(actual=1, expected=4) → -ERANGE。
// 这是 (22/0, 34) 16 个 mismatch 真根因(不是 attr type 5/7/13,改成
// 3/5/6 后这部分仍 ERANGE)。
constexpr std::uint32_t kDefaultRxRate = 1;
constexpr std::uint32_t kDefaultSignal = 0;

// Append a single nlattr at *p; advance *p; decrement *remaining.
// Caller responsible for ensuring `remaining` has space.
inline void AppendAttr(char*& p, std::size_t& remaining,
                       int type, const void* data, std::size_t size)
{
    auto* a = reinterpret_cast<::nlattr*>(p);
    a->nla_type = static_cast<std::uint16_t>(type);
    a->nla_len  = static_cast<std::uint16_t>(sizeof(::nlattr) + size);
    if (size > 0 && data != nullptr) {
        std::memcpy(a + 1, data, size);
    }
    const std::size_t aligned = NLA_ALIGN(a->nla_len);
    p += aligned;
    remaining = (remaining > aligned) ? (remaining - aligned) : 0;
}

int OpenGenericNetlinkSocket()
{
    return ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
}

// CTRL_CMD_GETFAMILY → return family id (>0) or -1 on absent / error.
int QueryFamilyId(int fd, const char* family_name)
{
    char buf[kNlmsgBufSize] = {};
    auto* nlh = reinterpret_cast<::nlmsghdr*>(buf);
    nlh->nlmsg_type  = GENL_ID_CTRL;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq   = 1;
    auto* gnh = reinterpret_cast<::genlmsghdr*>(nlh + 1);
    gnh->cmd     = CTRL_CMD_GETFAMILY;
    gnh->version = 1;
    char* p = reinterpret_cast<char*>(gnh + 1);
    std::size_t remaining = kNlmsgBufSize - NLMSG_HDRLEN - GENL_HDRLEN;
    const std::size_t name_len = std::strlen(family_name) + 1;
    AppendAttr(p, remaining, CTRL_ATTR_FAMILY_NAME, family_name, name_len);
    nlh->nlmsg_len = static_cast<std::uint32_t>(p - buf);

    ::sockaddr_nl sa{};
    sa.nl_family = AF_NETLINK;
    if (::sendto(fd, buf, nlh->nlmsg_len, 0,
                 reinterpret_cast<const ::sockaddr*>(&sa), sizeof(sa)) < 0) {
        return -1;
    }
    char rep[kNlmsgBufSize];
    ssize_t n = ::recv(fd, rep, sizeof(rep), 0);
    if (n < static_cast<ssize_t>(NLMSG_HDRLEN + GENL_HDRLEN)) return -1;
    const auto* rh = reinterpret_cast<const ::nlmsghdr*>(rep);
    if (rh->nlmsg_type == NLMSG_ERROR) {
        // [A2 ext] upstream `netlink_send_ext` 在 NLMSG_ERROR 时
        // `errno = -nlmsgerr->error`,这里同步,让 caller 看到 kernel 报的
        // 真 errno (EINVAL / EADDRINUSE / etc.),而不是 sendto/recv 都成功
        // 留下的 errno=0。
        const std::size_t need = NLMSG_HDRLEN + sizeof(::nlmsgerr);
        if (n >= static_cast<ssize_t>(need)) {
            const auto* err = reinterpret_cast<const ::nlmsgerr*>(rh + 1);
            if (err->error != 0) errno = -err->error;
        }
        return -1;
    }

    const char* attrs_p   = rep + NLMSG_HDRLEN + GENL_HDRLEN;
    const char* attrs_end = rep + n;
    while (attrs_p + sizeof(::nlattr) <= attrs_end) {
        const auto* a = reinterpret_cast<const ::nlattr*>(attrs_p);
        if (a->nla_len < sizeof(::nlattr) ||
            attrs_p + a->nla_len > attrs_end) {
            return -1;
        }
        if (a->nla_type == CTRL_ATTR_FAMILY_ID &&
            a->nla_len >= sizeof(::nlattr) + sizeof(std::uint16_t)) {
            std::uint16_t id = 0;
            std::memcpy(&id, a + 1, sizeof(id));
            return static_cast<int>(id);
        }
        attrs_p += NLA_ALIGN(a->nla_len);
    }
    return -1;
}

// Send a genl request whose body is just the cmd + version (no attrs);
// expect ACK (NLMSG_ERROR with error=0).
bool SendBareGenlCmd(int fd, int family_id, std::uint8_t cmd)
{
    char buf[kNlmsgBufSize] = {};
    auto* nlh = reinterpret_cast<::nlmsghdr*>(buf);
    nlh->nlmsg_type  = static_cast<std::uint16_t>(family_id);
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq   = 2;
    auto* gnh = reinterpret_cast<::genlmsghdr*>(nlh + 1);
    gnh->cmd     = cmd;
    gnh->version = 1;
    nlh->nlmsg_len = NLMSG_HDRLEN + GENL_HDRLEN;

    ::sockaddr_nl sa{};
    sa.nl_family = AF_NETLINK;
    if (::sendto(fd, buf, nlh->nlmsg_len, 0,
                 reinterpret_cast<const ::sockaddr*>(&sa), sizeof(sa)) < 0) {
        return false;
    }
    char rep[256];
    ssize_t n = ::recv(fd, rep, sizeof(rep), 0);
    if (n < static_cast<ssize_t>(sizeof(::nlmsghdr) + sizeof(::nlmsgerr))) {
        return false;
    }
    const auto* rh = reinterpret_cast<const ::nlmsghdr*>(rep);
    if (rh->nlmsg_type != NLMSG_ERROR) return false;
    const auto* err = reinterpret_cast<const ::nlmsgerr*>(rh + 1);
    if (err->error != 0) {
        // [A2 ext] upstream `netlink_send_ext` 把 kernel NLMSG_ERROR 写回 errno
        errno = -err->error;
        return false;
    }
    return true;
}

// HWSIM_CMD_FRAME: inject `frame` from `mac` (6 bytes) with fixed
// signal/rate. ACK expected.
bool SendHwsimFrame(int fd, int family_id,
                    const std::uint8_t* mac,
                    const void* frame, std::size_t frame_len)
{
    char buf[kNlmsgBufSize] = {};
    auto* nlh = reinterpret_cast<::nlmsghdr*>(buf);
    nlh->nlmsg_type  = static_cast<std::uint16_t>(family_id);
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq   = 3;
    auto* gnh = reinterpret_cast<::genlmsghdr*>(nlh + 1);
    gnh->cmd     = kHwsimCmdFrame;
    gnh->version = 1;
    char* p = reinterpret_cast<char*>(gnh + 1);
    std::size_t remaining = kNlmsgBufSize - NLMSG_HDRLEN - GENL_HDRLEN;
    if (frame_len + 64 > remaining) {
        return false;  // budget: frame + 4 attrs of headroom
    }
    AppendAttr(p, remaining, kHwsimAttrAddrTrans, mac, 6);
    AppendAttr(p, remaining, kHwsimAttrFrame,     frame, frame_len);
    AppendAttr(p, remaining, kHwsimAttrRxRate,    &kDefaultRxRate, sizeof(kDefaultRxRate));
    AppendAttr(p, remaining, kHwsimAttrSignal,    &kDefaultSignal, sizeof(kDefaultSignal));
    nlh->nlmsg_len = static_cast<std::uint32_t>(p - buf);

    ::sockaddr_nl sa{};
    sa.nl_family = AF_NETLINK;
    if (::sendto(fd, buf, nlh->nlmsg_len, 0,
                 reinterpret_cast<const ::sockaddr*>(&sa), sizeof(sa)) < 0) {
        return false;
    }
    char rep[256];
    ssize_t n = ::recv(fd, rep, sizeof(rep), 0);
    if (n < static_cast<ssize_t>(sizeof(::nlmsghdr) + sizeof(::nlmsgerr))) {
        return false;
    }
    const auto* rh = reinterpret_cast<const ::nlmsghdr*>(rep);
    if (rh->nlmsg_type != NLMSG_ERROR) return false;
    const auto* err = reinterpret_cast<const ::nlmsgerr*>(rh + 1);
    if (err->error != 0) {
        errno = -err->error;       // [A2 ext] kernel-reported errno
        return false;
    }
    return true;
}

} // namespace

// syz_80211_inject_frame(mac_addr, buf, buf_len) — upstream common_linux.h:5603
// [A2 errno propagation] upstream pattern: `errno = 0; rv = call(...); err = errno;`
//   - validation 失败 → errno 仍 0 (caller 清过)
//   - syscall 失败 → errno = 失败那条 syscall 设的值
// reFuzz 改对应:syscall 失败路径 capture errno + before-close 保存,validation
// 保留 {-1, 0}。
PseudoResult SyzWifi80211InjectFrame(const PseudoContext& ctx,
                                     const intptr_t* args, uint32_t argc)
{
    (void)ctx;
    if (args == nullptr || argc < 3) return Error(EINVAL);
    auto* mac     = reinterpret_cast<const std::uint8_t*>(args[0]);
    auto* buf     = reinterpret_cast<const void*>(args[1]);
    const int buf_len = static_cast<int>(args[2]);
    if (mac == nullptr || buf == nullptr) return Error(EINVAL);
    if (buf_len < 0 || buf_len > kWifiMaxInjectLen) {
        return PseudoResult{-1, 0};  // pure validation,upstream errno 仍 0
    }

    int sock = OpenGenericNetlinkSocket();
    if (sock < 0) return PseudoResult{-1, errno};  // socket() failure errno

    int family_id = QueryFamilyId(sock, "MAC80211_HWSIM");
    if (family_id <= 0) {
        const int e = errno;             // save before close (may reset errno)
        ::close(sock);
        return PseudoResult{-1, e};      // hwsim module absent — keep query errno
    }
    if (!SendBareGenlCmd(sock, family_id, kHwsimCmdRegister)) {
        const int e = errno;
        ::close(sock);
        return PseudoResult{-1, e};
    }
    bool ok = SendHwsimFrame(sock, family_id, mac, buf,
                             static_cast<std::size_t>(buf_len));
    const int e_after_send = ok ? 0 : errno;
    ::close(sock);
    return PseudoResult{ok ? 0 : -1, e_after_send};
}

// syz_80211_join_ibss(interface, ssid, ssid_len, mode) — upstream common_linux.h:5654
//
// 复用 sandbox::device_init::WifiJoinIbssFuzzTime,内部走 upstream 4 步
// (if_nametoindex → set_interface(ADHOC) → set_state(UP) → join_ibss)。
// caller 这里只做参数校验,以及把 errno → PseudoResult.errnum 装回去。
//
// [A2 errno propagation] 同 SyzWifi80211InjectFrame:validation 失败 errno
// 仍 0,helper 失败时 errno = kernel-reported errno(或 helper internal)。
PseudoResult SyzWifi80211JoinIbss(const PseudoContext& ctx,
                                  const intptr_t* args, uint32_t argc)
{
    (void)ctx;
    if (args == nullptr || argc < 4) return Error(EINVAL);
    auto* iface = reinterpret_cast<const char*>(args[0]);
    auto* ssid  = reinterpret_cast<const std::uint8_t*>(args[1]);
    const int ssid_len = static_cast<int>(args[2]);
    const int mode     = static_cast<int>(args[3]);
    if (iface == nullptr || ssid == nullptr) return Error(EINVAL);
    if (ssid_len < 0 || ssid_len > kWifiMaxSsidLen) {
        return PseudoResult{-1, 0};  // pure validation
    }
    if (mode < 0 || mode > kWifiJoinIbssBgNoScan) {
        return PseudoResult{-1, 0};
    }

    errno = 0;
    const int rc = ::refuzz::worker::sandbox::device_init::WifiJoinIbssFuzzTime(
        iface, ssid, ssid_len, mode);
    const int e = errno;
    return PseudoResult{rc, rc == 0 ? 0 : e};
}

} // namespace refuzz::worker::pseudo

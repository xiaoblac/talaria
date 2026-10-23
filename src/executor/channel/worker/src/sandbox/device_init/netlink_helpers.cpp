// Netlink foundation primitives —— D2 portion of sandbox-device-init plan。
//
// 1:1 port from syzkaller `executor/common_linux.h` (132-369),改动:
//   - `fail()` / `failmsg()` 替换 WorkerLog + 返回错误码 / 设置 errno
//   - `dofail` 保留语义:true → LOG loud,false → LOG quiet
//   - 类型 PascalCase (`Nlmsg`),字段同序同义于 upstream `struct nlmsg`
//
// 与上游严格 byte-equal 的部分:
//   - 消息内存 layout (struct Nlmsg.buf 4 KiB)
//   - nlmsghdr_len 写入位置 (= pos - buf)
//   - sockaddr_nl (AF_NETLINK only) sendto target
//   - GENL_ID_CTRL 查 family_id 时遍历 attr 用 NLMSG_ALIGN(nla_len)
//
// 不带上游 SYZ_EXECUTOR / SYZ_NIC_VF 等 #ifdef gate —— reFuzz worker 全
// path 都 enable(若 runtime-gate 化,future 在 WorkerProfile 加 device_init_mask)。

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "worker/sandbox/device_init/netlink_helpers.hpp"

#include "worker/log/log_macros.hpp"

#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/genetlink.h>
#include <linux/netlink.h>

#define NLLOG(fmt, ...) \
    ::refuzz::worker::log::WorkerLog("[netlink] " fmt "\n", ##__VA_ARGS__)

namespace refuzz::worker::sandbox::device_init {

void Nlmsg::Reset()
{
    ::memset(this, 0, sizeof(*this));
}

// === build =====================================================

void NetlinkInit(Nlmsg* msg, int typ, int flags,
                 const void* data, int size)
{
    msg->Reset();
    auto* hdr = reinterpret_cast<struct ::nlmsghdr*>(msg->buf);
    hdr->nlmsg_type = static_cast<__u16>(typ);
    hdr->nlmsg_flags = static_cast<__u16>(NLM_F_REQUEST | NLM_F_ACK | flags);
    if (size > 0 && data != nullptr) {
        ::memcpy(hdr + 1, data, static_cast<size_t>(size));
    }
    msg->pos = reinterpret_cast<char*>(hdr + 1) + NLMSG_ALIGN(size);
}

void NetlinkAttr(Nlmsg* msg, int typ, const void* data, int size)
{
    auto* attr = reinterpret_cast<struct ::nlattr*>(msg->pos);
    attr->nla_len = static_cast<__u16>(sizeof(*attr) + size);
    attr->nla_type = static_cast<__u16>(typ);
    if (size > 0 && data != nullptr) {
        ::memcpy(attr + 1, data, static_cast<size_t>(size));
    }
    msg->pos += NLMSG_ALIGN(attr->nla_len);
}

void NetlinkNest(Nlmsg* msg, int typ)
{
    auto* attr = reinterpret_cast<struct ::nlattr*>(msg->pos);
    attr->nla_type = static_cast<__u16>(typ);
    msg->pos += sizeof(*attr);
    // upstream 不检查 nesting 上界(信任 caller),这里 mirror;
    // 越界由 stack-corruption 体现,debug 时 LOG_DCHECK 加(暂略,匹配上游)。
    msg->nested[msg->nesting++] = attr;
}

void NetlinkDone(Nlmsg* msg)
{
    auto* attr = msg->nested[--msg->nesting];
    attr->nla_len = static_cast<__u16>(msg->pos - reinterpret_cast<char*>(attr));
}

// === I/O ======================================================

int NetlinkSendExt(Nlmsg* msg, int sock, std::uint16_t reply_type,
                   int* reply_len, bool dofail)
{
    if (msg->pos > msg->buf + sizeof(msg->buf) || msg->nesting) {
        NLLOG("send_ext: nlmsg overflow or unclosed nest (pos=%td nesting=%d) — drop",
              msg->pos - msg->buf, msg->nesting);
        // upstream fail("nlmsg overflow/bad nesting"); reFuzz 返回错误码不 abort。
        errno = EINVAL;
        return -1;
    }
    auto* hdr = reinterpret_cast<struct ::nlmsghdr*>(msg->buf);
    hdr->nlmsg_len = static_cast<__u32>(msg->pos - msg->buf);

    struct ::sockaddr_nl addr;
    ::memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;

    const ssize_t n_send = ::sendto(sock, msg->buf, hdr->nlmsg_len, 0,
                                    reinterpret_cast<struct ::sockaddr*>(&addr),
                                    sizeof(addr));
    if (n_send != static_cast<ssize_t>(hdr->nlmsg_len)) {
        if (dofail) {
            NLLOG("send_ext: short netlink write rc=%zd want=%u errno=%d (%s)",
                  n_send, hdr->nlmsg_len, errno, ::strerror(errno));
        } else {
            NLLOG("send_ext: short netlink write rc=%zd/%u errno=%d (quiet)",
                  n_send, hdr->nlmsg_len, errno);
        }
        return -1;
    }

    const ssize_t n_recv = ::recv(sock, msg->buf, sizeof(msg->buf), 0);
    if (reply_len) *reply_len = 0;

    if (n_recv < 0) {
        if (dofail) {
            NLLOG("send_ext: netlink read errno=%d (%s)", errno, ::strerror(errno));
        }
        return -1;
    }
    if (n_recv < static_cast<ssize_t>(sizeof(struct ::nlmsghdr))) {
        errno = EINVAL;
        if (dofail) {
            NLLOG("send_ext: short netlink read=%zd (<nlmsghdr)", n_recv);
        }
        return -1;
    }

    // re-fetch hdr,因为 recv 已覆盖 buf。
    hdr = reinterpret_cast<struct ::nlmsghdr*>(msg->buf);
    if (hdr->nlmsg_type == NLMSG_DONE) {
        return 0;
    }
    if (reply_len && hdr->nlmsg_type == reply_type) {
        *reply_len = static_cast<int>(n_recv);
        return 0;
    }
    if (n_recv < static_cast<ssize_t>(sizeof(struct ::nlmsghdr) +
                                      sizeof(struct ::nlmsgerr))) {
        errno = EINVAL;
        if (dofail) {
            NLLOG("send_ext: short netlink read=%zd (<nlmsghdr+nlmsgerr)", n_recv);
        }
        return -1;
    }
    if (hdr->nlmsg_type != NLMSG_ERROR) {
        errno = EINVAL;
        if (dofail) {
            NLLOG("send_ext: bad netlink ack type=%d", hdr->nlmsg_type);
        }
        return -1;
    }
    // upstream `errno = -((struct nlmsgerr*)(hdr+1))->error; return -errno;`
    // 等价 "成功时 error=0 → return 0;失败时 error<0 → errno = |error|"。
    const int kerr = -reinterpret_cast<struct ::nlmsgerr*>(hdr + 1)->error;
    errno = kerr;
    return -kerr;
}

int NetlinkSend(Nlmsg* msg, int sock)
{
    return NetlinkSendExt(msg, sock, 0, nullptr, /*dofail=*/true);
}

int NetlinkQueryFamilyId(Nlmsg* msg, int sock, const char* family_name,
                         bool dofail)
{
    struct ::genlmsghdr genlhdr;
    ::memset(&genlhdr, 0, sizeof(genlhdr));
    genlhdr.cmd = CTRL_CMD_GETFAMILY;
    NetlinkInit(msg, GENL_ID_CTRL, 0, &genlhdr, sizeof(genlhdr));
    NetlinkAttr(msg, CTRL_ATTR_FAMILY_NAME, family_name,
                static_cast<int>(::strnlen(family_name, GENL_NAMSIZ - 1) + 1));

    int n = 0;
    const int err = NetlinkSendExt(msg, sock, GENL_ID_CTRL, &n, dofail);
    if (err < 0) {
        NLLOG("query_family_id(%.*s) send_ext err=%d errno=%d (%s)",
              GENL_NAMSIZ, family_name, err, errno, ::strerror(errno));
        return -1;
    }

    uint16_t id = 0;
    auto* attr = reinterpret_cast<struct ::nlattr*>(
        msg->buf + NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(genlhdr)));
    for (; reinterpret_cast<char*>(attr) < msg->buf + n;
         attr = reinterpret_cast<struct ::nlattr*>(
             reinterpret_cast<char*>(attr) + NLMSG_ALIGN(attr->nla_len))) {
        if (attr->nla_type == CTRL_ATTR_FAMILY_ID) {
            id = *reinterpret_cast<uint16_t*>(attr + 1);
            break;
        }
    }
    if (!id) {
        NLLOG("query_family_id(%.*s) parse fail (no CTRL_ATTR_FAMILY_ID)",
              GENL_NAMSIZ, family_name);
        errno = EINVAL;
        return -1;
    }
    // upstream recv ack,reFuzz 镜像;失败也只是吞掉 stale ack,无 side-effect。
    (void)::recv(sock, msg->buf, sizeof(msg->buf), 0);

    return static_cast<int>(id);
}

// === parse ====================================================

int NetlinkNextMsg(const Nlmsg* msg, unsigned offset, unsigned total_len)
{
    const auto* hdr = reinterpret_cast<const struct ::nlmsghdr*>(msg->buf + offset);
    if (offset == total_len || offset + hdr->nlmsg_len > total_len) {
        return -1;
    }
    return static_cast<int>(hdr->nlmsg_len);
}

} // namespace refuzz::worker::sandbox::device_init

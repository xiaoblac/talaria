// InitializeTun — 端口 syzkaller `initialize_tun`
// (executor/common_linux.h:668-747)。
//
// 序列:
//   1) open("/dev/net/tun", O_RDWR | O_NONBLOCK)
//   2) dup2 to fd 200 (kTunFd) — fuzz-hidden high-band,与 syzkaller 同
//   3) ioctl(TUNSETIFF, "syz_tun" / IFF_TAP|IFF_NO_PI)
//   4) write_file accept_dad / router_solicitations = 0 (IPv6 抑制)
//   5) socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)
//   6) netlink: add_addr4 LOCAL_IPV4, add_addr6 LOCAL_IPV6
//      add_neigh REMOTE_IPV4 → REMOTE_MAC, add_neigh REMOTE_IPV6 → REMOTE_MAC
//      device_change up + LOCAL_MAC
//   7) close(sock)
//
// 调用 ctx:ApplyNone 内 NEWNET + ping_group_range 之后,SandboxCommonMountTmpfs
// 之前(对齐 upstream do_sandbox_none 序列)。
//
// Critical setup failures propagate to ApplySandbox so the loop reports a
// failed startup ACK and the daemon retries a fresh execution domain.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "worker/sandbox/device_init/device_init.hpp"
#include "worker/sandbox/device_init/netlink_helpers.hpp"
#include "worker/sandbox/device_init/netlink_builders.hpp"

#include "worker/log/log_macros.hpp"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/netlink.h>
#include <net/ethernet.h>      // ETH_ALEN

#define TUNLOG(fmt, ...) \
    ::refuzz::worker::log::WorkerLog("[device_init] tun: " fmt "\n", ##__VA_ARGS__)

namespace refuzz::worker::sandbox::device_init {

namespace {

// 与 syzkaller common_linux.h:650-656 byte-equal。
constexpr const char* kTunIface  = "syz_tun";
constexpr int         kTunFd     = 200;                    // common_linux.h:686
constexpr uint64_t    kLocalMac  = 0xaaaaaaaaaaaaULL;
constexpr uint64_t    kRemoteMac = 0xaaaaaaaaaabbULL;
constexpr const char* kLocalIpv4  = "172.20.20.170";
constexpr const char* kRemoteIpv4 = "172.20.20.187";
constexpr const char* kLocalIpv6  = "fe80::aa";
constexpr const char* kRemoteIpv6 = "fe80::bb";

void WriteSysctl(const char* path, const char* value)
{
    const int fd = ::open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        TUNLOG("sysctl open(%s) errno=%d (%s)", path, errno, ::strerror(errno));
        return;
    }
    const size_t n = ::strlen(value);
    const ssize_t w = ::write(fd, value, n);
    if (w != static_cast<ssize_t>(n)) {
        TUNLOG("sysctl write(%s) rc=%zd errno=%d", path, w, errno);
    }
    ::close(fd);
}

} // namespace

// Fuzz programs can unlink or replace this node. Recreate the exact TUN
// character device before opening it, matching syzkaller correct_dev_net_tun().
void CorrectDevNetTun()
{
    struct ::stat st{};
    if (::stat("/dev/net/tun", &st) == 0) {
        if (S_ISCHR(st.st_mode) && ::major(st.st_rdev) == 10 &&
            ::minor(st.st_rdev) == 200) {
            return;
        }
        if (::unlink("/dev/net/tun") != 0) {
            TUNLOG("unlink(/dev/net/tun) errno=%d (%s)",
                   errno, ::strerror(errno));
        }
    }
    if (::mkdir("/dev/net", 0755) != 0 && errno != EEXIST) {
        TUNLOG("mkdir(/dev/net) errno=%d (%s)", errno, ::strerror(errno));
    }
    if (::mknod("/dev/net/tun", S_IFCHR | 0666, ::makedev(10, 200)) != 0) {
        TUNLOG("mknod(/dev/net/tun) errno=%d (%s)", errno,
               ::strerror(errno));
    }
    if (::chmod("/dev/net/tun", 0666) != 0) {
        TUNLOG("chmod(/dev/net/tun) errno=%d (%s)", errno,
               ::strerror(errno));
    }
}

int InitializeTun()
{
    CorrectDevNetTun();
    int tunfd = ::open("/dev/net/tun", O_RDWR | O_NONBLOCK);
    if (tunfd < 0) {
        const int error_number = errno;
        TUNLOG("open(/dev/net/tun) errno=%d (%s)",
               errno, ::strerror(errno));
        return -error_number;
    }

    // upstream:dup2(tunfd, kTunFd=200);留住高位 fd,把 fuzz-visible 低 fd 让出来。
    if (tunfd != kTunFd) {
        if (::dup2(tunfd, kTunFd) < 0) {
            const int error_number = errno;
            TUNLOG("CRITICAL: dup2(tunfd=%d -> %d) errno=%d (%s)",
                   tunfd, kTunFd, errno, ::strerror(errno));
            ::close(tunfd);
            return -error_number;
        }
        ::close(tunfd);
        tunfd = kTunFd;
    }

    struct ::ifreq ifr;
    ::memset(&ifr, 0, sizeof(ifr));
    ::strncpy(ifr.ifr_name, kTunIface, IFNAMSIZ - 1);
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    if (::ioctl(tunfd, TUNSETIFF, &ifr) < 0) {
        const int error_number = errno;
        TUNLOG("CRITICAL: ioctl(TUNSETIFF, %s) errno=%d (%s)",
               kTunIface, errno, ::strerror(errno));
        ::close(tunfd);
        return -error_number;
    }

    // IPv6 DAD / router solicitations 抑制(upstream 注释:防止 spam,DAD
    // 没完成 address unusable)。可选,失败 LOG。
    char sysctl[128];
    ::snprintf(sysctl, sizeof(sysctl),
               "/proc/sys/net/ipv6/conf/%s/accept_dad", kTunIface);
    WriteSysctl(sysctl, "0");
    ::snprintf(sysctl, sizeof(sysctl),
               "/proc/sys/net/ipv6/conf/%s/router_solicitations", kTunIface);
    WriteSysctl(sysctl, "0");

    // netlink ROUTE socket for address / neighbor / link change ops。
    const int sock = ::socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) {
        const int error_number = errno;
        TUNLOG("CRITICAL: socket(NETLINK_ROUTE) errno=%d (%s)",
               errno, ::strerror(errno));
        return -error_number;
    }

    Nlmsg msg{};
    NetlinkAddAddr4(&msg, sock, kTunIface, kLocalIpv4);
    NetlinkAddAddr6(&msg, sock, kTunIface, kLocalIpv6);

    // REMOTE_IPV4 / REMOTE_IPV6 → REMOTE_MAC ARP/ND entries.
    {
        struct ::in_addr  v4;
        struct ::in6_addr v6;
        if (::inet_pton(AF_INET,  kRemoteIpv4, &v4) == 1) {
            NetlinkAddNeigh(&msg, sock, kTunIface, &v4, sizeof(v4),
                            &kRemoteMac, ETH_ALEN);
        }
        if (::inet_pton(AF_INET6, kRemoteIpv6, &v6) == 1) {
            NetlinkAddNeigh(&msg, sock, kTunIface, &v6, sizeof(v6),
                            &kRemoteMac, ETH_ALEN);
        }
    }

    // device up + LOCAL_MAC (upstream `netlink_device_change(&nlmsg, sock,
    // TUN_IFACE, true, 0, &macaddr, ETH_ALEN, NULL)` where macaddr=LOCAL_MAC)。
    NetlinkDeviceChange(&msg, sock, kTunIface, /*up=*/true,
                        /*master=*/nullptr, &kLocalMac, ETH_ALEN,
                        /*new_name=*/nullptr);

    ::close(sock);

    TUNLOG("ready: iface=%s fd=%d local=%s/%s remote=%s/%s",
           kTunIface, kTunFd, kLocalIpv4, kLocalIpv6, kRemoteIpv4, kRemoteIpv6);
    return 0;
}

} // namespace refuzz::worker::sandbox::device_init

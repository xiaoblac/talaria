// InitializeDevlinkPci — 端口 syzkaller `initialize_devlink_pci` +
// 周边 helpers (executor/common_linux.h:773-882)。
//
// 把 host "pci/0000:00:10.0" devlink instance 移到当前 net namespace,
// 然后用 dump 取到它的 ports 并 rename 为 "netpci0", "netpci1", ...
// (syscall description 知道 netpci 前缀)。
//
// 序列:
//   1) open /proc/self/ns/net 保存当前 netns fd
//   2) setns(kInitNetNsFd=201) → 切回 host netns
//   3) netlink_devlink_netns_move("pci", "0000:00:10.0", current_netns_fd)
//   4) setns(current_netns_fd) → 切回 sandbox netns
//   5) close 临时 netns fd
//   6) initialize_devlink_ports("pci", "0000:00:10.0", "netpci")
//
// 失败 silent-skip:host VM 没 PCI devlink device 是常态。

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "worker/sandbox/device_init/device_init.hpp"
#include "worker/sandbox/device_init/netlink_helpers.hpp"
#include "worker/sandbox/device_init/netlink_builders.hpp"

#include "worker/log/log_macros.hpp"

#include <errno.h>
#include <fcntl.h>
#include <sched.h>          // setns
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <net/if.h>         // IFNAMSIZ

#define DLLOG(fmt, ...) \
    ::refuzz::worker::log::WorkerLog("[device_init] devlink_pci: " fmt "\n", ##__VA_ARGS__)

namespace refuzz::worker::sandbox::device_init {

namespace {

// upstream common_linux.h:759-770 byte-equal
constexpr const char* kDevlinkFamilyName  = "devlink";
constexpr int kDevlinkCmdPortGet  = 5;
constexpr int kDevlinkCmdReload   = 37;
constexpr int kDevlinkAttrBusName     = 1;
constexpr int kDevlinkAttrDevName     = 2;
constexpr int kDevlinkAttrNetdevName  = 7;
constexpr int kDevlinkAttrNetnsFd     = 138;
constexpr int kInitNetNsFd = 201; // 与 sandbox.cpp 同步

// upstream netlink_devlink_netns_move (common_linux.h:773)。
void NetlinkDevlinkNetnsMove(Nlmsg* msg, const char* bus_name,
                             const char* dev_name, int netns_fd)
{
    const int sock = ::socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if (sock < 0) {
        DLLOG("netns_move: socket(NETLINK_GENERIC) errno=%d", errno);
        return;
    }
    const int id = NetlinkQueryFamilyId(msg, sock, kDevlinkFamilyName, true);
    if (id < 0) {
        DLLOG("netns_move: query family '%s' fail — CONFIG_NET_DEVLINK=n? 跳过",
              kDevlinkFamilyName);
        ::close(sock);
        return;
    }

    struct ::genlmsghdr genlhdr;
    ::memset(&genlhdr, 0, sizeof(genlhdr));
    genlhdr.cmd = kDevlinkCmdReload;
    NetlinkInit(msg, id, 0, &genlhdr, sizeof(genlhdr));
    NetlinkAttr(msg, kDevlinkAttrBusName, bus_name,
                static_cast<int>(::strlen(bus_name) + 1));
    NetlinkAttr(msg, kDevlinkAttrDevName, dev_name,
                static_cast<int>(::strlen(dev_name) + 1));
    NetlinkAttr(msg, kDevlinkAttrNetnsFd, &netns_fd, sizeof(netns_fd));
    const int err = NetlinkSend(msg, sock);
    if (err < 0) {
        DLLOG("netns_move(%s/%s) err=%d (%s) — devlink instance 可能不存在,跳过",
              bus_name, dev_name, err, ::strerror(errno));
    }
    ::close(sock);
}

} // namespace

// upstream initialize_devlink_ports (common_linux.h:805)。
void InitializeDevlinkPorts(const char* bus_name, const char* dev_name,
                            const char* netdev_prefix)
{
    const int sock = ::socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if (sock < 0) {
        DLLOG("ports: socket(NETLINK_GENERIC) errno=%d", errno);
        return;
    }
    const int rtsock = ::socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (rtsock < 0) {
        DLLOG("ports: socket(NETLINK_ROUTE) errno=%d", errno);
        ::close(sock);
        return;
    }

    Nlmsg msg{};
    Nlmsg msg2{};  // upstream `nlmsg2` —— device_change 在 dump 解析里用,
                   // 不复用 msg buffer 否则 dump 数据被覆盖。

    const int id = NetlinkQueryFamilyId(&msg, sock, kDevlinkFamilyName, true);
    if (id < 0) {
        DLLOG("ports: query family fail — 跳过");
        ::close(rtsock);
        ::close(sock);
        return;
    }

    struct ::genlmsghdr genlhdr;
    ::memset(&genlhdr, 0, sizeof(genlhdr));
    genlhdr.cmd = kDevlinkCmdPortGet;
    NetlinkInit(&msg, id, NLM_F_DUMP, &genlhdr, sizeof(genlhdr));
    NetlinkAttr(&msg, kDevlinkAttrBusName, bus_name,
                static_cast<int>(::strlen(bus_name) + 1));
    NetlinkAttr(&msg, kDevlinkAttrDevName, dev_name,
                static_cast<int>(::strlen(dev_name) + 1));

    int total_len = 0;
    const int err = NetlinkSendExt(&msg, sock, id, &total_len, true);
    if (err < 0) {
        DLLOG("ports: port_get dump err=%d (%s)", err, ::strerror(errno));
        ::close(rtsock);
        ::close(sock);
        return;
    }

    unsigned offset = 0;
    unsigned netdev_index = 0;
    int len = 0;
    while ((len = NetlinkNextMsg(&msg, offset, total_len)) != -1) {
        const auto* attr = reinterpret_cast<const struct ::nlattr*>(
            msg.buf + offset + NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(genlhdr)));
        for (; reinterpret_cast<const char*>(attr) < msg.buf + offset + len;
             attr = reinterpret_cast<const struct ::nlattr*>(
                 reinterpret_cast<const char*>(attr) + NLMSG_ALIGN(attr->nla_len))) {
            if (attr->nla_type == kDevlinkAttrNetdevName) {
                const char* port_name = reinterpret_cast<const char*>(attr + 1);
                char netdev_name[IFNAMSIZ];
                ::snprintf(netdev_name, sizeof(netdev_name), "%s%u",
                           netdev_prefix, netdev_index);
                NetlinkDeviceChange(&msg2, rtsock, port_name, /*up=*/true,
                                    nullptr, nullptr, 0,
                                    /*new_name=*/netdev_name);
                break;
            }
        }
        offset += len;
        netdev_index++;
    }

    ::close(rtsock);
    ::close(sock);
}

void InitializeDevlinkPci()
{
    const int netns = ::open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
    if (netns < 0) {
        DLLOG("CRITICAL: open(/proc/self/ns/net) errno=%d", errno);
        return;
    }
    if (::setns(kInitNetNsFd, 0) < 0) {
        DLLOG("setns(init_netns=%d) errno=%d (%s) — 跳过 devlink netns move",
              kInitNetNsFd, errno, ::strerror(errno));
        ::close(netns);
        return;
    }

    // 在 host netns 内做 devlink reload netns→sandbox netns。
    {
        Nlmsg msg{};
        NetlinkDevlinkNetnsMove(&msg, "pci", "0000:00:10.0", netns);
    }

    if (::setns(netns, 0) < 0) {
        DLLOG("CRITICAL: setns(this_netns=%d) errno=%d — 已 stranded 在 init netns!",
              netns, errno);
        // 这是 host netns,worker 继续做 init 会污染 host —— 但仍 close 防 fd 泄漏。
        ::close(netns);
        return;
    }
    ::close(netns);

    // 回到 sandbox netns 后 init ports。
    InitializeDevlinkPorts("pci", "0000:00:10.0", "netpci");
}

} // namespace refuzz::worker::sandbox::device_init

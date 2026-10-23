// InitializeNetdevicesInit — 端口 syzkaller `initialize_netdevices_init`
// (executor/common_linux.h:1696-1739)。
//
// 作用:在 unshare(CLONE_NEWNET) **之前** 操作 host netns 上的 NETROM / ROSE
// 设备(这两种 protocol 的 device 必须在原 netns 才能 ifdown/ifup),给它们
// 加 IPv4 (172.30.<idx>.<procid+1>) / IPv6 (fe88::<idx>:<procid+1>) 地址,
// up 起来,设 MAC。
//
// 注意:upstream 用 module-global `procid`,假设是 fuzz worker 的进程编号。
// reFuzz 当前是单 worker(paired-VM oracle),传入参数 default 0 即可。
// 多 worker case (future) 传 executor_id。
//
// 失败:全 LOG-and-continue;upstream socket() 失败 fail(),reFuzz LOG 即可
// (host 没 CONFIG_NETROM=y / CONFIG_ROSE=y 时 if_nametoindex 直接 0,builder
//  silent skip)。

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "worker/sandbox/device_init/device_init.hpp"
#include "worker/sandbox/device_init/netlink_helpers.hpp"
#include "worker/sandbox/device_init/netlink_builders.hpp"

#include "worker/log/log_macros.hpp"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/netlink.h>

#define NDILOG(fmt, ...) \
    ::refuzz::worker::log::WorkerLog("[device_init] netdevices_init: " fmt "\n", ##__VA_ARGS__)

namespace refuzz::worker::sandbox::device_init {

void InitializeNetdevicesInit(std::uint64_t procid)
{
    const int sock = ::socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) {
        NDILOG("CRITICAL: socket(NETLINK_ROUTE) errno=%d (%s)",
               errno, ::strerror(errno));
        return;
    }

    // upstream 表:nr (NETROM, mac 7 字节) + rose (ROSE, mac 5 字节, no IPv6, no up)
    struct DevType {
        const char* type;
        int macsize;
        bool noipv6;
        bool noup;
    };
    static const DevType devtypes[] = {
        {"nr",   7, true,  false},
        {"rose", 5, true,  true},
    };

    Nlmsg msg{};
    for (size_t i = 0; i < sizeof(devtypes) / sizeof(devtypes[0]); i++) {
        char dev[32];
        char addr[48];
        ::snprintf(dev, sizeof(dev), "%s%d", devtypes[i].type, (int)procid);

        // IPv4 syscall descriptions 知道这套地址(见 upstream 注释)。
        ::snprintf(addr, sizeof(addr), "172.30.%zu.%d", i, (int)procid + 1);
        NetlinkAddAddr4(&msg, sock, dev, addr);

        if (!devtypes[i].noipv6) {
            ::snprintf(addr, sizeof(addr), "fe88::%02zx:%02x",
                       i, (int)procid + 1);
            NetlinkAddAddr6(&msg, sock, dev, addr);
        }

        const int macsize = devtypes[i].macsize;
        uint64_t macaddr = 0xbbbbbbULL +
                           (static_cast<uint64_t>(i) << (8 * (macsize - 2))) +
                           (procid << (8 * (macsize - 1)));
        NetlinkDeviceChange(&msg, sock, dev, /*up=*/!devtypes[i].noup,
                            /*master=*/nullptr, &macaddr, macsize,
                            /*new_name=*/nullptr);
    }

    ::close(sock);

    NDILOG("ran for procid=%llu (host netns, before NEWNET)",
           static_cast<unsigned long long>(procid));
}

} // namespace refuzz::worker::sandbox::device_init

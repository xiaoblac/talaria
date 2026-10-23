// InitializeNetdevices — 端口 syzkaller `initialize_netdevices`
// (common_linux.h:1488-1693)。
//
// 在 unshare(NEWNET) 后(本 net ns)创建一大堆虚拟 net device:
//   bridge / bond / team / batadv / hsr / vxcan / veth / wireguard / dummy /
//   nlmon / caif / vcan / ip6gretap / nicvf(可选) /
//   virt_wifi / macvtap / macsec / vlan × 2 / macvlan × 2 / ipvlan × 2 /
//   geneve × 2 / netdevsim / xfrm
// 然后给每个 device 加 IPv4/IPv6 地址 + MAC + up。 syscall description 知道
// 这套 device names + IPs(sys/linux/vnet.txt / socket.txt)。
//
// 调用 ctx:ApplyNone 内 InitializeTun 之后,SandboxCommonMountTmpfs 之前。
// procid 用于 netdevsim 实例 id(每 worker 唯一);单 worker oracle default 0。

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

#include <arpa/inet.h>
#include <linux/if_ether.h>    // ETH_P_8021Q / ETH_P_8021AD
#include <linux/if_link.h>     // IPVLAN_MODE_L2 / L3S (may be missing on old kernels)
#include <linux/netlink.h>
#include <net/ethernet.h>      // ETH_ALEN

#ifndef IPVLAN_MODE_L2
#define IPVLAN_MODE_L2 0
#endif
#ifndef IPVLAN_MODE_L3S
#define IPVLAN_MODE_L3S 2
#endif
// upstream redefines IPVLAN_F_VEPA = 2,不依赖 system header。
#ifndef IPVLAN_F_VEPA_REFZ
#define IPVLAN_F_VEPA_REFZ 2
#endif

#define NDLOG(fmt, ...) \
    ::refuzz::worker::log::WorkerLog("[device_init] netdevices: " fmt "\n", ##__VA_ARGS__)

namespace refuzz::worker::sandbox::device_init {

namespace {

// upstream common_linux.h:1199-1201 byte-equal。
constexpr const char* kDevIpv4Fmt = "172.20.20.%d";
constexpr const char* kDevIpv6Fmt = "fe80::%02x";
constexpr uint64_t    kDevMac     = 0x00aaaaaaaaaaULL;

} // namespace

void InitializeNetdevices(std::uint64_t procid)
{
    // 临时 netdevsim name(devices[] 表里也要把它放进去 with addr setup)。
    char netdevsim[32];
    ::snprintf(netdevsim, sizeof(netdevsim), "netdevsim%d", (int)procid);

    // === devtypes:无参数 device factory(单 type / name)========
    struct DevType { const char* type; const char* dev; };
    static const DevType devtypes[] = {
        // ip6erspan 不能与 ip6gretap 同 ns,所以 ip6gretap 在前。
        {"ip6gretap", "ip6gretap0"},
        {"bridge",    "bridge0"},
        {"vcan",      "vcan0"},
        {"bond",      "bond0"},
        {"team",      "team0"},
        {"dummy",     "dummy0"},
        // NIC_VF (SYZ_NIC_VF) — 当前 reFuzz 不 enable,跳过 nicvf。
        {"nlmon",     "nlmon0"},
        {"caif",      "caif0"},
        {"batadv",    "batadv0"},
        // vxcan 加 vxcan1 → kernel 自建 vxcan0/vxcan1 对(类似 veth)。
        {"vxcan",     "vxcan1"},
        // veth 不带 name 一对(veth0/veth1 自动)。
        {"veth",      nullptr},
        {"wireguard", "wg0"},
        {"wireguard", "wg1"},
        {"wireguard", "wg2"},
    };
    static const char* const devmasters[] = {"bridge", "bond", "team", "batadv"};

    // === devices[]:加 addr/MAC/up 的全部 device 名 ==============
    // 顺序 = upstream 1545-1607 byte-equal,sys/linux/vnet.txt 同步。
    struct DevAddr { const char* name; int macsize; bool noipv6; };
    const DevAddr devices[] = {
        {"lo",                ETH_ALEN, false},
        {"sit0",              0,        false},
        {"bridge0",           ETH_ALEN, false},
        {"vcan0",             0,        true},
        {"tunl0",             0,        false},
        {"gre0",              0,        false},
        {"gretap0",           ETH_ALEN, false},
        {"ip_vti0",           0,        false},
        {"ip6_vti0",          0,        false},
        {"ip6tnl0",           0,        false},
        {"ip6gre0",           0,        false},
        {"ip6gretap0",        ETH_ALEN, false},
        {"erspan0",           ETH_ALEN, false},
        {"bond0",             ETH_ALEN, false},
        {"veth0",             ETH_ALEN, false},
        {"veth1",             ETH_ALEN, false},
        {"team0",             ETH_ALEN, false},
        {"veth0_to_bridge",   ETH_ALEN, false},
        {"veth1_to_bridge",   ETH_ALEN, false},
        {"veth0_to_bond",     ETH_ALEN, false},
        {"veth1_to_bond",     ETH_ALEN, false},
        {"veth0_to_team",     ETH_ALEN, false},
        {"veth1_to_team",     ETH_ALEN, false},
        {"veth0_to_hsr",      ETH_ALEN, false},
        {"veth1_to_hsr",      ETH_ALEN, false},
        {"hsr0",              0,        false},
        {"dummy0",            ETH_ALEN, false},
        // SYZ_NIC_VF 不 enable,跳过 "nicvf0"。
        {"nlmon0",            0,        false},
        {"vxcan0",            0,        true},
        {"vxcan1",            0,        true},
        {"caif0",             ETH_ALEN, false}, // caif up 可能 ENODEV — upstream TODO
        {"batadv0",           ETH_ALEN, false},
        {netdevsim,           ETH_ALEN, false},
        {"xfrm0",             ETH_ALEN, false},
        {"veth0_virt_wifi",   ETH_ALEN, false},
        {"veth1_virt_wifi",   ETH_ALEN, false},
        {"virt_wifi0",        ETH_ALEN, false},
        {"veth0_vlan",        ETH_ALEN, false},
        {"veth1_vlan",        ETH_ALEN, false},
        {"vlan0",             ETH_ALEN, false},
        {"vlan1",             ETH_ALEN, false},
        {"macvlan0",          ETH_ALEN, false},
        {"macvlan1",          ETH_ALEN, false},
        {"ipvlan0",           ETH_ALEN, false},
        {"ipvlan1",           ETH_ALEN, false},
        {"veth0_macvtap",     ETH_ALEN, false},
        {"veth1_macvtap",     ETH_ALEN, false},
        {"macvtap0",          ETH_ALEN, false},
        {"macsec0",           ETH_ALEN, false},
        {"veth0_to_batadv",   ETH_ALEN, false},
        {"veth1_to_batadv",   ETH_ALEN, false},
        {"batadv_slave_0",    ETH_ALEN, false},
        {"batadv_slave_1",    ETH_ALEN, false},
        {"geneve0",           ETH_ALEN, false},
        {"geneve1",           ETH_ALEN, false},
        {"wg0",               0,        false},
        {"wg1",               0,        false},
        {"wg2",               0,        false},
    };

    const int sock = ::socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) {
        NDLOG("CRITICAL: socket(NETLINK_ROUTE) errno=%d (%s)",
              errno, ::strerror(errno));
        return;
    }

    Nlmsg msg{};

    // Step 1:devtypes 批量创建。
    for (size_t i = 0; i < sizeof(devtypes) / sizeof(devtypes[0]); i++) {
        NetlinkAddDevice(&msg, sock, devtypes[i].type, devtypes[i].dev);
    }

    // Step 2:devmasters bridge/bond/team/batadv —— 每个 master 加两条
    // veth pair, slave_0 + veth0_to_*  /  slave_1 + veth1_to_*,然后把
    // slave_* 设到 master 下面(noup,kernel auto-up)。
    for (size_t i = 0; i < sizeof(devmasters) / sizeof(devmasters[0]); i++) {
        char master[32], slave0[32], veth0[32], slave1[32], veth1[32];
        ::snprintf(slave0, sizeof(slave0), "%s_slave_0", devmasters[i]);
        ::snprintf(veth0,  sizeof(veth0),  "veth0_to_%s", devmasters[i]);
        NetlinkAddVeth(&msg, sock, slave0, veth0);
        ::snprintf(slave1, sizeof(slave1), "%s_slave_1", devmasters[i]);
        ::snprintf(veth1,  sizeof(veth1),  "veth1_to_%s", devmasters[i]);
        NetlinkAddVeth(&msg, sock, slave1, veth1);
        ::snprintf(master, sizeof(master), "%s0", devmasters[i]);
        NetlinkDeviceChange(&msg, sock, slave0, /*up=*/false,
                            /*master=*/master, /*mac=*/nullptr, 0, /*new_name=*/nullptr);
        NetlinkDeviceChange(&msg, sock, slave1, /*up=*/false,
                            /*master=*/master, /*mac=*/nullptr, 0, /*new_name=*/nullptr);
    }

    NetlinkAddXfrm(&msg, sock, "xfrm0");

    // bridge_slave_0/1 必须手动 up;bond/team_slave_* kernel auto-up。
    NetlinkDeviceChange(&msg, sock, "bridge_slave_0", /*up=*/true, nullptr,
                        nullptr, 0, nullptr);
    NetlinkDeviceChange(&msg, sock, "bridge_slave_1", /*up=*/true, nullptr,
                        nullptr, 0, nullptr);

    // Step 3:HSR(略不同于 devmasters 的 master/slave pattern)。
    NetlinkAddVeth(&msg, sock, "hsr_slave_0", "veth0_to_hsr");
    NetlinkAddVeth(&msg, sock, "hsr_slave_1", "veth1_to_hsr");
    // hsr0 同 ns "hsr_slave_0/1" 已存在;NetlinkAddHsr 内 if_nametoindex 解析。
    // 注:upstream initialize_netdevices_init 不创建 hsr_slave_*,所以 hsr0
    //     已在 devtypes[] 之前没创;这里 NetlinkAddDevice("hsr",...) 没在
    //     devtypes,而是延迟到这里通过 hsr 隐式建。upstream 也是这个 sequence。
    {
        // 用 NetlinkAddHsr 而不是 NetlinkAddDevice("hsr", "hsr0") —— 因为
        // 必须带 slave1/slave2 indices。
        // 等价 upstream `netlink_add_hsr(&nlmsg, sock, "hsr0", "hsr_slave_0", "hsr_slave_1");`
        NetlinkAddHsr(&msg, sock, "hsr0", "hsr_slave_0", "hsr_slave_1");
    }
    NetlinkDeviceChange(&msg, sock, "hsr_slave_0", /*up=*/true, nullptr,
                        nullptr, 0, nullptr);
    NetlinkDeviceChange(&msg, sock, "hsr_slave_1", /*up=*/true, nullptr,
                        nullptr, 0, nullptr);

    // Step 4:virt_wifi over veth pair。
    NetlinkAddVeth(&msg, sock, "veth0_virt_wifi", "veth1_virt_wifi");
    NetlinkAddLinked(&msg, sock, "virt_wifi", "virt_wifi0", "veth1_virt_wifi");

    // Step 5:vlan / macvlan / ipvlan over veth pair。
    NetlinkAddVeth(&msg, sock, "veth0_vlan", "veth1_vlan");
    NetlinkAddVlan(&msg, sock, "vlan0", "veth0_vlan", 0,
                   static_cast<std::uint16_t>(::htons(ETH_P_8021Q)));
    NetlinkAddVlan(&msg, sock, "vlan1", "veth0_vlan", 1,
                   static_cast<std::uint16_t>(::htons(ETH_P_8021AD)));
    NetlinkAddMacvlan(&msg, sock, "macvlan0", "veth1_vlan");
    NetlinkAddMacvlan(&msg, sock, "macvlan1", "veth1_vlan");
    NetlinkAddIpvlan(&msg, sock, "ipvlan0", "veth0_vlan",
                     IPVLAN_MODE_L2, 0);
    NetlinkAddIpvlan(&msg, sock, "ipvlan1", "veth0_vlan",
                     IPVLAN_MODE_L3S, IPVLAN_F_VEPA_REFZ);

    // Step 6:macvtap / macsec over veth pair。
    NetlinkAddVeth(&msg, sock, "veth0_macvtap", "veth1_macvtap");
    NetlinkAddLinked(&msg, sock, "macvtap", "macvtap0", "veth0_macvtap");
    NetlinkAddLinked(&msg, sock, "macsec",  "macsec0",  "veth1_macvtap");

    // Step 7:geneve0/1 with remote endpoints (v4 → 172.20.20.24 即
    // veth0+14+10=24,v6 → fc00::01 non-link-local)。
    {
        char addr[32];
        ::snprintf(addr, sizeof(addr), kDevIpv4Fmt, 14 + 10);
        struct in_addr v4{};
        struct in6_addr v6{};
        if (::inet_pton(AF_INET, addr, &v4) <= 0) {
            NDLOG("geneve0 inet_pton(%s) fail", addr);
        }
        if (::inet_pton(AF_INET6, "fc00::01", &v6) <= 0) {
            NDLOG("geneve1 inet_pton(fc00::01) fail");
        }
        NetlinkAddGeneve(&msg, sock, "geneve0", 0, &v4, nullptr);
        NetlinkAddGeneve(&msg, sock, "geneve1", 1, nullptr, &v6);
    }

    // Step 8:netdevsim — sticky,sysfs 路径;port_count=4 与 socket_netlink_
    // generic_devlink.txt 同步。
    NetdevsimAdd(static_cast<unsigned>(procid), 4);

    // Step 9:wireguard 三 device 互为 peer 配置。
    NetlinkWireguardSetup();

    // Step 10:loop devices[] —— 每个 device 加 IPv4 + IPv6 + MAC + up。
    // 地址 shift 10 避开 0 subnet。
    for (size_t i = 0; i < sizeof(devices) / sizeof(devices[0]); i++) {
        char addr[64];
        ::snprintf(addr, sizeof(addr), kDevIpv4Fmt, static_cast<int>(i + 10));
        NetlinkAddAddr4(&msg, sock, devices[i].name, addr);
        if (!devices[i].noipv6) {
            ::snprintf(addr, sizeof(addr), kDevIpv6Fmt, static_cast<int>(i + 10));
            NetlinkAddAddr6(&msg, sock, devices[i].name, addr);
        }
        uint64_t macaddr = kDevMac +
                           (static_cast<uint64_t>(i + 10ULL) << 40);
        NetlinkDeviceChange(&msg, sock, devices[i].name, /*up=*/true,
                            /*master=*/nullptr, &macaddr,
                            devices[i].macsize, /*new_name=*/nullptr);
    }

    ::close(sock);

    NDLOG("ran: %zu devtypes + %zu devmasters + %zu devices procid=%llu",
          sizeof(devtypes) / sizeof(devtypes[0]),
          sizeof(devmasters) / sizeof(devmasters[0]),
          sizeof(devices) / sizeof(devices[0]),
          static_cast<unsigned long long>(procid));
}

} // namespace refuzz::worker::sandbox::device_init

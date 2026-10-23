// Netlink shared builders — D3 portion (cross-D3/D4/D5/D7 reusable)。
//
// 1:1 port from syzkaller `executor/common_linux.h` 544-624:
//   - netlink_device_change
//   - netlink_add_addr / netlink_add_addr4 / netlink_add_addr6
//   - netlink_add_neigh
//
// 与 upstream byte-equal except `debug()` → WorkerLog。
//
// Builder 不调 `fail()` —— upstream 也只 `debug()`。失败 LOG 不影响其它 builder。

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "worker/sandbox/device_init/netlink_builders.hpp"

#include "worker/log/log_macros.hpp"

// arpa/inet.h 必须在 linux/* 之前 —— 走 netinet/in.h 路径设上 _NETINET_IN_H
// guard,后续 linux/in.h (被 linux/if_addr.h / linux/neighbour.h 等隐式 pull)
// 会 skip IPPROTO_* enum 重定义。
#include <arpa/inet.h>         // inet_pton, pulls netinet/in.h
#include <errno.h>
#include <net/if.h>            // if_nametoindex
#include <string.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>
#include <linux/neighbour.h>
#include <linux/veth.h>

#define NLLOG(fmt, ...) \
    ::refuzz::worker::log::WorkerLog("[netlink] " fmt "\n", ##__VA_ARGS__)

namespace refuzz::worker::sandbox::device_init {

namespace {

// Upstream `static unsigned int queue_count = 2;` (common_linux.h:376) —
// 限制每 interface TX/RX 队列数,避免 many-core 机器上每个 interface 产生
// 海量 sysfs entries 拖慢 fuzz。reFuzz mirror。
constexpr unsigned int kQueueCount = 2;

// 与上游 netlink_add_device_impl byte-equal(common_linux.h:378):
//   建一个 ifinfomsg + IFLA_IFNAME(可选)+ NUM_TX/RX_QUEUES + 打开
//   IFLA_LINKINFO nest + 写 IFLA_INFO_KIND。 caller 接着可在 INFO_DATA
//   嵌入 type-specific attr,然后 NetlinkDone 一两次后 NetlinkSend。
// 注:**没 NetlinkDone IFLA_LINKINFO** —— caller 决定是否 NetlinkDone 后 close。
//     某些 builder (add_device, add_linked) 直接 done 一次然后 send;
//     某些 (add_veth, add_xfrm 等) nest 再开 INFO_DATA / VETH_INFO_PEER。
void NetlinkAddDeviceImpl(Nlmsg* msg, const char* type,
                          const char* name, bool up)
{
    struct ::ifinfomsg hdr;
    ::memset(&hdr, 0, sizeof(hdr));
    if (up) {
        hdr.ifi_flags = IFF_UP;
        hdr.ifi_change = IFF_UP;
    }
    NetlinkInit(msg, RTM_NEWLINK, NLM_F_EXCL | NLM_F_CREATE,
                &hdr, sizeof(hdr));
    if (name) {
        NetlinkAttr(msg, IFLA_IFNAME, name, static_cast<int>(::strlen(name)));
    }
    NetlinkAttr(msg, IFLA_NUM_TX_QUEUES, &kQueueCount, sizeof(kQueueCount));
    NetlinkAttr(msg, IFLA_NUM_RX_QUEUES, &kQueueCount, sizeof(kQueueCount));
    NetlinkNest(msg, IFLA_LINKINFO);
    NetlinkAttr(msg, IFLA_INFO_KIND, type, static_cast<int>(::strlen(type)));
}

} // namespace

void NetlinkDeviceChange(Nlmsg* msg, int sock, const char* name, bool up,
                         const char* master, const void* mac, int macsize,
                         const char* new_name)
{
    struct ::ifinfomsg hdr;
    ::memset(&hdr, 0, sizeof(hdr));
    if (up) {
        hdr.ifi_flags = IFF_UP;
        hdr.ifi_change = IFF_UP;
    }
    hdr.ifi_index = ::if_nametoindex(name);
    NetlinkInit(msg, RTM_NEWLINK, 0, &hdr, sizeof(hdr));
    if (new_name) {
        NetlinkAttr(msg, IFLA_IFNAME, new_name, static_cast<int>(::strlen(new_name)));
    }
    if (master) {
        const int ifindex = static_cast<int>(::if_nametoindex(master));
        NetlinkAttr(msg, IFLA_MASTER, &ifindex, sizeof(ifindex));
    }
    if (macsize) {
        NetlinkAttr(msg, IFLA_ADDRESS, mac, macsize);
    }
    const int err = NetlinkSend(msg, sock);
    if (err < 0) {
        NLLOG("device %s up=%d master=%s: err=%d (%s)",
              name, up ? 1 : 0, master ? master : "(none)",
              err, ::strerror(errno));
    }
}

int NetlinkAddAddr(Nlmsg* msg, int sock, const char* dev,
                   const void* addr, int addrsize)
{
    struct ::ifaddrmsg hdr;
    ::memset(&hdr, 0, sizeof(hdr));
    hdr.ifa_family = (addrsize == 4) ? AF_INET : AF_INET6;
    hdr.ifa_prefixlen = (addrsize == 4) ? 24 : 120;
    hdr.ifa_scope = RT_SCOPE_UNIVERSE;
    hdr.ifa_index = ::if_nametoindex(dev);
    NetlinkInit(msg, RTM_NEWADDR, NLM_F_CREATE | NLM_F_REPLACE, &hdr, sizeof(hdr));
    NetlinkAttr(msg, IFA_LOCAL, addr, addrsize);
    NetlinkAttr(msg, IFA_ADDRESS, addr, addrsize);
    return NetlinkSend(msg, sock);
}

void NetlinkAddAddr4(Nlmsg* msg, int sock, const char* dev, const char* addr)
{
    struct ::in_addr in_addr;
    if (::inet_pton(AF_INET, addr, &in_addr) != 1) {
        NLLOG("add_addr4 inet_pton(%s) fail", addr);
        return;
    }
    const int err = NetlinkAddAddr(msg, sock, dev, &in_addr, sizeof(in_addr));
    if (err < 0) {
        NLLOG("add addr4 %s dev %s err=%d (%s)",
              addr, dev, err, ::strerror(errno));
    }
}

void NetlinkAddAddr6(Nlmsg* msg, int sock, const char* dev, const char* addr)
{
    struct ::in6_addr in6_addr;
    if (::inet_pton(AF_INET6, addr, &in6_addr) != 1) {
        NLLOG("add_addr6 inet_pton(%s) fail", addr);
        return;
    }
    const int err = NetlinkAddAddr(msg, sock, dev, &in6_addr, sizeof(in6_addr));
    if (err < 0) {
        NLLOG("add addr6 %s dev %s err=%d (%s)",
              addr, dev, err, ::strerror(errno));
    }
}

void NetlinkAddNeigh(Nlmsg* msg, int sock, const char* name,
                     const void* addr, int addrsize,
                     const void* mac, int macsize)
{
    struct ::ndmsg hdr;
    ::memset(&hdr, 0, sizeof(hdr));
    hdr.ndm_family = (addrsize == 4) ? AF_INET : AF_INET6;
    hdr.ndm_ifindex = static_cast<int>(::if_nametoindex(name));
    hdr.ndm_state = NUD_PERMANENT;
    NetlinkInit(msg, RTM_NEWNEIGH, NLM_F_EXCL | NLM_F_CREATE, &hdr, sizeof(hdr));
    NetlinkAttr(msg, NDA_DST, addr, addrsize);
    NetlinkAttr(msg, NDA_LLADDR, mac, macsize);
    const int err = NetlinkSend(msg, sock);
    if (err < 0) {
        NLLOG("add neigh dev=%s addrsize=%d macsize=%d err=%d (%s)",
              name, addrsize, macsize, err, ::strerror(errno));
    }
}

// === D4 device builders ============================================

void NetlinkAddDevice(Nlmsg* msg, int sock, const char* type, const char* name)
{
    NetlinkAddDeviceImpl(msg, type, name, /*up=*/false);
    NetlinkDone(msg);  // close IFLA_LINKINFO
    const int err = NetlinkSend(msg, sock);
    if (err < 0) {
        NLLOG("add device name=%s type=%s err=%d (%s)",
              name ? name : "(auto)", type, err, ::strerror(errno));
    }
}

void NetlinkAddVeth(Nlmsg* msg, int sock, const char* name, const char* peer)
{
    NetlinkAddDeviceImpl(msg, "veth", name, /*up=*/false);
    NetlinkNest(msg, IFLA_INFO_DATA);
    NetlinkNest(msg, VETH_INFO_PEER);
    // upstream: pos += sizeof(struct ifinfomsg) — peer 段也带一个 ifinfomsg
    // 空头(全 0,kernel 用 IFLA_IFNAME 取名)。
    msg->pos += sizeof(struct ::ifinfomsg);
    NetlinkAttr(msg, IFLA_IFNAME, peer, static_cast<int>(::strlen(peer)));
    NetlinkAttr(msg, IFLA_NUM_TX_QUEUES, &kQueueCount, sizeof(kQueueCount));
    NetlinkAttr(msg, IFLA_NUM_RX_QUEUES, &kQueueCount, sizeof(kQueueCount));
    NetlinkDone(msg);  // close VETH_INFO_PEER
    NetlinkDone(msg);  // close IFLA_INFO_DATA
    NetlinkDone(msg);  // close IFLA_LINKINFO
    const int err = NetlinkSend(msg, sock);
    if (err < 0) {
        NLLOG("add veth %s peer %s err=%d (%s)",
              name, peer, err, ::strerror(errno));
    }
}

void NetlinkAddXfrm(Nlmsg* msg, int sock, const char* name)
{
    NetlinkAddDeviceImpl(msg, "xfrm", name, /*up=*/true);
    NetlinkNest(msg, IFLA_INFO_DATA);
    // IFLA_XFRM_IF_ID = 2 (老 header 没定义,upstream 写死)。
    int if_id = 1;
    NetlinkAttr(msg, 2, &if_id, sizeof(if_id));
    NetlinkDone(msg);  // close IFLA_INFO_DATA
    NetlinkDone(msg);  // close IFLA_LINKINFO
    const int err = NetlinkSend(msg, sock);
    if (err < 0) {
        NLLOG("add xfrm %s if_id=%d err=%d (%s)",
              name, if_id, err, ::strerror(errno));
    }
}

void NetlinkAddHsr(Nlmsg* msg, int sock, const char* name,
                   const char* slave1, const char* slave2)
{
    NetlinkAddDeviceImpl(msg, "hsr", name, /*up=*/false);
    NetlinkNest(msg, IFLA_INFO_DATA);
    int ifindex1 = static_cast<int>(::if_nametoindex(slave1));
    NetlinkAttr(msg, IFLA_HSR_SLAVE1, &ifindex1, sizeof(ifindex1));
    int ifindex2 = static_cast<int>(::if_nametoindex(slave2));
    NetlinkAttr(msg, IFLA_HSR_SLAVE2, &ifindex2, sizeof(ifindex2));
    NetlinkDone(msg);  // close IFLA_INFO_DATA
    NetlinkDone(msg);  // close IFLA_LINKINFO
    const int err = NetlinkSend(msg, sock);
    if (err < 0) {
        NLLOG("add hsr %s slave1=%s slave2=%s err=%d (%s)",
              name, slave1, slave2, err, ::strerror(errno));
    }
}

void NetlinkAddLinked(Nlmsg* msg, int sock,
                      const char* type, const char* name, const char* link)
{
    NetlinkAddDeviceImpl(msg, type, name, /*up=*/false);
    NetlinkDone(msg);  // close IFLA_LINKINFO (no INFO_DATA)
    int ifindex = static_cast<int>(::if_nametoindex(link));
    NetlinkAttr(msg, IFLA_LINK, &ifindex, sizeof(ifindex));
    const int err = NetlinkSend(msg, sock);
    if (err < 0) {
        NLLOG("add linked %s type=%s link=%s err=%d (%s)",
              name, type, link, err, ::strerror(errno));
    }
}

void NetlinkAddVlan(Nlmsg* msg, int sock, const char* name, const char* link,
                    std::uint16_t id, std::uint16_t proto)
{
    NetlinkAddDeviceImpl(msg, "vlan", name, /*up=*/false);
    NetlinkNest(msg, IFLA_INFO_DATA);
    NetlinkAttr(msg, IFLA_VLAN_ID, &id, sizeof(id));
    NetlinkAttr(msg, IFLA_VLAN_PROTOCOL, &proto, sizeof(proto));
    NetlinkDone(msg);  // close IFLA_INFO_DATA
    NetlinkDone(msg);  // close IFLA_LINKINFO
    int ifindex = static_cast<int>(::if_nametoindex(link));
    NetlinkAttr(msg, IFLA_LINK, &ifindex, sizeof(ifindex));
    const int err = NetlinkSend(msg, sock);
    if (err < 0) {
        NLLOG("add vlan %s link=%s id=%u err=%d (%s)",
              name, link, (unsigned)id, err, ::strerror(errno));
    }
}

void NetlinkAddMacvlan(Nlmsg* msg, int sock, const char* name, const char* link)
{
    NetlinkAddDeviceImpl(msg, "macvlan", name, /*up=*/false);
    NetlinkNest(msg, IFLA_INFO_DATA);
    std::uint32_t mode = MACVLAN_MODE_BRIDGE;
    NetlinkAttr(msg, IFLA_MACVLAN_MODE, &mode, sizeof(mode));
    NetlinkDone(msg);  // close IFLA_INFO_DATA
    NetlinkDone(msg);  // close IFLA_LINKINFO
    int ifindex = static_cast<int>(::if_nametoindex(link));
    NetlinkAttr(msg, IFLA_LINK, &ifindex, sizeof(ifindex));
    const int err = NetlinkSend(msg, sock);
    if (err < 0) {
        NLLOG("add macvlan %s link=%s mode=%u err=%d (%s)",
              name, link, (unsigned)mode, err, ::strerror(errno));
    }
}

void NetlinkAddGeneve(Nlmsg* msg, int sock, const char* name,
                      std::uint32_t vni,
                      const struct in_addr* addr4,
                      const struct in6_addr* addr6)
{
    NetlinkAddDeviceImpl(msg, "geneve", name, /*up=*/false);
    NetlinkNest(msg, IFLA_INFO_DATA);
    NetlinkAttr(msg, IFLA_GENEVE_ID, &vni, sizeof(vni));
    if (addr4) {
        NetlinkAttr(msg, IFLA_GENEVE_REMOTE, addr4, sizeof(*addr4));
    }
    if (addr6) {
        NetlinkAttr(msg, IFLA_GENEVE_REMOTE6, addr6, sizeof(*addr6));
    }
    NetlinkDone(msg);  // close IFLA_INFO_DATA
    NetlinkDone(msg);  // close IFLA_LINKINFO
    const int err = NetlinkSend(msg, sock);
    if (err < 0) {
        NLLOG("add geneve %s vni=%u err=%d (%s)",
              name, (unsigned)vni, err, ::strerror(errno));
    }
}

void NetlinkAddIpvlan(Nlmsg* msg, int sock, const char* name, const char* link,
                      std::uint16_t mode, std::uint16_t flags)
{
    // upstream redefines (common_linux.h:521-524):
    //   IFLA_IPVLAN_FLAGS  = 2
    //   IPVLAN_MODE_L3S    = 2 (already in header)
    //   IPVLAN_F_VEPA      = 2
    // 这些不影响 builder layout,caller 传值即可。
    constexpr int kIflaIpvlanFlags = 2;
    NetlinkAddDeviceImpl(msg, "ipvlan", name, /*up=*/false);
    NetlinkNest(msg, IFLA_INFO_DATA);
    NetlinkAttr(msg, IFLA_IPVLAN_MODE, &mode, sizeof(mode));
    NetlinkAttr(msg, kIflaIpvlanFlags, &flags, sizeof(flags));
    NetlinkDone(msg);  // close IFLA_INFO_DATA
    NetlinkDone(msg);  // close IFLA_LINKINFO
    int ifindex = static_cast<int>(::if_nametoindex(link));
    NetlinkAttr(msg, IFLA_LINK, &ifindex, sizeof(ifindex));
    const int err = NetlinkSend(msg, sock);
    if (err < 0) {
        NLLOG("add ipvlan %s link=%s mode=%u err=%d (%s)",
              name, link, (unsigned)mode, err, ::strerror(errno));
    }
}

} // namespace refuzz::worker::sandbox::device_init

// Netlink shared builders — 端口 syzkaller `executor/common_linux.h` 378-624 行
// 的 builder 集:`netlink_device_change` / `netlink_add_addr{,4,6}` /
// `netlink_add_neigh` + RTM_NEWLINK 系列 `netlink_add_device{,_impl}` /
// `netlink_add_veth` / `netlink_add_xfrm` / `netlink_add_hsr` / `netlink_add_linked` /
// `netlink_add_vlan` / `netlink_add_macvlan` / `netlink_add_geneve` /
// `netlink_add_ipvlan`。
//
// 范围:跨 D3-D5,D7 共享的 RTM_NEWLINK / RTM_NEWADDR / RTM_NEWNEIGH builder
// 高层封装,基于 netlink_helpers.hpp 的 NetlinkInit/Attr/Send foundation。
//
// 设计:
//   - 与上游同 signature(int sock 显式 caller-owned)
//   - Nlmsg* 仍 caller-owned(D2 决策)
//   - LOG-and-continue:`fail()`/`debug()` 同语义,失败 LOG 不 abort
//   - 全 builder 共用 NUM_TX/RX_QUEUES = 2 (= upstream `queue_count`)
//
// 调用 ctx:device_init / initialize_* init-time;调用方 ensure CAP_NET_ADMIN。

#pragma once

#include <cstdint>

// 不在 header 内 include <linux/in.h> / <netinet/in.h> —— 二者 IPPROTO_*
// enum 重定义冲突。caller .cpp 已 include 自己需要的(typically arpa/inet.h
// 走 netinet/in.h 路径),这里只声明结构体名即可,definition 在 caller 端
// 提供。
struct in_addr;
struct in6_addr;

#include "worker/sandbox/device_init/netlink_helpers.hpp"

namespace refuzz::worker::sandbox::device_init {

// === RTM_NEWLINK: 改 interface 属性 ============================
//
// 与上游 `netlink_device_change` byte-equal:
//   - `up` true → 加 IFF_UP flag (ifi_flags + ifi_change)
//   - `master` 非 null → 加 IFLA_MASTER (用 if_nametoindex 解析)
//   - `mac` / `macsize` 非 0 → 加 IFLA_ADDRESS
//   - `new_name` 非 null → 加 IFLA_IFNAME (即 rename)
//
// 失败仅 LOG(等价 upstream `debug()`)。
void NetlinkDeviceChange(Nlmsg* msg, int sock, const char* name, bool up,
                         const char* master, const void* mac, int macsize,
                         const char* new_name);

// === RTM_NEWADDR: 给 interface 加 IPv4/v6 地址 ==================
//
// `addrsize == 4` → AF_INET, prefixlen 24
// `addrsize == 16`→ AF_INET6, prefixlen 120
//
// 返回 NetlinkSend rc(0 / -errno / -1)。
int NetlinkAddAddr(Nlmsg* msg, int sock, const char* dev,
                   const void* addr, int addrsize);

// IPv4 wrap:`addr` 是 "172.20.20.170" 字串,inet_pton 转结构体后 call 上面。
// 失败 LOG。
void NetlinkAddAddr4(Nlmsg* msg, int sock, const char* dev, const char* addr);

// IPv6 wrap:同上,addr 是 "fe80::aa" 字串。
void NetlinkAddAddr6(Nlmsg* msg, int sock, const char* dev, const char* addr);

// === RTM_NEWNEIGH: 静态 ARP / ND entry ==========================
//
// `addrsize` 4 → AF_INET, 16 → AF_INET6;`macsize` 通常 ETH_ALEN=6。
// state = NUD_PERMANENT。失败 LOG。
void NetlinkAddNeigh(Nlmsg* msg, int sock, const char* name,
                     const void* addr, int addrsize,
                     const void* mac, int macsize);

// === RTM_NEWLINK device builders (D4 set, used by initialize_netdevices) ===

// 创建无父 / 无 peer 的简单虚拟设备:bridge / bond / team / dummy / nlmon /
// vcan / vxcan(name 可 null,kernel 自动取名)/ batadv / wireguard ...
// 失败 LOG。对齐 common_linux.h:398。
void NetlinkAddDevice(Nlmsg* msg, int sock, const char* type, const char* name);

// veth pair:创建 `name` ↔ `peer` 两 veth 端点。两边 NUM_TX/RX_QUEUES=kQueueCount。
// 对齐 common_linux.h:409。
void NetlinkAddVeth(Nlmsg* msg, int sock, const char* name, const char* peer);

// xfrm interface:type="xfrm" + IFLA_XFRM_IF_ID=1 + up。
// 对齐 common_linux.h:428。
void NetlinkAddXfrm(Nlmsg* msg, int sock, const char* name);

// HSR (High-availability Seamless Redundancy):type="hsr" + slave1+slave2 ifindex。
// 对齐 common_linux.h:443。
void NetlinkAddHsr(Nlmsg* msg, int sock, const char* name,
                   const char* slave1, const char* slave2);

// 基于 `link` 的派生设备(macvtap / macsec / virt_wifi 等):
// 加 IFLA_INFO_KIND=type + IFLA_LINK=if_nametoindex(link)。
// 对齐 common_linux.h:460。
void NetlinkAddLinked(Nlmsg* msg, int sock,
                      const char* type, const char* name, const char* link);

// VLAN device:link=父 device,id=tag,proto=htons(ETH_P_8021Q) 或 ETH_P_8021AD。
// 对齐 common_linux.h:472。
void NetlinkAddVlan(Nlmsg* msg, int sock, const char* name, const char* link,
                    std::uint16_t id, std::uint16_t proto);

// MACVLAN device (mode=BRIDGE):link=父 device。
// 对齐 common_linux.h:488。
void NetlinkAddMacvlan(Nlmsg* msg, int sock, const char* name, const char* link);

// GENEVE tunnel:vni=virtual network id;addr4 或 addr6 之一非 null (remote endpoint)。
// 对齐 common_linux.h:504。
void NetlinkAddGeneve(Nlmsg* msg, int sock, const char* name,
                      std::uint32_t vni,
                      const struct in_addr* addr4,
                      const struct in6_addr* addr6);

// IPVLAN device:link=父 device,mode IPVLAN_MODE_L2/L3/L3S,
// flags IPVLAN_F_VEPA(2)等。对齐 common_linux.h:526。
void NetlinkAddIpvlan(Nlmsg* msg, int sock, const char* name, const char* link,
                      std::uint16_t mode, std::uint16_t flags);

} // namespace refuzz::worker::sandbox::device_init

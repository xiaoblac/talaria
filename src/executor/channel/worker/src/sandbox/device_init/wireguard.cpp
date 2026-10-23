// NetlinkWireguardSetup — 端口 syzkaller `netlink_wireguard_setup`
// (common_linux.h:1251-1453)。
//
// 给 wg0/wg1/wg2 三个已 NetlinkAddDevice("wireguard", ...) 创建的接口注入
// pre-shared keys、private/public keys、peers + endpoints + AllowedIPs。
// 三个 wg 全互为 peer 一组测试 topology(每个看见其它两个为 peer,allowed
// 一半 v4 + 一半 v6 IP 空间)。 keys / ports / IPs 与上游 byte-equal,
// syscall description 依赖这套常量。
//
// Topology(byte-equal upstream):
//   wg0 (port 20001, priv_a)
//     peer_b at loopback:20002  v4   v6 AllowedIP: first_half (0.0.0.0/1 + ::/1)
//     peer_c at [::1]:20003     v6   v4/v6 AllowedIP: second_half (128.0.0.0/1 + 8000::/1)
//   wg1 (port 20002, priv_b)
//     peer_a at [::1]:20001     v6   v4/v6 AllowedIP: first_half
//     peer_c at loopback:20003  v4   v4/v6 AllowedIP: second_half
//   wg2 (port 20003, priv_c)
//     peer_a at [::1]:20001     v6   v4/v6 AllowedIP: first_half
//     peer_b at loopback:20002  v4   v4/v6 AllowedIP: second_half
//
// 失败 LOG(对齐 upstream `debug()`),不影响其它 init。

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "worker/sandbox/device_init/device_init.hpp"
#include "worker/sandbox/device_init/netlink_helpers.hpp"

#include "worker/log/log_macros.hpp"

#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <netinet/in.h>

#define WGLOG(fmt, ...) \
    ::refuzz::worker::log::WorkerLog("[device_init] wireguard: " fmt "\n", ##__VA_ARGS__)

namespace refuzz::worker::sandbox::device_init {

namespace {

constexpr const char* kWgGenlName = "wireguard";

// upstream enum wg_cmd
constexpr int kWgCmdSetDevice = 1;
// upstream enum wgdevice_attribute
constexpr int kWgDeviceA_Ifname     = 2;
constexpr int kWgDeviceA_PrivateKey = 3;
constexpr int kWgDeviceA_ListenPort = 6;
constexpr int kWgDeviceA_Peers      = 8;
// upstream enum wgpeer_attribute
constexpr int kWgPeerA_PublicKey                = 1;
constexpr int kWgPeerA_Endpoint                 = 3;
constexpr int kWgPeerA_PersistentKeepalive      = 4;
constexpr int kWgPeerA_AllowedIPs               = 9;
// upstream enum wgallowedip_attribute
constexpr int kWgAllowedIpA_Family   = 1;
constexpr int kWgAllowedIpA_IPAddr   = 2;
constexpr int kWgAllowedIpA_CIDRMask = 3;

// upstream key tables (byte-equal)。32 字节 nul-tolerant binary。
constexpr unsigned char kPrivateA[32] = {
    0xa0,0x5c,0xa8,0x4f,0x6c,0x9c,0x8e,0x38,0x53,0xe2,0xfd,0x7a,0x70,0xae,0x0f,0xb2,
    0x0f,0xa1,0x52,0x60,0x0c,0xb0,0x08,0x45,0x17,0x4f,0x08,0x07,0x6f,0x8d,0x78,0x43};
constexpr unsigned char kPrivateB[32] = {
    0xb0,0x80,0x73,0xe8,0xd4,0x4e,0x91,0xe3,0xda,0x92,0x2c,0x22,0x43,0x82,0x44,0xbb,
    0x88,0x5c,0x69,0xe2,0x69,0xc8,0xe9,0xd8,0x35,0xb1,0x14,0x29,0x3a,0x4d,0xdc,0x6e};
constexpr unsigned char kPrivateC[32] = {
    0xa0,0xcb,0x87,0x9a,0x47,0xf5,0xbc,0x64,0x4c,0x0e,0x69,0x3f,0xa6,0xd0,0x31,0xc7,
    0x4a,0x15,0x53,0xb6,0xe9,0x01,0xb9,0xff,0x2f,0x51,0x8c,0x78,0x04,0x2f,0xb5,0x42};
constexpr unsigned char kPublicA[32] = {
    0x97,0x5c,0x9d,0x81,0xc9,0x83,0xc8,0x20,0x9e,0xe7,0x81,0x25,0x4b,0x89,0x9f,0x8e,
    0xd9,0x25,0xae,0x9f,0x09,0x23,0xc2,0x3c,0x62,0xf5,0x3c,0x57,0xcd,0xbf,0x69,0x1c};
constexpr unsigned char kPublicB[32] = {
    0xd1,0x73,0x28,0x99,0xf6,0x11,0xcd,0x89,0x94,0x03,0x4d,0x7f,0x41,0x3d,0xc9,0x57,
    0x63,0x0e,0x54,0x93,0xc2,0x85,0xac,0xa4,0x00,0x65,0xcb,0x63,0x11,0xbe,0x69,0x6b};
constexpr unsigned char kPublicC[32] = {
    0xf4,0x4d,0xa3,0x67,0xa8,0x8e,0xe6,0x56,0x4f,0x02,0x02,0x11,0x45,0x67,0x27,0x08,
    0x2f,0x5c,0xeb,0xee,0x8b,0x1b,0xf5,0xeb,0x73,0x37,0x34,0x1b,0x45,0x9b,0x39,0x22};

constexpr std::uint16_t kListenA = 20001;
constexpr std::uint16_t kListenB = 20002;
constexpr std::uint16_t kListenC = 20003;
constexpr std::uint16_t kPersistentKeepalives[6] = {1, 3, 7, 9, 14, 19};

// 加一个 AllowedIP entry(嵌套 in WGPEER_A_ALLOWEDIPS)。 caller 已 NetlinkNest
// 过 WGPEER_A_ALLOWEDIPS;本 helper 内部 nest/done 单条 entry。
void EmitAllowedIp(Nlmsg* msg, std::uint16_t family,
                   const void* addr, int addrlen, std::uint8_t cidr)
{
    NetlinkNest(msg, NLA_F_NESTED | 0);
    NetlinkAttr(msg, kWgAllowedIpA_Family, &family, sizeof(family));
    NetlinkAttr(msg, kWgAllowedIpA_IPAddr, addr, addrlen);
    NetlinkAttr(msg, kWgAllowedIpA_CIDRMask, &cidr, sizeof(cidr));
    NetlinkDone(msg);
}

// 加一个 peer:public_key + endpoint + persistent_keepalive_interval +
// AllowedIPs (v4_addr/1 + v6_addr/1)。
void EmitPeer(Nlmsg* msg, const unsigned char* public_key,
              const void* endpoint, int endpoint_len,
              std::uint16_t keepalive,
              const struct in_addr& v4_addr,
              const struct in6_addr& v6_addr)
{
    constexpr std::uint16_t kAfInet  = AF_INET;
    constexpr std::uint16_t kAfInet6 = AF_INET6;
    constexpr std::uint8_t  kHalfCidr = 1;

    NetlinkNest(msg, NLA_F_NESTED | 0);  // open peer
    NetlinkAttr(msg, kWgPeerA_PublicKey, public_key, 32);
    NetlinkAttr(msg, kWgPeerA_Endpoint, endpoint, endpoint_len);
    NetlinkAttr(msg, kWgPeerA_PersistentKeepalive, &keepalive, sizeof(keepalive));

    NetlinkNest(msg, NLA_F_NESTED | kWgPeerA_AllowedIPs);
    EmitAllowedIp(msg, kAfInet,  &v4_addr, sizeof(v4_addr), kHalfCidr);
    EmitAllowedIp(msg, kAfInet6, &v6_addr, sizeof(v6_addr), kHalfCidr);
    NetlinkDone(msg);  // close WGPEER_A_ALLOWEDIPS
    NetlinkDone(msg);  // close peer
}

void SetDeviceWg(Nlmsg* msg, int sock, int family_id,
                 const char* ifname,
                 const unsigned char* private_key,
                 std::uint16_t listen_port,
                 // peer 1
                 const unsigned char* peer1_pub,
                 const void* peer1_endpoint, int peer1_endpoint_len,
                 std::uint16_t peer1_keepalive,
                 const struct in_addr& peer1_v4, const struct in6_addr& peer1_v6,
                 // peer 2
                 const unsigned char* peer2_pub,
                 const void* peer2_endpoint, int peer2_endpoint_len,
                 std::uint16_t peer2_keepalive,
                 const struct in_addr& peer2_v4, const struct in6_addr& peer2_v6)
{
    struct ::genlmsghdr genlhdr;
    ::memset(&genlhdr, 0, sizeof(genlhdr));
    genlhdr.cmd = kWgCmdSetDevice;
    genlhdr.version = 1;

    NetlinkInit(msg, family_id, 0, &genlhdr, sizeof(genlhdr));
    NetlinkAttr(msg, kWgDeviceA_Ifname, ifname,
                static_cast<int>(::strlen(ifname) + 1));
    NetlinkAttr(msg, kWgDeviceA_PrivateKey, private_key, 32);
    NetlinkAttr(msg, kWgDeviceA_ListenPort, &listen_port, sizeof(listen_port));

    NetlinkNest(msg, NLA_F_NESTED | kWgDeviceA_Peers);
    EmitPeer(msg, peer1_pub, peer1_endpoint, peer1_endpoint_len,
             peer1_keepalive, peer1_v4, peer1_v6);
    EmitPeer(msg, peer2_pub, peer2_endpoint, peer2_endpoint_len,
             peer2_keepalive, peer2_v4, peer2_v6);
    NetlinkDone(msg);  // close WGDEVICE_A_PEERS

    const int err = NetlinkSend(msg, sock);
    if (err < 0) {
        WGLOG("setup %s err=%d (%s)", ifname, err, ::strerror(errno));
    }
}

} // namespace

void NetlinkWireguardSetup()
{
    const int sock = ::socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if (sock < 0) {
        WGLOG("socket(NETLINK_GENERIC) errno=%d (%s)", errno, ::strerror(errno));
        return;
    }

    Nlmsg msg{};
    const int id = NetlinkQueryFamilyId(&msg, sock, kWgGenlName, /*dofail=*/true);
    if (id < 0) {
        WGLOG("query family '%s' fail — CONFIG_WIREGUARD=n? 跳过", kWgGenlName);
        ::close(sock);
        return;
    }

    // 准备 endpoints (与上游 sockaddr 同 byte-equal)。
    struct ::sockaddr_in  ep_b_v4{};
    ep_b_v4.sin_family = AF_INET;
    ep_b_v4.sin_port = ::htons(kListenB);
    ep_b_v4.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);

    struct ::sockaddr_in  ep_c_v4{};
    ep_c_v4.sin_family = AF_INET;
    ep_c_v4.sin_port = ::htons(kListenC);
    ep_c_v4.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);

    struct ::sockaddr_in6 ep_a_v6{};
    ep_a_v6.sin6_family = AF_INET6;
    ep_a_v6.sin6_port = ::htons(kListenA);
    ep_a_v6.sin6_addr = in6addr_loopback;

    struct ::sockaddr_in6 ep_c_v6{};
    ep_c_v6.sin6_family = AF_INET6;
    ep_c_v6.sin6_port = ::htons(kListenC);
    ep_c_v6.sin6_addr = in6addr_loopback;

    // AllowedIP "halves" (与上游 byte-equal):
    //   first_half_v4  = 0.0.0.0 /1
    //   second_half_v4 = 128.0.0.0 /1
    //   first_half_v6  = ::      /1
    //   second_half_v6 = 8000::  /1
    struct ::in_addr first_v4 {};
    struct ::in_addr second_v4 {};
    second_v4.s_addr = ::htonl(static_cast<std::uint32_t>(128) << 24);
    struct ::in6_addr first_v6 {};
    struct ::in6_addr second_v6 {};
    second_v6.s6_addr[0] = 0x80;

    // wg0: peer_b (v4 endpoint, first_half) + peer_c (v6 endpoint, second_half)
    SetDeviceWg(&msg, sock, id, "wg0", kPrivateA, kListenA,
                kPublicB, &ep_b_v4, sizeof(ep_b_v4),
                kPersistentKeepalives[0], first_v4, first_v6,
                kPublicC, &ep_c_v6, sizeof(ep_c_v6),
                kPersistentKeepalives[1], second_v4, second_v6);

    // wg1: peer_a (v6 endpoint, first_half) + peer_c (v4 endpoint, second_half)
    SetDeviceWg(&msg, sock, id, "wg1", kPrivateB, kListenB,
                kPublicA, &ep_a_v6, sizeof(ep_a_v6),
                kPersistentKeepalives[2], first_v4, first_v6,
                kPublicC, &ep_c_v4, sizeof(ep_c_v4),
                kPersistentKeepalives[3], second_v4, second_v6);

    // wg2: peer_a (v6 endpoint, first_half) + peer_b (v4 endpoint, second_half)
    SetDeviceWg(&msg, sock, id, "wg2", kPrivateC, kListenC,
                kPublicA, &ep_a_v6, sizeof(ep_a_v6),
                kPersistentKeepalives[4], first_v4, first_v6,
                kPublicB, &ep_b_v4, sizeof(ep_b_v4),
                kPersistentKeepalives[5], second_v4, second_v6);

    ::close(sock);
}

} // namespace refuzz::worker::sandbox::device_init

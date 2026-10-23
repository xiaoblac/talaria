// InitializeWifiDevices — 端口 syzkaller `initialize_wifi_devices`
// (executor/common_linux.h:1100-1167) + 周边 wifi helper 全集
// (set_interface_state / nl80211_set_interface / nl80211_join_ibss /
// get_ifla_operstate / await_ifla_operstate / nl80211_setup_ibss_interface /
// hwsim80211_create_device,common_linux.h:885-1098)。
//
// 创建 2 个 mac80211_hwsim 虚拟 radio,自动生成 wlan0 / wlan1,
// 各自 join 同一个 IBSS network。给 syz_80211_inject_frame /
// syz_80211_join_ibss 等 fuzz pseudo 一个 ready-to-use wireless stack。
//
// kernel 要求:CONFIG_MAC80211_HWSIM + CONFIG_CFG80211 + CONFIG_NL80211；
// 缺失或初始化失败时拒绝 domain startup。
//
// 调用 ctx:ApplyNone 内 InitializeNetdevices 之后,SandboxCommonMountTmpfs
// 之前。Sandbox 已 DropSyzkallerCaps,CAP_NET_ADMIN / CAP_SYS_ADMIN 仍保留。

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "worker/sandbox/device_init/device_init.hpp"
#include "worker/sandbox/device_init/netlink_helpers.hpp"

#include "worker/log/log_macros.hpp"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <time.h>

#include <net/if.h>            // ifreq, IFF_UP, SIOCGIFFLAGS, SIOCSIFFLAGS
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <linux/nl80211.h>
#include <linux/rfkill.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>    // ETH_ALEN

#define WIFI_LOG(fmt, ...) \
    ::refuzz::worker::log::WorkerLog("[device_init] wifi: " fmt "\n", ##__VA_ARGS__)

namespace refuzz::worker::sandbox::device_init {

namespace {

// upstream common_linux.h:887-899 byte-equal。
constexpr int     kWifiInitialDeviceCount = 2;
constexpr uint8_t kWifiMacBase[6]    = {0x08, 0x02, 0x11, 0x00, 0x00, 0x00};
constexpr uint8_t kWifiIbssBssid[6]  = {0x50, 0x50, 0x50, 0x50, 0x50, 0x50};
constexpr uint8_t kWifiIbssSsid[6]   = {0x10, 0x10, 0x10, 0x10, 0x10, 0x10};
constexpr int     kWifiDefaultFrequency = 2412;

// upstream common_linux.h:902-906 byte-equal — mac80211_hwsim 私有 cmd/attr 号。
constexpr int kHwsimCmdNewRadio       = 4;
constexpr int kHwsimAttrSupportP2pDev = 14;
constexpr int kHwsimAttrPermAddr      = 22;

// upstream common_linux.h:920 — IFF_OPER_UP value (linux/if.h 与 net/if.h 冲突,
// upstream 也 inline 这个常量)。
constexpr int kIfOperUp = 6;

// upstream `struct join_ibss_props`。 PascalCase + uint8_t 而非 uint8。
struct JoinIbssProps {
    int wiphy_freq;
    bool wiphy_freq_fixed;
    const uint8_t* mac;
    const uint8_t* ssid;
    int ssid_len;
};

// 端口 set_interface_state (common_linux.h:931)。ioctl SIOCGIFFLAGS/SIOCSIFFLAGS。
int SetInterfaceState(const char* interface_name, int on)
{
    const int sock = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        WIFI_LOG("set_intf_state(%s) socket errno=%d", interface_name, errno);
        return -1;
    }
    struct ::ifreq ifr;
    ::memset(&ifr, 0, sizeof(ifr));
    ::strncpy(ifr.ifr_name, interface_name, IFNAMSIZ - 1);
    if (::ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        WIFI_LOG("set_intf_state(%s) SIOCGIFFLAGS errno=%d",
                 interface_name, errno);
        ::close(sock);
        return -1;
    }
    if (on) ifr.ifr_flags |= IFF_UP;
    else    ifr.ifr_flags &= ~IFF_UP;
    const int ret = ::ioctl(sock, SIOCSIFFLAGS, &ifr);
    ::close(sock);
    if (ret < 0) {
        WIFI_LOG("set_intf_state(%s) SIOCSIFFLAGS errno=%d",
                 interface_name, errno);
        return -1;
    }
    return 0;
}

// 端口 nl80211_set_interface (common_linux.h:963)。
int Nl80211SetInterface(Nlmsg* msg, int sock, int nl80211_family,
                       uint32_t ifindex, uint32_t iftype, bool dofail)
{
    struct ::genlmsghdr genlhdr;
    ::memset(&genlhdr, 0, sizeof(genlhdr));
    genlhdr.cmd = NL80211_CMD_SET_INTERFACE;
    NetlinkInit(msg, nl80211_family, 0, &genlhdr, sizeof(genlhdr));
    NetlinkAttr(msg, NL80211_ATTR_IFINDEX, &ifindex, sizeof(ifindex));
    NetlinkAttr(msg, NL80211_ATTR_IFTYPE,  &iftype,  sizeof(iftype));
    const int err = NetlinkSendExt(msg, sock, 0, nullptr, dofail);
    if (err < 0) {
        WIFI_LOG("nl80211_set_interface(if=%u type=%u) err=%d (%s)",
                 ifindex, iftype, err, ::strerror(errno));
    }
    return err;
}

// 端口 nl80211_join_ibss (common_linux.h:980)。
int Nl80211JoinIbss(Nlmsg* msg, int sock, int nl80211_family,
                   uint32_t ifindex, const JoinIbssProps* props, bool dofail)
{
    struct ::genlmsghdr genlhdr;
    ::memset(&genlhdr, 0, sizeof(genlhdr));
    genlhdr.cmd = NL80211_CMD_JOIN_IBSS;
    NetlinkInit(msg, nl80211_family, 0, &genlhdr, sizeof(genlhdr));
    NetlinkAttr(msg, NL80211_ATTR_IFINDEX,    &ifindex, sizeof(ifindex));
    NetlinkAttr(msg, NL80211_ATTR_SSID,       props->ssid, props->ssid_len);
    NetlinkAttr(msg, NL80211_ATTR_WIPHY_FREQ, &props->wiphy_freq,
                sizeof(props->wiphy_freq));
    if (props->mac) {
        NetlinkAttr(msg, NL80211_ATTR_MAC, props->mac, ETH_ALEN);
    }
    if (props->wiphy_freq_fixed) {
        NetlinkAttr(msg, NL80211_ATTR_FREQ_FIXED, nullptr, 0);
    }
    const int err = NetlinkSendExt(msg, sock, 0, nullptr, dofail);
    if (err < 0) {
        WIFI_LOG("nl80211_join_ibss(if=%u) err=%d (%s)",
                 ifindex, err, ::strerror(errno));
    }
    return err;
}

// 端口 get_ifla_operstate (common_linux.h:1002)。
int GetIflaOperstate(Nlmsg* msg, int ifindex, bool dofail)
{
    struct ::ifinfomsg info;
    ::memset(&info, 0, sizeof(info));
    info.ifi_family = AF_UNSPEC;
    info.ifi_index = ifindex;

    const int sock = ::socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) {
        WIFI_LOG("get_operstate socket errno=%d", errno);
        return -1;
    }
    NetlinkInit(msg, RTM_GETLINK, 0, &info, sizeof(info));
    int n = 0;
    const int err = NetlinkSendExt(msg, sock, RTM_NEWLINK, &n, dofail);
    ::close(sock);
    if (err) {
        WIFI_LOG("get_operstate send_ext err=%d (%s)",
                 err, ::strerror(errno));
        return -1;
    }
    struct ::rtattr* attr = IFLA_RTA(NLMSG_DATA(msg->buf));
    for (; RTA_OK(attr, n); attr = RTA_NEXT(attr, n)) {
        if (attr->rta_type == IFLA_OPERSTATE) {
            return *(reinterpret_cast<int32_t*>(RTA_DATA(attr)));
        }
    }
    return -1;
}

// 端口 await_ifla_operstate (common_linux.h:1034)。1 ms sleep loop。
// 与上游同 byte-equal — 无 timeout(只在 dofail=true 时回-1 + log)。
int AwaitIflaOperstate(Nlmsg* msg, const char* interface,
                      int operstate, bool dofail)
{
    const int ifindex = static_cast<int>(::if_nametoindex(interface));
    if (ifindex == 0) {
        WIFI_LOG("await_operstate(%s) if_nametoindex=0", interface);
        return -1;
    }
    struct ::timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = 1000 * 1000;  // 1 ms
    while (true) {
        ::nanosleep(&ts, nullptr);
        const int ret = GetIflaOperstate(msg, ifindex, dofail);
        if (ret < 0) {
            return ret;
        }
        if (ret == operstate) {
            return 0;
        }
    }
}

// 端口 nl80211_setup_ibss_interface (common_linux.h:1048)。
int Nl80211SetupIbssInterface(Nlmsg* msg, int sock, int nl80211_family_id,
                              const char* interface,
                              const JoinIbssProps* ibss_props, bool dofail)
{
    const uint32_t ifindex = ::if_nametoindex(interface);
    if (ifindex == 0) {
        WIFI_LOG("setup_ibss_intf(%s) if_nametoindex=0", interface);
        return -1;
    }
    int ret = Nl80211SetInterface(msg, sock, nl80211_family_id, ifindex,
                                  NL80211_IFTYPE_ADHOC, dofail);
    if (ret < 0) {
        WIFI_LOG("setup_ibss_intf(%s) set_interface ret=%d", interface, ret);
        return -1;
    }
    ret = SetInterfaceState(interface, 1);
    if (ret < 0) {
        WIFI_LOG("setup_ibss_intf(%s) set_state ret=%d", interface, ret);
        return -1;
    }
    ret = Nl80211JoinIbss(msg, sock, nl80211_family_id, ifindex,
                          ibss_props, dofail);
    if (ret < 0) {
        WIFI_LOG("setup_ibss_intf(%s) join_ibss ret=%d", interface, ret);
        return -1;
    }
    return 0;
}

// 端口 hwsim80211_create_device (common_linux.h:1085)。
int Hwsim80211CreateDevice(Nlmsg* msg, int sock, int hwsim_family,
                           const uint8_t mac_addr[ETH_ALEN])
{
    struct ::genlmsghdr genlhdr;
    ::memset(&genlhdr, 0, sizeof(genlhdr));
    genlhdr.cmd = kHwsimCmdNewRadio;
    NetlinkInit(msg, hwsim_family, 0, &genlhdr, sizeof(genlhdr));
    NetlinkAttr(msg, kHwsimAttrSupportP2pDev, nullptr, 0);
    NetlinkAttr(msg, kHwsimAttrPermAddr, mac_addr, ETH_ALEN);
    const int err = NetlinkSend(msg, sock);
    if (err < 0) {
        WIFI_LOG("hwsim_create_device err=%d (%s)", err, ::strerror(errno));
    }
    return err;
}

} // namespace

int InitializeWifiDevices()
{
    // === 解 rfkill block (全局 unblock) ===
    const int rfkill = ::open("/dev/rfkill", O_RDWR | O_CLOEXEC);
    if (rfkill < 0) {
        const int error_number = errno;
        WIFI_LOG("open(/dev/rfkill) errno=%d (%s)",
                 errno, ::strerror(errno));
        return -error_number;
    }
    struct ::rfkill_event event;
    ::memset(&event, 0, sizeof(event));
    event.type = RFKILL_TYPE_ALL;
    event.op = RFKILL_OP_CHANGE_ALL;
    const ssize_t rfkill_w = ::write(rfkill, &event, sizeof(event));
    if (rfkill_w != static_cast<ssize_t>(sizeof(event))) {
        const int error_number = rfkill_w < 0 ? errno : EIO;
        WIFI_LOG("write(/dev/rfkill) rc=%zd errno=%d",
                 rfkill_w, error_number);
        ::close(rfkill);
        return -error_number;
    }
    ::close(rfkill);

    // === query nl80211 + MAC80211_HWSIM family ids ===
    const int sock = ::socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if (sock < 0) {
        const int error_number = errno;
        WIFI_LOG("CRITICAL: socket(NETLINK_GENERIC) errno=%d", errno);
        return -error_number;
    }

    Nlmsg msg{};
    const int hwsim_family_id   = NetlinkQueryFamilyId(&msg, sock,
                                                       "MAC80211_HWSIM", true);
    const int nl80211_family_id = NetlinkQueryFamilyId(&msg, sock,
                                                       "nl80211", true);
    if (hwsim_family_id < 0 || nl80211_family_id < 0) {
        const int error_number = errno != 0 ? errno : ENOENT;
        WIFI_LOG("query family failed (hwsim_id=%d nl80211_id=%d)",
                 hwsim_family_id, nl80211_family_id);
        ::close(sock);
        return -error_number;
    }

    JoinIbssProps ibss_props{};
    ibss_props.wiphy_freq       = kWifiDefaultFrequency;
    ibss_props.wiphy_freq_fixed = true;
    ibss_props.mac              = kWifiIbssBssid;
    ibss_props.ssid             = kWifiIbssSsid;
    ibss_props.ssid_len         = sizeof(kWifiIbssSsid);

    // === 创建 hwsim radios + 配 wlan0/wlan1 进 IBSS ===
    uint8_t mac_addr[6];
    ::memcpy(mac_addr, kWifiMacBase, sizeof(mac_addr));
    for (int device_id = 0; device_id < kWifiInitialDeviceCount; device_id++) {
        mac_addr[5] = static_cast<uint8_t>(device_id);
        const int create_result =
            Hwsim80211CreateDevice(&msg, sock, hwsim_family_id, mac_addr);
        if (create_result < 0) {
            WIFI_LOG("hwsim_create_device(id=%d) failed", device_id);
            ::close(sock);
            return create_result;
        }
        char interface[8] = "wlan0";
        interface[4] = static_cast<char>('0' + device_id);
        if (Nl80211SetupIbssInterface(&msg, sock, nl80211_family_id,
                                      interface, &ibss_props, true) < 0) {
            const int error_number = errno != 0 ? errno : EIO;
            WIFI_LOG("setup_ibss(%s) failed", interface);
            ::close(sock);
            return -error_number;
        }
    }

    // === 等所有 wlan* 进 OPER_UP ===
    for (int device_id = 0; device_id < kWifiInitialDeviceCount; device_id++) {
        char interface[8] = "wlan0";
        interface[4] = static_cast<char>('0' + device_id);
        if (AwaitIflaOperstate(&msg, interface, kIfOperUp, true) < 0) {
            const int error_number = errno != 0 ? errno : EIO;
            WIFI_LOG("await_operstate(%s) failed", interface);
            ::close(sock);
            return -error_number;
        }
    }

    ::close(sock);

    WIFI_LOG("ready: %d hwsim radios joined IBSS (ssid/bssid bytewise = upstream)",
             kWifiInitialDeviceCount);
    return 0;
}

// upstream `syz_80211_join_ibss` fuzz-time path (common_linux.h:5654)。
// 复用 setup-time 同一组 file-static helper (Nl80211SetupIbssInterface 内含
// if_nametoindex / Nl80211SetInterface(ADHOC) / SetInterfaceState(UP) /
// Nl80211JoinIbss),保证 setup vs fuzz 行为完全一致。
//
// mode == kWifiJoinIbssNoScan (0) 时再 await_ifla_operstate(IF_OPER_UP),
// 对齐 upstream:5700。
int WifiJoinIbssFuzzTime(const char* iface,
                         const std::uint8_t* ssid,
                         int ssid_len,
                         int mode)
{
    constexpr int kJoinIbssNoScan = 0;
    constexpr int kJoinIbssBgNoScan = 2;

    if (iface == nullptr || ssid == nullptr || ssid_len < 0) {
        errno = EINVAL;
        return -1;
    }

    const int sock = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC,
                              NETLINK_GENERIC);
    if (sock < 0) {
        return -1;  // errno set by socket()
    }

    Nlmsg msg{};
    const int nl80211_family_id =
        NetlinkQueryFamilyId(&msg, sock, "nl80211", /*dofail=*/false);
    if (nl80211_family_id < 0) {
        const int e = errno;
        ::close(sock);
        errno = e;
        return -1;
    }

    JoinIbssProps ibss_props{};
    ibss_props.wiphy_freq       = kWifiDefaultFrequency;
    ibss_props.wiphy_freq_fixed = (mode == kJoinIbssNoScan || mode == kJoinIbssBgNoScan);
    ibss_props.mac              = kWifiIbssBssid;
    ibss_props.ssid             = ssid;
    ibss_props.ssid_len         = ssid_len;

    const int rc = Nl80211SetupIbssInterface(&msg, sock, nl80211_family_id,
                                              iface, &ibss_props,
                                              /*dofail=*/false);
    const int err_after_setup = errno;
    ::close(sock);
    if (rc < 0) {
        errno = err_after_setup;
        return -1;
    }

    if (mode == kJoinIbssNoScan) {
        Nlmsg wait_msg{};
        if (AwaitIflaOperstate(&wait_msg, iface, kIfOperUp, /*dofail=*/false) < 0) {
            return -1;  // errno preserved by AwaitIflaOperstate
        }
    }
    return 0;
}

} // namespace refuzz::worker::sandbox::device_init

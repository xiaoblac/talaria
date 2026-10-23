// InitializeVhci — 端口 syzkaller `initialize_vhci` + 周边 HCI helpers
// (executor/common_linux.h:2660-2923)。
//
// 起 mac80211_hwsim 之后 Bluetooth 同时需要 virtual HCI controller。
// 序列:
//   1) open AF_BLUETOOTH/SOCK_RAW HCI socket
//   2) open /dev/vhci → dup2 fd 202 (kVhciFd)
//   3) write vhci_vendor_pkt_request (协议 handshake)
//   4) read 回 vhci_pkt(可能先回 HCI_OP_RESET command,需 ack)
//   5) read 最终 vhci VENDOR_PKT 取 hci dev_id
//   6) pthread spawn event_thread:读 vhci 的 cmd,回 cmd_complete event
//   7) ioctl HCIDEVUP (kernel 内部 issue 一连串 init commands,event_thread 回)
//   8) ioctl HCISETSCAN(page scan)
//   9) 推送 fake BR/EDR conn_request → conn_complete → remote_features
//   10) 推送 fake LE conn_complete
//   11) event_thread exit(由 WRITE_SCAN_ENABLE 触发 return true)→ pthread_join
//
// 注意 upstream 的 initialize_vhci 调用顺序是:**进 sandbox_common 之前 / fork
// 之后** —— see do_sandbox_none()。 reFuzz ApplyNone 序列里要插在 SandboxCommon
// 之前还是之后?上游是之前。但 reFuzz SandboxCommon 做了 PDEATHSIG / rlimit /
// unshare(NEWNS|NEWIPC|...)/ mount priv,vhci open 这些都不冲突。
// 决策:为 byte-equal,放 SandboxCommon 之前。
//
// kernel 要求 CONFIG_BT + CONFIG_BT_HCIVHCI；缺失或初始化失败时拒绝
// domain startup。

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "worker/sandbox/device_init/device_init.hpp"

#include "worker/log/log_macros.hpp"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include <linux/rfkill.h>

// Bluetooth headers — hand-roll 最小 ABI 子集而不依赖 libbluetooth-dev,
// 保 cross-distro build。结构 layout / 常量值与 BlueZ userspace header
// (<bluetooth/hci.h>) byte-equal — Bluetooth Core Specification + Linux
// kernel ABI 是稳定的。

#define VHCI_LOG(fmt, ...) \
    ::refuzz::worker::log::WorkerLog("[device_init] vhci: " fmt "\n", ##__VA_ARGS__)

namespace refuzz::worker::sandbox::device_init {

namespace {

// === bluetooth socket ABI ============================================
constexpr int kAfBluetooth = 31;   // upstream AF_BLUETOOTH (Linux PF_BLUETOOTH)
constexpr int kBtprotoHci  = 1;    // upstream BTPROTO_HCI

// === HCI packet types ================================================
constexpr uint8_t kHciCommandPkt = 0x01;
constexpr uint8_t kHciEventPkt   = 0x04;
constexpr uint8_t kHciVendorPkt  = 0xff;

// === HCI opcodes (subset used here) ==================================
// 来自 Bluetooth Core Spec / drivers/bluetooth/* kernel ABI。
constexpr uint16_t kHciOpReset             = 0x0c03;
constexpr uint16_t kHciOpWriteScanEnable   = 0x0c1a;
constexpr uint16_t kHciOpReadBdAddr        = 0x1009;
constexpr uint16_t kHciOpReadBufferSize    = 0x1005;

// === HCI event codes (subset) ========================================
constexpr uint8_t kHciEvConnComplete   = 0x03;
constexpr uint8_t kHciEvConnRequest    = 0x04;
constexpr uint8_t kHciEvRemoteFeatures = 0x0b;
constexpr uint8_t kHciEvCmdComplete    = 0x0e;
constexpr uint8_t kHciEvLeMeta         = 0x3e;
constexpr uint8_t kHciEvLeConnComplete = 0x01;  // sub-event under LE_META

// === HCI link types / scan / role ====================================
constexpr uint8_t kAclLink  = 0x01;
constexpr uint8_t kScanPage = 0x02;

// === HCI ioctls ======================================================
#ifndef HCIDEVUP
#define HCIDEVUP   _IOW('H', 201, int)
#endif
// [D12 vhci re-entry fix] 防御性 cleanup 用 — kernel ABI
// include/net/bluetooth/hci_sock.h:201-204。HCIDEVDOWN 把 stale hci0 拉低,
// kernel 立即停往它发 HCI 命令,解 stdio per-program-restart 模式下第二次
// InitializeVhci 撞 "Bluetooth: hci0: command tx timeout" 风暴的死局。
#ifndef HCIDEVDOWN
#define HCIDEVDOWN _IOW('H', 202, int)
#endif
#ifndef HCISETSCAN
#define HCISETSCAN _IOW('H', 221, int)
#endif

// upstream common_linux.h:2807-2809
constexpr uint16_t kHciHandle1 = 200;
constexpr uint16_t kHciHandle2 = 201;
// upstream common_linux.h:2829-2831
constexpr int kVhciFd = 202;
constexpr uint8_t kHciPrimary = 0;

// === HCI struct layouts (byte-equal upstream / BlueZ) ================
struct __attribute__((packed)) BdAddr {
    uint8_t b[6];
};

struct __attribute__((packed)) HciCommandHdr {
    uint16_t opcode;
    uint8_t  plen;
};

struct __attribute__((packed)) HciEventHdr {
    uint8_t evt;
    uint8_t plen;
};

struct __attribute__((packed)) HciEvCmdComplete {
    uint8_t  ncmd;
    uint16_t opcode;
};

struct __attribute__((packed)) HciEvConnRequest {
    BdAddr  bdaddr;
    uint8_t dev_class[3];
    uint8_t link_type;
};

struct __attribute__((packed)) HciEvConnComplete {
    uint8_t  status;
    uint16_t handle;
    BdAddr   bdaddr;
    uint8_t  link_type;
    uint8_t  encr_mode;
};

struct __attribute__((packed)) HciEvRemoteFeatures {
    uint8_t  status;
    uint16_t handle;
    uint8_t  features[8];
};

struct __attribute__((packed)) HciEvLeMeta {
    uint8_t subevent;
};

struct __attribute__((packed)) HciEvLeConnComplete {
    uint8_t  status;
    uint16_t handle;
    uint8_t  role;
    uint8_t  bdaddr_type;
    BdAddr   bdaddr;
    uint16_t interval;
    uint16_t latency;
    uint16_t supervision_timeout;
    uint8_t  clk_accurancy;
};

struct __attribute__((packed)) HciRpReadBdAddr {
    uint8_t status;
    BdAddr  bdaddr;
};

struct __attribute__((packed)) HciRpReadBufferSize {
    uint8_t  status;
    uint16_t acl_mtu;
    uint8_t  sco_mtu;
    uint16_t acl_max_pkt;
    uint16_t sco_max_pkt;
};

// Note: HCIDEVUP/HCISETSCAN macros 用 `int`/`hci_dev_req*` 当 arg type;
// _IOW size 来自 sizeof — hci_dev_req 必须保持 layout byte-equal kernel ABI。
struct HciDevReq {
    uint16_t dev_id;
    uint32_t dev_opt;
};

// upstream vhci_vendor_pkt_request
struct __attribute__((packed)) VhciVendorPktRequest {
    uint8_t type;
    uint8_t opcode;
};

// upstream vhci_pkt union (匹配 vhci 协议:type 1 字节 + 跟随结构)。
struct __attribute__((packed)) VhciPkt {
    uint8_t type;
    union {
        struct __attribute__((packed)) {
            uint8_t  opcode;
            uint16_t id;
        } vendor_pkt;
        HciCommandHdr command_hdr;
    };
};

// vhci_fd 必须 file-static 让 event_thread 看见(thread arg = vhci_fd 可避免
// global,但匹配 upstream 用 global)。 reFuzz 用 single global,thread-safe
// 是 sandbox init 阶段不会 concurrent。
int g_vhci_fd = -1;

int RfkillUnblockAll()
{
    const int fd = ::open("/dev/rfkill", O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        const int error_number = errno;
        VHCI_LOG("rfkill: open(/dev/rfkill) errno=%d (%s)",
                 errno, ::strerror(errno));
        return -error_number;
    }
    struct ::rfkill_event event;
    ::memset(&event, 0, sizeof(event));
    event.idx = 0;
    event.type = RFKILL_TYPE_ALL;
    event.op = RFKILL_OP_CHANGE_ALL;
    event.soft = 0;
    event.hard = 0;
    if (::write(fd, &event, sizeof(event)) < 0) {
        const int error_number = errno;
        VHCI_LOG("rfkill: write errno=%d (%s)", errno, ::strerror(errno));
        ::close(fd);
        return -error_number;
    }
    ::close(fd);
    return 0;
}

void HciSendEventPacket(int fd, uint8_t evt, const void* data, size_t data_len)
{
    HciEventHdr hdr;
    hdr.evt = evt;
    hdr.plen = static_cast<uint8_t>(data_len);

    uint8_t type = kHciEventPkt;
    struct ::iovec iv[3];
    iv[0].iov_base = &type;
    iv[0].iov_len  = sizeof(type);
    iv[1].iov_base = &hdr;
    iv[1].iov_len  = sizeof(hdr);
    iv[2].iov_base = const_cast<void*>(data);
    iv[2].iov_len  = data_len;
    if (::writev(fd, iv, sizeof(iv) / sizeof(iv[0])) < 0) {
        VHCI_LOG("hci_send_event_packet evt=%u errno=%d (%s)",
                 (unsigned)evt, errno, ::strerror(errno));
        _exit(2);
    }
}

void HciSendEventCmdComplete(int fd, uint16_t opcode,
                             const void* data, size_t data_len)
{
    HciEventHdr hdr;
    hdr.evt = kHciEvCmdComplete;
    hdr.plen = static_cast<uint8_t>(sizeof(HciEvCmdComplete) + data_len);

    HciEvCmdComplete evt_hdr;
    evt_hdr.ncmd = 1;
    evt_hdr.opcode = opcode;

    uint8_t type = kHciEventPkt;
    struct ::iovec iv[4];
    iv[0].iov_base = &type;
    iv[0].iov_len  = sizeof(type);
    iv[1].iov_base = &hdr;
    iv[1].iov_len  = sizeof(hdr);
    iv[2].iov_base = &evt_hdr;
    iv[2].iov_len  = sizeof(evt_hdr);
    iv[3].iov_base = const_cast<void*>(data);
    iv[3].iov_len  = data_len;
    if (::writev(fd, iv, sizeof(iv) / sizeof(iv[0])) < 0) {
        VHCI_LOG("hci_send_event_cmd_complete op=0x%04x errno=%d (%s)",
                 (unsigned)opcode, errno, ::strerror(errno));
        _exit(2);
    }
}

// process_command_pkt — 处理 kernel HCI subsystem 发起的 init command。
// 返回 true 表示 event_thread 该退出(收到 SCAN_ENABLE 后初始化完成)。
bool ProcessCommandPkt(int fd, const char* buf, ssize_t buf_size)
{
    const auto* hdr = reinterpret_cast<const HciCommandHdr*>(buf);
    if (buf_size < static_cast<ssize_t>(sizeof(*hdr)) ||
        hdr->plen != buf_size - static_cast<ssize_t>(sizeof(*hdr))) {
        VHCI_LOG("process_command_pkt: invalid size=%zd plen=%u",
                 buf_size, (unsigned)hdr->plen);
        _exit(2);
    }
    switch (hdr->opcode) {
    case kHciOpWriteScanEnable: {
        uint8_t status = 0;
        HciSendEventCmdComplete(fd, hdr->opcode, &status, sizeof(status));
        return true;
    }
    case kHciOpReadBdAddr: {
        HciRpReadBdAddr rp;
        ::memset(&rp, 0, sizeof(rp));
        rp.status = 0;
        ::memset(&rp.bdaddr, 0xaa, sizeof(rp.bdaddr));
        HciSendEventCmdComplete(fd, hdr->opcode, &rp, sizeof(rp));
        return false;
    }
    case kHciOpReadBufferSize: {
        HciRpReadBufferSize rp;
        ::memset(&rp, 0, sizeof(rp));
        rp.status = 0;
        rp.acl_mtu = 1021;
        rp.sco_mtu = 96;
        rp.acl_max_pkt = 4;
        rp.sco_max_pkt = 6;
        HciSendEventCmdComplete(fd, hdr->opcode, &rp, sizeof(rp));
        return false;
    }
    }
    char dummy[0xf9];
    ::memset(dummy, 0, sizeof(dummy));
    HciSendEventCmdComplete(fd, hdr->opcode, dummy, sizeof(dummy));
    return false;
}

void* EventThread(void* /*arg*/)
{
    while (true) {
        char buf[1024];
        ::memset(buf, 0, sizeof(buf));
        const ssize_t n = ::read(g_vhci_fd, buf, sizeof(buf));
        if (n < 0) {
            const int error_number = errno;
            VHCI_LOG("event_thread: read errno=%d", error_number);
            _exit(2);
        }
        if (n > 0 && static_cast<uint8_t>(buf[0]) == kHciCommandPkt) {
            if (ProcessCommandPkt(g_vhci_fd, buf + 1, n - 1)) {
                break;
            }
        }
    }
    return nullptr;
}

} // namespace

int InitializeVhci()
{
    const int hci_sock = ::socket(kAfBluetooth, SOCK_RAW, kBtprotoHci);
    if (hci_sock < 0) {
        const int error_number = errno;
        VHCI_LOG("socket(AF_BLUETOOTH) errno=%d (%s)",
                 errno, ::strerror(errno));
        return -error_number;
    }

    // [D12 vhci re-entry fix] 防御性 cleanup:在 stdio per-program-restart 模式下
    // (L3 paired oracle / syzgen-driven 单次 binary 装一次 sandbox),前一个
    // refuzz 进程因 PID NS 死被 SIGKILL,/dev/vhci fd close 触发的
    // hci_unregister_dev() 是 async,落后于新进程 open /dev/vhci。这时旧 hci0
    // 仍在 kernel 注册表里但无 owner thread → kernel 往 hci0 发 HCI 命令 →
    // tx 队列拥塞 → 2s 一条 "Bluetooth: hci0: command tx timeout" 风暴,卡死
    // 新进程整套 D-init,L3 oracle 跑两条 prog 就 hang。
    //
    // 主动 HCIDEVDOWN dev_id=0 把 stale hci0 拉低,kernel 立即停 tx 发送;
    // ENODEV(没旧实例,clean state)是正常路径,继续。注:kernel 没暴露
    // HCIDEVREMOVE,unregister 只能等 vhci_release() async 完成,我们做不
    // 主动;HCIDEVDOWN 足够止血。新 vhci open 可能拿 hci0(旧的真消失了)
    // 或 hci1(还没消失),都不影响 sandbox D-init 走完。
    if (::ioctl(hci_sock, HCIDEVDOWN, 0) == 0) {
        VHCI_LOG("re-entry: HCIDEVDOWN(hci0) OK — stale instance brought down");
    }

    int vhci = ::open("/dev/vhci", O_RDWR);
    if (vhci < 0) {
        const int error_number = errno;
        VHCI_LOG("open(/dev/vhci) errno=%d (%s)",
                 errno, ::strerror(errno));
        ::close(hci_sock);
        return -error_number;
    }
    if (vhci != kVhciFd) {
        if (::dup2(vhci, kVhciFd) < 0) {
            const int error_number = errno;
            VHCI_LOG("CRITICAL: dup2(vhci=%d -> %d) errno=%d",
                     vhci, kVhciFd, errno);
            ::close(vhci);
            ::close(hci_sock);
            return -error_number;
        }
        ::close(vhci);
    }
    g_vhci_fd = kVhciFd;

    // 1) write vhci_vendor_pkt_request (HCI_VENDOR_PKT = 0xff, primary)
    VhciVendorPktRequest vendor_req{kHciVendorPkt, kHciPrimary};
    const ssize_t vendor_written =
        ::write(g_vhci_fd, &vendor_req, sizeof(vendor_req));
    if (vendor_written != static_cast<ssize_t>(sizeof(vendor_req))) {
        const int error_number = vendor_written < 0 ? errno : EIO;
        VHCI_LOG("CRITICAL: write(vendor_pkt) rc=%zd errno=%d",
                 vendor_written, error_number);
        ::close(g_vhci_fd);
        g_vhci_fd = -1;
        ::close(hci_sock);
        return -error_number;
    }

    // 2) read vhci response — kernel 可能先回 HCI_OP_RESET command,需 ack。
    VhciPkt pkt;
    ssize_t packet_read = ::read(g_vhci_fd, &pkt, sizeof(pkt));
    if (packet_read != static_cast<ssize_t>(sizeof(pkt))) {
        const int error_number = packet_read < 0 ? errno : EIO;
        VHCI_LOG("CRITICAL: read(vhci_pkt) rc=%zd errno=%d",
                 packet_read, error_number);
        ::close(g_vhci_fd);
        g_vhci_fd = -1;
        ::close(hci_sock);
        return -error_number;
    }
    if (pkt.type == kHciCommandPkt && pkt.command_hdr.opcode == kHciOpReset) {
        char response[1] = {0};
        HciSendEventCmdComplete(g_vhci_fd, kHciOpReset,
                                response, sizeof(response));
        packet_read = ::read(g_vhci_fd, &pkt, sizeof(pkt));
        if (packet_read != static_cast<ssize_t>(sizeof(pkt))) {
            const int error_number = packet_read < 0 ? errno : EIO;
            VHCI_LOG("CRITICAL: read(vhci_pkt, after-reset) rc=%zd errno=%d",
                     packet_read, error_number);
            ::close(g_vhci_fd);
            g_vhci_fd = -1;
            ::close(hci_sock);
            return -error_number;
        }
    }
    if (pkt.type != kHciVendorPkt) {
        VHCI_LOG("CRITICAL: wrong response packet type=0x%02x", (unsigned)pkt.type);
        ::close(g_vhci_fd);
        g_vhci_fd = -1;
        ::close(hci_sock);
        return -EPROTO;
    }

    const int dev_id = pkt.vendor_pkt.id;

    // 3) spawn event_thread for command-complete responses。
    pthread_t th;
    const int create_result =
        ::pthread_create(&th, nullptr, &EventThread, nullptr);
    if (create_result != 0) {
        VHCI_LOG("CRITICAL: pthread_create error=%d", create_result);
        ::close(g_vhci_fd);
        g_vhci_fd = -1;
        ::close(hci_sock);
        return -create_result;
    }

    // 4) HCIDEVUP — kernel issues init commands, EventThread responds。
    int ret = ::ioctl(hci_sock, HCIDEVUP, dev_id);
    if (ret) {
        if (errno == ERFKILL) {
            const int rfkill_result = RfkillUnblockAll();
            if (rfkill_result != 0) {
                ::close(g_vhci_fd);
                g_vhci_fd = -1;
                ::close(hci_sock);
                return rfkill_result;
            }
            ret = ::ioctl(hci_sock, HCIDEVUP, dev_id);
        }
        if (ret && errno != EALREADY) {
            const int error_number = errno;
            VHCI_LOG("ioctl(HCIDEVUP) errno=%d (%s)", errno, ::strerror(errno));
            ::close(g_vhci_fd);
            g_vhci_fd = -1;
            ::close(hci_sock);
            return -error_number;
        }
    }

    // 5) HCISETSCAN page-scan(让 fake conn 能 accept)。
    HciDevReq dr;
    ::memset(&dr, 0, sizeof(dr));
    dr.dev_id = static_cast<uint16_t>(dev_id);
    dr.dev_opt = kScanPage;
    if (::ioctl(hci_sock, HCISETSCAN, &dr)) {
        const int error_number = errno;
        VHCI_LOG("ioctl(HCISETSCAN) errno=%d (%s)",
                 errno, ::strerror(errno));
        ::close(g_vhci_fd);
        g_vhci_fd = -1;
        ::close(hci_sock);
        return -error_number;
    }

    // 6) Fake a BR/EDR connection with bd addr 10:aa:aa:aa:aa:aa
    // (sys/linux/socket_bluetooth.txt 同步)。
    HciEvConnRequest req;
    ::memset(&req, 0, sizeof(req));
    ::memset(&req.bdaddr, 0xaa, sizeof(req.bdaddr));
    req.bdaddr.b[5] = 0x10;
    req.link_type = kAclLink;
    HciSendEventPacket(g_vhci_fd, kHciEvConnRequest, &req, sizeof(req));

    HciEvConnComplete complete;
    ::memset(&complete, 0, sizeof(complete));
    complete.status = 0;
    complete.handle = kHciHandle1;
    ::memset(&complete.bdaddr, 0xaa, sizeof(complete.bdaddr));
    complete.bdaddr.b[5] = 0x10;
    complete.link_type = kAclLink;
    complete.encr_mode = 0;
    HciSendEventPacket(g_vhci_fd, kHciEvConnComplete, &complete, sizeof(complete));

    HciEvRemoteFeatures features;
    ::memset(&features, 0, sizeof(features));
    features.status = 0;
    features.handle = kHciHandle1;
    HciSendEventPacket(g_vhci_fd, kHciEvRemoteFeatures, &features, sizeof(features));

    // 7) Fake a LE connection with bd addr 11:aa:aa:aa:aa:aa
    struct __attribute__((packed)) {
        HciEvLeMeta         le_meta;
        HciEvLeConnComplete le_conn;
    } le_conn;
    ::memset(&le_conn, 0, sizeof(le_conn));
    le_conn.le_meta.subevent = kHciEvLeConnComplete;
    ::memset(&le_conn.le_conn.bdaddr, 0xaa, sizeof(le_conn.le_conn.bdaddr));
    le_conn.le_conn.bdaddr.b[5] = 0x11;
    le_conn.le_conn.role = 1;
    le_conn.le_conn.handle = kHciHandle2;
    HciSendEventPacket(g_vhci_fd, kHciEvLeMeta, &le_conn, sizeof(le_conn));

    // 8) Wait for event_thread — 它由 WRITE_SCAN_ENABLE 触发 return true 退出。
    // byte-equal upstream pthread_join(common_linux.h:2921):无 timeout。
    // 上游假设 kernel BT subsystem 在 HCIDEVUP+HCISETSCAN 后**一定**发
    // WRITE_SCAN_ENABLE。如果不发(eg. full-config KASAN kernel BT init
    // race / hci0: command tx timeout × 4)→ pthread_join 永等。
    //
    // 不在这里加 timed_join。与 syzkaller 一样由外层 sandbox-handshake
    // watchdog 处理卡住：默认 60 秒后停止 domain，并按启动重试策略重建。
    const int join_result = ::pthread_join(th, nullptr);
    if (join_result != 0) {
        ::close(g_vhci_fd);
        g_vhci_fd = -1;
        ::close(hci_sock);
        return -join_result;
    }
    ::close(hci_sock);

    VHCI_LOG("ready: hci dev_id=%d fd=%d", dev_id, kVhciFd);
    return 0;
}

} // namespace refuzz::worker::sandbox::device_init

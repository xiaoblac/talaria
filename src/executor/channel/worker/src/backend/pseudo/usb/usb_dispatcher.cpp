// PR-D4 — USB family dispatcher implementation.
//
// All 25 syz_usb_*$ pseudos share one of 6 handler bodies (connect /
// control_io / disconnect / ep_read / ep_write / usbip_server_init).
// Variants ($cdc_ecm / $hid / $rtl8150 / etc.) differ only in their
// caller-supplied descriptor payload, which we pass through to the
// kernel via raw-gadget ioctls without further interpretation.
//
// Per plan §10 Q6 rule 3 (handler-active + non-degradable), the cap
// gate (kCapNeedsRoot|kCapNeedsUsb) is enforced in pseudo_dispatcher.cpp
// before this dispatcher is reached.

#include "worker/backend/pseudo/usb/usb_dispatcher.hpp"

#include "worker/backend/pseudo/usb/usb_enumeration.hpp"
#include "worker/backend/pseudo/usb/usb_helpers.hpp"
#include "worker/backend/pseudo/usb/usb_state.hpp"
#include "worker/log/log_macros.hpp"

#include <cerrno>
#include <cstring>
#include <sys/ioctl.h>
#include <unistd.h>

// [PR-D4 review fix C12 2026-05-07] Require upstream raw-gadget header
// (no fallback structs that could silently diverge from kernel uapi).
// usb_helpers.cpp does the same check + pins offsets via static_assert.
#if !__has_include(<linux/usb/raw_gadget.h>)
#  error "raw-gadget kernel UAPI header missing — install linux-headers \
or build on a kernel >= 5.7"
#endif
#include <linux/usb/ch9.h>          // usb_ctrlrequest, USB_DIR_IN — PR-2
#include <linux/usb/raw_gadget.h>

namespace refuzz::worker::pseudo {

namespace {

PseudoResult Error(int err, const char* reason = nullptr)
{
    return PseudoResult{-1, err, reason};
}

// [usb async-settle parity] syzkaller sleeps 200ms at the end of every USB
// pseudo (syz_usb_connect/control_io/ep_write/ep_read/disconnect —
// common_usb_linux.h:399/518/553/592/605) so the kernel's ASYNC USB work
// (driver bind/probe, hub_event, URB completion) runs and registers its
// coverage before the call returns. reFuzz had only the control_io sleep and
// relied on the task-end remote-cover settle loop for the rest, but the
// driver-probe coverage (usbhid/cdc bind, drivers/hid, drivers/net/usb) stayed
// ~0 — the async probe needs this per-call settle to advance. Mirror syz's
// placement exactly.
constexpr unsigned kUsbAsyncSettleUs = 200u * 1000u;  // syz sleep_ms(200)


// ---- syz_usb_connect family (10 variants) ------------------------------
// Upstream pseudo signature (sys/linux/vusb.txt:25):
//   syz_usb_connect(speed, dev_len, dev ptr[in, usb_device_descriptor],
//                   conn_descs ptr[in, vusb_connect_descriptors]) fd_usb
//
// [当前版本 PR-1 dummy_udc per proc_slot — 2026-05-20] 用 ctx.proc_slot_id
// 合成 dummy_udc.<N>,与上游 procid 路径对齐,避免 UDC contention 导致
// register -EBUSY → STATE_DEV_FAILED 级联。
//
// [当前版本 PR-3 enumeration event loop — 2026-05-20] 在 INIT+RUN 之后
// 跑一个 EVENT_FETCH 循环消费 host 推过来的 GET_DESCRIPTOR /
// SET_CONFIGURATION 等枚举 SETUP,直到 SET_CONFIGURATION 完成
// (ath9k 变体到 vendor firmware-download-comp 完成)。响应来自
// args[2] (dev_ptr) 经 UsbParseDescriptor 解析出的 device_index;字符串
// 描述符回退到默认 "syz"。args[3] (conn_descs) 的 qual/bos/strs 暂不
// 解析(留给 PR-4)。镜像上游 common_usb_linux.h:265-403 的 connect 主
// 循环。
//
// 行为差异(故意保留):
//   * connect 末尾不 sleep_ms(200)。F8 (03_findings.md) 曾在 connect 加
//     sleep 无效 → 当时误判 "timing race 假设证伪"。2026-05-24 单程序隔离
//     (docs/plans/hiddev-gadget-lifetime-dossier.md) 推翻该结论:创建
//     /dev/usb/hiddev* 的 async usbhid probe 是被 **control_io 里的
//     GET_DESCRIPTOR(report, wVal=0x2200) 交换** 触发的,不是 connect。
//     所以 wait 必须在 control_io 末尾(见 UsbControlIo 的 usleep,镜像
//     上游 common_usb_linux.h:518),connect 这里 sleep 太早、无用。
//   * 不维护 fd → device_index 全局映射 (upstream usb_devices[]) —
//     device_index 挂在 UsbState 上,per-PseudoContext 隔离
using OutHandler = bool (*)(const struct usb_ctrlrequest&, bool*);

PseudoResult UsbConnectImpl(const PseudoContext& ctx,
                            const intptr_t* args, uint32_t argc,
                            OutHandler out_handler)
{
    UsbState& state = GetOrCreateUsbState(ctx);

    // args layout: [speed, dev_len, dev_ptr, conn_descs_ptr]
    //
    // [REVERT 2026-05-20] Earlier PR-5.7 added a "lenient degrade" path
    // that bypassed these gates and still called INIT+RUN with synthesized
    // defaults on bad input. Verification (run/exec-oracle-usb-fix-verify2-)
    // showed the extra 9 INIT+RUN+raw_release cycles caused +1140
    // errno_mismatch on syz_mount_image (loop-device EBUSY ripple from
    // additional async kernel work between programs). The ~45k unique PCs
    // of "fluke coverage" recovered by leniency cost ~7% overall jaccard,
    // net negative. Stick with strict parsing.
    if (argc < 3) {
        return Error(EINVAL, "connect: argc<3");
    }
    const auto         dev_len = static_cast<std::size_t>(args[1]);
    const auto* const  dev_ptr = reinterpret_cast<const std::uint8_t*>(args[2]);
    if (dev_ptr == nullptr || dev_len == 0) {
        // [lan78xx errno parity 2026-05-24] Degenerate connect (fuzzer produced
        // dev=NULL / dev_len=0). syzkaller's syz_usb_connect rejects this at
        // `if (!dev) return -1` (common_usb_linux.h:273) and reports the
        // executor's pre-call errno=EFAULT sentinel (executor.cc:1565 — no
        // syscall runs on this path so errno is never overwritten). Match that
        // errno rather than our own EINVAL. Confirmed by dev_len probe: the wire
        // encodes dev=NULL/dev_len=0 identically on both sides — this is pure
        // errno parity, not an arg-resolution divergence.
        return Error(EFAULT, "connect: dev ptr/len (null descriptor)");
    }

    // Parse device descriptor blob BEFORE INIT — failing here means the
    // caller-supplied payload is malformed; no point bringing the gadget
    // up just to STALL forever on GET_DESCRIPTOR.
    if (!UsbParseDescriptor(dev_ptr, dev_len, state.device_index)) {
        // [lan78xx errno parity 2026-05-24] syzkaller's add_usb_index →
        // parse_usb_descriptor reject (e.g. dev_len < sizeof(dev)+sizeof(config))
        // returns NULL → connect `if (!index) return -1` (common_usb_linux.h:296)
        // → EFAULT sentinel (usb_raw_open already succeeded, errno untouched).
        // Match the sentinel errno, same family as the null-descriptor reject above.
        return Error(EFAULT, "connect: parse_usb_descriptor");
    }

    if (UsbInitAndRunGadget(state, ctx.proc_slot_id) < 0) {
        return Error(errno, "USB_RAW_IOCTL_INIT|RUN");
    }

    // [PR-5.3 2026-05-20] kMaxEnumIterations bounds the number of CONTROL
    // SETUPs we process (i.e., descriptor fetches + the final
    // SET_CONFIGURATION). Non-CONTROL events (CONNECT/RESET notifications
    // the kernel pushes between programs) MUST NOT count — they're "free"
    // and an unlucky burst would starve the descriptor responses.
    // Separately kMaxNonControlEvents prevents an infinite loop if the
    // kernel only ever pushes non-CONTROL events (driver bug / fuzz state
    // corruption).
    constexpr int          kMaxEnumIterations    = 256;
    constexpr int          kMaxNonControlEvents  = 1024;
    constexpr std::size_t  kMaxControlData       = 4096;
    bool                   done                  = false;
    int                    control_iter          = 0;
    int                    noncontrol_iter       = 0;
    struct usb_qualifier_descriptor qual_storage = {};

    // args[3] = conn_descs ptr[in, vusb_connect_descriptors] (may be null). The
    // executor resolves the struct + its inner qual/bos/str pointers; pass it to
    // the IN-response lookup so BOS / DEVICE_QUALIFIER / per-index STRING come
    // from the program (upstream syz_usb_connect passes a3 → descs).
    const VusbConnectDescriptors* conn_descs =
        (argc >= 4 && args[3] != 0)
            ? reinterpret_cast<const VusbConnectDescriptors*>(args[3])
            : nullptr;

    while (!done && control_iter < kMaxEnumIterations &&
           noncontrol_iter < kMaxNonControlEvents) {
        struct {
            struct usb_raw_event   inner;
            struct usb_ctrlrequest ctrl;
        } event = {};
        event.inner.type   = 0;
        event.inner.length = sizeof(event.ctrl);
        if (::ioctl(state.raw_gadget_fd, USB_RAW_IOCTL_EVENT_FETCH, &event) < 0) {
            return Error(errno, "connect: EVENT_FETCH");
        }
        if (event.inner.type != USB_RAW_EVENT_CONTROL) {
            // CONNECT / DISCONNECT / RESET events have no data — ignore
            // and re-fetch. Bounded by kMaxNonControlEvents.
            ++noncontrol_iter;
            continue;
        }
        ++control_iter;

        const bool          in_dir = (event.ctrl.bRequestType & USB_DIR_IN) != 0;
        const std::uint8_t* response_data   = nullptr;
        std::uint32_t       response_length = 0;
        bool                handled         = false;

        if (in_dir) {
            handled = UsbLookupConnectResponseIn(
                state.device_index, conn_descs, event.ctrl, qual_storage,
                &response_data, &response_length);
        } else {
            handled = out_handler(event.ctrl, &done);
            // For OUT requests upstream sets response_length = wLength
            // (just acknowledges, no data sent back).
            if (handled) {
                response_length = static_cast<std::uint32_t>(
                    static_cast<__u16>(event.ctrl.wLength));
            }
            // STANDARD SET_CONFIGURATION on the generic path → drive
            // CONFIGURE + EP_ENABLE (matches upstream common_usb_linux.h:363-369).
            if (handled &&
                (event.ctrl.bRequestType & USB_TYPE_MASK) == USB_TYPE_STANDARD &&
                event.ctrl.bRequest == USB_REQ_SET_CONFIGURATION) {
                if (UsbConfigureDevice(state.raw_gadget_fd, state.device_index) < 0) {
                    return Error(errno, "connect: configure_device");
                }
            }
        }

        if (!handled) {
            // common_usb_linux.h:349-352.
            ::refuzz::worker::log::WorkerLog(
                "[usb] connect_stall slot=%u dir=%s "
                "type=0x%02x req=0x%02x val=0x%04x idx=0x%04x len=%u\n",
                static_cast<unsigned>(ctx.proc_slot_id),
                in_dir ? "IN" : "OUT",
                static_cast<unsigned>(event.ctrl.bRequestType),
                static_cast<unsigned>(event.ctrl.bRequest),
                static_cast<unsigned>(event.ctrl.wValue),
                static_cast<unsigned>(event.ctrl.wIndex),
                static_cast<unsigned>(event.ctrl.wLength));
            (void)::ioctl(state.raw_gadget_fd, USB_RAW_IOCTL_EP0_STALL, 0);
            continue;
        }

        // Build + emit the response.
        struct {
            struct usb_raw_ep_io inner;
            unsigned char        data[kMaxControlData];
        } response = {};
        response.inner.ep    = 0;
        response.inner.flags = 0;

        std::uint32_t emit_len = response_length;
        const std::uint16_t   wLen = static_cast<__u16>(event.ctrl.wLength);
        if (emit_len > wLen) {
            emit_len = wLen;
        }
        if (emit_len > kMaxControlData) {
            emit_len = kMaxControlData;
        }
        response.inner.length = emit_len;
        if (response_data != nullptr && emit_len > 0) {
            std::memcpy(response.data, response_data, emit_len);
        }

        const bool do_write = in_dir && wLen > 0;
        const unsigned long op = do_write ? USB_RAW_IOCTL_EP0_WRITE
                                          : USB_RAW_IOCTL_EP0_READ;
        if (::ioctl(state.raw_gadget_fd, op, &response) < 0) {
            return Error(errno, do_write ? "connect: EP0_WRITE"
                                         : "connect: EP0_READ");
        }
    }
    if (!done) {
        // Hit one of the iteration caps without seeing SET_CONFIGURATION /
        // firmware-download-comp. Not a hard failure (the gadget is
        // RUNNING and post-connect handlers may still drive coverage) but
        // worth surfacing — typical causes: caller-supplied descriptors
        // omit the configuration the host wants, or kernel pushed only
        // CONNECT events without follow-up SETUPs.
        ::refuzz::worker::log::WorkerLog(
            "[usb] connect_cap_exceeded slot=%u control_iter=%d "
            "noncontrol_iter=%d\n",
            static_cast<unsigned>(ctx.proc_slot_id),
            control_iter, noncontrol_iter);
    }
    // [usb async-settle parity] syz_usb_connect sleep_ms(200) at
    // common_usb_linux.h:399 — lets the post-SET_CONFIGURATION driver bind/probe
    // run before the program proceeds.
    ::usleep(kUsbAsyncSettleUs);
    return PseudoResult{0, 0, nullptr};
}

PseudoResult UsbConnect(const PseudoContext& ctx,
                        const intptr_t* args, uint32_t argc)
{
    return UsbConnectImpl(ctx, args, argc,
                          &UsbLookupConnectResponseOutGeneric);
}

PseudoResult UsbConnectAth9k(const PseudoContext& ctx,
                             const intptr_t* args, uint32_t argc)
{
    return UsbConnectImpl(ctx, args, argc,
                          &UsbLookupConnectResponseOutAth9k);
}

// ---- syz_usb_control_io family (9 variants) ----------------------------
// Upstream pseudo signature (sys/linux/vusb.txt:26):
//   syz_usb_control_io(fd fd_usb, descs ptr[in, vusb_descriptors],
//                      resps ptr[in, vusb_responses])
//
// [当前版本 lan78xx-fix descs/resps lookup — 2026-05-20]
// 旧实现裸 EP0_WRITE 零填充,IN+wLength>0 路径不解析 descs/resps,lan78xx
// probe 阶段 kernel 报 EPROTO/EPIPE → 33+9 mismatch (Tier 4)。现在按上游
// common_usb_linux.h:433-521 完整流程:
//   1. USB_RAW_IOCTL_EVENT_FETCH 阻塞等下一条 SETUP
//   2. IN+wLength>0 → UsbLookupControlResponse(args[1]=descs, args[2]=resps)
//        → 拿真 descriptor 数据 → EP0_WRITE,未匹配则 STALL EP0
//   3. OUT/IN+wLength==0 → SET_INTERFACE 路由(影响 ep handle 查找) →
//        EP0_READ 兜底
PseudoResult UsbControlIo(const PseudoContext& ctx,
                          const intptr_t* args, uint32_t argc)
{
    UsbState& state = GetOrCreateUsbState(ctx);
    if (state.raw_gadget_fd < 0 || !state.gadget_running) {
        // [lan78xx errno parity 2026-05-24] Cascade from a failed connect (e.g.
        // the null-descriptor reject above): no gadget fd exists. syzkaller's
        // syz_usb_control_io has no gadget-state guard — it does EVENT_FETCH on
        // the fd carried in from the (failed) connect's result, which is -1, so
        // the ioctl returns EBADF (common_usb_linux.h:442). Match EBADF rather
        // than our internal EINVAL so the cascade lines up with syzkaller.
        return Error(EBADF, "control_io: gadget not running (bad/absent fd)");
    }

    // 解析 caller-supplied descs / resps (args[1] / args[2])。两者都可能
    // 是 nullptr(syzlang ptr[in, ...] 可空)或 wire 上 ResultArg 解出来
    // 是 scratch 范围外的 special pointer — UsbLookupControlResponse 自身
    // tolerate nullptr。
    const VusbDescriptors* descs = nullptr;
    const VusbResponses*   resps = nullptr;
    if (argc >= 2 && args[1] != 0) {
        descs = reinterpret_cast<const VusbDescriptors*>(args[1]);
    }
    if (argc >= 3 && args[2] != 0) {
        resps = reinterpret_cast<const VusbResponses*>(args[2]);
    }

    // EVENT_FETCH 等下一条 SETUP。kernel 把 usb_ctrlrequest 放在 event
    // header 之后的 data[] 区域;event.length = 我们能接收的字节数,
    // 给 sizeof(ctrl) 就够 (SETUP 包固定 8 bytes)。
    struct {
        struct usb_raw_event   inner;
        struct usb_ctrlrequest ctrl;
    } event = {};
    event.inner.type   = 0;
    event.inner.length = sizeof(event.ctrl);
    if (::ioctl(state.raw_gadget_fd, USB_RAW_IOCTL_EVENT_FETCH, &event) < 0) {
        return Error(errno, "USB_RAW_IOCTL_EVENT_FETCH");
    }
    if (event.inner.type != USB_RAW_EVENT_CONTROL) {
        return Error(EPROTO, "control_io: event type != CONTROL");
    }

    constexpr std::size_t kMaxControlData = 4096;  // upstream USB_MAX_PACKET_SIZE
    const bool        in_dir = (event.ctrl.bRequestType & USB_DIR_IN) != 0;
    const std::uint16_t wLen = static_cast<__u16>(event.ctrl.wLength);

    const std::uint8_t* response_data   = nullptr;
    std::uint32_t       response_length = 0;

    if (in_dir && wLen > 0) {
        // IN with non-zero length:host 想要数据。按 upstream common_usb_linux.h
        // :463-468 走 descs/resps lookup;**未匹配时 STALL EP0 + 返回 EFAULT**。
        //
        // [lan78xx errno parity 2026-05-24] 之前 baseline 在 lookup-miss 时不
        // STALL、零填充 EP0_WRITE 返 0,跟 syz 端 errno 14 mismatch(14→0);上次
        // STALL 尝试返 EPROTO(71) 仍 mismatch(14→71)且 jaccard 退化。真因:syz
        // 的 errno 14 不是 STALL 的真实 errno,而是 executor.cc:1565 在每个 call
        // 前预置的 `errno=EFAULT` 哨兵——unknown-request 走
        // `usb_raw_ep0_stall(fd); return -1;`(common_usb_linux.h:466-467),
        // EVENT_FETCH + STALL 两个 ioctl 都成功 → errno 从未被覆盖 → 残留 EFAULT
        // 被 reserrno 记下。reFuzz 复刻:STALL EP0(对齐 raw_ioctl_ep0_stall PC
        // 路径)+ 显式返回 EFAULT(复刻哨兵值),干净返回,不再走零填充 EP0_WRITE。
        // lookup 命中的 control_io 变体不受影响,仍落到下方 EP0_WRITE 真 descriptor。
        if (!UsbLookupControlResponse(descs, resps, event.ctrl,
                                      &response_data, &response_length)) {
            return Error(EFAULT, "control_io: unknown IN request, stalled");
        }
    } else {
        // OUT 或 IN+wLength=0:上游 common_usb_linux.h:470-481 在 STANDARD
        // 或 SET_INTERFACE 时调用 lookup_interface + set_interface。reFuzz
        // 之前的实现把 "STANDARD" 跟 "SET_INTERFACE" 写成 AND,upstream 写
        // 的是 OR。这里按 upstream 修正。
        if ((event.ctrl.bRequestType & USB_TYPE_MASK) == USB_TYPE_STANDARD ||
            event.ctrl.bRequest == USB_REQ_SET_INTERFACE) {
            const auto iface_num = static_cast<std::uint8_t>(event.ctrl.wIndex);
            const auto alt_set   = static_cast<std::uint8_t>(event.ctrl.wValue);
            const int  iface_idx = UsbLookupInterface(state.device_index,
                                                      iface_num, alt_set);
            if (iface_idx >= 0) {
                UsbSetInterface(state.raw_gadget_fd, state.device_index,
                                iface_idx);
            } else {
                ::refuzz::worker::log::WorkerLog(
                    "[usb] control_io_set_interface_miss slot=%u "
                    "iface_num=%u alt=%u ifaces_total=%d\n",
                    static_cast<unsigned>(ctx.proc_slot_id),
                    static_cast<unsigned>(iface_num),
                    static_cast<unsigned>(alt_set),
                    state.device_index.ifaces_num);
            }
        }
        // OUT acknowledges with response_length = wLength (upstream:484).
        response_length = wLen;
    }

    // Final length clamping — upstream `if (event.ctrl.wLength < response_length)
    // response_length = event.ctrl.wLength;` 防止 host 拿到比 wLen 多的字节。
    if (response_length > wLen) {
        response_length = wLen;
    }
    if (response_length > kMaxControlData) {
        response_length = kMaxControlData;
    }
    // "Something fishy" 兜底:IN+wLength=0 时 upstream 走 max-buf EP0_READ
    // (common_usb_linux.h:494-497)。
    std::size_t op_len = response_length;
    if (in_dir && wLen == 0) {
        op_len = kMaxControlData;
    }

    struct {
        struct usb_raw_ep_io inner;
        unsigned char        data[kMaxControlData];
    } response = {};
    response.inner.ep     = 0;
    response.inner.flags  = 0;
    response.inner.length = static_cast<__u32>(op_len);
    if (response_data != nullptr && response_length > 0) {
        std::memcpy(response.data, response_data, response_length);
    }

    const bool do_write = in_dir && wLen > 0;
    const unsigned long op = do_write ? USB_RAW_IOCTL_EP0_WRITE
                                      : USB_RAW_IOCTL_EP0_READ;
    if (::ioctl(state.raw_gadget_fd, op, &response) < 0) {
        return Error(errno, do_write ? "USB_RAW_IOCTL_EP0_WRITE"
                                     : "USB_RAW_IOCTL_EP0_READ");
    }
    // [hiddev gadget-lifetime fix 2026-05-24] Mirror syzkaller
    // common_usb_linux.h:518 sleep_ms(200) at the end of syz_usb_control_io.
    // The post-SET_CONFIGURATION HID report-descriptor exchange happens HERE
    // (not in connect), and it kicks the async usbhid workqueue probe that
    // creates /dev/usb/hiddev* + /dev/hidraw*. Single-program isolation
    // (docs/plans/hiddev-gadget-lifetime-dossier.md) showed the probe finishes
    // ~49ms AFTER this exchange, but reFuzz's program reaches syz_open_dev$hiddev
    // and tears down in ~15ms → the node never exists at open time → ENOENT.
    // This wait lets the probe create the node before the open. F8's earlier
    // sleep was in connect (call 0) — too early — which is why it had no effect.
    // Covered by the control_io per-call timeout attr
    // (syz_usb_control_io$hid=300ms, sys/linux/vusb.txt → kLinuxAmd64CallTimeoutMs)
    // so it does not trip the threaded blocked threshold.
    ::usleep(kUsbAsyncSettleUs);  // syz_usb_control_io sleep_ms(200) :518
    return PseudoResult{0, 0, nullptr};
}

// ---- syz_usb_disconnect ------------------------------------------------
PseudoResult UsbDisconnect(const PseudoContext& ctx,
                           const intptr_t* /*args*/, uint32_t /*argc*/)
{
    UsbState& state = GetOrCreateUsbState(ctx);
    if (state.raw_gadget_fd < 0) {
        return Error(EINVAL, "disconnect: no raw-gadget fd");
    }
    if (UsbDisconnectGadget(state) < 0) {
        return Error(errno, "raw-gadget close");
    }
    // [usb async-settle parity] syz_usb_disconnect sleep_ms(200) at
    // common_usb_linux.h:605 — lets the kernel's disconnect/unbind teardown run.
    ::usleep(kUsbAsyncSettleUs);
    return PseudoResult{0, 0, nullptr};
}

// ---- syz_usb_ep_read ---------------------------------------------------
// Upstream signature (sys/linux/vusb.txt:28):
//   syz_usb_ep_read(fd fd_usb, ep int8, len len[data], data buffer[out])
//
// [当前版本 PR-4 endpoint handle 映射 — 2026-05-20] 旧版直接拿 args[1]
// (bEndpointAddress) 当 kernel ep handle 喂给 EP_READ ioctl,但 kernel
// 期望的是 USB_RAW_IOCTL_EP_ENABLE 返回的 handle(0/1/2...),不是 wire
// address (0x81 等)。upstream 用 lookup_endpoint(fd, addr) 转换,这里
// 用 UsbLookupEndpoint 走同一条路。device_index 由 UsbConnect 解析
// device descriptor 并通过 UsbConfigureDevice 在 SET_CONFIGURATION 时
// EP_ENABLE 填好。
PseudoResult UsbEpRead(const PseudoContext& ctx,
                       const intptr_t* args, uint32_t argc)
{
    UsbState& state = GetOrCreateUsbState(ctx);
    if (state.raw_gadget_fd < 0 || !state.gadget_running) {
        return Error(EINVAL, "ep_read: gadget not running");
    }
    if (argc < 4) {
        return Error(EINVAL, "ep_read: argc<4");
    }
    const auto ep_addr  = static_cast<std::uint8_t>(args[1] & 0xFF);
    const int  ep_handle = UsbLookupEndpoint(state.device_index, ep_addr);
    if (ep_handle < 0) {
        ::refuzz::worker::log::WorkerLog(
            "[usb] ep_read_lookup_miss slot=%u ep_addr=0x%02x "
            "iface_cur=%d parsed=%d\n",
            static_cast<unsigned>(ctx.proc_slot_id),
            static_cast<unsigned>(ep_addr),
            state.device_index.iface_cur,
            state.device_index.parsed ? 1 : 0);
        return Error(EINVAL, "ep_read: endpoint not found");
    }
    constexpr std::size_t kMaxEpData = 4096;
    struct {
        __u16 ep;
        __u16 flags;
        __u32 length;
        __u8  data[kMaxEpData];
    } io = {};
    io.ep     = static_cast<__u16>(ep_handle);
    io.flags  = 0;
    const std::size_t want = static_cast<std::size_t>(args[2]);
    io.length = static_cast<__u32>((want < kMaxEpData) ? want : kMaxEpData);
    if (::ioctl(state.raw_gadget_fd, USB_RAW_IOCTL_EP_READ, &io) < 0) {
        return Error(errno, "USB_RAW_IOCTL_EP_READ");
    }
    // Copy out the read bytes if the caller provided a buffer.
    if (args[3] != 0 && io.length > 0) {
        auto* dst = reinterpret_cast<__u8*>(args[3]);
        std::memcpy(dst, io.data, io.length);
    }
    // [usb async-settle parity] syz_usb_ep_read sleep_ms(200) at
    // common_usb_linux.h:592 — lets async URB completion coverage register.
    ::usleep(kUsbAsyncSettleUs);
    return PseudoResult{static_cast<intptr_t>(io.length), 0, nullptr};
}

// ---- syz_usb_ep_write family (3 variants) ------------------------------
// Upstream signature (sys/linux/vusb.txt:27):
//   syz_usb_ep_write(fd fd_usb, ep int8, len len[data], data ptr[in, array[int8, 0:256]])
//
// [当前版本 PR-4 endpoint handle 映射 — 2026-05-20] 同 UsbEpRead 的
// rationale:UsbLookupEndpoint(addr) → kernel ep handle。
PseudoResult UsbEpWrite(const PseudoContext& ctx,
                        const intptr_t* args, uint32_t argc)
{
    UsbState& state = GetOrCreateUsbState(ctx);
    if (state.raw_gadget_fd < 0 || !state.gadget_running) {
        return Error(EINVAL, "ep_write: gadget not running");
    }
    if (argc < 4) {
        return Error(EINVAL, "ep_write: argc<4");
    }
    const auto ep_addr  = static_cast<std::uint8_t>(args[1] & 0xFF);
    const int  ep_handle = UsbLookupEndpoint(state.device_index, ep_addr);
    if (ep_handle < 0) {
        ::refuzz::worker::log::WorkerLog(
            "[usb] ep_write_lookup_miss slot=%u ep_addr=0x%02x "
            "iface_cur=%d parsed=%d\n",
            static_cast<unsigned>(ctx.proc_slot_id),
            static_cast<unsigned>(ep_addr),
            state.device_index.iface_cur,
            state.device_index.parsed ? 1 : 0);
        return Error(EINVAL, "ep_write: endpoint not found");
    }
    constexpr std::size_t kMaxEpData = 4096;
    struct {
        __u16 ep;
        __u16 flags;
        __u32 length;
        __u8  data[kMaxEpData];
    } io = {};
    io.ep    = static_cast<__u16>(ep_handle);
    io.flags = 0;
    const std::size_t want = static_cast<std::size_t>(args[2]);
    io.length = static_cast<__u32>((want < kMaxEpData) ? want : kMaxEpData);
    if (args[3] != 0 && io.length > 0) {
        const auto* src = reinterpret_cast<const __u8*>(args[3]);
        std::memcpy(io.data, src, io.length);
    }
    if (::ioctl(state.raw_gadget_fd, USB_RAW_IOCTL_EP_WRITE, &io) < 0) {
        return Error(errno, "USB_RAW_IOCTL_EP_WRITE");
    }
    // [usb async-settle parity] syz_usb_ep_write sleep_ms(200) at
    // common_usb_linux.h:553 — lets async URB completion coverage register.
    ::usleep(kUsbAsyncSettleUs);
    return PseudoResult{static_cast<intptr_t>(io.length), 0, nullptr};
}

// ---- syz_usbip_server_init --------------------------------------------
// Separate from raw-gadget — opens a USBIP attach interface.
PseudoResult UsbipServerInit(const PseudoContext& ctx,
                             const intptr_t* /*args*/, uint32_t /*argc*/)
{
    UsbState& state = GetOrCreateUsbState(ctx);
    if (UsbipServerOpen(state) < 0) {
        return Error(errno, "usbip_server: open");
    }
    return PseudoResult{0, 0, nullptr};
}

} // namespace

PseudoResult DispatchUsbPseudo(const PseudoContext& ctx,
                               const refuzz::fuzzer::syz::PseudoMeta& meta,
                               const intptr_t* args,
                               uint32_t argc)
{
    if (meta.name == nullptr) {
        return Error(EINVAL, "usb: meta.name nullptr");
    }
    const char* name = meta.name;
    // Most-specific prefix first so connect_ath9k doesn't fall into the
    // generic "syz_usb_connect" branch.
    if (std::strcmp(name, "syz_usb_disconnect") == 0) {
        return UsbDisconnect(ctx, args, argc);
    }
    if (std::strcmp(name, "syz_usbip_server_init") == 0) {
        return UsbipServerInit(ctx, args, argc);
    }
    if (std::strncmp(name, "syz_usb_ep_read", 15) == 0) {
        return UsbEpRead(ctx, args, argc);
    }
    if (std::strncmp(name, "syz_usb_ep_write", 16) == 0) {
        return UsbEpWrite(ctx, args, argc);
    }
    if (std::strncmp(name, "syz_usb_control_io", 18) == 0) {
        return UsbControlIo(ctx, args, argc);
    }
    // ath9k variant uses a different OUT-response handler (vendor firmware
    // download phase past SET_CONFIGURATION). Route it before the generic
    // `syz_usb_connect` prefix branch.
    if (std::strcmp(name, "syz_usb_connect_ath9k") == 0) {
        return UsbConnectAth9k(ctx, args, argc);
    }
    if (std::strncmp(name, "syz_usb_connect", 15) == 0) {
        return UsbConnect(ctx, args, argc);
    }
    return Error(ENOSYS, "usb: unknown pseudo name");
}

} // namespace refuzz::worker::pseudo

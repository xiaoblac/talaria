// PR-D4 — USB raw-gadget lifecycle helpers implementation.

#include "worker/backend/pseudo/usb/usb_helpers.hpp"
#include "worker/backend/pseudo/usb/usb_state.hpp"
#include "worker/log/log_macros.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

// raw-gadget UAPI requires <linux/usb/raw_gadget.h>.
//
// [PR-D4 review fix C12 2026-05-07] Earlier the worker carried local
// fallback struct definitions when the header was missing — those could
// silently disagree with the kernel ABI on hosts where uapi evolved
// (driver_name grew from 32 to 64 bytes, etc.) and produce wrong-offset
// ioctl payloads with no compile-time signal. New policy: require the
// header. Hosts without raw-gadget kernel support can't usefully run
// this worker anyway, so failing the build is the right error mode.
#if !__has_include(<linux/usb/raw_gadget.h>)
#  error "raw-gadget kernel UAPI header missing — install linux-headers \
or build on a kernel >= 5.7"
#endif
#include <linux/usb/raw_gadget.h>
#include <cstddef>

// Pin every kernel-shared offset reFuzz reads/writes. If a future kernel
// uapi evolution moves any field, the build fails here rather than
// producing silent ioctl-arg corruption at runtime. ep_io is the most-
// touched struct (control_io / ep_read / ep_write all build it on a
// stack-bound buffer with the header up front).
static_assert(offsetof(struct usb_raw_ep_io, ep) == 0,
              "usb_raw_ep_io::ep must be at offset 0");
static_assert(offsetof(struct usb_raw_ep_io, flags) == 2,
              "usb_raw_ep_io::flags must be at offset 2");
static_assert(offsetof(struct usb_raw_ep_io, length) == 4,
              "usb_raw_ep_io::length must be at offset 4");
static_assert(offsetof(struct usb_raw_ep_io, data) == 8,
              "usb_raw_ep_io::data must be at offset 8");

namespace refuzz::worker::pseudo {

int UsbOpenRawGadget(UsbState& state)
{
    if (state.raw_gadget_fd >= 0) {
        return 0;
    }
    const int fd = ::open("/dev/raw-gadget", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    state.raw_gadget_fd = fd;
    return 0;
}

// [当前版本 PR-1 dummy_udc per proc_slot — 2026-05-20] 详情见 hpp doc。
//
// [PR-5.2 2026-05-20] INIT/RUN 失败时把刚打开的 fd 关掉。kernel raw-gadget
// 的 dev->state 在 INIT 半途失败或 RUN 失败时会进 STATE_DEV_FAILED
// (raw_gadget.c:602),持续持有这个 fd 反复重试也无济于事 — close 让
// 下个 connect 拿一个干净的 dev_new。
int UsbInitAndRunGadget(UsbState& state, std::uint32_t proc_slot_id)
{
    if (UsbOpenRawGadget(state) < 0) {
        return -1;
    }
    struct usb_raw_init init = {};
    const char drv[] = "dummy_udc";
    std::memcpy(init.driver_name, drv, sizeof(drv) - 1);
    std::snprintf(reinterpret_cast<char*>(init.device_name),
                  sizeof(init.device_name),
                  "dummy_udc.%u",
                  static_cast<unsigned>(proc_slot_id));
    init.speed = 3;  // USB_SPEED_HIGH
    const auto fail = [&](const char* stage) {
        const int saved = errno;
        ::refuzz::worker::log::WorkerLog(
            "[usb] init_run_fail slot=%u stage=%s errno=%d\n",
            static_cast<unsigned>(proc_slot_id), stage, saved);
        ::close(state.raw_gadget_fd);
        state.raw_gadget_fd  = -1;
        state.gadget_running = false;
        errno = saved;
    };
    if (::ioctl(state.raw_gadget_fd, USB_RAW_IOCTL_INIT, &init) < 0) {
        fail("INIT");
        return -1;
    }
    if (::ioctl(state.raw_gadget_fd, USB_RAW_IOCTL_RUN, 0) < 0) {
        fail("RUN");
        return -1;
    }
    state.gadget_running = true;
    ::refuzz::worker::log::WorkerLog(
        "[usb] init_run_ok slot=%u udc=dummy_udc.%u\n",
        static_cast<unsigned>(proc_slot_id),
        static_cast<unsigned>(proc_slot_id));
    return 0;
}

int UsbDisconnectGadget(UsbState& state)
{
    if (state.raw_gadget_fd < 0) {
        errno = EINVAL;
        return -1;
    }
    // raw-gadget kernel driver auto-disconnects on close; explicit
    // disconnect ioctl is not in mainline UAPI. We just close + reset
    // state. Mirrors upstream syz_usb_disconnect behavior (no dedicated
    // ioctl in common_usb_linux.h:599; just close).
    ::close(state.raw_gadget_fd);
    state.raw_gadget_fd = -1;
    state.gadget_running = false;
    return 0;
}

int UsbipServerOpen(UsbState& state)
{
    if (state.usbip_server_fd >= 0) {
        return 0;
    }
    // Try /dev/usbip-vhci-hcd first; fall back to /sys/devices entry if
    // that fails (different kernels expose USBIP differently).
    int fd = ::open("/sys/devices/platform/vhci_hcd.0/attach", O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        fd = ::open("/sys/devices/platform/vhci_hcd.0/usbip_attach", O_WRONLY | O_CLOEXEC);
    }
    if (fd < 0) {
        return -1;
    }
    state.usbip_server_fd = fd;
    return 0;
}

} // namespace refuzz::worker::pseudo

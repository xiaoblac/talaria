#pragma once

// PR-D4 — per-program USB raw-gadget sub-context (plan §5.2 + §5.2-amendment).
//
// UsbState owns the device-emulation lifecycle shared across the 25
// syz_usb_*$ pseudos within a program:
//   * /dev/raw-gadget fd (open lazily on first connect dispatch; close on
//     teardown via Cleanup)
//   * Active flag (RUN issued vs not; controls whether subsequent
//     control_io / ep_read / ep_write / disconnect are valid)
//   * USBIP server fd (separate path — syz_usbip_server_init opens
//     /dev/usbip-vhci-hcd or similar; tracked here for reverse-cleanup)
//
// Cleanup runs in reverse-creation order via RegisterCleanup callback
// registered on first dispatch. Sub-context lookup by `&PseudoContext`
// ptr per the §5.2-amendment convention; same TU-local-map pattern as
// PR-D1 MountState + PR-D2 KvmState.

#include "worker/backend/pseudo/pseudo_context.hpp"
#include "worker/backend/pseudo/usb/usb_enumeration.hpp"

namespace refuzz::worker::pseudo {

struct UsbState {
    // /dev/raw-gadget fd. -1 means "not opened yet" (lazy on first connect).
    int raw_gadget_fd = -1;

    // True iff USB_RAW_IOCTL_RUN was successfully issued (gadget is active).
    // Subsequent control_io / ep_read / ep_write / disconnect require this.
    bool gadget_running = false;

    // /dev/usbip* fd from syz_usbip_server_init. -1 means not opened.
    // Separate from raw-gadget (different kernel module + device node).
    int usbip_server_fd = -1;

    // [PR-3] Parsed device-descriptor index built by UsbConnect from
    // caller-supplied dev bytes. Pointers reference the program scratch
    // buffer and stay valid for the duration of the program. Used by
    // control_io / ep_*/ disconnect handlers to find endpoints + provide
    // descriptor responses without re-parsing.
    UsbDeviceIndex device_index{};

    // Best-effort teardown — never throws.
    void Cleanup();
};

UsbState& GetOrCreateUsbState(const PseudoContext& ctx);

} // namespace refuzz::worker::pseudo

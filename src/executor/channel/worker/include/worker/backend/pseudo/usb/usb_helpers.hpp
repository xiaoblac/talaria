#pragma once

// PR-D4 — USB raw-gadget lifecycle helpers shared across all 25 syz_usb_*
// handlers (excluding usbip_server_init, which uses a separate device).
//
// Mirrors upstream `executor/common_usb_linux.h` at the *behavior* level
// (plan §2.1: no embedded syzkaller code). Each helper is a thin
// ioctl/syscall wrapper using the worker's existing pattern.
//
// Surface deliberately bounded — plan §8 stop condition triggers if
// the implementation surface area exceeds upstream's ~600 LOC by more
// than 50%. This file plus usb_dispatcher.cpp combined target ≤ 600 LOC
// to stay within budget.

#include <cstddef>
#include <cstdint>

namespace refuzz::worker::pseudo {

struct UsbState;

// Open /dev/raw-gadget (O_RDWR | O_CLOEXEC) and store fd in
// state.raw_gadget_fd. Idempotent: if already open, returns 0.
// Returns -1+errno on failure (handler caller surfaces as PseudoResult.err).
int UsbOpenRawGadget(UsbState& state);

// [当前版本 PR-1 dummy_udc per proc_slot — 2026-05-20]
// Synthesize a usb_raw_init payload with driver_name="dummy_udc" +
// device_name="dummy_udc.<proc_slot_id>" + speed=USB_SPEED_HIGH, issue
// USB_RAW_IOCTL_INIT, then USB_RAW_IOCTL_RUN. Sets state.gadget_running
// = true on success. Returns 0 on success, -1+errno on failure
// (state.gadget_running stays false).
//
// proc_slot_id mirrors upstream syzkaller's `dummy_udc.%llu" % procid`
// (executor/common_usb_linux.h:307) — each worker slot binds its own UDC
// instance so register doesn't race with the previous program's pending
// unbind (kernel sets match_existing_only=1 → -EBUSY when UDC busy →
// dev->state=STATE_DEV_FAILED → all subsequent ioctls EINVAL). Operator
// must load `dummy_hcd num=N` with N ≥ worker slot count for this to
// hold; insufficient num leaves matching UDCs missing and INIT will fail
// loudly rather than silently colliding.
//
// We deliberately ignore any caller-supplied "init bytes": the syz pseudo
// signature passes a usb_device_descriptor pointer in args[2], not a
// usb_raw_init struct — passing those bytes to USB_RAW_IOCTL_INIT
// produces garbage driver_name/device_name and explains the prior 88%
// EBUSY rate on connects. The 18-byte device_descriptor is meant for
// upstream's add_usb_index() bookkeeping (PR-3 scope), not INIT.
int UsbInitAndRunGadget(UsbState& state, std::uint32_t proc_slot_id);

// Issue USB_RAW_IOCTL_DISCONNECT. Best-effort — failures don't unwind
// state. Sets state.gadget_running = false unconditionally so subsequent
// pseudos don't try to drive a dead gadget. Returns 0 on success,
// -1+errno on ioctl failure.
int UsbDisconnectGadget(UsbState& state);

// Open /dev/usbip-vhci-hcd or similar USBIP entry. Stores fd in
// state.usbip_server_fd. Idempotent. Returns 0 on success, -1+errno
// otherwise.
//
// Used by syz_usbip_server_init only — separate from raw-gadget.
int UsbipServerOpen(UsbState& state);

} // namespace refuzz::worker::pseudo

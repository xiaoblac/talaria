#pragma once

// [当前版本 PR-3 USB enumeration helpers — 2026-05-20]
//
// Port of upstream syzkaller's USB device-index + enumeration helpers
// (executor/common_usb.h + executor/common_usb_linux.h). Adapted for the
// reFuzz worker:
//   * UsbDeviceIndex storage lives on UsbState (one per PseudoContext),
//     not a global fd-keyed table — matches the rest of reFuzz's pseudo
//     state convention.
//   * No add_usb_index / lookup_usb_index indirection; handlers call the
//     parser directly on UsbState::device_index.
//   * Function names PascalCase to match the rest of worker/pseudo/usb/.
//
// Surface kept narrow: parse + lookup + configure + set-interface — just
// enough for UsbConnect to drive enumeration to SET_CONFIGURATION and for
// post-connect handlers (control_io / ep_*) to find endpoints by address.

#include <cstddef>
#include <cstdint>

#include <linux/usb/ch9.h>

namespace refuzz::worker::pseudo {

struct UsbState;

constexpr int kUsbMaxIfaceNum = 4;
constexpr int kUsbMaxEpNum    = 32;

struct UsbEndpointIndex {
    struct usb_endpoint_descriptor desc{};
    // Raw-gadget endpoint handle as returned by USB_RAW_IOCTL_EP_ENABLE.
    // Stays at the sentinel below until SetInterface enables this ep.
    int handle = -1;
};

struct UsbIfaceIndex {
    struct usb_interface_descriptor* iface = nullptr;
    std::uint8_t bInterfaceNumber  = 0;
    std::uint8_t bAlternateSetting = 0;
    std::uint8_t bInterfaceClass   = 0;
    UsbEndpointIndex eps[kUsbMaxEpNum]{};
    int eps_num = 0;
};

struct UsbDeviceIndex {
    bool parsed = false;
    // Pointers into the caller-supplied "dev" buffer (program scratch).
    // The buffer lives for the whole program → safe to hold across
    // multiple pseudo dispatches within one program.
    struct usb_device_descriptor* dev    = nullptr;
    struct usb_config_descriptor* config = nullptr;
    std::uint8_t bDeviceClass            = 0;
    std::uint8_t bMaxPower               = 0;
    int          config_length           = 0;
    UsbIfaceIndex ifaces[kUsbMaxIfaceNum]{};
    int          ifaces_num              = 0;
    int          iface_cur               = -1;
};

// Parse a syz-supplied device-descriptor blob: first sizeof(usb_device_descriptor)
// bytes are the device desc, followed by one or more config_desc + interface_desc
// + endpoint_desc records (TLV walk by desc_length). Stores pointers + bookkeeping
// in `idx`. Returns true on success; false on buffer too short / malformed.
bool UsbParseDescriptor(const std::uint8_t* buffer, std::size_t length,
                        UsbDeviceIndex& idx);

// ─── syz_usb_connect conn_descs wire layout (args[3]) ───────────────
// Byte-equal mirror of upstream `vusb_connect_descriptors`
// (executor/common_usb.h:556-568). The caller fuzz program supplies args[3] as
// a pointer to this packed struct; the inner `qual`/`bos`/`str` pointers are
// resolved by the executor's arg copyin (same as control_io's VusbDescriptors).
// Either the whole struct or any inner pointer may be null. Used by
// UsbLookupConnectResponseIn to answer BOS / DEVICE_QUALIFIER / STRING.
struct VusbConnectStringDescriptor {
    std::uint32_t len;
    char*         str;
} __attribute__((packed));

struct VusbConnectDescriptors {
    std::uint32_t                qual_len;
    char*                        qual;
    std::uint32_t                bos_len;
    char*                        bos;
    std::uint32_t                strs_len;
    VusbConnectStringDescriptor  strs[0];
} __attribute__((packed));

// Build a response to an IN control transfer based on bRequest / wValue. On
// match, sets *response_data + *response_length to point into the caller-supplied
// device-descriptor buffer (or into qual_storage for synthesized DEVICE_QUALIFIER)
// and returns true. Returns false on unknown request (caller should STALL).
//
// `descs` (args[3], may be nullptr) supplies the caller's BOS / DEVICE_QUALIFIER /
// per-index STRING descriptors, mirroring upstream lookup_connect_response_in
// (common_usb.h:587). qual_storage is a caller-owned scratch struct used only
// when synthesizing a DEVICE_QUALIFIER on the fly (no caller-supplied qual).
bool UsbLookupConnectResponseIn(const UsbDeviceIndex& idx,
                                const VusbConnectDescriptors* descs,
                                const struct usb_ctrlrequest& ctrl,
                                struct usb_qualifier_descriptor& qual_storage,
                                const std::uint8_t** response_data,
                                std::uint32_t* response_length);

// Process an OUT control transfer. For "generic" devices, SET_CONFIGURATION
// terminates the enumeration loop (*done = true). Returns false on unknown
// request (caller should STALL).
bool UsbLookupConnectResponseOutGeneric(const struct usb_ctrlrequest& ctrl,
                                        bool* done);

// ath9k variant: vendor firmware-download requests terminate the loop.
// SET_CONFIGURATION is acknowledged but does NOT set done (matches upstream
// common_usb_linux.h:700-727).
bool UsbLookupConnectResponseOutAth9k(const struct usb_ctrlrequest& ctrl,
                                      bool* done);

// VBUS_DRAW + CONFIGURE + SetInterface(0). Mirrors upstream
// configure_device in common_usb_linux.h:247-266.
int UsbConfigureDevice(int fd, UsbDeviceIndex& idx);

// EP_DISABLE previous alt-setting's endpoints (if any), then EP_ENABLE the
// new alt-setting's endpoints. n is an index into idx.ifaces, not a wire
// interface number.
void UsbSetInterface(int fd, UsbDeviceIndex& idx, int n);

// Resolve a wire (bInterfaceNumber, bAlternateSetting) pair to an index
// into idx.ifaces. Returns -1 if not found. Used by control_io's
// SET_INTERFACE handling.
int UsbLookupInterface(const UsbDeviceIndex& idx,
                       std::uint8_t bInterfaceNumber,
                       std::uint8_t bAlternateSetting);

// Resolve a wire bEndpointAddress to the raw-gadget endpoint handle
// (returned by USB_RAW_IOCTL_EP_ENABLE) for the current interface.
// Returns -1 if no current interface set or address not found.
int UsbLookupEndpoint(const UsbDeviceIndex& idx,
                      std::uint8_t bEndpointAddress);

// ─── syz_usb_control_io descs / resps wire layout ───────────────────
// Byte-equal mirror of upstream `executor/common_usb.h:733-757`. The
// caller fuzz program supplies args[1] / args[2] as pointers to these
// structs in scratch memory; layout must match what syzlang vusb_descriptors
// / vusb_responses describe (packed, len-prefixed, flexible array tail).
//
// Notes:
//   * `len` is the **total byte size** of the struct including the array
//     tail — the number of entries is computed by upstream as:
//        descs_num = (descs->len - offsetof(struct vusb_descriptors, descs))
//                    / sizeof(descs->descs[0]);
//   * Each `descs[i]` / `resps[i]` is itself a pointer to a packed payload
//     struct (also length-prefixed). The payload's `data[]` tail is the
//     bytes that get written back as the IN-control-transfer response.
//   * `generic` is a fallback descriptor / response served if no entry
//     matches the (req_type, desc_type) / (type, req) tuple.
struct VusbDescriptorPayload {
    std::uint8_t  req_type;
    std::uint8_t  desc_type;
    std::uint32_t len;
    char          data[0];
} __attribute__((packed));

struct VusbDescriptors {
    std::uint32_t                  len;
    VusbDescriptorPayload*         generic;
    VusbDescriptorPayload*         descs[0];
} __attribute__((packed));

struct VusbResponsePayload {
    std::uint8_t  type;
    std::uint8_t  req;
    std::uint32_t len;
    char          data[0];
} __attribute__((packed));

struct VusbResponses {
    std::uint32_t                  len;
    VusbResponsePayload*           generic;
    VusbResponsePayload*           resps[0];
} __attribute__((packed));

// Build a response for an IN CONTROL transfer by walking `descs` (for
// GET_DESCRIPTOR) or `resps` (for everything else), with fallback to
// `generic`. Mirrors upstream `lookup_control_response` (common_usb.h:765).
// Either argument may be nullptr (treated as empty). Returns true on match;
// on false caller should STALL EP0.
bool UsbLookupControlResponse(const VusbDescriptors* descs,
                              const VusbResponses* resps,
                              const struct usb_ctrlrequest& ctrl,
                              const std::uint8_t** response_data,
                              std::uint32_t* response_length);

} // namespace refuzz::worker::pseudo

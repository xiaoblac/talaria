// [当前版本 PR-3 USB enumeration helpers — 2026-05-20]
//
// Implementation. Port of upstream syzkaller's enumeration plumbing —
// see usb_enumeration.hpp for the rationale + scope notes.

#include "worker/backend/pseudo/usb/usb_enumeration.hpp"
#include "worker/log/log_macros.hpp"

#include <cerrno>
#include <cstring>
#include <sys/ioctl.h>

#include <linux/usb/raw_gadget.h>

namespace refuzz::worker::pseudo {

namespace {

// Default minimal STRING descriptors mirrored from upstream
// common_usb.h:572-580.
constexpr std::uint8_t kDefaultLangId[] = {
    4, USB_DT_STRING,
    0x09, 0x04,   // English (United States)
};
constexpr std::uint8_t kDefaultString[] = {
    8, USB_DT_STRING,
    's', 0, 'y', 0, 'z', 0,   // UTF-16LE "syz"
};

}  // namespace

bool UsbParseDescriptor(const std::uint8_t* buffer, std::size_t length,
                        UsbDeviceIndex& idx)
{
    if (buffer == nullptr ||
        length < sizeof(struct usb_device_descriptor) +
                     sizeof(struct usb_config_descriptor)) {
        ::refuzz::worker::log::WorkerLog(
            "[usb] parse_descriptor_fail reason=short_buffer "
            "dev_len=%zu min=%zu buf_null=%d\n",
            length,
            sizeof(struct usb_device_descriptor) +
                sizeof(struct usb_config_descriptor),
            buffer == nullptr ? 1 : 0);
        return false;
    }

    idx = {};   // reset bookkeeping
    idx.dev = const_cast<struct usb_device_descriptor*>(
        reinterpret_cast<const struct usb_device_descriptor*>(buffer));
    idx.config = const_cast<struct usb_config_descriptor*>(
        reinterpret_cast<const struct usb_config_descriptor*>(
            buffer + sizeof(struct usb_device_descriptor)));
    idx.bDeviceClass   = idx.dev->bDeviceClass;
    idx.bMaxPower      = idx.config->bMaxPower;
    idx.config_length  = static_cast<int>(
        length - sizeof(struct usb_device_descriptor));
    idx.iface_cur      = -1;

    std::size_t offset = 0;
    while (true) {
        if (offset + 1 >= length) {
            break;
        }
        const std::uint8_t desc_length = buffer[offset];
        const std::uint8_t desc_type   = buffer[offset + 1];
        if (desc_length <= 2) {
            break;
        }
        if (offset + desc_length > length) {
            break;
        }
        if (desc_type == USB_DT_INTERFACE &&
            idx.ifaces_num < kUsbMaxIfaceNum) {
            auto* iface = const_cast<struct usb_interface_descriptor*>(
                reinterpret_cast<const struct usb_interface_descriptor*>(
                    buffer + offset));
            auto& slot = idx.ifaces[idx.ifaces_num];
            slot.iface             = iface;
            slot.bInterfaceNumber  = iface->bInterfaceNumber;
            slot.bAlternateSetting = iface->bAlternateSetting;
            slot.bInterfaceClass   = iface->bInterfaceClass;
            ++idx.ifaces_num;
        }
        if (desc_type == USB_DT_ENDPOINT && idx.ifaces_num > 0) {
            auto& iface = idx.ifaces[idx.ifaces_num - 1];
            if (iface.eps_num < kUsbMaxEpNum) {
                std::memcpy(&iface.eps[iface.eps_num].desc,
                            buffer + offset,
                            sizeof(iface.eps[iface.eps_num].desc));
                ++iface.eps_num;
            }
        }
        offset += desc_length;
    }

    idx.parsed = true;
    int total_eps = 0;
    for (int i = 0; i < idx.ifaces_num; ++i) {
        total_eps += idx.ifaces[i].eps_num;
    }
    ::refuzz::worker::log::WorkerLog(
        "[usb] parse_descriptor_ok dev_len=%zu n_ifaces=%d n_eps_total=%d "
        "idVendor=0x%04x idProduct=0x%04x bMaxPower=%u\n",
        length, idx.ifaces_num, total_eps,
        static_cast<unsigned>(idx.dev->idVendor),
        static_cast<unsigned>(idx.dev->idProduct),
        static_cast<unsigned>(idx.bMaxPower));
    return true;
}

bool UsbLookupConnectResponseIn(const UsbDeviceIndex& idx,
                                const VusbConnectDescriptors* descs,
                                const struct usb_ctrlrequest& ctrl,
                                struct usb_qualifier_descriptor& qual_storage,
                                const std::uint8_t** response_data,
                                std::uint32_t* response_length)
{
    if (!idx.parsed) {
        return false;
    }
    // Mirror of upstream lookup_connect_response_in (common_usb.h:587-663):
    // STANDARD GET_DESCRIPTOR for DEVICE / CONFIG / STRING / BOS /
    // DEVICE_QUALIFIER, drawing BOS / per-index STRING / QUALIFIER from the
    // caller-supplied conn_descs (args[3]) when present. CLASS/VENDOR requests
    // during connect are still unknown here (STALL) — those are serviced by
    // syz_usb_control_io.
    if ((ctrl.bRequestType & USB_TYPE_MASK) != USB_TYPE_STANDARD) {
        return false;
    }
    if (ctrl.bRequest != USB_REQ_GET_DESCRIPTOR) {
        return false;
    }
    const std::uint8_t desc_type = static_cast<std::uint8_t>(ctrl.wValue >> 8);
    switch (desc_type) {
    case USB_DT_DEVICE:
        *response_data   = reinterpret_cast<const std::uint8_t*>(idx.dev);
        *response_length = sizeof(*idx.dev);
        return true;
    case USB_DT_CONFIG:
        *response_data   = reinterpret_cast<const std::uint8_t*>(idx.config);
        *response_length = static_cast<std::uint32_t>(idx.config_length);
        return true;
    case USB_DT_STRING: {
        const std::uint8_t str_idx = static_cast<std::uint8_t>(ctrl.wValue);
        // Caller-supplied string at this index wins (upstream common_usb.h:613).
        if (descs != nullptr && str_idx < descs->strs_len &&
            descs->strs[str_idx].str != nullptr) {
            *response_data =
                reinterpret_cast<const std::uint8_t*>(descs->strs[str_idx].str);
            *response_length = descs->strs[str_idx].len;
            return true;
        }
        if (str_idx == 0) {
            *response_data   = kDefaultLangId;
            *response_length = kDefaultLangId[0];
            return true;
        }
        *response_data   = kDefaultString;
        *response_length = kDefaultString[0];
        return true;
    }
    case USB_DT_BOS:
        // upstream common_usb.h:626-629 — answer from conn_descs (an absent/empty
        // BOS yields a zero-length response, NOT a STALL). Only STALL if the
        // program supplied no conn_descs at all.
        if (descs == nullptr) {
            return false;
        }
        *response_data   = reinterpret_cast<const std::uint8_t*>(descs->bos);
        *response_length = descs->bos_len;
        return true;
    case USB_DT_DEVICE_QUALIFIER: {
        // Caller-supplied qualifier wins; else synthesize from DEVICE
        // (upstream common_usb.h:630-648).
        if (descs != nullptr && descs->qual != nullptr) {
            *response_data   = reinterpret_cast<const std::uint8_t*>(descs->qual);
            *response_length = descs->qual_len;
            return true;
        }
        qual_storage.bLength             = sizeof(qual_storage);
        qual_storage.bDescriptorType     = USB_DT_DEVICE_QUALIFIER;
        qual_storage.bcdUSB              = idx.dev->bcdUSB;
        qual_storage.bDeviceClass        = idx.dev->bDeviceClass;
        qual_storage.bDeviceSubClass     = idx.dev->bDeviceSubClass;
        qual_storage.bDeviceProtocol     = idx.dev->bDeviceProtocol;
        qual_storage.bMaxPacketSize0     = idx.dev->bMaxPacketSize0;
        qual_storage.bNumConfigurations  = idx.dev->bNumConfigurations;
        qual_storage.bRESERVED           = 0;
        *response_data   = reinterpret_cast<const std::uint8_t*>(&qual_storage);
        *response_length = sizeof(qual_storage);
        return true;
    }
    default:
        return false;
    }
}

bool UsbLookupConnectResponseOutGeneric(const struct usb_ctrlrequest& ctrl,
                                        bool* done)
{
    if ((ctrl.bRequestType & USB_TYPE_MASK) != USB_TYPE_STANDARD) {
        return false;
    }
    if (ctrl.bRequest == USB_REQ_SET_CONFIGURATION) {
        *done = true;
        return true;
    }
    return false;
}

// drivers/net/wireless/ath/ath9k/hif_usb.h
namespace {
constexpr std::uint8_t kAth9kFirmwareDownload     = 0x30;
constexpr std::uint8_t kAth9kFirmwareDownloadComp = 0x31;
}  // namespace

bool UsbLookupConnectResponseOutAth9k(const struct usb_ctrlrequest& ctrl,
                                      bool* done)
{
    switch (ctrl.bRequestType & USB_TYPE_MASK) {
    case USB_TYPE_STANDARD:
        if (ctrl.bRequest == USB_REQ_SET_CONFIGURATION) {
            return true;
        }
        return false;
    case USB_TYPE_VENDOR:
        if (ctrl.bRequest == kAth9kFirmwareDownload) {
            return true;
        }
        if (ctrl.bRequest == kAth9kFirmwareDownloadComp) {
            *done = true;
            return true;
        }
        return false;
    default:
        return false;
    }
}

namespace {

int IoctlEpEnable(int fd, struct usb_endpoint_descriptor* desc)
{
    return ::ioctl(fd, USB_RAW_IOCTL_EP_ENABLE, desc);
}

int IoctlEpDisable(int fd, std::uint32_t handle)
{
    return ::ioctl(fd, USB_RAW_IOCTL_EP_DISABLE, handle);
}

}  // namespace

void UsbSetInterface(int fd, UsbDeviceIndex& idx, int n)
{
    if (idx.iface_cur >= 0 && idx.iface_cur < idx.ifaces_num) {
        auto& cur = idx.ifaces[idx.iface_cur];
        for (int ep = 0; ep < cur.eps_num; ++ep) {
            if (cur.eps[ep].handle >= 0) {
                (void)IoctlEpDisable(
                    fd, static_cast<std::uint32_t>(cur.eps[ep].handle));
                cur.eps[ep].handle = -1;
            }
        }
    }
    if (n >= 0 && n < idx.ifaces_num) {
        auto& iface = idx.ifaces[n];
        int enabled = 0;
        for (int ep = 0; ep < iface.eps_num; ++ep) {
            const int rv = IoctlEpEnable(fd, &iface.eps[ep].desc);
            if (rv >= 0) {
                iface.eps[ep].handle = rv;
                ++enabled;
            } else {
                ::refuzz::worker::log::WorkerLog(
                    "[usb] ep_enable_fail iface_idx=%d ep_idx=%d "
                    "ep_addr=0x%02x errno=%d\n",
                    n, ep,
                    static_cast<unsigned>(
                        iface.eps[ep].desc.bEndpointAddress),
                    errno);
            }
        }
        idx.iface_cur = n;
        ::refuzz::worker::log::WorkerLog(
            "[usb] set_interface iface_idx=%d iface_num=%u alt=%u "
            "eps_total=%d eps_enabled=%d\n",
            n,
            static_cast<unsigned>(iface.bInterfaceNumber),
            static_cast<unsigned>(iface.bAlternateSetting),
            iface.eps_num, enabled);
    }
}

int UsbConfigureDevice(int fd, UsbDeviceIndex& idx)
{
    if (!idx.parsed) {
        errno = EINVAL;
        return -1;
    }
    // VBUS_DRAW is _IOW(__u32) but kernel raw_ioctl_vbus_draw uses
    // `unsigned long value` directly as the power level (raw_gadget.c:1223
    // — `usb_gadget_vbus_draw(dev->gadget, 2 * value)`). Pass by value, NOT
    // by pointer. Upstream usb_raw_vbus_draw does the same
    // (common_usb_linux.h:126-129).
    if (::ioctl(fd, USB_RAW_IOCTL_VBUS_DRAW,
                static_cast<unsigned long>(idx.bMaxPower)) < 0) {
        ::refuzz::worker::log::WorkerLog(
            "[usb] vbus_draw_fail power=%u errno=%d\n",
            static_cast<unsigned>(idx.bMaxPower), errno);
        return -1;
    }
    if (::ioctl(fd, USB_RAW_IOCTL_CONFIGURE, 0) < 0) {
        ::refuzz::worker::log::WorkerLog(
            "[usb] configure_fail errno=%d\n", errno);
        return -1;
    }
    UsbSetInterface(fd, idx, 0);
    return 0;
}

int UsbLookupInterface(const UsbDeviceIndex& idx,
                       std::uint8_t bInterfaceNumber,
                       std::uint8_t bAlternateSetting)
{
    for (int i = 0; i < idx.ifaces_num; ++i) {
        if (idx.ifaces[i].bInterfaceNumber == bInterfaceNumber &&
            idx.ifaces[i].bAlternateSetting == bAlternateSetting) {
            return i;
        }
    }
    return -1;
}

int UsbLookupEndpoint(const UsbDeviceIndex& idx,
                      std::uint8_t bEndpointAddress)
{
    if (idx.iface_cur < 0 || idx.iface_cur >= idx.ifaces_num) {
        return -1;
    }
    const auto& iface = idx.ifaces[idx.iface_cur];
    for (int ep = 0; ep < iface.eps_num; ++ep) {
        if (iface.eps[ep].desc.bEndpointAddress == bEndpointAddress) {
            return iface.eps[ep].handle;
        }
    }
    return -1;
}

// 镜像上游 lookup_control_response (common_usb.h:765-826)。逐字段对齐:
//   req_type = ctrl.bRequestType & USB_TYPE_MASK
//   desc_type = ctrl.wValue >> 8
//   USB_REQ_GET_DESCRIPTOR → walk descs[]; 否则 walk resps[]
//   匹配:(req_type, desc_type) for descs;(type, req) for resps
//   未匹配 → fallback generic 兜底;再未匹配 → false (caller STALL)
//
// 长度计算逻辑严格保留:`(struct.len - offsetof(struct, array)) / sizeof(ptr)`。
// caller (UsbControlIo) 必须保证 descs/resps 指针有效或 nullptr。
bool UsbLookupControlResponse(const VusbDescriptors* descs,
                              const VusbResponses* resps,
                              const struct usb_ctrlrequest& ctrl,
                              const std::uint8_t** response_data,
                              std::uint32_t* response_length)
{
    int descs_num = 0;
    int resps_num = 0;

    if (descs != nullptr) {
        const std::size_t base = offsetof(VusbDescriptors, descs);
        if (descs->len > base) {
            descs_num = static_cast<int>(
                (descs->len - base) / sizeof(descs->descs[0]));
        }
    }
    if (resps != nullptr) {
        const std::size_t base = offsetof(VusbResponses, resps);
        if (resps->len > base) {
            resps_num = static_cast<int>(
                (resps->len - base) / sizeof(resps->resps[0]));
        }
    }

    const std::uint8_t req       = ctrl.bRequest;
    const std::uint8_t req_type  = ctrl.bRequestType & USB_TYPE_MASK;
    const std::uint8_t desc_type = static_cast<std::uint8_t>(ctrl.wValue >> 8);

    if (req == USB_REQ_GET_DESCRIPTOR) {
        for (int i = 0; i < descs_num; ++i) {
            const VusbDescriptorPayload* desc = descs->descs[i];
            if (desc == nullptr) continue;
            if (desc->req_type == req_type && desc->desc_type == desc_type) {
                *response_length = desc->len;
                *response_data = (desc->len != 0)
                    ? reinterpret_cast<const std::uint8_t*>(&desc->data[0])
                    : nullptr;
                return true;
            }
        }
        if (descs != nullptr && descs->generic != nullptr) {
            *response_data =
                reinterpret_cast<const std::uint8_t*>(&descs->generic->data[0]);
            *response_length = descs->generic->len;
            return true;
        }
        return false;
    }

    for (int i = 0; i < resps_num; ++i) {
        const VusbResponsePayload* resp = resps->resps[i];
        if (resp == nullptr) continue;
        if (resp->type == req_type && resp->req == req) {
            *response_length = resp->len;
            *response_data = (resp->len != 0)
                ? reinterpret_cast<const std::uint8_t*>(&resp->data[0])
                : nullptr;
            return true;
        }
    }
    if (resps != nullptr && resps->generic != nullptr) {
        *response_data =
            reinterpret_cast<const std::uint8_t*>(&resps->generic->data[0]);
        *response_length = resps->generic->len;
        return true;
    }
    return false;
}

}  // namespace refuzz::worker::pseudo

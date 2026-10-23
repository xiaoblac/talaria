// Port of upstream sys/linux/init_vusb.go.
//
// Three SpecialType bodies share the same skeleton:
//   1. generate_special_arg → default-walk USB descriptor struct
//   2. ArgContainsAny short-circuit (squash artifact, no patching)
//   3. patch USB IDs into idVendor / idProduct / class / subclass /
//      protocol / interface fields, sourced from the per-driver USB
//      ID database in usb_ids.gen.cpp (regenerated from upstream's
//      sys/linux/init_vusb_ids.go via tools/syz_usbgen_emit).
//
// Without (3) the descriptors are schema-valid but won't match any
// real Linux USB driver's match table — the kernel's USB probe path
// won't fire, and most USB driver code is unreachable. Step (3) is
// where this body actually earns its keep; it's the same dance
// upstream does in init_vusb.go::patchUsbDeviceID +
// randUsbDeviceID + patchGroupArg.
//
// Soft-fail discipline (plan §8 stop condition): every type-cast
// and field-name check is defensive. A schema mismatch (e.g.,
// upstream changed an inner index or renamed a field) yields a
// no-op patch instead of an abort, mirroring the plan's "any of the
// 14 SpecialType bodies surfacing a schema mismatch — soft-fail
// rather than abort" rule.

#include "refuzz/program/syz/any.hpp"
#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/linux/generated/usb_ids.gen.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/type.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace refuzz::program::syz::linux_special_types {

namespace {

// USB_DEVICE_ID match-flag bits — mirror init_vusb.go:14-25.
constexpr std::uint16_t kMatchVendor      = 1u << 0;
constexpr std::uint16_t kMatchProduct     = 1u << 1;
constexpr std::uint16_t kMatchDevLo       = 1u << 2;
constexpr std::uint16_t kMatchDevHi       = 1u << 3;
constexpr std::uint16_t kMatchDevClass    = 1u << 4;
constexpr std::uint16_t kMatchDevSubClass = 1u << 5;
constexpr std::uint16_t kMatchDevProto    = 1u << 6;
constexpr std::uint16_t kMatchIntClass    = 1u << 7;
constexpr std::uint16_t kMatchIntSubClass = 1u << 8;
constexpr std::uint16_t kMatchIntProtocol = 1u << 9;
constexpr std::uint16_t kMatchIntNumber   = 1u << 10;

constexpr std::size_t kBytesPerUsbId = 17;
constexpr std::size_t kBytesPerHidId = 12;

struct UsbDeviceID {
    std::uint16_t match_flags;
    std::uint16_t id_vendor;
    std::uint16_t id_product;
    std::uint16_t bcd_device_lo;
    std::uint16_t bcd_device_hi;
    std::uint8_t  b_device_class;
    std::uint8_t  b_device_sub_class;
    std::uint8_t  b_device_protocol;
    std::uint8_t  b_interface_class;
    std::uint8_t  b_interface_sub_class;
    std::uint8_t  b_interface_protocol;
    std::uint8_t  b_interface_number;
};

std::uint16_t read_u16_le(const std::uint8_t* p) {
    return static_cast<std::uint16_t>(p[0]) |
           (static_cast<std::uint16_t>(p[1]) << 8);
}

UsbDeviceID parse_usb_device_id(const std::string& blob, std::size_t offset) {
    const std::uint8_t* p =
        reinterpret_cast<const std::uint8_t*>(blob.data()) + offset;
    UsbDeviceID id{};
    id.match_flags           = read_u16_le(p + 0);
    id.id_vendor             = read_u16_le(p + 2);
    id.id_product            = read_u16_le(p + 4);
    id.bcd_device_lo         = read_u16_le(p + 6);
    id.bcd_device_hi         = read_u16_le(p + 8);
    id.b_device_class        = p[10];
    id.b_device_sub_class    = p[11];
    id.b_device_protocol     = p[12];
    id.b_interface_class     = p[13];
    id.b_interface_sub_class = p[14];
    id.b_interface_protocol  = p[15];
    id.b_interface_number    = p[16];
    return id;
}

// Mirror of init_vusb.go::patchGroupArg (lines 246-253). Walks a
// GroupArg's inner[index] slot, soft-fails on type / index / name
// mismatch, sets the underlying ConstArg's val on success.
bool patch_group_arg(Arg* arg, std::size_t index,
                     const std::string& field, std::uint64_t value) {
    if (arg == nullptr || arg->arg_kind() != ArgKind::kGroup) return false;
    auto* ga = static_cast<GroupArg*>(arg);
    const Type* t = ga->type();
    if (t == nullptr || t->kind() != TypeKind::kStruct) return false;
    const auto* st = static_cast<const StructType*>(t);
    if (index >= st->fields().size()) return false;
    if (st->fields()[index].name() != field) return false;
    auto& inner = ga->mutable_inner();
    if (index >= inner.size()) return false;
    Arg* slot = inner[index].get();
    if (slot == nullptr || slot->arg_kind() != ArgKind::kConst) return false;
    static_cast<ConstArg*>(slot)->set_val(value);
    return true;
}

// Mirror of init_vusb.go::randUsbDeviceID (lines 164-215). Picks a
// 17-byte record at random from the binary blob, then fills in the
// non-matching slots with random values when patch_non_matching is
// true (so every patched field has a defined value, not just the
// match-flag-claimed ones).
UsbDeviceID rand_usb_device_id(Target::IGen* g, const std::string& ids,
                               bool patch_non_matching) {
    const std::size_t total = ids.size() / kBytesPerUsbId;
    UsbDeviceID id{};
    if (total == 0) return id;
    const std::size_t idx =
        static_cast<std::size_t>(g->rand(static_cast<int>(total)));
    id = parse_usb_device_id(ids, idx * kBytesPerUsbId);
    if (!patch_non_matching) return id;

    if ((id.match_flags & kMatchVendor) == 0) {
        id.id_vendor = static_cast<std::uint16_t>(g->rand(0xffff + 1));
    }
    if ((id.match_flags & kMatchProduct) == 0) {
        id.id_product = static_cast<std::uint16_t>(g->rand(0xffff + 1));
    }
    if ((id.match_flags & kMatchDevLo) == 0) {
        id.bcd_device_lo = 0x0;
    }
    if ((id.match_flags & kMatchDevHi) == 0) {
        id.bcd_device_hi = 0xffff;
    }
    if ((id.match_flags & kMatchDevClass) == 0) {
        id.b_device_class = static_cast<std::uint8_t>(g->rand(0xff + 1));
    }
    if ((id.match_flags & kMatchDevSubClass) == 0) {
        id.b_device_sub_class = static_cast<std::uint8_t>(g->rand(0xff + 1));
    }
    if ((id.match_flags & kMatchDevProto) == 0) {
        id.b_device_protocol = static_cast<std::uint8_t>(g->rand(0xff + 1));
    }
    if ((id.match_flags & kMatchIntClass) == 0) {
        id.b_interface_class = static_cast<std::uint8_t>(g->rand(0xff + 1));
    }
    if ((id.match_flags & kMatchIntSubClass) == 0) {
        id.b_interface_sub_class = static_cast<std::uint8_t>(g->rand(0xff + 1));
    }
    if ((id.match_flags & kMatchIntProtocol) == 0) {
        id.b_interface_protocol = static_cast<std::uint8_t>(g->rand(0xff + 1));
    }
    if ((id.match_flags & kMatchIntNumber) == 0) {
        id.b_interface_number = static_cast<std::uint8_t>(g->rand(0xff + 1));
    }
    return id;
}

// Mirror of init_vusb.go::patchUsbDeviceID (lines 115-162). Walks the
// usb_device_descriptor GroupArg root → dev → configurations[0] →
// configuration → interfaces[i] → settings[0], patching idVendor /
// idProduct / bcdDevice / class / subclass / protocol / interface
// number from a randomly picked UsbDeviceID record. Soft-fails on
// any structural mismatch.
void patch_usb_device_id(Target::IGen* g, Arg* arg,
                         const std::string& ids,
                         bool patch_non_matching) {
    if (arg == nullptr || arg->arg_kind() != ArgKind::kGroup) return;
    auto* root = static_cast<GroupArg*>(arg);
    if (root->mutable_inner().empty()) return;
    Arg* dev_arg = root->mutable_inner()[0].get();
    if (dev_arg == nullptr) return;

    UsbDeviceID id = rand_usb_device_id(g, ids, patch_non_matching);

    if ((id.match_flags & kMatchVendor) != 0 || patch_non_matching) {
        patch_group_arg(dev_arg, 7, "idVendor", id.id_vendor);
    }
    if ((id.match_flags & kMatchProduct) != 0 || patch_non_matching) {
        patch_group_arg(dev_arg, 8, "idProduct", id.id_product);
    }
    if ((id.match_flags & kMatchDevLo) != 0 ||
        (id.match_flags & kMatchDevHi) != 0 || patch_non_matching) {
        // Mirror init_vusb.go:127 verbatim: uint16 wrap on subtraction
        // (so hi<lo yields a large unsigned span, not zero), +1 keeps
        // the rand argument ≥ 1.  The static_cast<uint16_t> is needed
        // because C++ promotes uint16 operands to int for arithmetic;
        // without it, hi<lo would produce a negative int and break the
        // wrap behavior upstream relies on.
        const std::uint16_t diff =
            static_cast<std::uint16_t>(id.bcd_device_hi - id.bcd_device_lo);
        const std::uint16_t bcd = id.bcd_device_lo +
            static_cast<std::uint16_t>(g->rand(static_cast<int>(diff) + 1));
        patch_group_arg(dev_arg, 9, "bcdDevice", bcd);
    }
    if ((id.match_flags & kMatchDevClass) != 0 || patch_non_matching) {
        patch_group_arg(dev_arg, 3, "bDeviceClass", id.b_device_class);
    }
    if ((id.match_flags & kMatchDevSubClass) != 0 || patch_non_matching) {
        patch_group_arg(dev_arg, 4, "bDeviceSubClass", id.b_device_sub_class);
    }
    if ((id.match_flags & kMatchDevProto) != 0 || patch_non_matching) {
        patch_group_arg(dev_arg, 5, "bDeviceProtocol", id.b_device_protocol);
    }

    // Walk dev_arg → inner[14] (configurations array) → [0] (first
    // config) → inner[0] (config struct) → inner[8] (interfaces).
    // Each step is type-checked and soft-fails on mismatch.
    if (dev_arg->arg_kind() != ArgKind::kGroup) return;
    auto* dev_g = static_cast<GroupArg*>(dev_arg);
    if (dev_g->mutable_inner().size() < 15) return;
    Arg* configs_arg = dev_g->mutable_inner()[14].get();
    if (configs_arg == nullptr ||
        configs_arg->arg_kind() != ArgKind::kGroup) return;
    auto* configs_g = static_cast<GroupArg*>(configs_arg);
    if (configs_g->mutable_inner().empty()) return;
    Arg* first_config = configs_g->mutable_inner()[0].get();
    if (first_config == nullptr ||
        first_config->arg_kind() != ArgKind::kGroup) return;
    auto* first_g = static_cast<GroupArg*>(first_config);
    if (first_g->mutable_inner().empty()) return;
    Arg* config_arg = first_g->mutable_inner()[0].get();
    if (config_arg == nullptr ||
        config_arg->arg_kind() != ArgKind::kGroup) return;
    auto* config_g = static_cast<GroupArg*>(config_arg);
    if (config_g->mutable_inner().size() < 9) return;
    Arg* interfaces_arg = config_g->mutable_inner()[8].get();
    if (interfaces_arg == nullptr ||
        interfaces_arg->arg_kind() != ArgKind::kGroup) return;

    auto* ifaces_g = static_cast<GroupArg*>(interfaces_arg);
    auto& iface_list = ifaces_g->mutable_inner();
    for (std::size_t i = 0; i < iface_list.size(); ++i) {
        Arg* iface = iface_list[i].get();
        if (iface == nullptr || iface->arg_kind() != ArgKind::kGroup) continue;
        auto* iface_g = static_cast<GroupArg*>(iface);
        if (iface_g->mutable_inner().empty()) continue;
        Arg* iface_inner = iface_g->mutable_inner()[0].get();
        if (iface_inner == nullptr) continue;
        if (i > 0) {
            // Generate fresh IDs for every interface beyond the first
            // (mirror init_vusb.go:147).
            id = rand_usb_device_id(g, ids, patch_non_matching);
        }
        if ((id.match_flags & kMatchDevClass) != 0 || patch_non_matching) {
            patch_group_arg(iface_inner, 5, "bInterfaceClass",
                            id.b_interface_class);
        }
        if ((id.match_flags & kMatchDevSubClass) != 0 || patch_non_matching) {
            patch_group_arg(iface_inner, 6, "bInterfaceSubClass",
                            id.b_interface_sub_class);
        }
        if ((id.match_flags & kMatchDevProto) != 0 || patch_non_matching) {
            patch_group_arg(iface_inner, 7, "bInterfaceProtocol",
                            id.b_interface_protocol);
        }
        if ((id.match_flags & kMatchIntNumber) != 0 || patch_non_matching) {
            patch_group_arg(iface_inner, 2, "bInterfaceNumber",
                            id.b_interface_number);
        }
    }
}

// =========================================================================
// Body variants — three usb_device_descriptor* SpecialType entries.
// =========================================================================

// Shared prelude: default-walk arg + ArgContainsAny squash short-circuit.
// Returns the arg (or nullptr) to the caller's local for further patching.
std::unique_ptr<Arg>
prelude(Target::IGen* g, const Type* typ, Dir dir,
        std::vector<std::unique_ptr<Call>>* calls,
        bool* squashed) {
    *squashed = false;
    auto arg = g->generate_special_arg(typ, dir, calls);
    if (arg == nullptr) return nullptr;
    if (arg_contains_any(g->target(), *arg)) {
        *squashed = true;
    }
    return arg;
}

// usb_device_descriptor — default body. Patches from the full
// kUsbIdsAll pool with patchNonMatching=true so every field has a
// real value (mirror init_vusb.go:65).
std::unique_ptr<Arg>
generate_usb_device_descriptor(Target::IGen* g, const Type* typ, Dir dir,
                               const Arg* /*old*/,
                               std::vector<std::unique_ptr<Call>>* calls) {
    bool squashed = false;
    auto arg = prelude(g, typ, dir, calls, &squashed);
    if (arg == nullptr || squashed) return arg;
    patch_usb_device_id(g, arg.get(), linux_usb_ids::kUsbIdsAll,
                        /*patch_non_matching=*/true);
    return arg;
}

// usb_device_descriptor_printer — three-way coin flip mirroring
// upstream (init_vusb.go:83-110):
//   - 1/3: leave syzlang IDs as-is.
//   - 1/3 (= 1/2 of remaining): patch in USBLP_QUIRK_BIDIR or
//     USBLP_QUIRK_BAD_CLASS hardcoded vendor/product values.
//   - 1/3: patch from usbIds["usblp"] subset (patchNonMatching=false
//     so only the match-claimed fields get touched).
std::unique_ptr<Arg>
generate_usb_printer_descriptor(Target::IGen* g, const Type* typ, Dir dir,
                                const Arg* /*old*/,
                                std::vector<std::unique_ptr<Call>>* calls) {
    bool squashed = false;
    auto arg = prelude(g, typ, dir, calls, &squashed);
    if (arg == nullptr || squashed) return arg;

    // Branch 1: 1/3 leave as-is.
    if (g->one_of(3)) return arg;

    // Branch 2 & 3: drill down to dev_arg for either-path patching.
    if (arg->arg_kind() != ArgKind::kGroup) return arg;
    auto* root = static_cast<GroupArg*>(arg.get());
    if (root->mutable_inner().empty()) return arg;
    Arg* dev_arg = root->mutable_inner()[0].get();
    if (dev_arg == nullptr) return arg;

    if (g->one_of(2)) {
        // Branch 2: hardcoded printer-class quirk IDs.
        const bool bidir = g->one_of(2);
        const std::uint16_t id_vendor  = bidir ? 0x03f0 : 0x04b8;
        const std::uint16_t id_product = bidir ? 0x0004 : 0x0202;
        patch_group_arg(dev_arg, 7, "idVendor", id_vendor);
        patch_group_arg(dev_arg, 8, "idProduct", id_product);
    } else {
        // Branch 3: patch from usblp driver match table; leave
        // unmatched fields untouched (patchNonMatching=false).
        auto it = linux_usb_ids::kUsbIds.find("usblp");
        if (it != linux_usb_ids::kUsbIds.end()) {
            patch_usb_device_id(g, arg.get(), it->second,
                                /*patch_non_matching=*/false);
        }
    }
    return arg;
}

// usb_device_descriptor_hid — pulls 12-byte HidDeviceID records out
// of kHidIdsAll, patches idVendor / idProduct only (mirror
// init_vusb.go:217-244). HID records carry no match-flags layer,
// so vendor / product are always patched.
std::unique_ptr<Arg>
generate_usb_hid_descriptor(Target::IGen* g, const Type* typ, Dir dir,
                            const Arg* /*old*/,
                            std::vector<std::unique_ptr<Call>>* calls) {
    bool squashed = false;
    auto arg = prelude(g, typ, dir, calls, &squashed);
    if (arg == nullptr || squashed) return arg;

    const std::string& ids = linux_usb_ids::kHidIdsAll;
    const std::size_t total = ids.size() / kBytesPerHidId;
    if (total == 0) return arg;
    const std::size_t idx =
        static_cast<std::size_t>(g->rand(static_cast<int>(total)));
    const std::size_t off = idx * kBytesPerHidId;
    if (off + kBytesPerHidId > ids.size()) return arg;

    // HidDeviceID layout (init_vusb.go:46-51):
    //   bus(2 LE) | group(2 LE) | vendor(4 LE) | product(4 LE)
    // Only vendor + product are patched.
    const std::uint8_t* p =
        reinterpret_cast<const std::uint8_t*>(ids.data()) + off;
    const std::uint32_t vendor =
        static_cast<std::uint32_t>(p[4]) |
        (static_cast<std::uint32_t>(p[5]) << 8) |
        (static_cast<std::uint32_t>(p[6]) << 16) |
        (static_cast<std::uint32_t>(p[7]) << 24);
    const std::uint32_t product =
        static_cast<std::uint32_t>(p[8]) |
        (static_cast<std::uint32_t>(p[9]) << 8) |
        (static_cast<std::uint32_t>(p[10]) << 16) |
        (static_cast<std::uint32_t>(p[11]) << 24);

    if (arg->arg_kind() != ArgKind::kGroup) return arg;
    auto* root = static_cast<GroupArg*>(arg.get());
    if (root->mutable_inner().empty()) return arg;
    Arg* dev_arg = root->mutable_inner()[0].get();
    if (dev_arg == nullptr) return arg;
    patch_group_arg(dev_arg, 7, "idVendor", vendor);
    patch_group_arg(dev_arg, 8, "idProduct", product);
    return arg;
}

} // namespace

Target::SpecialTypeFn make_usb_device_descriptor_fn() {
    return generate_usb_device_descriptor;
}

Target::SpecialTypeFn make_usb_printer_descriptor_fn() {
    return generate_usb_printer_descriptor;
}

Target::SpecialTypeFn make_usb_hid_descriptor_fn() {
    return generate_usb_hid_descriptor;
}

} // namespace refuzz::program::syz::linux_special_types

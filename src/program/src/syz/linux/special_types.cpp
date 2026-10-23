// reFuzz syz_v2 — linux/amd64 SpecialTypes generator registration site.
//
// Mirrors syzkaller `sys/linux/init.go`'s `target.SpecialTypes` map.
// Bodies live in per-family translation units (special_types_time.cpp,
// special_types_alg.cpp, special_types_netfilter.cpp,
// special_types_usb.cpp); this file owns the registration table only.

#include "refuzz/program/syz/target.hpp"

namespace refuzz::program::syz {

namespace linux_special_types {

Target::SpecialTypeFn make_timespec_fn();   // shared for timespec + timeval
Target::SpecialTypeFn make_sockaddr_alg_fn();
Target::SpecialTypeFn make_alg_name_fn();
Target::SpecialTypeFn make_alg_aead_name_fn();
Target::SpecialTypeFn make_alg_hash_name_fn();
Target::SpecialTypeFn make_alg_skcipher_name_fn();
Target::SpecialTypeFn make_iptables_fn();   // shared for ipt + ip6t
Target::SpecialTypeFn make_arptables_fn();
Target::SpecialTypeFn make_ebtables_fn();
Target::SpecialTypeFn make_usb_device_descriptor_fn();
Target::SpecialTypeFn make_usb_printer_descriptor_fn();
Target::SpecialTypeFn make_usb_hid_descriptor_fn();

} // namespace linux_special_types

void linux_amd64_register_special_types(Target& target) {
    namespace lst = linux_special_types;

    // Timing-sensitive structures.
    target.register_special_type("timespec", lst::make_timespec_fn());
    target.register_special_type("timeval",  lst::make_timespec_fn());

    // Cryptographic ALG_* family.
    target.register_special_type("sockaddr_alg",      lst::make_sockaddr_alg_fn());
    target.register_special_type("alg_name",          lst::make_alg_name_fn());
    target.register_special_type("alg_aead_name",     lst::make_alg_aead_name_fn());
    target.register_special_type("alg_hash_name",     lst::make_alg_hash_name_fn());
    target.register_special_type("alg_skcipher_name", lst::make_alg_skcipher_name_fn());

    // {ip,ip6,arp,eb}tables blobs.
    target.register_special_type("ipt_replace",  lst::make_iptables_fn());
    target.register_special_type("ip6t_replace", lst::make_iptables_fn());
    target.register_special_type("arpt_replace", lst::make_arptables_fn());
    target.register_special_type("ebt_replace",  lst::make_ebtables_fn());

    // USB device descriptor variants.
    target.register_special_type("usb_device_descriptor",         lst::make_usb_device_descriptor_fn());
    target.register_special_type("usb_device_descriptor_printer", lst::make_usb_printer_descriptor_fn());
    target.register_special_type("usb_device_descriptor_hid",     lst::make_usb_hid_descriptor_fn());
}

} // namespace refuzz::program::syz

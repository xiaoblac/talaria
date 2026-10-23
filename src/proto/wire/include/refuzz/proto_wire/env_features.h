// Copyright 2026 reFuzz project author -------youngkk.
//
// [syscall-support-detection Step C] EnvFeatures — the guest↔host wire contract
// for VM-probed environment facts. A worker (the per-VM init worker, worker_id
// == 0) probes the guest at startup and publishes this POD into the ivshmem
// ShmHeader; the host reads it and folds it into control/support's SupportEnv.
//
// This header is DUMB on purpose: it carries *generic* facts (which filesystems
// the kernel exposes, which device nodes are openable) and assigns them NO
// syscall meaning. The fact→syscall-support mapping lives solely in
// control/support::is_supported (e.g. raw-gadget ⇒ syz_usb_*, fs∈list ⇒
// syz_mount_image$fs). Mirrors syzkaller pkg/vminfo: host decides+interprets,
// guest just gathers, results travel as data.
//
// POD / C-compatible so it can be embedded verbatim in the ivshmem layout and
// shared byte-for-byte between the guest worker and the host.

#ifndef REFUZZ_PROTO_WIRE_ENV_FEATURES_H
#define REFUZZ_PROTO_WIRE_ENV_FEATURES_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Schema version of the EnvFeatures payload itself (independent of the ivshmem
// PROTOCOL_VERSION). Bump when the struct layout / flag meanings change so a
// host can reject a stale guest payload.
//   v2 (C4.1): + kernel_major/minor (/proc/version) + lsm[] (/sys/kernel/security/lsm).
#define ENV_FEATURES_VERSION 2u

// Device-availability flags — generic "is this node openable" facts. No
// syscall-domain meaning here; control/support maps each bit to support.
#define ENV_FEAT_RAW_GADGET  (1u << 0) // /dev/raw-gadget    (USB gadget fuzzing)
#define ENV_FEAT_KVM         (1u << 1) // /dev/kvm           (syz_kvm_*)
#define ENV_FEAT_TUN         (1u << 2) // /dev/net/tun       (tun/tap net)
// /sys/kernel/security/lsm was readable. Clear ⇒ securityfs not mounted / file
// absent ⇒ host must NOT disable LSM syscalls (mirror syz's ENOENT-break: an
// unreadable list is "no evidence", not "no LSMs"). Set ⇒ lsm[] is authoritative.
#define ENV_FEAT_LSM_PRESENT (1u << 3)

// Capacity for the '\n'-separated /proc/filesystems name list. A typical kernel
// exposes ~40-80 short names; 2 KiB is comfortably under the ShmHeader reserved
// page and leaves headroom.
#define ENV_FILESYSTEMS_CAP 2048u

// Capacity for the raw /sys/kernel/security/lsm contents (a short comma list,
// e.g. "capability,landlock,lockdown,yama,apparmor"). 256 B is ample.
#define ENV_LSM_CAP 256u

// Per-VM environment facts. Filled once by the init worker, read once by the
// host. All fields little-endian native (same host/guest arch — amd64).
struct EnvFeatures {
    uint32_t version;          // == ENV_FEATURES_VERSION
    uint32_t flags;            // OR of ENV_FEAT_*
    uint32_t filesystems_len;  // bytes used in filesystems[] (<= ENV_FILESYSTEMS_CAP)
    uint32_t kernel_major;     // /proc/version major; 0 = unknown/unparsed
    uint32_t kernel_minor;     // /proc/version minor (0 is a valid minor)
    uint32_t lsm_len;          // bytes used in lsm[] (<= ENV_LSM_CAP)
    uint32_t reserved;         // pad / future use
    char     filesystems[ENV_FILESYSTEMS_CAP]; // '\n'-separated fs names
    char     lsm[ENV_LSM_CAP];                 // raw /sys/kernel/security/lsm bytes
};

// ---- contract helpers (C-compatible; internal linkage) -------------------

static inline int env_features_has_flag(const struct EnvFeatures* e, uint32_t bit)
{
    return e != NULL && (e->flags & bit) != 0u;
}

// True iff `name` appears as a whole '\n'-delimited token in filesystems[].
// (Whole-token match so "ext4" does not spuriously match "ext4dev".)
static inline int env_features_has_filesystem(const struct EnvFeatures* e,
                                              const char* name)
{
    if (e == NULL || name == NULL) {
        return 0;
    }
    size_t nlen = strlen(name);
    if (nlen == 0u || e->filesystems_len == 0u) {
        return 0;
    }
    uint32_t cap = e->filesystems_len;
    if (cap > ENV_FILESYSTEMS_CAP) {
        cap = ENV_FILESYSTEMS_CAP;
    }
    uint32_t i = 0u;
    while (i < cap) {
        uint32_t j = i;
        while (j < cap && e->filesystems[j] != '\n') {
            ++j;
        }
        if ((uint32_t)(j - i) == (uint32_t)nlen &&
            memcmp(e->filesystems + i, name, nlen) == 0) {
            return 1;
        }
        i = j + 1u;
    }
    return 0;
}

// Append one fs name + '\n' to filesystems[] if it fits; returns 1 on success,
// 0 if it would overflow (caller stops). Used by the guest probe.
static inline int env_features_append_filesystem(struct EnvFeatures* e,
                                                 const char* name)
{
    if (e == NULL || name == NULL) {
        return 0;
    }
    size_t nlen = strlen(name);
    if (nlen == 0u) {
        return 1; // nothing to add, not an overflow
    }
    if (e->filesystems_len + nlen + 1u > ENV_FILESYSTEMS_CAP) {
        return 0;
    }
    memcpy(e->filesystems + e->filesystems_len, name, nlen);
    e->filesystems_len += (uint32_t)nlen;
    e->filesystems[e->filesystems_len] = '\n';
    e->filesystems_len += 1u;
    return 1;
}

// True iff the probed kernel is at least major.minor. Returns 0 when the version
// is unknown (kernel_major == 0) so the caller treats it as "no evidence" rather
// than "too old". Mirror of syz matchKernelVersion's major*1000+minor compare.
static inline int env_features_kernel_at_least(const struct EnvFeatures* e,
                                               uint32_t major, uint32_t minor)
{
    if (e == NULL || e->kernel_major == 0u) {
        return 0;
    }
    return (e->kernel_major * 1000u + e->kernel_minor) >= (major * 1000u + minor);
}

// Copy the raw /sys/kernel/security/lsm contents into lsm[] (truncating to cap)
// and mark it present. Call ONLY when the file was successfully read (even 0
// bytes) — that is what distinguishes "no LSMs enabled" from "list unreadable".
static inline void env_features_set_lsm(struct EnvFeatures* e,
                                        const char* data, size_t len)
{
    if (e == NULL) {
        return;
    }
    if (data == NULL) {
        len = 0u;
    }
    if (len > ENV_LSM_CAP) {
        len = ENV_LSM_CAP;
    }
    if (len > 0u) {
        memcpy(e->lsm, data, len);
    }
    e->lsm_len = (uint32_t)len;
    e->flags |= ENV_FEAT_LSM_PRESENT;
}

// True iff `name` appears as a substring of lsm[] (syz uses bytes.Contains, not
// a token match: the list is comma-separated and an LSM name has no spurious
// superstring among the real LSM names).
static inline int env_features_has_lsm(const struct EnvFeatures* e,
                                       const char* name)
{
    if (e == NULL || name == NULL || e->lsm_len == 0u) {
        return 0;
    }
    size_t nlen = strlen(name);
    if (nlen == 0u) {
        return 0;
    }
    uint32_t cap = e->lsm_len;
    if (cap > ENV_LSM_CAP) {
        cap = ENV_LSM_CAP;
    }
    if ((size_t)cap < nlen) {
        return 0;
    }
    for (uint32_t i = 0u; (size_t)i + nlen <= (size_t)cap; ++i) {
        if (memcmp(e->lsm + i, name, nlen) == 0) {
            return 1;
        }
    }
    return 0;
}

#endif // REFUZZ_PROTO_WIRE_ENV_FEATURES_H

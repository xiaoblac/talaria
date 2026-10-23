// Copyright 2026 reFuzz project author -------youngkk.

#include "worker/env/env_probe.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <cstring>

namespace refuzz::worker::env {

namespace {

// raw-gadget / kvm / tun are normally opened O_RDWR; fall back to O_RDONLY.
// open()+close() has no side effect — binding/creation happens via ioctl, not
// open — so this is a safe "does the node exist and is it usable" probe.
bool DeviceOpenable(const char* path) {
    int fd = ::open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        fd = ::open(path, O_RDONLY | O_CLOEXEC);
    }
    if (fd < 0) {
        return false;
    }
    ::close(fd);
    return true;
}

} // namespace

void ParseProcFilesystems(const char* content, std::size_t len, ::EnvFeatures* out) {
    if (content == nullptr || out == nullptr) {
        return;
    }
    std::size_t i = 0;
    while (i < len) {
        std::size_t eol = i;
        while (eol < len && content[eol] != '\n') {
            ++eol;
        }
        // fs name = substring after the last tab/space within [i, eol). This
        // drops the optional "nodev" prefix that /proc/filesystems emits.
        std::size_t name_start = i;
        for (std::size_t k = i; k < eol; ++k) {
            if (content[k] == '\t' || content[k] == ' ') {
                name_start = k + 1;
            }
        }
        const std::size_t name_len = eol - name_start;
        if (name_len > 0 && name_len < 64) {
            char buf[64];
            std::memcpy(buf, content + name_start, name_len);
            buf[name_len] = '\0';
            if (!env_features_append_filesystem(out, buf)) {
                return; // filesystems[] full — stop appending
            }
        }
        i = eol + 1;
    }
}

void ParseKernelVersion(const char* content, std::size_t len,
                        uint32_t* major, uint32_t* minor) {
    if (major != nullptr) *major = 0;
    if (minor != nullptr) *minor = 0;
    if (content == nullptr || major == nullptr || minor == nullptr) {
        return;
    }
    // Find the first " <digits>.<digits>." token (syz kernelVersionRe).
    for (std::size_t i = 0; i + 1 < len; ++i) {
        if (content[i] != ' ') {
            continue;
        }
        std::size_t j = i + 1;
        std::size_t maj_start = j;
        uint32_t maj = 0;
        while (j < len && content[j] >= '0' && content[j] <= '9') {
            maj = maj * 10u + static_cast<uint32_t>(content[j] - '0');
            ++j;
        }
        if (j == maj_start || j >= len || content[j] != '.') {
            continue; // need digits then '.'
        }
        ++j; // skip '.'
        std::size_t min_start = j;
        uint32_t min = 0;
        while (j < len && content[j] >= '0' && content[j] <= '9') {
            min = min * 10u + static_cast<uint32_t>(content[j] - '0');
            ++j;
        }
        if (j == min_start || j >= len || content[j] != '.') {
            continue; // need digits then '.'
        }
        // Matched " <maj>.<min>." — major 0 is the unknown sentinel, so a real
        // 0.x kernel (does not exist) is the only thing rejected; minor 0 is ok.
        if (maj > 0u && maj <= 999u && min <= 999u) {
            *major = maj;
            *minor = min;
            return;
        }
    }
}

void ProbeEnvFeatures(::EnvFeatures* out) {
    if (out == nullptr) {
        return;
    }
    std::memset(out, 0, sizeof(*out));
    out->version = ENV_FEATURES_VERSION;

    // /proc/filesystems (small; a single bounded read is enough).
    int fd = ::open("/proc/filesystems", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        char buf[4096];
        std::size_t total = 0;
        ssize_t n;
        while (total < sizeof(buf) &&
               (n = ::read(fd, buf + total, sizeof(buf) - total)) > 0) {
            total += static_cast<std::size_t>(n);
        }
        ::close(fd);
        if (total > 0) {
            ParseProcFilesystems(buf, total, out);
        }
    }

    // /proc/version → kernel major.minor (kernel-version-gated syscalls).
    fd = ::open("/proc/version", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        char buf[512];
        ssize_t n = ::read(fd, buf, sizeof(buf) - 1);
        ::close(fd);
        if (n > 0) {
            ParseKernelVersion(buf, static_cast<std::size_t>(n),
                               &out->kernel_major, &out->kernel_minor);
        }
    }

    // /sys/kernel/security/lsm → active LSM list. A failed open (ENOENT:
    // securityfs not mounted) leaves ENV_FEAT_LSM_PRESENT clear so the host
    // does not disable LSM syscalls on missing evidence.
    fd = ::open("/sys/kernel/security/lsm", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        char buf[ENV_LSM_CAP];
        std::size_t total = 0;
        ssize_t n;
        while (total < sizeof(buf) &&
               (n = ::read(fd, buf + total, sizeof(buf) - total)) > 0) {
            total += static_cast<std::size_t>(n);
        }
        ::close(fd);
        env_features_set_lsm(out, buf, total); // marks present even if total==0
    }

    // Device-node availability (generic facts; control/support maps to support).
    if (DeviceOpenable("/dev/raw-gadget")) out->flags |= ENV_FEAT_RAW_GADGET;
    if (DeviceOpenable("/dev/kvm"))        out->flags |= ENV_FEAT_KVM;
    if (DeviceOpenable("/dev/net/tun"))    out->flags |= ENV_FEAT_TUN;
}

} // namespace refuzz::worker::env

#include "worker/backend/pseudo/pseudo_context.hpp"
#include "worker/backend/pseudo/pseudo_result.hpp"

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

// TIOCGPTN — pty number ioctl. <sys/ioctl.h> on glibc pulls it through
// <asm/ioctls.h>; pin a numeric fallback for hosts that don't.
#ifndef TIOCGPTN
#  include <linux/tty.h>
#endif

namespace refuzz::worker::pseudo {
namespace {

bool HasBaseName(const char* name, const char* base)
{
    if (name == nullptr) {
        return false;
    }
    const size_t n = std::strlen(base);
    return std::strncmp(name, base, n) == 0 &&
           (name[n] == '\0' || name[n] == '$');
}

PseudoResult Error(int err)
{
    return PseudoResult{-1, err};
}

PseudoResult OpenPath(const char* path, int flags)
{
    errno = 0;
    const int fd = open(path, flags | O_CLOEXEC);
    if (fd < 0) {
        return Error(errno);
    }
    return PseudoResult{fd, 0};
}

// Single-character mod-10 hash substitution mirroring upstream
// common_linux.h:2432-2435. Each '#' becomes one digit (nb % 10), then
// nb /= 10 for the next '#'. Buffer truncation is silent (matches upstream
// strncpy(buf, ..., sizeof(buf)-1)).
void SubstituteHashMod10(char* buf, size_t buf_size, const char* pattern, unsigned long nb)
{
    if (buf_size == 0) return;
    std::strncpy(buf, pattern, buf_size - 1);
    buf[buf_size - 1] = '\0';
    for (char* h = std::strchr(buf, '#'); h != nullptr; h = std::strchr(buf, '#')) {
        *h = static_cast<char>('0' + (nb % 10));
        nb /= 10;
    }
}

} // namespace

PseudoResult DispatchDevicePseudo(const PseudoContext& ctx,
                                  const refuzz::fuzzer::syz::PseudoMeta& meta,
                                  const intptr_t* args,
                                  uint32_t argc)
{
    if (HasBaseName(meta.name, "syz_open_dev")) {
        if (args == nullptr || argc < 3 || args[0] == 0) {
            return Error(EINVAL);
        }
        const long a0 = static_cast<long>(args[0]);
        const long a1 = static_cast<long>(args[1]);
        const int  a2 = static_cast<int>(args[2]);
        // [silent-drift fix] syz_open_dev$char(0xc, major, minor) /
        // syz_open_dev$block(0xb, major, minor) — upstream
        // common_linux.h:2419-2424. a0 is the class const, NOT a string ptr.
        if (a0 == 0xc || a0 == 0xb) {
            char buf[128];
            std::snprintf(buf, sizeof(buf), "/dev/%s/%d:%d",
                          a0 == 0xc ? "char" : "block",
                          static_cast<uint8_t>(a1),
                          static_cast<uint8_t>(a2));
            // reFuzz's fresh program child can fault stack/string pages while
            // preparing the helper path. Upstream traces for syz_open_dev start
            // at the open(2) kernel path, so keep the per-call KCOV window on
            // the actual open operation, not helper-local prep.
            ctx.KcovCursorReset();
            return OpenPath(buf, O_RDWR);
        }
        // Generic syz_open_dev(pattern, id, flags) — common_linux.h:2426-2436.
        // Single-char # mod-10 substitution (NOT %ld) + strip O_CREAT.
        // Keep the caller's remaining flags exactly; upstream does not
        // promote flags==0 to O_RDWR here.
        char buf[1024];
        SubstituteHashMod10(buf, sizeof(buf),
                            reinterpret_cast<const char*>(a0),
                            static_cast<unsigned long>(a1));
        int flags = a2 & ~O_CREAT;
        // See the char/block branch above: path substitution is userspace
        // helper prep; reset immediately before the kernel-visible open(2).
        ctx.KcovCursorReset();
        return OpenPath(buf, flags);
    }

    if (HasBaseName(meta.name, "syz_open_pts")) {
        if (args == nullptr || argc < 2) {
            return Error(EINVAL);
        }
        // [silent-drift fix] upstream common_linux.h:2476-2481 — args[0] is
        // the master pty fd (from openpty etc.), not a pts number. Must
        // ioctl(TIOCGPTN) to get the slave number, then open /dev/pts/<n>.
        const int master_fd = static_cast<int>(args[0]);
        int ptyno = 0;
        if (::ioctl(master_fd, TIOCGPTN, &ptyno) != 0) {
            return Error(errno);
        }
        char path[128];
        std::snprintf(path, sizeof(path), "/dev/pts/%d", ptyno);
        int flags = static_cast<int>(args[1]);
        if (flags == 0) {
            flags = O_RDWR;
        }
        return OpenPath(path, flags);
    }

    return Error(ENOSYS);
}

} // namespace refuzz::worker::pseudo

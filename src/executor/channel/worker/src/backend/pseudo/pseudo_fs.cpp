#include "worker/backend/pseudo/pseudo_context.hpp"
#include "worker/backend/pseudo/pseudo_result.hpp"
// [silent-drift fix] Share the loop-device + zlib-decompress helper with
// mount-image, mirroring upstream design at common_linux.h:2967 where
// setup_loop_device is unwrapped under
//   #if SYZ_EXECUTOR || __NR_syz_mount_image || __NR_syz_read_part_table
#include "worker/backend/pseudo/mount/mount_helpers.hpp"
#include "worker/log/log_macros.hpp"

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <linux/loop.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

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

// [silent-drift fix] Mirror upstream syz_read_part_table at
// common_linux.h:3046-3090:
//   1. setup_loop_device(data, size, loopname, &loopfd) — shared helper
//      (zlib-decompresses image into memfd, attaches to loop device)
//   2. LOOP_GET_STATUS64 + LOO_FLAGS_PARTSCAN | LOOP_SET_STATUS64
//      → kernel scans partition table
//   3. for i in 1..7: stat(/dev/loop<N>pi); on success symlink to ./file<j>
//      so subsequent caller programs can reach the partitions by relative
//      path
//   4. cleanup: LOOP_CLR_FD + close(loopfd)
//
// Previous reFuzz impl wrote raw image bytes (no zlib) and skipped the
// partition symlink loop entirely — caller's later access to ./file0 etc.
// would always ENOENT.
//
// reFuzz divergence (legitimate, charter-approved):
//   * Worker is long-running so we ALWAYS reset the loop device, not only
//     on failure (upstream leaks on success because process-exit cleans up).
// (Loop allocation aligned to upstream `/dev/loop<procid>` 2026-05-19 —
//  see mount_helpers.hpp for rationale.)
PseudoResult ReadPartTable(const PseudoContext& ctx, size_t size, const void* image)
{
    if (size == 0 || image == nullptr) {
        return Error(EINVAL);
    }

    const auto* data = static_cast<const uint8_t*>(image);
    char loopname[64] = {};
    int loopfd = -1;
    const MountTimingDiagContext diag{ctx.DiagnosticExecutorId(),
                                      "syz_read_part_table",
                                      "read_part_table"};
    const bool diag_on = MountTimingDiagEnabled();
    // Setup can be terminated after attaching the backing fd but before it
    // returns, so publish the exact cleanup candidate first.
    ctx.RecordLoopDeviceUsed(ctx.EffectiveLoopSlot());
    if (SetupLoopDevice(data,
                        size,
                        ctx.EffectiveLoopSlot(),
                        loopname,
                        sizeof(loopname),
                        &loopfd,
                        &diag) < 0) {
        return Error(errno);
    }
    int err = 0;
    int result = 0;
    loop_info64 info{};
    if (diag_on) {
        ::refuzz::worker::log::WorkerLog(
            "[mount-timing] event=part_get_status_enter ts_us=%llu eid=%llu op=%s fs=%s slot=%u loop=%s\n",
            static_cast<unsigned long long>(MountTimingNowUs()),
            static_cast<unsigned long long>(ctx.DiagnosticExecutorId()),
            diag.op,
            diag.fs,
            ctx.proc_slot_id,
            loopname);
    }
    const int get_status_rc = ::ioctl(loopfd, LOOP_GET_STATUS64, &info);
    const int get_status_err = get_status_rc == 0 ? 0 : errno;
    if (diag_on) {
        ::refuzz::worker::log::WorkerLog(
            "[mount-timing] event=part_get_status_exit ts_us=%llu eid=%llu op=%s fs=%s slot=%u loop=%s rc=%d errno=%d\n",
            static_cast<unsigned long long>(MountTimingNowUs()),
            static_cast<unsigned long long>(ctx.DiagnosticExecutorId()),
            diag.op,
            diag.fs,
            ctx.proc_slot_id,
            loopname,
            get_status_rc,
            get_status_err);
    }
    if (get_status_rc != 0) {
        err = get_status_err;
        result = -1;
    } else {
        info.lo_flags |= LO_FLAGS_PARTSCAN;
        // Narrow per-call KCOV window — mirror upstream common_linux.h:3064
        // `cover_reset(0)` between LOOP_GET_STATUS64 and LOOP_SET_STATUS64.
        // SetupLoopDevice above runs zlib inflate → repeated write(memfd) →
        // shmem/folio/page-fault PCs; LOOP_SET_STATUS64 with LO_FLAGS_PARTSCAN
        // is the call whose coverage we want attributed to syz_read_part_table.
        ctx.KcovCursorReset();
        if (diag_on) {
            ::refuzz::worker::log::WorkerLog(
                "[mount-timing] event=part_set_status_enter ts_us=%llu eid=%llu op=%s fs=%s slot=%u loop=%s\n",
                static_cast<unsigned long long>(MountTimingNowUs()),
                static_cast<unsigned long long>(ctx.DiagnosticExecutorId()),
                diag.op,
                diag.fs,
                ctx.proc_slot_id,
                loopname);
        }
        const int set_status_rc = ::ioctl(loopfd, LOOP_SET_STATUS64, &info);
        const int set_status_err = set_status_rc == 0 ? 0 : errno;
        if (diag_on) {
            ::refuzz::worker::log::WorkerLog(
                "[mount-timing] event=part_set_status_exit ts_us=%llu eid=%llu op=%s fs=%s slot=%u loop=%s rc=%d errno=%d\n",
                static_cast<unsigned long long>(MountTimingNowUs()),
                static_cast<unsigned long long>(ctx.DiagnosticExecutorId()),
                diag.op,
                diag.fs,
                ctx.proc_slot_id,
                loopname,
                set_status_rc,
                set_status_err);
        }
        if (set_status_rc != 0) {
            err = set_status_err;
            result = -1;
        }
    }

    // Partition symlink loop (mirror common_linux.h:3072-3083). Best-effort
    // — symlink failures only logged upstream, ignored. Caller programs
    // expect ./file<N> relative paths to be reachable after this returns.
    if (result == 0) {
        int loop_nr = -1;
        if (std::sscanf(loopname, "/dev/loop%d", &loop_nr) == 1 && loop_nr >= 0) {
            unsigned long j = 0;
            for (unsigned long i = 1; i < 8; ++i) {
                char part_path[64];
                std::snprintf(part_path, sizeof(part_path),
                              "/dev/loop%dp%lu", loop_nr, i);
                struct stat sb;
                if (::stat(part_path, &sb) == 0) {
                    char linkname[64];
                    std::snprintf(linkname, sizeof(linkname),
                                  "./file%lu", j++);
                    (void)::symlink(part_path, linkname);
                }
            }
        }
    }

    ResetLoopDevice(loopname, &diag);
    ::close(loopfd);
    return result == 0 ? PseudoResult{0, 0} : Error(err);
}

} // namespace

PseudoResult DispatchFsPseudo(const PseudoContext& ctx,
                              const refuzz::fuzzer::syz::PseudoMeta& meta,
                              const intptr_t* args,
                              uint32_t argc)
{
    if (HasBaseName(meta.name, "syz_read_part_table")) {
        if (args == nullptr || argc < 2) {
            return Error(EINVAL);
        }
        return ReadPartTable(ctx,
                             static_cast<size_t>(args[0]),
                             reinterpret_cast<const void*>(args[1]));
    }
    return PseudoResult{-1, ENOSYS};
}

} // namespace refuzz::worker::pseudo

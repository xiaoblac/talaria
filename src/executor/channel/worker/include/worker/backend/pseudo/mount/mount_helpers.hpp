#pragma once

// PR-D1 — mount-image shared helpers (loop device + zlib decompress + opts adjuster).
//
// Mirrors upstream `executor/common_linux.h::syz_mount_image` (lines 3093-3199)
// at the *behavior* level, not byte-for-byte (plan §2.1: no embedded syzkaller code).
//
// Deviations from upstream documented at:
//   * (none currently — 2026-05-19 SetupLoopDevice switched to `/dev/loop
//     <proc_slot_id>` static naming to mirror upstream common_linux.h:3054/:3129.
//     The previous LOOP_CTL_GET_FREE dynamic-allocation path was
//     production-divergent: sequential syz_mount_image calls within one
//     program reuse the same loop on upstream → get EBUSY when the previous
//     fs is still mounted, while reFuzz's GET_FREE silently picked a fresh
//     loop and succeeded, generating false errno_mismatch in the paired
//     oracle. proc_slot_id is the runtime execution slot identity from
//     PseudoContext.proc_slot_id, set by the KernelWireDriver /
//     KernelThreadPool wiring to the driver's proc_slot_id_ (= channel-
//     assigned worker_id).)
//
//   * DecompressZlib — upstream uses puff_zlib_to_file (mini-zlib decoder).
//     reFuzz uses libz inflate(). Same wire format (zlib RFC1950 deflate
//     stream); same kernel-observable effect (decompressed bytes in memfd).

#include <cstddef>
#include <cstdint>

namespace refuzz::worker::pseudo {

struct MountTimingDiagContext {
    uint64_t executor_id = 0;
    const char* op = nullptr;
    const char* fs = nullptr;
};

bool MountTimingDiagEnabled();
uint64_t MountTimingNowUs();

// Decompress a zlib-deflate stream from `in` (in_size bytes) into the
// open writable fd `memfd`, expanding incrementally with libz inflate().
// Returns 0 on success, -1 on decode/write failure (errno set).
int DecompressZlibToFd(const uint8_t* in, std::size_t in_size, int memfd);

// Open the loop device named for this runtime execution slot, mirroring
// upstream's hardcoded `/dev/loop<procid>`:
//   1. snprintf loopname_out "/dev/loop<proc_slot_id>"
//   2. open loopname_out (O_RDWR | O_CLOEXEC) → out_loopfd
// loopname_buf must point to a >= 16-byte buffer.
// Returns 0 on success, -1 on failure (errno set).
int OpenLoopDeviceByProcSlot(uint32_t proc_slot_id,
                             char* loopname_buf,
                             std::size_t loopname_cap,
                             int* out_loopfd);

// Setup loop device backing for mount-image (mirror upstream
// common_linux.h:2981 setup_loop_device):
//   1. memfd_create(image_bytes, in_size) — empty memfd
//   2. DecompressZlibToFd(in, in_size, memfd) — fills memfd
//   3. OpenLoopDeviceByProcSlot(proc_slot_id) → loopname + loopfd
//   4. ioctl(loopfd, LOOP_SET_FD, memfd) — retry once on EBUSY (mirrors upstream)
//   5. close memfd (loop device holds backing reference)
//   6. *out_loopfd = loopfd
// Caller must close loopfd before mount(2) (BLK_DEV_WRITE_MOUNTED kernel
// restriction — kernel won't let mount proceed while loop fd is open).
//
// loopname_buf must point to a >= 16-byte buffer.
// Returns 0 on success, -1 on failure (errno set; resources cleaned up).
int SetupLoopDevice(const uint8_t* image_bytes,
                    std::size_t in_size,
                    uint32_t proc_slot_id,
                    char* loopname_buf,
                    std::size_t loopname_cap,
                    int* out_loopfd,
                    const MountTimingDiagContext* diag = nullptr);

// Tear down a loop device by name: open(loopname, O_RDWR) → ioctl(LOOP_CLR_FD)
// → close. Best-effort (no return value); failures are logged via debug only,
// matching upstream reset_loop_device.
void ResetLoopDevice(const char* loopname,
                     const MountTimingDiagContext* diag = nullptr);

// Build mount options buffer applying per-fs adjusters from upstream
// common_linux.h:3146-3168:
//   * iso9660 — set MS_RDONLY in *flags
//   * ext{2,3,4} — append ",errors=continue" if opts has errors=panic OR no
//                  remount-ro
//   * xfs — append ",nouuid"
//   * gfs2* — append ",errors=withdraw" if opts has errors=panic or debug
//
// Inputs: fs (filesystem name), base_opts (caller's mount options string).
// Outputs: out_opts is filled (caller-provided buffer >= 256 bytes); flags
// may be modified in-place.
//
// Returns 0 on success, -1 if base_opts too long for buffer (truncated; caller
// can ignore but trace oracle will note).
int BuildMountOpts(const char* fs,
                   const char* base_opts,
                   long* flags_inout,
                   char* out_opts,
                   std::size_t out_cap);

} // namespace refuzz::worker::pseudo

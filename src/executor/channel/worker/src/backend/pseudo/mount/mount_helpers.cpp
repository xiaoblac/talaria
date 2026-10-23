// PR-D1 — mount-image shared helpers implementation.
//
// See header for behavioral contract + upstream divergence notes.

#include "worker/backend/pseudo/mount/mount_helpers.hpp"

#include "worker/log/log_macros.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <fcntl.h>
#include <linux/loop.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>  // [PR-D1 review fix C8] MS_RDONLY symbolic constant
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>

namespace refuzz::worker::pseudo {

namespace {

constexpr std::size_t kZlibBlock = 64 * 1024;  // 64KiB inflate chunk

// [sparse mount-image materialization] Fast all-zero test (word-at-a-time).
// Mount images (btrfs/ext4 min device ~128 MiB) are mostly zeros; an all-zero
// decompressed chunk is written as a sparse hole (lseek, no page) instead of
// forcing shmem to alloc+zero the pages — the per-program-dominant cost on a
// KASAN guest. Caller guarantees `buf` is 8-byte aligned (alignas below).
bool IsAllZero(const uint8_t* p, std::size_t n)
{
    const std::size_t words = n / sizeof(std::uint64_t);
    const auto* w = reinterpret_cast<const std::uint64_t*>(p);
    for (std::size_t i = 0; i < words; ++i) {
        if (w[i] != 0) return false;
    }
    for (std::size_t i = words * sizeof(std::uint64_t); i < n; ++i) {
        if (p[i] != 0) return false;
    }
    return true;
}

const char* DiagOp(const MountTimingDiagContext* diag)
{
    return (diag != nullptr && diag->op != nullptr) ? diag->op : "-";
}

const char* DiagFs(const MountTimingDiagContext* diag)
{
    return (diag != nullptr && diag->fs != nullptr) ? diag->fs : "-";
}

uint64_t DiagExecutorId(const MountTimingDiagContext* diag)
{
    return diag != nullptr ? diag->executor_id : 0;
}

// Return memfd_create syscall result; -1 on failure.
int MemfdCreate(const char* name, unsigned int flags)
{
    return static_cast<int>(::syscall(SYS_memfd_create, name, flags));
}

// Sleep 1ms — mirrors upstream usleep(1000) retry pause for LOOP_SET_FD/EBUSY.
void Sleep1ms()
{
    struct timespec ts = {0, 1'000'000};
    ::nanosleep(&ts, nullptr);
}

} // namespace

bool MountTimingDiagEnabled()
{
    static const bool enabled = [] {
        const char* v = std::getenv("REFUZZ_MOUNT_TIMING_DIAG");
        return v != nullptr && v[0] != '\0' &&
               !(v[0] == '0' && v[1] == '\0');
    }();
    return enabled;
}

uint64_t MountTimingNowUs()
{
    struct timespec ts = {};
    if (::clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return static_cast<uint64_t>(ts.tv_sec) * 1000000ULL +
           static_cast<uint64_t>(ts.tv_nsec / 1000ULL);
}

int DecompressZlibToFd(const uint8_t* in, std::size_t in_size, int memfd)
{
    if (memfd < 0) {
        errno = EINVAL;
        return -1;
    }
    // [PR-D1.O' Fix 3] Mirror upstream common_zlib.h:472-473 —
    //   if (sourcelen < ZLIB_HEADER_WIDTH /* 2 */) return 0;
    // Short input is success-empty (no bytes written), NOT failure. Previously
    // reFuzz returned -1+EINVAL/EIO on short input which diverged: malformed/
    // mutated images with sourcelen<2 would fail here whereas upstream lets
    // them through as no-op writes (mount(2) then sees an empty memfd and
    // either accepts it for tmpfs-shaped fs or fails at fs-validate stage).
    constexpr std::size_t kZlibHeaderWidth = 2;
    if (in_size < kZlibHeaderWidth) {
        return 0;
    }
    if (in == nullptr) {
        errno = EINVAL;
        return -1;
    }
    z_stream zs = {};
    zs.next_in  = const_cast<Bytef*>(reinterpret_cast<const Bytef*>(in));
    zs.avail_in = static_cast<uInt>(in_size);
    // inflateInit accepts zlib (RFC1950) wrapper — same as upstream puff_zlib_to_file.
    if (inflateInit(&zs) != Z_OK) {
        errno = EIO;
        return -1;
    }
    // [PR-D1.O' Fix 3] Mirror upstream common_zlib.h:478 — cap output at
    // 132 MiB to bound resource use under malicious zlib streams (zip-bomb:
    // tiny input, huge output). Upstream uses a single mmap'd 132 MiB buffer;
    // reFuzz inflates incrementally and tracks total bytes produced.
    constexpr std::size_t kMaxInflatedBytes = static_cast<std::size_t>(132) << 20;
    std::size_t total_produced = 0;
    alignas(std::uint64_t) uint8_t buf[kZlibBlock];  // aligned for IsAllZero word scan
    int ret = Z_OK;
    while (ret != Z_STREAM_END) {
        zs.next_out  = buf;
        zs.avail_out = static_cast<uInt>(sizeof(buf));
        ret = inflate(&zs, Z_NO_FLUSH);
        if (ret != Z_OK && ret != Z_STREAM_END) {
            inflateEnd(&zs);
            errno = EIO;
            return -1;
        }
        const std::size_t produced = sizeof(buf) - zs.avail_out;
        if (total_produced + produced > kMaxInflatedBytes) {
            inflateEnd(&zs);
            errno = EFBIG;
            return -1;
        }
        // [sparse materialization] Mount images are mostly zeros; an all-zero
        // chunk becomes a sparse hole (lseek past it) rather than ~16 shmem
        // pages alloc+zero'd under KASAN. The loop device reads holes as zeros,
        // so the mounted fs is byte-identical — only the page-fault/alloc cost
        // for the zero regions is removed. Non-zero chunks write as before.
        if (IsAllZero(buf, produced)) {
            if (::lseek(memfd, static_cast<off_t>(produced), SEEK_CUR) < 0) {
                inflateEnd(&zs);
                return -1;
            }
            total_produced += produced;
            continue;
        }
        std::size_t written = 0;
        while (written < produced) {
            const ssize_t w = ::write(memfd, buf + written, produced - written);
            if (w < 0) {
                if (errno == EINTR) continue;
                inflateEnd(&zs);
                return -1;
            }
            written += static_cast<std::size_t>(w);
        }
        total_produced += produced;
    }
    inflateEnd(&zs);
    // If the final chunk(s) were sparse holes (lseek, not write), the memfd size
    // is short of total_produced. Extend it so the loop device sees the full
    // image size (trailing zeros as a hole). No-op when the last write extended.
    if (total_produced > 0 &&
        ::ftruncate(memfd, static_cast<off_t>(total_produced)) != 0) {
        return -1;
    }
    return 0;
}

// [chunk-based mount image — align modern syzkaller's non-zero-segment images]
// Wire format for a pre-segmented, UNCOMPRESSED mount image. Produced HOST-side
// (the replayer decompresses the zlib image ONCE at corpus-load and extracts the
// non-zero runs), consumed here WITHOUT any decompression — the per-program win.
// Detected by the 4-byte magic at the start of the img arg; zlib streams begin
// with 0x78, never 'S', so there is no collision with the legacy compressed path.
// KEEP IN SYNC with the producer in tools/refuzz_exec_replayer/corpus_replay.cpp.
//   [4]   magic 'S','E','G','S'
//   [4]   u32 total_size   (decompressed image size = loop backing size)
//   [4]   u32 nseg
//   nseg × { u64 offset; u32 len; u8 data[len] }   (non-zero runs only)
constexpr uint8_t   kMountSegMagic[4]    = {'S', 'E', 'G', 'S'};
constexpr std::size_t kMountSegHeaderBytes = 12;

bool HasMountSegMagic(const uint8_t* p, std::size_t n)
{
    return n >= kMountSegHeaderBytes &&
           std::memcmp(p, kMountSegMagic, sizeof(kMountSegMagic)) == 0;
}

// [dense mount image — zstd] zstd-compressed image frame, produced host-side
// (mount_image_segment.cpp) for DENSE images where SEGS (uncompressed non-zero
// runs) overflows the program wire. zstd's ratio ≥ zlib (so it still fits the
// wire) yet decompresses ~5-15× faster than zlib inflate — the per-exec dominant
// cost. Detected by the zstd frame magic 0x28 B5 2F FD (distinct from zlib's 0x78
// and SEGS 'S'). Decompressed straight into the memfd via mmap (dense images have
// few zeros, so the sparse-hole win is negligible; decompress speed is the point).
// zstd symbols resolve at runtime from the guest rootfs's libzstd.so.1.
extern "C" {
unsigned long long ZSTD_getFrameContentSize(const void* src, std::size_t srcSize);
std::size_t        ZSTD_decompress(void* dst, std::size_t dstCap,
                                   const void* src, std::size_t srcSize);
unsigned           ZSTD_isError(std::size_t code);
}

bool HasZstdMagic(const uint8_t* p, std::size_t n)
{
    return n >= 4 && p[0] == 0x28 && p[1] == 0xB5 && p[2] == 0x2F && p[3] == 0xFD;
}

// Decompress a zstd frame straight into `memfd`. 0 on success, -1 (errno) on
// malformed/oversized input. ZSTD_getFrameContentSize reads the size the host-side
// ZSTD_compress pledged into the frame header (UNKNOWN/ERROR sentinels = (ull)-1/-2).
int DecompressZstdToFd(const uint8_t* in, std::size_t in_size, int memfd)
{
    constexpr std::size_t kMaxInflatedBytes = static_cast<std::size_t>(132) << 20;
    if (memfd < 0 || in == nullptr || in_size < 4) {
        errno = EINVAL;
        return -1;
    }
    const unsigned long long content = ZSTD_getFrameContentSize(in, in_size);
    if (content == ~0ULL || content == (~0ULL - 1ULL) || content == 0ULL ||
        content > kMaxInflatedBytes) {
        errno = EINVAL;
        return -1;
    }
    const std::size_t out_size = static_cast<std::size_t>(content);
    if (::ftruncate(memfd, static_cast<off_t>(out_size)) != 0) {
        return -1;
    }
    void* p = ::mmap(nullptr, out_size, PROT_READ | PROT_WRITE, MAP_SHARED, memfd, 0);
    if (p == MAP_FAILED) {
        return -1;
    }
    const std::size_t got = ZSTD_decompress(p, out_size, in, in_size);
    ::munmap(p, out_size);
    if (ZSTD_isError(got) || got != out_size) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

// Materialize a SEGS-format image into memfd as a sparse file (ftruncate to the
// full size + pwrite each non-zero segment at its offset — zero regions stay
// holes, read back as zeros, byte-identical to the original image). No zlib.
// Returns the image size (>=0) on success, -1 (errno set) on malformed input.
int WriteSegmentsToFd(const uint8_t* in, std::size_t in_size, int memfd)
{
    if (memfd < 0 || in == nullptr || in_size < kMountSegHeaderBytes) {
        errno = EINVAL;
        return -1;
    }
    uint32_t total_size = 0;
    uint32_t nseg       = 0;
    std::memcpy(&total_size, in + 4, sizeof(total_size));
    std::memcpy(&nseg, in + 8, sizeof(nseg));
    constexpr uint32_t kMaxInflated = static_cast<uint32_t>(132u << 20);
    if (total_size > kMaxInflated) {
        errno = EFBIG;
        return -1;
    }
    if (::ftruncate(memfd, static_cast<off_t>(total_size)) != 0) {
        return -1;
    }
    std::size_t cur = kMountSegHeaderBytes;
    for (uint32_t i = 0; i < nseg; ++i) {
        if (cur + 12 > in_size) {  // u64 offset + u32 len
            errno = EINVAL;
            return -1;
        }
        uint64_t off = 0;
        uint32_t len = 0;
        std::memcpy(&off, in + cur, sizeof(off));
        cur += sizeof(off);
        std::memcpy(&len, in + cur, sizeof(len));
        cur += sizeof(len);
        if (len == 0 || cur + len > in_size || off + len > total_size) {
            errno = EINVAL;
            return -1;
        }
        std::size_t w = 0;
        while (w < len) {
            const ssize_t k = ::pwrite(memfd, in + cur + w, len - w,
                                       static_cast<off_t>(off + w));
            if (k < 0) {
                if (errno == EINTR) continue;
                return -1;
            }
            w += static_cast<std::size_t>(k);
        }
        cur += len;
    }
    return static_cast<int>(total_size);
}

int OpenLoopDeviceByProcSlot(uint32_t proc_slot_id,
                             char* loopname_buf,
                             std::size_t loopname_cap,
                             int* out_loopfd)
{
    if (loopname_buf == nullptr || loopname_cap < 16 || out_loopfd == nullptr) {
        errno = EINVAL;
        return -1;
    }
    // Mirror upstream common_linux.h:3129 / :3054 — snprintf("/dev/loop%llu",
    // procid) + open(O_RDWR). Per-slot loop naming is intentional: it
    // produces EBUSY on re-mount within one program (kernel won't let
    // LOOP_SET_FD replace the active backing fd while a filesystem is still
    // mounted on top), and the EBUSY is part of the kernel-observable
    // behavior we need to match. proc_slot_id is the runtime execution slot
    // identity assigned by the channel layer (PseudoContext.proc_slot_id).
    std::snprintf(loopname_buf, loopname_cap, "/dev/loop%u", proc_slot_id);
    const int loopfd = ::open(loopname_buf, O_RDWR | O_CLOEXEC);
    if (loopfd < 0) {
        return -1;
    }
    *out_loopfd = loopfd;
    return 0;
}

int SetupLoopDevice(const uint8_t* image_bytes,
                    std::size_t in_size,
                    uint32_t proc_slot_id,
                    char* loopname_buf,
                    std::size_t loopname_cap,
                    int* out_loopfd,
                    const MountTimingDiagContext* diag)
{
    const bool diag_on = MountTimingDiagEnabled();
    if (diag_on) {
        ::refuzz::worker::log::WorkerLog(
            "[mount-timing] event=setup_start ts_us=%llu eid=%llu op=%s fs=%s slot=%u size=%zu\n",
            static_cast<unsigned long long>(MountTimingNowUs()),
            static_cast<unsigned long long>(DiagExecutorId(diag)),
            DiagOp(diag),
            DiagFs(diag),
            proc_slot_id,
            in_size);
    }
    if (image_bytes == nullptr || in_size == 0 ||
        loopname_buf == nullptr || loopname_cap < 16 || out_loopfd == nullptr) {
        if (diag_on) {
            ::refuzz::worker::log::WorkerLog(
                "[mount-timing] event=setup_invalid ts_us=%llu eid=%llu op=%s fs=%s slot=%u errno=%d\n",
                static_cast<unsigned long long>(MountTimingNowUs()),
                static_cast<unsigned long long>(DiagExecutorId(diag)),
                DiagOp(diag),
                DiagFs(diag),
                proc_slot_id,
                EINVAL);
        }
        errno = EINVAL;
        return -1;
    }

    const int memfd = MemfdCreate("syzkaller", 0);
    if (memfd < 0) {
        const int saved_err = errno;
        if (diag_on) {
            ::refuzz::worker::log::WorkerLog(
                "[mount-timing] event=memfd_fail ts_us=%llu eid=%llu op=%s fs=%s slot=%u errno=%d\n",
                static_cast<unsigned long long>(MountTimingNowUs()),
                static_cast<unsigned long long>(DiagExecutorId(diag)),
                DiagOp(diag),
                DiagFs(diag),
                proc_slot_id,
                saved_err);
        }
        errno = saved_err;
        return -1;
    }

    // [chunk-based / dense mount image] Pick the materializer by leading magic:
    //   SEGS (sparse, host-segmented) → no decompress;
    //   zstd (dense, host-transcoded zlib→zstd) → fast zstd decompress;
    //   else legacy zlib inflate (still sparse-writes zero chunks).
    const int fill_rc =
        HasMountSegMagic(image_bytes, in_size)
            ? WriteSegmentsToFd(image_bytes, in_size, memfd)
        : HasZstdMagic(image_bytes, in_size)
            ? DecompressZstdToFd(image_bytes, in_size, memfd)
            : DecompressZlibToFd(image_bytes, in_size, memfd);
    if (fill_rc < 0) {
        const int saved_err = errno;
        if (diag_on) {
            ::refuzz::worker::log::WorkerLog(
                "[mount-timing] event=decompress_fail ts_us=%llu eid=%llu op=%s fs=%s slot=%u errno=%d\n",
                static_cast<unsigned long long>(MountTimingNowUs()),
                static_cast<unsigned long long>(DiagExecutorId(diag)),
                DiagOp(diag),
                DiagFs(diag),
                proc_slot_id,
                saved_err);
        }
        ::close(memfd);
        errno = saved_err;
        return -1;
    }
    if (diag_on) {
        ::refuzz::worker::log::WorkerLog(
            "[mount-timing] event=decompress_done ts_us=%llu eid=%llu op=%s fs=%s slot=%u\n",
            static_cast<unsigned long long>(MountTimingNowUs()),
            static_cast<unsigned long long>(DiagExecutorId(diag)),
            DiagOp(diag),
            DiagFs(diag),
            proc_slot_id);
    }

    int loopfd = -1;
    if (OpenLoopDeviceByProcSlot(proc_slot_id, loopname_buf, loopname_cap, &loopfd) < 0) {
        const int saved_err = errno;
        if (diag_on) {
            ::refuzz::worker::log::WorkerLog(
                "[mount-timing] event=open_loop_fail ts_us=%llu eid=%llu op=%s fs=%s slot=%u errno=%d\n",
                static_cast<unsigned long long>(MountTimingNowUs()),
                static_cast<unsigned long long>(DiagExecutorId(diag)),
                DiagOp(diag),
                DiagFs(diag),
                proc_slot_id,
                saved_err);
        }
        ::close(memfd);
        errno = saved_err;
        return -1;
    }
    if (diag_on) {
        ::refuzz::worker::log::WorkerLog(
            "[mount-timing] event=open_loop_done ts_us=%llu eid=%llu op=%s fs=%s slot=%u loop=%s\n",
            static_cast<unsigned long long>(MountTimingNowUs()),
            static_cast<unsigned long long>(DiagExecutorId(diag)),
            DiagOp(diag),
            DiagFs(diag),
            proc_slot_id,
            loopname_buf);
    }

    if (::ioctl(loopfd, LOOP_SET_FD, memfd) < 0) {
        if (errno != EBUSY) {
            const int saved_err = errno;
            if (diag_on) {
                ::refuzz::worker::log::WorkerLog(
                    "[mount-timing] event=loop_set_fd_fail ts_us=%llu eid=%llu op=%s fs=%s slot=%u loop=%s errno=%d\n",
                    static_cast<unsigned long long>(MountTimingNowUs()),
                    static_cast<unsigned long long>(DiagExecutorId(diag)),
                    DiagOp(diag),
                    DiagFs(diag),
                    proc_slot_id,
                    loopname_buf,
                    saved_err);
            }
            ::close(loopfd);
            ::close(memfd);
            errno = saved_err;
            return -1;
        }
        if (diag_on) {
            ::refuzz::worker::log::WorkerLog(
                "[mount-timing] event=loop_set_fd_ebusy ts_us=%llu eid=%llu op=%s fs=%s slot=%u loop=%s\n",
                static_cast<unsigned long long>(MountTimingNowUs()),
                static_cast<unsigned long long>(DiagExecutorId(diag)),
                DiagOp(diag),
                DiagFs(diag),
                proc_slot_id,
                loopname_buf);
        }
        // Mirror upstream retry: LOOP_CLR_FD, sleep 1ms, re-attempt LOOP_SET_FD.
        ::ioctl(loopfd, LOOP_CLR_FD, 0);
        Sleep1ms();
        if (::ioctl(loopfd, LOOP_SET_FD, memfd) < 0) {
            const int saved_err = errno;
            if (diag_on) {
                ::refuzz::worker::log::WorkerLog(
                    "[mount-timing] event=loop_set_fd_retry_fail ts_us=%llu eid=%llu op=%s fs=%s slot=%u loop=%s errno=%d\n",
                    static_cast<unsigned long long>(MountTimingNowUs()),
                    static_cast<unsigned long long>(DiagExecutorId(diag)),
                    DiagOp(diag),
                    DiagFs(diag),
                    proc_slot_id,
                    loopname_buf,
                    saved_err);
            }
            ::close(loopfd);
            ::close(memfd);
            errno = saved_err;
            return -1;
        }
    }
    if (diag_on) {
        ::refuzz::worker::log::WorkerLog(
            "[mount-timing] event=loop_set_fd_done ts_us=%llu eid=%llu op=%s fs=%s slot=%u loop=%s\n",
            static_cast<unsigned long long>(MountTimingNowUs()),
            static_cast<unsigned long long>(DiagExecutorId(diag)),
            DiagOp(diag),
            DiagFs(diag),
            proc_slot_id,
            loopname_buf);
    }

    ::close(memfd);
    *out_loopfd = loopfd;
    return 0;
}

void ResetLoopDevice(const char* loopname, const MountTimingDiagContext* diag)
{
    const bool diag_on = MountTimingDiagEnabled();
    if (loopname == nullptr) {
        if (diag_on) {
            ::refuzz::worker::log::WorkerLog(
                "[mount-timing] event=reset_loop_null ts_us=%llu eid=%llu op=%s fs=%s\n",
                static_cast<unsigned long long>(MountTimingNowUs()),
                static_cast<unsigned long long>(DiagExecutorId(diag)),
                DiagOp(diag),
                DiagFs(diag));
        }
        return;
    }
    if (diag_on) {
        ::refuzz::worker::log::WorkerLog(
            "[mount-timing] event=reset_loop_start ts_us=%llu eid=%llu op=%s fs=%s loop=%s\n",
            static_cast<unsigned long long>(MountTimingNowUs()),
            static_cast<unsigned long long>(DiagExecutorId(diag)),
            DiagOp(diag),
            DiagFs(diag),
            loopname);
    }
    const int fd = ::open(loopname, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        const int saved_err = errno;
        if (diag_on) {
            ::refuzz::worker::log::WorkerLog(
                "[mount-timing] event=reset_loop_open_fail ts_us=%llu eid=%llu op=%s fs=%s loop=%s errno=%d\n",
                static_cast<unsigned long long>(MountTimingNowUs()),
                static_cast<unsigned long long>(DiagExecutorId(diag)),
                DiagOp(diag),
                DiagFs(diag),
                loopname,
                saved_err);
        }
        errno = saved_err;
        return;
    }
    const int rc = ::ioctl(fd, LOOP_CLR_FD, 0);
    const int saved_err = errno;
    if (diag_on) {
        ::refuzz::worker::log::WorkerLog(
            "[mount-timing] event=reset_loop_ioctl ts_us=%llu eid=%llu op=%s fs=%s loop=%s rc=%d errno=%d\n",
            static_cast<unsigned long long>(MountTimingNowUs()),
            static_cast<unsigned long long>(DiagExecutorId(diag)),
            DiagOp(diag),
            DiagFs(diag),
            loopname,
            rc,
            rc == 0 ? 0 : saved_err);
    }
    ::close(fd);
}

namespace {

// errors=remount-ro detection mirrors upstream lines 3151-3158: substring
// must be terminated by ',' or end-of-string on both sides (otherwise a
// substring inside a longer option is not a real remount-ro setting).
bool HasExactOptionToken(const char* opts, const char* needle)
{
    const char* p = std::strstr(opts, needle);
    if (p == nullptr) {
        return false;
    }
    const char before = (p == opts) ? '\0' : *(p - 1);
    const char after  = *(p + std::strlen(needle));
    const bool before_ok = (before == '\0' || before == ',');
    const bool after_ok  = (after  == '\0' || after  == ',');
    return before_ok && after_ok;
}

void AppendOpt(char* out, std::size_t cap, const char* opt)
{
    const std::size_t cur = std::strlen(out);
    if (cur + std::strlen(opt) + 1 > cap) {
        return;  // truncate silently — matches upstream behavior on overflow
    }
    std::strcat(out, opt);
}

} // namespace

int BuildMountOpts(const char* fs,
                   const char* base_opts,
                   long* flags_inout,
                   char* out_opts,
                   std::size_t out_cap)
{
    if (fs == nullptr || base_opts == nullptr ||
        flags_inout == nullptr || out_opts == nullptr || out_cap < 32) {
        errno = EINVAL;
        return -1;
    }
    // Reserve 32 bytes for adjuster suffix (mirrors upstream `sizeof(opts)-32` margin).
    const std::size_t reserve = 32;
    const std::size_t base_len = std::strlen(base_opts);
    const bool truncated = (base_len > out_cap - reserve);
    const std::size_t copy_len = truncated ? (out_cap - reserve) : base_len;
    std::memcpy(out_opts, base_opts, copy_len);
    out_opts[copy_len] = '\0';

    // Per-fs adjusters mirror common_linux.h:3146-3168.
    if (std::strcmp(fs, "iso9660") == 0) {
        // [PR-D1 review fix C8] use MS_RDONLY from <sys/mount.h> (was
        // hardcoded `1L` with a comment). Symbolic form survives a future
        // kernel ABI change; comment was the only thing keeping it correct.
        *flags_inout |= static_cast<long>(MS_RDONLY);
    } else if (std::strncmp(fs, "ext", 3) == 0) {
        bool has_remount_ro = HasExactOptionToken(out_opts, "errors=remount-ro");
        if (std::strstr(out_opts, "errors=panic") != nullptr || !has_remount_ro) {
            AppendOpt(out_opts, out_cap, ",errors=continue");
        }
    } else if (std::strcmp(fs, "xfs") == 0) {
        AppendOpt(out_opts, out_cap, ",nouuid");
    } else if (std::strncmp(fs, "gfs2", 4) == 0 &&
               (std::strstr(out_opts, "errors=panic") != nullptr ||
                std::strstr(out_opts, "debug") != nullptr)) {
        AppendOpt(out_opts, out_cap, ",errors=withdraw");
    }
    return truncated ? -1 : 0;
}

} // namespace refuzz::worker::pseudo

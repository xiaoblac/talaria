// Copyright 2026 reFuzz project author -------youngkk.
//
// RemoteKcovBuffer impl — mirrors KcovCollector's resource handling.
// See header + docs/plans/refuzz-remote-kcov.md for the why.

#include "worker/coverage/remote_kcov_buffer.hpp"

#include "worker/log/log_macros.hpp"

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

// KCOV ioctl + remote-enable surface. Values copied verbatim from
// syzkaller's executor/executor_linux.h (lines 22-53) and the kernel's
// include/uapi/linux/kcov.h. Guarded so we never clash with a future
// system header that defines them.
#ifndef KCOV_INIT_TRACE
#define KCOV_INIT_TRACE  _IOR('c', 1, unsigned long)
#endif
#ifndef KCOV_TRACE_PC
#define KCOV_TRACE_PC    0
#endif

// kcov_remote_arg<N> wire struct (executor_linux.h:25-33). We enable COMMON +
// USB (num_handles=1) to mirror syz, so handles[0] carries the USB handle.
#ifndef REFUZZ_KCOV_REMOTE_ARG
#define REFUZZ_KCOV_REMOTE_ARG 1
template <int N>
struct refuzz_kcov_remote_arg {
    uint32_t trace_mode;
    uint32_t area_size;
    uint32_t num_handles;
    uint32_t pad;
    uint64_t common_handle;
    uint64_t handles[N];
};
#endif

// KCOV_REMOTE_ENABLE ioctl number (executor_linux.h:39). The kernel decodes
// _IOW('c', 102, ...) by command number only; the size field carried by the
// macro is informational (we pass kcov_remote_arg<1> at the call site), so the
// <0> here is just for the macro's size argument and does not constrain it.
#ifndef KCOV_REMOTE_ENABLE
#define KCOV_REMOTE_ENABLE _IOW('c', 102, refuzz_kcov_remote_arg<0>)
#endif

// Subsystem + handle helpers (executor_linux.h:42-53).
#ifndef KCOV_SUBSYSTEM_COMMON
#define KCOV_SUBSYSTEM_COMMON (0x00ull << 56)
#endif
#ifndef KCOV_SUBSYSTEM_USB
#define KCOV_SUBSYSTEM_USB (0x01ull << 56)
#endif
#ifndef KCOV_SUBSYSTEM_MASK
#define KCOV_SUBSYSTEM_MASK (0xffull << 56)
#endif
#ifndef KCOV_INSTANCE_MASK
#define KCOV_INSTANCE_MASK (0xffffffffull)
#endif

#define REFUZZ_HAVE_KCOV 1

namespace refuzz::worker {

namespace {

inline uint64_t RefuzzKcovRemoteHandle(uint64_t subsys, uint64_t inst)
{
    if ((subsys & ~KCOV_SUBSYSTEM_MASK) || (inst & ~KCOV_INSTANCE_MASK)) {
        return 0;
    }
    return subsys | inst;
}

} // namespace

RemoteKcovBuffer::RemoteKcovBuffer(std::size_t entry_count,
                                   uint32_t instance,
                                   KcovChildMode child_mode)
    : entry_count_(entry_count < 1024u ? 1024u : entry_count)
    , instance_(instance)
    , child_mode_(child_mode)
{}

RemoteKcovBuffer::~RemoteKcovBuffer()
{
#if REFUZZ_HAVE_KCOV
    if (area_ != nullptr) {
        munmap(area_, entry_count_ * sizeof(uint64_t));
    }
    if (fd_ >= 0) {
        close(fd_);
    }
#endif
}

bool RemoteKcovBuffer::Init()
{
#if REFUZZ_HAVE_KCOV
    fd_ = open("/sys/kernel/debug/kcov", O_RDWR);
    if (fd_ < 0) {
        ::refuzz::worker::log::WorkerLog(
            "[remote-kcov] open failed: %s (errno=%d)\n", strerror(errno), errno);
        return false;
    }
    if (ioctl(fd_, KCOV_INIT_TRACE, entry_count_) < 0) {
        ::refuzz::worker::log::WorkerLog(
            "[remote-kcov] KCOV_INIT_TRACE failed: %s (errno=%d)\n",
            strerror(errno), errno);
        close(fd_);
        fd_ = -1;
        return false;
    }
    if (!EnsureMapped()) {
        close(fd_);
        fd_ = -1;
        return false;
    }
    enabled_ = true;
    return true;
#else
    return false;
#endif
}

bool RemoteKcovBuffer::EnsureMapped()
{
#if REFUZZ_HAVE_KCOV
    if (area_ != nullptr) {
        return true;
    }
    if (fd_ < 0) {
        return false;
    }
    const size_t map_bytes = entry_count_ * sizeof(uint64_t);
    area_ = static_cast<uint64_t*>(
        mmap(nullptr, map_bytes, PROT_READ | PROT_WRITE, MAP_SHARED, fd_, 0));
    if (area_ == MAP_FAILED) {
        ::refuzz::worker::log::WorkerLog(
            "[remote-kcov] mmap failed: %s (errno=%d)\n", strerror(errno), errno);
        area_ = nullptr;
        return false;
    }
    // Same fork strategy as KcovCollector: MADV_DONTFORK on the parent mapping
    // so dup_mmap skips this VMA on program-child fork; child re-mmaps via
    // ResetMappingForChild() + the next EnsureMapped(). Non-fatal on failure.
    if (child_mode_ == KcovChildMode::kFreshPerProgram &&
        madvise(area_, map_bytes, MADV_DONTFORK) != 0) {
        ::refuzz::worker::log::WorkerLog(
            "[remote-kcov] madvise(MADV_DONTFORK) failed: %s (errno=%d) "
            "— child will inherit this mapping instead of remapping\n",
            strerror(errno), errno);
    }
    return true;
#else
    return false;
#endif
}

bool RemoteKcovBuffer::EnableRemote()
{
#if REFUZZ_HAVE_KCOV
    if (!enabled_ || fd_ < 0) {
        return false;
    }
    // [当前版本 COMMON+USB + EEXIST-retry] Enable COMMON + USB remote coverage,
    // mirroring syz (executor_linux.h:194-202): num_handles=1, common_handle=
    // COMMON|inst, handles[0]=USB|inst. Previously num_handles=0 (COMMON only),
    // so USB-subsystem async coverage was never collected.
    //
    // On a worker respawn-by-topology, the killed child's kcov fd can still hold
    // our handle in the kernel's kcov_remote_map for a moment → KCOV_REMOTE_ENABLE
    // returns EEXIST and the respawned worker would otherwise run local-only for
    // the rest of the session. The handle VALUE is arbitrary (the ioctl sets
    // current->kcov_handle to whatever we pass; it only has to be unique among
    // live handles), so on EEXIST we retry with a worker-strided fresh instance
    // until a free slot is found. Stride (64) > any worker count, so retried
    // slots never collide with another worker's base instance (worker w probes
    // w+1, w+1+64, w+1+128, … — disjoint across workers).
    static constexpr uint64_t kRetryStride = 64;
    static constexpr int      kMaxRetries  = 4;
    for (int attempt = 0; attempt <= kMaxRetries; ++attempt) {
        const uint64_t inst = static_cast<uint64_t>(instance_) +
                              static_cast<uint64_t>(attempt) * kRetryStride;
        refuzz_kcov_remote_arg<1> arg = {};
        arg.trace_mode = static_cast<uint32_t>(KCOV_TRACE_PC);
        arg.area_size = static_cast<uint32_t>(entry_count_);
        arg.num_handles = 1;
        arg.common_handle = RefuzzKcovRemoteHandle(KCOV_SUBSYSTEM_COMMON, inst);
        arg.handles[0] = RefuzzKcovRemoteHandle(KCOV_SUBSYSTEM_USB, inst);
        if (ioctl(fd_, KCOV_REMOTE_ENABLE, &arg) == 0) {
            remote_enabled_ = true;
            ::refuzz::worker::log::WorkerLog(
                "[remote-kcov] KCOV_REMOTE_ENABLE ok fd=%d instance=%u "
                "common_handle=0x%llx usb_handle=0x%llx area_entries=%zu%s\n",
                fd_, static_cast<unsigned>(inst),
                static_cast<unsigned long long>(arg.common_handle),
                static_cast<unsigned long long>(arg.handles[0]),
                entry_count_,
                attempt > 0 ? " (after EEXIST retry)" : "");
            return true;
        }
        const int e = errno;
        if (e != EEXIST || attempt == kMaxRetries) {
            // Non-EEXIST error, or retries exhausted: a kernel without remote
            // KCOV (or a genuinely stuck handle) must NOT break local KCOV.
            ::refuzz::worker::log::WorkerLog(
                "[remote-kcov] KCOV_REMOTE_ENABLE failed fd=%d instance=%u "
                "common_handle=0x%llx errno=%d (%s)%s\n",
                fd_, static_cast<unsigned>(inst),
                static_cast<unsigned long long>(arg.common_handle),
                e, strerror(e),
                e == EEXIST ? " — retries exhausted" : "");
            return false;
        }
        // EEXIST: handle still live from a prior (respawned) worker — step to
        // the next strided instance and retry.
        ::refuzz::worker::log::WorkerLog(
            "[remote-kcov] KCOV_REMOTE_ENABLE EEXIST on instance=%u, retrying "
            "with instance=%u\n",
            static_cast<unsigned>(inst),
            static_cast<unsigned>(inst + kRetryStride));
    }
    return false;  // unreachable: loop returns on success or final-attempt failure
#else
    return false;
#endif
}

void RemoteKcovBuffer::ResetMappingForChild()
{
#if REFUZZ_HAVE_KCOV
    if (child_mode_ == KcovChildMode::kFreshPerProgram) {
        area_ = nullptr;
    }
#endif
}

void RemoteKcovBuffer::ResetProgram()
{
#if REFUZZ_HAVE_KCOV
    if (!enabled_ || area_ == nullptr) {
        return;
    }
    area_[0] = 0;
#endif
}

uint64_t RemoteKcovBuffer::CollectCount() const
{
#if REFUZZ_HAVE_KCOV
    if (!enabled_ || area_ == nullptr) {
        return 0;
    }
    uint64_t n = area_[0];
    if (n > entry_count_ - 1) {
        n = entry_count_ - 1;
    }
    return n;
#else
    return 0;
#endif
}

void RemoteKcovBuffer::EnsureMappedAndCollectPCs(std::vector<uint64_t>* out)
{
#if REFUZZ_HAVE_KCOV
    if (out == nullptr) {
        return;
    }
    out->clear();
    if (!enabled_) {
        return;
    }
    // In the program-child the parent mapping was MADV_DONTFORK'd away and
    // OnChildPostFork() dropped area_; re-mmap the inherited fd so we view the
    // kernel kcov->area the COMMON handle accumulated into.
    if (area_ == nullptr) {
        (void)EnsureMapped();
    }
    CollectPCs(out);
#else
    (void)out;
#endif
}

void RemoteKcovBuffer::CollectPCs(std::vector<uint64_t>* out) const
{
#if REFUZZ_HAVE_KCOV
    if (out == nullptr) {
        return;
    }
    out->clear();
    if (!enabled_ || area_ == nullptr) {
        return;
    }
    uint64_t n = area_[0];
    if (n > entry_count_ - 1) {
        n = entry_count_ - 1;
    }
    out->reserve(static_cast<size_t>(n));
    for (uint64_t i = 0; i < n; ++i) {
        out->push_back(area_[i + 1]);
    }
#else
    (void)out;
#endif
}

bool RemoteKcovBuffer::RemapFdAtOrAbove(int* next_fd)
{
#if REFUZZ_HAVE_KCOV
    if (next_fd == nullptr) {
        return false;
    }
    if (fd_ < 0) {
        return true;
    }
    if (fd_ >= *next_fd) {
        *next_fd = fd_ + 1;
        return true;
    }
    const int new_fd = ::fcntl(fd_, F_DUPFD_CLOEXEC, *next_fd);
    if (new_fd < 0) {
        return false;
    }
    ::close(fd_);
    fd_ = new_fd;
    *next_fd = new_fd + 1;
    return true;
#else
    (void)next_fd;
    return true;
#endif
}

} // namespace refuzz::worker

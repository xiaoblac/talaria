// Copyright 2026 reFuzz project author -------youngkk.
//
// RemoteKcovBuffer (Gap 1 / S1): a SECOND /dev/kcov buffer enabled via
// KCOV_REMOTE_ENABLE with a COMMON subsystem handle. This is ADDITIVE to the
// existing per-task local KCOV (KcovCollector): the local buffer captures the
// synchronous syscall-task coverage, this one captures coverage produced in
// kernel worker-threads / softirqs / kthreads that act "on behalf of" the
// current task (ext4 jbd2 journal, btrfs workers, net mac80211 softirq RX, ...).
//
// Kernel mechanism (verified, see docs/plans/refuzz-remote-kcov.md §1):
//   - KCOV_REMOTE_ENABLE(common_handle=H) registers H→area and sets
//     task->kcov_handle = H. kcov_handle is INHERITED across clone/fork
//     (kcov_task_init). Async processing routes coverage tagged with H into
//     H's area. Enabling H in loop_child BEFORE it forks program-children /
//     pool-threads makes the whole tree inherit H.
//   - This ioctl does NOT capture the enabling task's synchronous coverage; it
//     only feeds the remote area. So it MUST NOT replace the local KCOV_ENABLE.
//
// Resource handling mirrors KcovCollector. Legacy fresh mode uses
// MADV_DONTFORK + child re-mmap; production inherited mode keeps the loop mmap.
//
// S1 scope: enable + per-program reset + a count for WorkerLog verification.
// No wire-protocol / host changes (those are S2/S3).

#pragma once

#include "worker/coverage/kcov_collector.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace refuzz::worker {

// syzkaller 08ab31164 `kExtraCoverSize`: one per-executor remote buffer with
// 1M entries (8 MiB on 64-bit Linux), independently sized from the 512K-entry
// local per-thread buffers.
inline constexpr std::size_t kSyzkallerExtraKcovEntries = 1024u << 10;

class RemoteKcovBuffer {
public:
    // entry_count: KCOV area entry count (area_[1..N] usable, area_[0] is the
    //   kernel cursor) — same units as KcovCollector / KCOV_INIT_TRACE.
    // instance: per-(worker/proc) unique instance used to build the COMMON
    //   handle kcov_remote_handle(KCOV_SUBSYSTEM_COMMON, instance). Mirrors
    //   syzkaller's `procid + 1` (executor_linux.h:200). Single worker may use
    //   a fixed value.
    explicit RemoteKcovBuffer(
        std::size_t entry_count,
        uint32_t instance,
        KcovChildMode child_mode = KcovChildMode::kFreshPerProgram);
    ~RemoteKcovBuffer();
    RemoteKcovBuffer(const RemoteKcovBuffer&) = delete;
    RemoteKcovBuffer& operator=(const RemoteKcovBuffer&) = delete;
    RemoteKcovBuffer(RemoteKcovBuffer&&) = delete;
    RemoteKcovBuffer& operator=(RemoteKcovBuffer&&) = delete;

    // open /sys/kernel/debug/kcov + KCOV_INIT_TRACE + mmap. Best-effort:
    // returns false on any failure (caller logs + continues — existing local
    // KCOV must keep working).
    bool Init();

    // KCOV_REMOTE_ENABLE with common_handle = kcov_remote_handle(
    // KCOV_SUBSYSTEM_COMMON, instance_), num_handles=0 (no USB handle in S1).
    // MUST be called on the task that should own kcov_handle = H (loop_child)
    // BEFORE it forks program-children / pool-threads so they inherit H.
    // Best-effort: returns false on failure, never throws / aborts.
    bool EnableRemote();

    // Per-program boundary: clear the kernel write cursor (area_[0] = 0).
    void ResetProgram();

    // Number of remote PCs accumulated since the last ResetProgram(), clamped
    // to entry_count_ - 1. S1 only needs the count (for WorkerLog).
    uint64_t CollectCount() const;

    // Copy the accumulated remote PCs into *out (area_[1..count]). Unused in S1
    // (no wire yet) but provided for S2/S3.
    void CollectPCs(std::vector<uint64_t>* out) const;

    // [remote-kcov S2] Program-child collect: re-mmap if needed, then copy the
    // accumulated remote PCs. The per-program reset happens in loop_child
    // BEFORE the program-child fork (loop_runtime), but the emit runs in the
    // program-child's KcovSink::PackFeedback — where OnChildPostFork() has
    // nulled area_ (MADV_DONTFORK left no PTEs). CollectPCs()/CollectCount()
    // early-return on area_==nullptr, so the program-child must EnsureMapped()
    // first; the re-mmap views the SAME kernel kcov->area the COMMON handle
    // feeds (inherited fd), so it observes the softirq/kthread coverage the
    // pool threads accumulated. Non-const because it re-mmaps.
    void EnsureMappedAndCollectPCs(std::vector<uint64_t>* out);

    bool Enabled() const { return enabled_; }

    // Child fd-table hygiene + child-mode-specific mapping handling.
    void ResetMappingForChild();
    bool RemapFdAtOrAbove(int* next_fd);
    int InternalFd() const { return fd_; }

    // RLIMIT_AS sizing input (declared worst-case VA budget).
    std::size_t BufferBytes() const { return entry_count_ * sizeof(uint64_t); }

private:
    bool EnsureMapped();

    std::size_t entry_count_;
    uint32_t    instance_;
    int         fd_ = -1;
    uint64_t*   area_ = nullptr;
    bool        enabled_ = false;   // Init() succeeded (fd + mmap ready)
    bool        remote_enabled_ = false;  // KCOV_REMOTE_ENABLE succeeded
    KcovChildMode child_mode_ = KcovChildMode::kFreshPerProgram;
};

} // namespace refuzz::worker

// PR-D1 — per-program mount sub-context implementation.

#include "worker/backend/pseudo/mount/mount_state.hpp"

#include "worker/backend/pseudo/mount/mount_helpers.hpp"

#include <cerrno>
#include <memory>
#include <mutex>
#include <pthread.h>
#include <sys/mount.h>
#include <unistd.h>
#include <unordered_map>

namespace refuzz::worker::pseudo {

namespace {

// Global by-context map. Worker is currently single-threaded per ChildMain
// (one program at a time), but the mutex is cheap insurance against
// future re-entrant test harnesses.
std::mutex g_mount_state_mutex;
std::unordered_map<const PseudoContext*, std::unique_ptr<MountState>> g_mount_state_by_ctx;

// [fork-safety 2026-08-08] Keep the state map self-consistent across any
// multi-threaded fork. The current program fork normally happens before the
// child lazily constructs its driver/pool, so this is defensive protection for
// future call paths and for forks made while pseudo state is being updated.
// prepare owns the mutex across fork; parent and child both release that
// prepare lock. This avoids reinitializing a live std::mutex object, which is
// undefined behavior and can corrupt the C++ mutex implementation.
void PseudoStateAtForkPrepare()
{
    g_mount_state_mutex.lock();
}

void PseudoStateAtForkParent()
{
    g_mount_state_mutex.unlock();
}

void PseudoStateAtForkChild()
{
    g_mount_state_mutex.unlock();
}

struct PseudoStateAtForkRegistrar {
    PseudoStateAtForkRegistrar()
    {
        (void)pthread_atfork(&PseudoStateAtForkPrepare,
                             &PseudoStateAtForkParent,
                             &PseudoStateAtForkChild);
    }
};
const PseudoStateAtForkRegistrar g_pseudo_state_atfork_registrar;

// [PR-D1 review fix C9 2026-05-06] Move the unique_ptr out of the map
// under lock, then drop the lock BEFORE calling Cleanup(). Cleanup runs
// umount2 + LOOP_CLR_FD which can be slow under kernel contention; with
// the previous "Cleanup() under lock" code, future multi-program-per-
// worker would block all teardowns on this mutex. Single-threaded today
// so the behavior is identical, but the change is free and unblocks
// concurrency without a follow-up audit.
std::unique_ptr<MountState> ExtractMountStateForTeardown(const PseudoContext* ctx_ptr)
{
    std::lock_guard<std::mutex> lock(g_mount_state_mutex);
    auto it = g_mount_state_by_ctx.find(ctx_ptr);
    if (it == g_mount_state_by_ctx.end()) {
        return nullptr;
    }
    auto extracted = std::move(it->second);
    g_mount_state_by_ctx.erase(it);
    return extracted;
}

} // namespace

void MountState::Cleanup()
{
    // [R1 mount/loop teardown locus 2026-06-06] DoubleFork program-child: the
    // loop_child parent owns the authoritative post-reap teardown (loop_runtime
    // RemoveDirRecursive / next-iteration fixed-slot loop reset). There, the
    // program-child is already reaped so ALL its fds (dirfd + every file the
    // program opened inside the mount) are closed by the kernel → umount2(0) is
    // synchronous and LOOP_CLR_FD then succeeds. Doing teardown *here* (in-child,
    // before _exit, with those fds still open) can only EBUSY and degrade to a
    // lazy MNT_DETACH — which detaches from the path and makes the parent's
    // subsequent synchronous umount a no-op racing the async detach. So skip
    // entirely; the child _exit reclaims fds + cwd. Inline/Reusable topology has
    // no reap boundary and falls through to the full in-process teardown below.
    if (defer_teardown) {
        return;
    }
    // [PR-D1 review fix C7] Restore CWD FIRST (before umount), so that
    // umount2 doesn't have to walk a deleted/unmounted dir to figure out
    // we're sitting in it. fchdir(O_PATH fd) is itself reliable even if
    // the directory tree we point at was already unmounted/removed.
    if (saved_cwd_fd >= 0) {
        (void)::fchdir(saved_cwd_fd);
        ::close(saved_cwd_fd);
        saved_cwd_fd = -1;
    }
    // [reorder-clear 2026-06-03] umount targets in reverse order, SYNCHRONOUSLY so
    // each fs is fully detached before we clear its backing loop below. The old
    // unconditional MNT_DETACH is lazy: the fs lingers, so the subsequent
    // ResetLoopDevice open(O_RDWR) EBUSYs and the next fixed-slot reset retries it.
    // With sync umount the loop is free, so the in-child clear succeeds. Fall back
    // to MNT_DETACH only when the mount is genuinely busy (preserve "never block").
    while (!active_mount_targets.empty()) {
        const std::string& target = active_mount_targets.back();
        if (::umount2(target.c_str(), 0) < 0 && (errno == EBUSY || errno == EAGAIN)) {
            ::umount2(target.c_str(), MNT_DETACH);
        }
        active_mount_targets.pop_back();
    }
    // Now that the filesystems are detached, clear the backing loop devices
    // in-child (open(O_RDWR)+LOOP_CLR_FD succeeds with no fs mounted).
    while (!active_loopnames.empty()) {
        const std::string& loopname = active_loopnames.back();
        ResetLoopDevice(loopname.c_str());
        active_loopnames.pop_back();
    }
}

MountState& GetOrCreateMountState(const PseudoContext& ctx)
{
    std::lock_guard<std::mutex> lock(g_mount_state_mutex);
    const PseudoContext* key = &ctx;
    auto it = g_mount_state_by_ctx.find(key);
    if (it != g_mount_state_by_ctx.end()) {
        return *it->second;
    }
    auto state = std::make_unique<MountState>();
    MountState& ref = *state;
    // [R1] Capture the teardown locus decided by KernelWireDriver (DoubleFork
    // program-child → defer to loop_child parent; Inline → tear down in-child).
    ref.defer_teardown = ctx.defer_mount_teardown;
    g_mount_state_by_ctx[key] = std::move(state);

    // Register cleanup on ctx. The lambda captures by value (the ptr)
    // so the address remains stable even if the ctx storage moves —
    // RegisterCleanup is invoked from PseudoRuntimeContext::Cleanup()
    // which sees the same `ctx` instance, so identity is preserved.
    //
    // [PR-D1 review fix C9] Extract from the map under lock, drop the
    // lock, then run Cleanup() on the moved-out state. Keeps slow
    // umount2/LOOP_CLR_FD off the critical section.
    ctx.RegisterCleanup([key]() {
        auto extracted = ExtractMountStateForTeardown(key);
        if (extracted != nullptr) {
            extracted->Cleanup();
        }
    });
    return ref;
}

} // namespace refuzz::worker::pseudo

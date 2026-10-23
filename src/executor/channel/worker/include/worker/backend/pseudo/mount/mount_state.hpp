#pragma once

// PR-D1 — per-program mount sub-context (plan §5.2 Tier 3 default pattern).
//
// MountState owns the per-program mount lifecycle: active loop devices that
// need ioctl(LOOP_CLR_FD) on teardown and active mount targets that need
// umount(2). Cleanup runs in reverse insertion order so nested mounts unwind
// correctly.
//
// Lookup is by `&PseudoContext` identity — KernelWireDriver allocates a fresh
// PseudoRuntimeContext per Execute() call (one per program), so the address
// is a stable per-program key. GetOrCreateMountState() registers a cleanup
// callback on the context the first time it is called for that context;
// subsequent calls in the same program share the same MountState instance.
//
// State is heap-allocated and lives in an anonymous-namespace global map
// inside `mount_state.cpp`. Plan §5.2 forbids fields on PseudoRuntimeContext
// for Tier 3 families; this side-channel keeps the requirement satisfied
// while still providing per-program persistence.

#include "worker/backend/pseudo/pseudo_context.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace refuzz::worker::pseudo {

struct MountState {
    // Loop device names registered via SetupLoopDevice. ResetLoopDevice
    // is called on each in reverse order at Cleanup() (mirrors upstream
    // `error_clear_loop` cleanup at common_linux.h:3194-3195).
    std::vector<std::string> active_loopnames;

    // Mount target dirs registered after a successful mount(2). umount2
    // (MNT_DETACH) is called on each in reverse order at Cleanup().
    // Upstream syz-executor relies on per-process tear-down via setns +
    // namespace destruction; reFuzz keeps the worker process across
    // many programs, so explicit umount is required between programs.
    std::vector<std::string> active_mount_targets;

    // [PR-D1 review fix C7 2026-05-06] Saved CWD fd from the FIRST
    // chdir(target) call this program issued (subsequent chdirs are
    // not stacked — upstream syz-executor doesn't restore between
    // chdirs either, only after the program ends). -1 means no chdir
    // happened yet OR the save itself failed (e.g., getcwd-equivalent
    // unavailable). Cleanup() does fchdir(saved_cwd_fd) + close, so
    // the worker process CWD reverts at program teardown rather than
    // leaking the mount-image target into the next program.
    //
    // Why O_PATH instead of O_RDONLY: O_PATH refers to the inode
    // without keeping the dir busy or holding a real fd table slot
    // beyond what fchdir(2) needs, which is the cheapest "save dir"
    // primitive on modern Linux. Reverts cleanly even if the directory
    // tree was unmounted/removed in the meantime.
    int saved_cwd_fd = -1;

    // [R1 mount/loop teardown locus] Mirrors PseudoContext::defer_mount_teardown
    // captured at GetOrCreateMountState time. true ⇔ DoubleFork program-child:
    // the loop_child parent does the authoritative post-reap teardown, so
    // Cleanup() below is a no-op (in-child umount can only EBUSY on still-open
    // fds → lazy MNT_DETACH that defeats the parent's synchronous umount). false
    // ⇔ Inline/Reusable: Cleanup() does the full in-process teardown.
    bool defer_teardown = false;

    // Tear down all active mounts + loop devices in reverse order, and
    // restore CWD if changed. Best-effort: failures are logged via debug
    // only, never propagated (matches upstream reset_loop_device contract
    // — Cleanup must not throw / abort).
    void Cleanup();
};

// Lookup-or-allocate the MountState attached to this PseudoContext.
// First call also registers a cleanup callback on `ctx` so the state
// is torn down at program end. Returns a stable reference for the
// duration of the program.
MountState& GetOrCreateMountState(const PseudoContext& ctx);

} // namespace refuzz::worker::pseudo

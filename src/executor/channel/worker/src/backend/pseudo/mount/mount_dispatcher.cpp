// PR-D1 — mount-image domain handler implementation.
//
// One handler covers the whole `syz_mount_image$<fs>` family (kMount domain).
// Per-fs adjusters live in `mount_helpers.cpp::BuildMountOpts`. Sub-context
// state (active loopnames + mount targets) lives in `mount_state.cpp`.
//
// This handler is rule-3 in plan §10 Q6 generalization: handler-active +
// non-degradable. Cap mask `kCapNeedsRoot|kCapNeedsMount` is enforced at the
// dispatcher gate (pseudo_dispatcher.cpp:96-99); when the gate passes we know
// the worker holds the right caps. Lifecycle errors fail-closed via PseudoResult.

#include "worker/backend/pseudo/mount/mount_dispatcher.hpp"

#include "worker/backend/pseudo/mount/mount_helpers.hpp"
#include "worker/backend/pseudo/mount/mount_state.hpp"
#include "worker/log/log_macros.hpp"

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

namespace refuzz::worker::pseudo {

namespace {

PseudoResult Error(int err, const char* reason = nullptr)
{
    return PseudoResult{-1, err, reason};
}

const char* LogStr(const char* s)
{
    return s != nullptr ? s : "-";
}

// Extract a 6-char prefix from the pseudo name to identify the family
// quickly. We don't actually need the fs name from the meta — args[0]
// is the fs name string already (matches upstream syz_mount_image
// signature; the meta name only tells us the domain).
//
// Pull fs name from the syscall arg-0 ptr safely. Returns nullptr on
// nul/empty/garbage.
const char* SafeCStr(const void* p, std::size_t max_len = 64)
{
    if (p == nullptr) {
        return nullptr;
    }
    // Caller supplies a userspace-style cstr in scratch memory; KernelWireDriver
    // already materialized it into the worker's address space. Bound the scan
    // to avoid running off allocated buffers.
    const char* s = static_cast<const char*>(p);
    for (std::size_t i = 0; i < max_len; ++i) {
        if (s[i] == '\0') {
            return s;
        }
    }
    return nullptr;
}

} // namespace

PseudoResult DispatchMountPseudo(const PseudoContext& ctx,
                                 const refuzz::fuzzer::syz::PseudoMeta& meta,
                                 const intptr_t* args,
                                 uint32_t argc)
{
    (void)meta;  // name is informational; behavior driven by args[0].
    if (args == nullptr || argc < 7) {
        return Error(EINVAL, "syz_mount_image: argc<7");
    }

    const char* fs        = SafeCStr(reinterpret_cast<const void*>(args[0]));
    const char* target    = SafeCStr(reinterpret_cast<const void*>(args[1]),
                                     /*max_len=*/256);
    long        flags     = static_cast<long>(args[2]);
    const char* mount_opts = SafeCStr(reinterpret_cast<const void*>(args[3]),
                                      /*max_len=*/256);
    const long  change_dir = static_cast<long>(args[4]);
    const std::size_t size = static_cast<std::size_t>(args[5]);
    const uint8_t*    image = reinterpret_cast<const uint8_t*>(args[6]);

    if (fs == nullptr || fs[0] == '\0') {
        return Error(EINVAL, "syz_mount_image: missing fs name");
    }
    if (target == nullptr || target[0] == '\0') {
        return Error(EINVAL, "syz_mount_image: missing target dir");
    }
    if (mount_opts == nullptr) {
        // Upstream tolerates NULL opts via the strncpy(opts, "", ...) path; keep
        // a stable empty string here.
        mount_opts = "";
    }

    MountState& state = GetOrCreateMountState(ctx);

    // ---- Phase 1: optional loop-device backing for image-bearing fs ----
    //
    // [v1 — keep loopname registered until program teardown; ROLLBACK only
    //  if we accept the per-call leak observed in PR-D1 review C6.]
    // const bool need_loop = (size != 0) && (image != nullptr);
    // if (need_loop) {
    //     int loopfd = -1;
    //     if (SetupLoopDevice(...) < 0) return Error(errno, "setup_loop_device");
    //     state.active_loopnames.emplace_back(loopname);
    //     ::close(loopfd);
    //     source = loopname;
    // }
    //
    // [v2 PR-D1 review fix C6 2026-05-06 — 当前版本]
    // Mirror upstream `error_clear_loop:` discipline at common_linux.h:3193-3197:
    // ResetLoopDevice runs on EVERY return path that previously did
    // setup_loop_device, success and failure alike. We only register the
    // loopname into state.active_loopnames AFTER mount(2) succeeds — that way
    // a mount failure releases the loop device immediately rather than
    // accumulating until program teardown. Default kernel max_loop=256, so
    // a fuzz program with 256+ failed mount-image calls would otherwise
    // exhaust /dev/loop* and silently degrade subsequent calls.
    char loopname[64] = {};
    const char* source = nullptr;
    bool loop_attached = false;  // tracks whether ResetLoopDevice is owed
    // [PR-D1.O' Fix 4] Match upstream common_linux.h:3117 — `need_loop_device =
    // !!size`. Previously reFuzz added `&& image != nullptr` defensively which
    // diverged: with size>0 + image=NULL, reFuzz silently fell through to
    // mount(NULL, ...) (works for tmpfs, fails for others). Upstream invokes
    // setup_loop_device(NULL, size, ...) and either crashes inside puff or
    // returns -1; reFuzz's SetupLoopDevice rejects NULL gracefully with EINVAL,
    // matching upstream's "fail" outcome without the crash.
    const bool need_loop = (size != 0);
    const MountTimingDiagContext diag{ctx.DiagnosticExecutorId(),
                                      "syz_mount_image",
                                      fs};
    const bool diag_on = MountTimingDiagEnabled();
    if (need_loop) {
        int loopfd = -1;
        // Publish the cleanup candidate before SetupLoopDevice: a timeout can
        // land after LOOP_SET_FD but before the helper returns.
        ctx.RecordLoopDeviceUsed(ctx.EffectiveLoopSlot());
        if (SetupLoopDevice(image,
                            size,
                            ctx.EffectiveLoopSlot(),
                            loopname,
                            sizeof(loopname),
                            &loopfd,
                            &diag) < 0) {
            return Error(errno, "setup_loop_device");
        }
        loop_attached = true;
        // Close loopfd before mount(2) — kernel BLK_DEV_WRITE_MOUNTED check
        // refuses mount while loop fd is held open by anyone (upstream
        // common_linux.h:3132-3134).
        ::close(loopfd);
        source = loopname;
    }

    // Helper to release loop on early-exit. Must run before any return
    // that follows a successful SetupLoopDevice but has not yet promoted
    // the loopname into state.active_loopnames.
    auto release_unowned_loop = [&]() {
        if (loop_attached) {
            ResetLoopDevice(loopname, &diag);
            loop_attached = false;
        }
    };

    // ---- Phase 2: target dir + opts buffer + per-fs adjuster ----
    ::mkdir(target, 0777);  // ignore EEXIST — matches upstream behavior

    char opts[256] = {};
    (void)BuildMountOpts(fs, mount_opts, &flags, opts, sizeof(opts));

    // Narrow per-call KCOV window — mirror upstream common_linux.h:3171
    // `cover_reset(0)` between setup_loop_device and mount(2). The
    // SetupLoopDevice call above runs zlib inflate → repeated write(memfd)
    // → shmem_file_write_iter / folio / page-fault PCs which flood the kcov
    // ring (default ~524K slot cap) before mount(2) can record anything.
    // Discarding the prep phase here keeps the per-call slice scoped to
    // mount(2) → open(target) → chdir(target), which is what upstream
    // attributes to syz_mount_image and what the paired-oracle comparator
    // expects for Jaccard equivalence.
    ctx.KcovCursorReset();

    // ---- Phase 3: mount(2) ----
    if (diag_on) {
        ::refuzz::worker::log::WorkerLog(
            "[mount-timing] event=mount_enter ts_us=%llu eid=%llu op=%s fs=%s slot=%u source=%s target=%s flags=0x%lx opts=%s\n",
            static_cast<unsigned long long>(MountTimingNowUs()),
            static_cast<unsigned long long>(ctx.DiagnosticExecutorId()),
            diag.op,
            diag.fs,
            ctx.proc_slot_id,
            LogStr(source),
            LogStr(target),
            static_cast<unsigned long>(flags),
            LogStr(opts));
    }
    const int mount_rc = ::mount(source, target, fs, static_cast<unsigned long>(flags), opts);
    const int mount_err = mount_rc == 0 ? 0 : errno;
    if (diag_on) {
        ::refuzz::worker::log::WorkerLog(
            "[mount-timing] event=mount_exit ts_us=%llu eid=%llu op=%s fs=%s slot=%u source=%s target=%s rc=%d errno=%d\n",
            static_cast<unsigned long long>(MountTimingNowUs()),
            static_cast<unsigned long long>(ctx.DiagnosticExecutorId()),
            diag.op,
            diag.fs,
            ctx.proc_slot_id,
            LogStr(source),
            LogStr(target),
            mount_rc,
            mount_err);
    }
    if (mount_rc < 0) {
        release_unowned_loop();
        return Error(mount_err, "mount");
    }
    // [reorder-clear 2026-06-03] On SUCCESS the loop now carries a mounted fs, so
    // an immediate ResetLoopDevice here only EBUSYs on open(O_RDWR) (can't open the
    // device while its fs is mounted) — it never actually detaches the loop, which
    // is then left orphaned for the next fixed-slot reset to reclaim. (The old
    // "detach before return" contract was therefore never met for mounted loops.)
    // Instead TRACK the loop and let MountState::Cleanup clear it AFTER a
    // synchronous umount, when open(O_RDWR)+LOOP_CLR_FD finally succeeds in-child —
    // eliminating reset_loop_open_fail and leaving reset_loop as a backstop.
    // loop_attached is cleared so a later early-exit can't double-handle it.
    state.active_loopnames.emplace_back(loopname);
    loop_attached = false;
    state.active_mount_targets.emplace_back(target);

    // ---- Phase 4: open(target, O_RDONLY|O_DIRECTORY) → return fd ----
    if (diag_on) {
        ::refuzz::worker::log::WorkerLog(
            "[mount-timing] event=open_target_enter ts_us=%llu eid=%llu op=%s fs=%s slot=%u target=%s\n",
            static_cast<unsigned long long>(MountTimingNowUs()),
            static_cast<unsigned long long>(ctx.DiagnosticExecutorId()),
            diag.op,
            diag.fs,
            ctx.proc_slot_id,
            LogStr(target));
    }
    const int dirfd = ::open(target, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    const int open_err = dirfd >= 0 ? 0 : errno;
    if (diag_on) {
        ::refuzz::worker::log::WorkerLog(
            "[mount-timing] event=open_target_exit ts_us=%llu eid=%llu op=%s fs=%s slot=%u target=%s rc=%d errno=%d\n",
            static_cast<unsigned long long>(MountTimingNowUs()),
            static_cast<unsigned long long>(ctx.DiagnosticExecutorId()),
            diag.op,
            diag.fs,
            ctx.proc_slot_id,
            LogStr(target),
            dirfd,
            open_err);
    }
    if (dirfd < 0) {
        return Error(open_err, "open(target,O_RDONLY|O_DIRECTORY)");
    }
    ctx.RegisterOwnedFd(dirfd);  // close at program teardown

    // [syz coverage-parity 2026-06-03] syz_mount_image always calls
    // reset_loop_device(loopname) on the success path (common_linux.h:3610),
    // AFTER cover_reset(0) — a futile open(/dev/loopN, O_RDWR)+LOOP_CLR_FD+close
    // that EBUSYs on the still-mounted loop but, via the FAILED open, still
    // exercises the whole block-device-open + fd alloc/release + LSM/idmapping
    // lifecycle in the per-call KCOV window: blkdev_open, file_to_blk_mode,
    // sb_permission, make_vfsgid, get_unused_fd→put_unused_fd/__clear_open_fd,
    // fput/__fput_deferred/file_free, security_file_free/apparmor/landlock,
    // blkdev_put_no_open, put_device. reFuzz defers the REAL loop cleanup to
    // MountState::Cleanup (active_loopnames above); without reproducing syz's
    // in-window futile clear here, the paired oracle under-attributes that whole
    // cluster to syz_mount_image (SEM@0.9 across all 18 fs variants — verified
    // via funnel funcdiff 2026-06-03). The clear EBUSYs (loop still mounted) →
    // no actual detach → the deferred cleanup is unaffected; this is coverage
    // parity only. (Intentionally re-introduces, scoped to coverage, the
    // per-call ResetLoopDevice that the [reorder-clear] note above moved out.)
    if (need_loop) {
        ResetLoopDevice(loopname, &diag);
    }

    // ---- Phase 5: optional chdir ----
    //
    // [PR-D1 review fix C7 2026-05-06] Worker process CWD persists across
    // programs. Without save-and-restore, a successful chdir(target) leaks
    // into the next program. Capture pre-chdir CWD on the FIRST chdir of
    // the program (state.saved_cwd_fd starts at -1). Cleanup() will
    // fchdir back at program teardown.
    //
    // O_PATH | O_DIRECTORY: refers to the inode without holding it busy
    // and survives even if the dir tree is later unmounted/removed —
    // exactly what we want for "remember-where-I-came-from".
    if (change_dir != 0) {
        if (state.saved_cwd_fd < 0) {
            const int cwd_fd = ::open(".",
                                      O_PATH | O_DIRECTORY | O_CLOEXEC);
            if (cwd_fd >= 0) {
                state.saved_cwd_fd = cwd_fd;
            }
            // open(".") failure is non-fatal — we proceed without CWD
            // restore (rare; only if /proc/self/cwd is unreadable).
        }
        // [PR-D1.O' Fix 1] Mirror upstream common_linux.h:3185-3197:
        //   res = chdir(target);   // overwrites res (was dirfd)
        //   if (res == -1) err = errno;
        //   ...
        //   errno = err; return res;
        // chdir success → returns 0 (dirfd is overwritten); failure → returns
        // -1 + chdir errno. dirfd remains owned by the worker for teardown
        // (RegisterOwnedFd above) — overwriting the return value does not leak
        // the fd, just hides it from the program. Caller programs are written
        // expecting this contract; previous reFuzz "always return dirfd"
        // diverged.
        if (diag_on) {
            ::refuzz::worker::log::WorkerLog(
                "[mount-timing] event=chdir_enter ts_us=%llu eid=%llu op=%s fs=%s slot=%u target=%s\n",
                static_cast<unsigned long long>(MountTimingNowUs()),
                static_cast<unsigned long long>(ctx.DiagnosticExecutorId()),
                diag.op,
                diag.fs,
                ctx.proc_slot_id,
                LogStr(target));
        }
        const int chdir_rc = ::chdir(target);
        const int chdir_err = chdir_rc == 0 ? 0 : errno;
        if (diag_on) {
            ::refuzz::worker::log::WorkerLog(
                "[mount-timing] event=chdir_exit ts_us=%llu eid=%llu op=%s fs=%s slot=%u target=%s rc=%d errno=%d\n",
                static_cast<unsigned long long>(MountTimingNowUs()),
                static_cast<unsigned long long>(ctx.DiagnosticExecutorId()),
                diag.op,
                diag.fs,
                ctx.proc_slot_id,
                LogStr(target),
                chdir_rc,
                chdir_err);
        }
        if (chdir_rc < 0) {
            return PseudoResult{-1, chdir_err, "chdir"};
        }
        return PseudoResult{0, 0, nullptr};
    }

    return PseudoResult{static_cast<intptr_t>(dirfd), 0, nullptr};
}

} // namespace refuzz::worker::pseudo

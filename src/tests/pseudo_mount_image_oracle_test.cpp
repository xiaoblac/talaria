// PR-D1 / PR-D1.O' — mount-image source-derived semantic oracle.
//
// Plan §7.1 now binds Tier-3 oracles to upstream pseudo semantics adapted
// through reFuzz architecture, not byte-equal syscall text. This file
// hand-derives goldens from `executor/common_linux.h:3093-3199`
// (syz_mount_image) and `executor/common_zlib.h` and asserts the behavior
// reFuzz must preserve.
//
// Architecture deltas intentionally accepted here:
//   * Loop allocation: reFuzz uses LOOP_CTL_GET_FREE; upstream uses
//     /dev/loop<procid>. Different syscall sequence; same kernel-observable
//     effect.
//   * Decompression: reFuzz uses libz inflate; upstream uses puff_zlib.
//     Same wire format (RFC1950 zlib stream); different code path.
//   * Cleanup: reFuzz is a long-running worker, so explicit teardown exists
//     where upstream process lifetime sometimes supplies cleanup.
//
// The oracle covers deterministic adjuster output plus phase-level contracts
// that are load-bearing for syz_mount_image: return-value semantics, loop
// lifecycle, zlib short-input behavior, and need_loop selection. Root-required
// rows exercise real mount(2) when available and otherwise skip.

#include "worker/backend/pseudo/mount/mount_dispatcher.hpp"
#include "worker/backend/pseudo/mount/mount_helpers.hpp"
#include "worker/backend/pseudo/mount/mount_state.hpp"
#include "worker/backend/pseudo/pseudo_dispatcher.hpp"
#include "worker/backend/pseudo/pseudo_runtime.hpp"
#include "refuzz/program/syz/pseudo/target_view.hpp"

#include <zlib.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/syscall.h>  // SYS_memfd_create for the zlib short-input phase golden
#include <unistd.h>
#include <vector>

namespace {

#define CHECK(expr)                                                         \
    do {                                                                    \
        if (!(expr)) {                                                      \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,    \
                         #expr);                                            \
            std::abort();                                                   \
        }                                                                   \
    } while (0)

#define RUN_TEST(fn)                                                        \
    do {                                                                    \
        std::fprintf(stderr, "RUN  %s\n", #fn);                             \
        fn();                                                               \
        std::fprintf(stderr, "OK   %s\n", #fn);                             \
    } while (0)

namespace pmnt = ::refuzz::worker::pseudo;

// --- Hand-derived golden table ---------------------------------------------
//
// For each (fs, base_opts, base_flags) input, the expected adjuster output is
// pinned. Source for each row is `executor/common_linux.h:3146-3168`. Any
// upstream rebase that changes adjuster behavior must update this table or
// the test fails — that's the oracle's purpose.

struct Golden {
    const char* fs;
    const char* base_opts;
    long        base_flags;
    const char* expected_opts;
    long        expected_flags;
    const char* source_line;  // for debug + audit trail
};

constexpr Golden kGoldens[] = {
    // --- ext4 ---
    {
        "ext4", "errors=panic", 0,
        "errors=panic,errors=continue", 0,
        "common_linux.h:3148-3160 ext4 errors=panic → append errors=continue",
    },
    {
        "ext4", "noatime", 0,
        "noatime,errors=continue", 0,
        "common_linux.h:3148-3160 ext4 no remount-ro → append errors=continue",
    },
    {
        "ext4", "errors=remount-ro,noatime", 0,
        "errors=remount-ro,noatime", 0,
        "common_linux.h:3148-3160 ext4 has remount-ro → no append",
    },
    // --- btrfs ---
    {
        "btrfs", "compress=zstd", 0,
        "compress=zstd", 0,
        "common_linux.h: btrfs has no adjuster — opts pass through",
    },
    {
        "btrfs", "", 0,
        "", 0,
        "btrfs empty opts pass through",
    },
    // --- vfat ---
    {
        "vfat", "iocharset=utf8", 0,
        "iocharset=utf8", 0,
        "common_linux.h: vfat has no adjuster",
    },
    // --- squashfs ---
    {
        "squashfs", "noatime", 0,
        "noatime", 0,
        "common_linux.h: squashfs has no adjuster",
    },
    // --- ntfs3 ---
    {
        "ntfs3", "uid=0", 0,
        "uid=0", 0,
        "common_linux.h: ntfs3 has no adjuster",
    },
    // --- tmpfs ---
    {
        "tmpfs", "size=64M", 0,
        "size=64M", 0,
        "common_linux.h: tmpfs has no adjuster (also no loop device path)",
    },
    // --- iso9660 (covered by adjuster but not in PR-D1 batch — pin anyway
    //     for adjuster regression coverage; iso9660 is in PR-D1.A bulk) ---
    {
        "iso9660", "noatime", 0,
        "noatime", 1L,  // MS_RDONLY=1 forced
        "common_linux.h:3146-3147 iso9660 forces MS_RDONLY in flags",
    },
    // --- xfs (PR-D1.A bulk) — pin xfs adjuster ---
    {
        "xfs", "noatime", 0,
        "noatime,nouuid", 0,
        "common_linux.h:3161-3164 xfs append nouuid",
    },
    // --- gfs2 (PR-D1.A bulk) — pin gfs2 adjuster ---
    {
        "gfs2", "errors=panic", 0,
        "errors=panic,errors=withdraw", 0,
        "common_linux.h:3165-3168 gfs2 errors=panic → errors=withdraw",
    },
    {
        "gfs2", "debug", 0,
        "debug,errors=withdraw", 0,
        "common_linux.h:3165-3168 gfs2 debug → errors=withdraw",
    },
    {
        "gfs2", "noatime", 0,
        "noatime", 0,
        "common_linux.h:3165-3168 gfs2 no panic/debug → no append",
    },
    {
        "gfs2meta", "errors=panic", 0,
        "errors=panic,errors=withdraw", 0,
        "common_linux.h:3165-3168 gfs2 prefix matches gfs2meta",
    },
};

void test_all_goldens_match_handler_output()
{
    int matches = 0;
    for (const auto& g : kGoldens) {
        long flags = g.base_flags;
        char opts[256] = {};
        const int rc = pmnt::BuildMountOpts(g.fs, g.base_opts, &flags,
                                            opts, sizeof(opts));
        if (rc != 0) {
            std::fprintf(stderr,
                         "FAIL: BuildMountOpts(%s, %s) returned %d, "
                         "expected 0 — source: %s\n",
                         g.fs, g.base_opts, rc, g.source_line);
            std::abort();
        }
        if (std::strcmp(opts, g.expected_opts) != 0) {
            std::fprintf(stderr,
                         "FAIL: BuildMountOpts(%s, %s) opts=\"%s\", "
                         "expected \"%s\" — source: %s\n",
                         g.fs, g.base_opts, opts, g.expected_opts,
                         g.source_line);
            std::abort();
        }
        if (flags != g.expected_flags) {
            std::fprintf(stderr,
                         "FAIL: BuildMountOpts(%s, %s) flags=%ld, "
                         "expected %ld — source: %s\n",
                         g.fs, g.base_opts, flags, g.expected_flags,
                         g.source_line);
            std::abort();
        }
        ++matches;
    }
    std::fprintf(stderr, "  matched %d goldens\n", matches);
}

void test_pr_d1_batch_coverage_includes_six_reference_fs()
{
    // Pin: 6 reference fs (PR-D1 foundation batch per plan §7.1) all have
    // at least one golden row. If a fs is removed from the batch or a
    // golden is deleted, this test catches the drift.
    const char* required[] = {
        "ext4", "btrfs", "vfat", "squashfs", "ntfs3", "tmpfs",
    };
    for (const char* fs : required) {
        bool found = false;
        for (const auto& g : kGoldens) {
            if (std::strcmp(g.fs, fs) == 0) {
                found = true;
                break;
            }
        }
        if (!found) {
            std::fprintf(stderr, "FAIL: PR-D1 batch fs %s missing from goldens\n", fs);
            std::abort();
        }
    }
}

// ---- [PR-D1.O'] End-to-end syz_mount_image phase goldens ----------------
//
// Transcribed from upstream `executor/common_linux.h:3093-3198` (the full
// syz_mount_image function body). Each row pins one phase-level contract
// that the handler must satisfy. These complement the BuildMountOpts
// adjuster goldens above by covering dispatcher-level outcomes (return
// value semantics, loop lifecycle, zlib bounds, need_loop selection).
//
// Root-required rows that exercise real mount(2) skip on non-root —
// matches PR-D1.O' Step 0 decision (a) "root-required + skip-on-non-root".

namespace fz   = ::refuzz::fuzzer::syz;
namespace pwk  = ::refuzz::worker;
namespace pwkp = ::refuzz::worker::pseudo;

const fz::PseudoMeta* FindMeta(const char* name)
{
    return fz::FindPseudoByName(fz::kDefaultSyzTarget.pseudos, name);
}

std::vector<uint8_t> MakeZlibBlob(const std::string& payload)
{
    std::vector<uint8_t> out(payload.size() + 256);
    z_stream zs = {};
    deflateInit(&zs, Z_BEST_SPEED);
    zs.next_in   = reinterpret_cast<Bytef*>(const_cast<char*>(payload.data()));
    zs.avail_in  = static_cast<uInt>(payload.size());
    zs.next_out  = out.data();
    zs.avail_out = static_cast<uInt>(out.size());
    deflate(&zs, Z_FINISH);
    out.resize(zs.total_out);
    deflateEnd(&zs);
    return out;
}

// Phase golden: chdir return value (Fix 1).
// Source: common_linux.h:3185-3197 — `res = chdir(target); ... return res;`
// Contract: when change_dir != 0 and chdir succeeds → ret = 0 (NOT dirfd).
void test_phase_chdir_overwrites_return_value()
{
    if (::geteuid() != 0) {
        std::fprintf(stderr, "  SKIP (root-required: real mount(2)+chdir)\n");
        return;
    }
    pwk::PseudoRuntimeContext ctx(&fz::kDefaultSyzTarget);
    const auto* meta = FindMeta("syz_mount_image$tmpfs");
    CHECK(meta != nullptr);
    char target[128];
    std::snprintf(target, sizeof(target),
                  "/tmp/refuzz-oracle-chdir-%d", ::getpid());
    intptr_t a[7] = {
        reinterpret_cast<intptr_t>("tmpfs"),
        reinterpret_cast<intptr_t>(target),
        0L, reinterpret_cast<intptr_t>(""), 1L /* change_dir */, 0, 0,
    };
    auto r = pwk::DispatchPseudo(ctx, meta->nr, a, 7);
    if (r.ret == -1) {
        // Mount may legitimately fail in CI sandboxes; the salient pin
        // is that whenever it succeeds, chdir-success → ret=0.
        std::fprintf(stderr, "  mount path failed (errno=%d), pin not exercised\n",
                     r.err);
        return;
    }
    // Source: common_linux.h:3186 — `res = chdir(target);` overwrites res
    // (which was the dirfd from line 3179). chdir returns 0 on success.
    CHECK(r.ret == 0);
    CHECK(r.err == 0);
}

// Phase golden: loop reset timing (Fix 2).
// Source: common_linux.h:3193-3197 — `error_clear_loop:` reset is
// unconditional before return. Contract: after dispatch returns,
// active_loopnames is empty regardless of mount success/failure.
void test_phase_loop_reset_unconditional()
{
    pwk::PseudoRuntimeContext ctx(&fz::kDefaultSyzTarget);
    const auto* meta = FindMeta("syz_mount_image$ext4");
    CHECK(meta != nullptr);
    auto blob = MakeZlibBlob(std::string(512, 'x'));
    char target[128];
    std::snprintf(target, sizeof(target),
                  "/tmp/refuzz-oracle-loop-reset-%d", ::getpid());
    intptr_t a[7] = {
        reinterpret_cast<intptr_t>("ext4"),
        reinterpret_cast<intptr_t>(target),
        0L, reinterpret_cast<intptr_t>(""), 0L,
        static_cast<intptr_t>(blob.size()),
        reinterpret_cast<intptr_t>(blob.data()),
    };
    auto r = pwk::DispatchPseudo(ctx, meta->nr, a, 7);
    (void)r;  // outcome path varies by environment; the invariant pinned
              // here is on state, not return value.
    auto& s = pwkp::GetOrCreateMountState(ctx);
    // Source: common_linux.h:3193 — reset_loop_device runs always.
    CHECK(s.active_loopnames.empty());
}

// Phase golden: zlib short input is success-empty (Fix 3).
// Source: common_zlib.h:472-473 — `if (sourcelen < 2) return 0;`
// Contract: 0 or 1 byte input → success without writing memfd.
void test_phase_zlib_short_input_success_empty()
{
    int memfd = static_cast<int>(::syscall(SYS_memfd_create, "oracle", 0));
    CHECK(memfd >= 0);
    int rc = pwkp::DecompressZlibToFd(nullptr, 0, memfd);
    CHECK(rc == 0);
    uint8_t single = 0x78;
    rc = pwkp::DecompressZlibToFd(&single, 1, memfd);
    CHECK(rc == 0);
    ::close(memfd);
}

// Phase golden: need_loop_device == !!size (Fix 4).
// Source: common_linux.h:3117 — `int need_loop_device = !!size;`
// Contract: size>0 + image=NULL → loop setup invoked → fails at memfd
// fill, returns -1+EINVAL. Must NOT silently fall through to mount(NULL).
void test_phase_need_loop_size_only()
{
    pwk::PseudoRuntimeContext ctx(&fz::kDefaultSyzTarget);
    const auto* meta = FindMeta("syz_mount_image$ext4");
    CHECK(meta != nullptr);
    intptr_t a[7] = {
        reinterpret_cast<intptr_t>("ext4"),
        reinterpret_cast<intptr_t>("/tmp/refuzz-oracle-need-loop"),
        0L, reinterpret_cast<intptr_t>(""), 0L,
        4096,  // size > 0
        0,     // image = NULL
    };
    auto r = pwk::DispatchPseudo(ctx, meta->nr, a, 7);
    CHECK(r.ret == -1);
    // EINVAL surfaces from SetupLoopDevice's nullptr guard. Pre-Fix-4,
    // reFuzz silently skipped loop setup and surfaced mount(2)'s errno
    // instead (different errno + path).
    CHECK(r.err == EINVAL);
}

}  // namespace

int main()
{
    RUN_TEST(test_all_goldens_match_handler_output);
    RUN_TEST(test_pr_d1_batch_coverage_includes_six_reference_fs);
    // [PR-D1.O'] phase-level goldens (transcribed from common_linux.h:3093-3198)
    RUN_TEST(test_phase_chdir_overwrites_return_value);
    RUN_TEST(test_phase_loop_reset_unconditional);
    RUN_TEST(test_phase_zlib_short_input_success_empty);
    RUN_TEST(test_phase_need_loop_size_only);
    return 0;
}

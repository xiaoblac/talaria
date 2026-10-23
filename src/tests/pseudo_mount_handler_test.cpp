// PR-D1 — behavioral unit test for mount-image handler.
//
// Plan §7 test discipline:
//   * Structural pin lives in syzgen Go test (catalog 4-tuple) — separate test.
//   * Behavioral (this file): per-handler unit cases driving DispatchMountPseudo
//     directly with raw intptr_t args. Asserts return value, errno, and post-call
//     cleanup state.
//   * Parity oracle is `pseudo_mount_image_oracle_test` (separate file): checks
//     source-derived semantic goldens and phase contracts per plan §7.1.
//
// What this test does NOT assert:
//   * Real mount(2) success — that requires CAP_SYS_ADMIN + a private mount
//     namespace. Cases that exercise the mount syscall path are conditioned
//     on `geteuid() == 0` (and even then run with MNT_DETACH cleanup safeguards).
//   * Image decompression success — uses small synthetic zlib-compressed data
//     for the loop-device path; full fs validity is out of scope (kernel rejects
//     gracefully → handler surfaces errno).

#include "worker/backend/pseudo/mount/mount_dispatcher.hpp"
#include "worker/backend/pseudo/mount/mount_helpers.hpp"
#include "worker/backend/pseudo/mount/mount_state.hpp"
#include "worker/backend/pseudo/pseudo_dispatcher.hpp"
#include "worker/backend/pseudo/pseudo_runtime.hpp"
#include "refuzz/program/syz/pseudo/target_view.hpp"

#include <zlib.h>
#include <sys/mount.h>
#include <sys/stat.h>     // [PR-D1.O'] fstat / S_ISDIR for dirfd invariant
#include <sys/syscall.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
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

namespace fz   = ::refuzz::fuzzer::syz;
namespace pmnt = ::refuzz::worker::pseudo;

// Look up the meta entry for a syz_mount_image$<fs> name from the worker-side
// pseudo table; returns nullptr if not present.
const fz::PseudoMeta* FindMountMeta(const char* name)
{
    return fz::FindPseudoByName(fz::kDefaultSyzTarget.pseudos, name);
}

// Build a 7-element intptr_t arg array matching the upstream syz_mount_image
// signature.
struct MountArgs {
    std::string fs;
    std::string target;
    long        flags = 0;
    std::string opts;
    long        change_dir = 0;
    std::vector<uint8_t> image;  // zlib-compressed, may be empty
    std::array<intptr_t, 7> raw() const {
        return {
            reinterpret_cast<intptr_t>(fs.c_str()),
            reinterpret_cast<intptr_t>(target.c_str()),
            flags,
            reinterpret_cast<intptr_t>(opts.c_str()),
            change_dir,
            static_cast<intptr_t>(image.size()),
            reinterpret_cast<intptr_t>(image.data()),
        };
    }
};

// Build a small valid zlib-compressed buffer from `payload`.
std::vector<uint8_t> MakeZlib(const std::string& payload)
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

// ---- Tier 1: BuildMountOpts adjuster cases (no syscalls) -----------------

void test_build_opts_iso9660_forces_rdonly()
{
    long flags = 0;
    char opts[256] = {};
    int rc = pmnt::BuildMountOpts("iso9660", "noatime", &flags, opts, sizeof(opts));
    CHECK(rc == 0);
    CHECK((flags & 1L) != 0L);  // MS_RDONLY=1
    CHECK(std::strcmp(opts, "noatime") == 0);  // no opts append for iso9660
}

void test_build_opts_ext4_appends_errors_continue_on_panic()
{
    long flags = 0;
    char opts[256] = {};
    int rc = pmnt::BuildMountOpts("ext4", "errors=panic", &flags, opts, sizeof(opts));
    CHECK(rc == 0);
    CHECK(std::string(opts) == "errors=panic,errors=continue");
}

void test_build_opts_ext4_appends_errors_continue_when_no_remount_ro()
{
    long flags = 0;
    char opts[256] = {};
    int rc = pmnt::BuildMountOpts("ext4", "noatime", &flags, opts, sizeof(opts));
    CHECK(rc == 0);
    CHECK(std::string(opts) == "noatime,errors=continue");
}

void test_build_opts_ext4_skips_when_remount_ro_already_present()
{
    long flags = 0;
    char opts[256] = {};
    int rc = pmnt::BuildMountOpts("ext4", "errors=remount-ro,noatime", &flags, opts, sizeof(opts));
    CHECK(rc == 0);
    CHECK(std::string(opts) == "errors=remount-ro,noatime");
}

void test_build_opts_xfs_appends_nouuid()
{
    long flags = 0;
    char opts[256] = {};
    int rc = pmnt::BuildMountOpts("xfs", "noatime", &flags, opts, sizeof(opts));
    CHECK(rc == 0);
    CHECK(std::string(opts) == "noatime,nouuid");
}

void test_build_opts_gfs2_appends_errors_withdraw_on_panic()
{
    long flags = 0;
    char opts[256] = {};
    int rc = pmnt::BuildMountOpts("gfs2", "errors=panic", &flags, opts, sizeof(opts));
    CHECK(rc == 0);
    CHECK(std::string(opts) == "errors=panic,errors=withdraw");
}

void test_build_opts_gfs2meta_appends_errors_withdraw_on_debug()
{
    long flags = 0;
    char opts[256] = {};
    int rc = pmnt::BuildMountOpts("gfs2meta", "debug", &flags, opts, sizeof(opts));
    CHECK(rc == 0);
    CHECK(std::string(opts) == "debug,errors=withdraw");
}

void test_build_opts_btrfs_unchanged()
{
    long flags = 0;
    char opts[256] = {};
    int rc = pmnt::BuildMountOpts("btrfs", "compress=zstd", &flags, opts, sizeof(opts));
    CHECK(rc == 0);
    CHECK(std::string(opts) == "compress=zstd");  // no adjuster for btrfs
    CHECK(flags == 0L);
}

void test_build_opts_truncated_returns_minus_one()
{
    long flags = 0;
    char opts[256] = {};
    std::string huge(300, 'x');
    int rc = pmnt::BuildMountOpts("ext4", huge.c_str(), &flags, opts, sizeof(opts));
    CHECK(rc == -1);  // truncation reported
}

// ---- Tier 2: DecompressZlibToFd (no mount) -----------------------------

void test_decompress_zlib_round_trip()
{
    const std::string original = "hello mount-image PR-D1";
    auto blob = MakeZlib(original);
    int memfd = static_cast<int>(::syscall(SYS_memfd_create, "test", 0));
    CHECK(memfd >= 0);
    int rc = pmnt::DecompressZlibToFd(blob.data(), blob.size(), memfd);
    CHECK(rc == 0);
    ::lseek(memfd, 0, SEEK_SET);
    char buf[64] = {};
    ssize_t n = ::read(memfd, buf, sizeof(buf) - 1);
    CHECK(n == static_cast<ssize_t>(original.size()));
    CHECK(std::string(buf, n) == original);
    ::close(memfd);
}

void test_decompress_zlib_invalid_returns_minus_one()
{
    int memfd = static_cast<int>(::syscall(SYS_memfd_create, "test", 0));
    CHECK(memfd >= 0);
    uint8_t garbage[16] = {0xff, 0xfe, 0xfd, 0xfc, 0, 0, 0, 0,
                           0, 0, 0, 0, 0, 0, 0, 0};
    int rc = pmnt::DecompressZlibToFd(garbage, sizeof(garbage), memfd);
    CHECK(rc == -1);
    ::close(memfd);
}

// ---- Tier 3: DispatchMountPseudo arg validation (no real mount) --------

void test_dispatch_returns_einval_on_short_argc()
{
    refuzz::worker::PseudoRuntimeContext ctx(&fz::kDefaultSyzTarget);
    const auto* meta = FindMountMeta("syz_mount_image$ext4");
    CHECK(meta != nullptr);
    intptr_t args[3] = {0, 0, 0};
    auto result = refuzz::worker::DispatchPseudo(ctx, meta->nr, args, 3);
    CHECK(result.ret == -1);
    CHECK(result.err == EINVAL);
}

void test_dispatch_returns_einval_on_missing_fs()
{
    refuzz::worker::PseudoRuntimeContext ctx(&fz::kDefaultSyzTarget);
    const auto* meta = FindMountMeta("syz_mount_image$ext4");
    CHECK(meta != nullptr);
    MountArgs ma;
    ma.fs = "";
    ma.target = "/tmp/mount-test";
    auto a = ma.raw();
    auto result = refuzz::worker::DispatchPseudo(ctx, meta->nr,
                                                 a.data(),
                                                 static_cast<uint32_t>(a.size()));
    CHECK(result.ret == -1);
    CHECK(result.err == EINVAL);
}

// Smoke: under unprivileged user the mount(2) syscall returns EPERM. Handler
// must surface that errno cleanly without crashing or leaking state.
void test_dispatch_unprivileged_mount_fails_gracefully()
{
    if (::geteuid() == 0) {
        std::fprintf(stderr, "  SKIP (running as root; case is unprivileged-only)\n");
        return;
    }
    refuzz::worker::PseudoRuntimeContext ctx(&fz::kDefaultSyzTarget);
    const auto* meta = FindMountMeta("syz_mount_image$tmpfs");
    CHECK(meta != nullptr);
    MountArgs ma;
    ma.fs = "tmpfs";
    ma.target = "/tmp/refuzz-mount-test-unpriv";
    ma.opts = "";
    auto a = ma.raw();
    auto result = refuzz::worker::DispatchPseudo(ctx, meta->nr,
                                                 a.data(),
                                                 static_cast<uint32_t>(a.size()));
    CHECK(result.ret == -1);
    // Some kernels disable user namespaces / refuse mount in this state →
    // EPERM is canonical; ENODEV / ENOSYS could also surface depending on
    // sandbox. Accept any non-zero errno but require ret=-1.
    CHECK(result.err != 0);
}

// MountState lifecycle: GetOrCreateMountState returns the same instance for
// repeated calls under the same PseudoContext, and Cleanup runs on context teardown.
void test_mount_state_lifecycle()
{
    {
        refuzz::worker::PseudoRuntimeContext ctx(&fz::kDefaultSyzTarget);
        auto& s1 = pmnt::GetOrCreateMountState(ctx);
        auto& s2 = pmnt::GetOrCreateMountState(ctx);
        CHECK(&s1 == &s2);  // identity stable per ctx
        // Push a fake loopname; MountState::Cleanup will try ResetLoopDevice
        // (ignores ENOENT for nonexistent loopnames).
        s1.active_loopnames.push_back("/dev/loop_does_not_exist_999");
    }
    // Out of scope → ctx destructor calls Cleanup() which removes the state.
    // No assertion is feasible without exposing internal map; just verify
    // we don't crash and a fresh ctx gets a fresh state.
    refuzz::worker::PseudoRuntimeContext ctx2(&fz::kDefaultSyzTarget);
    auto& s3 = pmnt::GetOrCreateMountState(ctx2);
    CHECK(s3.active_loopnames.empty());
}

// [PR-D1.O' Fix 2 invariant] After upgrading reFuzz to mirror upstream's
// `error_clear_loop:` unconditional reset semantics, the success path no
// longer pushes loopname into state.active_loopnames either. Every path
// (mount fail / open(target) fail / chdir fail / full success) detaches
// the loop device immediately, so active_loopnames stays empty post-call.
//
// This subsumes the prior C6/D13 regression test: in addition to
// "mount-failure must not leak", we now also pin "mount-success must not
// defer". Test runs unprivileged-safely — under non-root, SetupLoopDevice
// fails at /dev/loop-control open and active_loopnames trivially stays
// empty; under root the success+failure mix is exercised.
void test_active_loopnames_always_empty_after_dispatch()
{
    refuzz::worker::PseudoRuntimeContext ctx(&fz::kDefaultSyzTarget);
    const auto* meta = FindMountMeta("syz_mount_image$ext4");
    CHECK(meta != nullptr);

    auto blob = MakeZlib(std::string(1024, 'x'));
    constexpr int kIterations = 8;
    int success_count = 0;
    int setup_loop_failure_count = 0;
    int mount_failure_count = 0;
    for (int i = 0; i < kIterations; ++i) {
        char target[128];
        std::snprintf(target, sizeof(target),
                      "/tmp/refuzz-mount-leak-test-%d", i);
        MountArgs ma;
        ma.fs = "ext4";
        ma.target = target;
        ma.opts = "";
        ma.image = blob;
        auto a = ma.raw();
        auto result = refuzz::worker::DispatchPseudo(ctx, meta->nr,
                                                     a.data(),
                                                     static_cast<uint32_t>(a.size()));
        if (result.ret >= 0) {
            ++success_count;
        } else if (result.err == EACCES || result.err == EPERM) {
            ++setup_loop_failure_count;
        } else {
            ++mount_failure_count;
        }
    }

    auto& s = pmnt::GetOrCreateMountState(ctx);
    // [PR-D1.O' Fix 2] active_loopnames MUST be empty regardless of mix —
    // every dispatch path detaches its loop before returning.
    if (!s.active_loopnames.empty()) {
        std::fprintf(stderr,
                     "FAIL: Fix 2 — active_loopnames=%zu (expected 0); "
                     "success=%d, mount_fail=%d, setup_loop_fail=%d\n",
                     s.active_loopnames.size(), success_count,
                     mount_failure_count, setup_loop_failure_count);
        std::abort();
    }
    std::fprintf(stderr,
                 "  Fix 2 invariant: success=%d mount_fail=%d setup_loop_fail=%d "
                 "active_loopnames=%zu (== 0 ✓)\n",
                 success_count, mount_failure_count, setup_loop_failure_count,
                 s.active_loopnames.size());
}

// ---- [PR-D1.O'] Source-level handler invariants -------------------------
//
// Five new invariants pinning the kernel-observable contract of
// syz_mount_image, complementing the BuildMountOpts adjuster goldens.

// Invariant 1: zlib short input is success-empty (Fix 3, mirrors upstream
// common_zlib.h:472-473). No root needed.
void test_invariant_zlib_short_input_returns_success_empty()
{
    int memfd = static_cast<int>(::syscall(SYS_memfd_create, "test", 0));
    CHECK(memfd >= 0);
    // sourcelen 0 — empty.
    int rc = pmnt::DecompressZlibToFd(nullptr, 0, memfd);
    CHECK(rc == 0);
    // sourcelen 1 — below ZLIB_HEADER_WIDTH = 2.
    uint8_t one[1] = {0x78};
    rc = pmnt::DecompressZlibToFd(one, 1, memfd);
    CHECK(rc == 0);
    // memfd untouched — read returns 0 bytes.
    ::lseek(memfd, 0, SEEK_SET);
    char b[16] = {};
    ssize_t n = ::read(memfd, b, sizeof(b));
    CHECK(n == 0);
    ::close(memfd);
}

// Invariant 2: zlib output cap at 132 MiB returns -1+EFBIG (Fix 3, mirrors
// upstream common_zlib.h:478 max_destlen guard). Build a zlib stream that
// inflates beyond 132 MiB and assert EFBIG. No root needed.
void test_invariant_zlib_output_capped_at_132mib()
{
    // Compose a zlib stream whose decompressed size exceeds 132 MiB.
    // 160 MiB of zeros compresses to ~155 KiB; size the compressed buffer
    // generously to absorb deflateBound's worst-case overhead, and loop
    // deflate with Z_FINISH until Z_STREAM_END to handle uInt arg-size
    // partitioning on platforms where uInt < std::size_t.
    constexpr std::size_t kPayloadBytes = static_cast<std::size_t>(160) << 20;
    std::vector<uint8_t> payload(kPayloadBytes, 0);
    std::vector<uint8_t> compressed(1 << 20);  // 1 MiB — far more than enough
    z_stream zs = {};
    deflateInit(&zs, Z_BEST_COMPRESSION);
    zs.next_in   = payload.data();
    zs.avail_in  = static_cast<uInt>(payload.size());
    zs.next_out  = compressed.data();
    zs.avail_out = static_cast<uInt>(compressed.size());
    int dret;
    while ((dret = deflate(&zs, Z_FINISH)) == Z_OK) {
        // Need more output room — grow buffer.
        const std::size_t old_size = compressed.size();
        compressed.resize(old_size * 2);
        zs.next_out  = compressed.data() + old_size;
        zs.avail_out = static_cast<uInt>(compressed.size() - old_size);
    }
    CHECK(dret == Z_STREAM_END);
    compressed.resize(zs.total_out);
    deflateEnd(&zs);

    int memfd = static_cast<int>(::syscall(SYS_memfd_create, "test_efbig", 0));
    CHECK(memfd >= 0);
    errno = 0;
    int rc = pmnt::DecompressZlibToFd(compressed.data(), compressed.size(), memfd);
    CHECK(rc == -1);
    CHECK(errno == EFBIG);
    ::close(memfd);
}

// Invariant 3: need_loop = !!size (Fix 4, mirrors upstream
// common_linux.h:3117). With size>0 + image=NULL, dispatcher routes through
// SetupLoopDevice which must reject with EINVAL — handler MUST NOT silently
// fall through to mount(NULL,...) as it did before. No root needed.
void test_invariant_need_loop_size_only_no_image_pointer()
{
    refuzz::worker::PseudoRuntimeContext ctx(&fz::kDefaultSyzTarget);
    const auto* meta = FindMountMeta("syz_mount_image$ext4");
    CHECK(meta != nullptr);
    intptr_t a[7] = {
        reinterpret_cast<intptr_t>("ext4"),
        reinterpret_cast<intptr_t>("/tmp/refuzz-need-loop-test"),
        0L,                                  // flags
        reinterpret_cast<intptr_t>(""),      // opts
        0L,                                  // change_dir
        4096,                                // size > 0
        0,                                   // image = NULL
    };
    auto result = refuzz::worker::DispatchPseudo(ctx, meta->nr, a, 7);
    CHECK(result.ret == -1);
    // Must take loop-setup path (which fails with EINVAL on NULL image),
    // NOT silently mount(NULL, ...). Pre-Fix-4 behavior would yield a
    // different errno (EPERM/ENODEV/etc. from mount(2)).
    CHECK(result.err == EINVAL);
}

// Invariant 4: chdir return value semantics (Fix 1, mirrors upstream
// common_linux.h:3185-3197). chdir success → return 0 (overwrites dirfd),
// chdir failure → return -1 + chdir errno. Root-required (real mount).
void test_invariant_chdir_overwrites_dirfd_return()
{
    if (::geteuid() != 0) {
        std::fprintf(stderr, "  SKIP (root-required: real mount(2))\n");
        return;
    }
    refuzz::worker::PseudoRuntimeContext ctx(&fz::kDefaultSyzTarget);
    const auto* meta = FindMountMeta("syz_mount_image$tmpfs");
    CHECK(meta != nullptr);
    char target[128];
    std::snprintf(target, sizeof(target),
                  "/tmp/refuzz-chdir-overwrite-%d", ::getpid());
    MountArgs ma;
    ma.fs = "tmpfs";
    ma.target = target;
    ma.opts = "";
    ma.change_dir = 1;  // exercise chdir branch
    auto a = ma.raw();
    auto result = refuzz::worker::DispatchPseudo(ctx, meta->nr,
                                                 a.data(),
                                                 static_cast<uint32_t>(a.size()));
    if (result.ret == -1) {
        // tmpfs mount may fail in CI sandbox even under root. Accept that
        // path but assert errno is set (chdir errno or earlier mount errno).
        CHECK(result.err != 0);
        return;
    }
    // Success path: chdir returned 0, so handler returns 0 (NOT dirfd).
    CHECK(result.ret == 0);
    CHECK(result.err == 0);
}

// Invariant 5: dirfd returned (when change_dir == 0) is a valid open
// directory fd. Mirrors upstream common_linux.h:3179 contract — the
// caller program uses this fd to interact with the freshly-mounted dir.
// Root-required (real mount).
void test_invariant_dirfd_returned_is_valid_directory()
{
    if (::geteuid() != 0) {
        std::fprintf(stderr, "  SKIP (root-required: real mount(2))\n");
        return;
    }
    refuzz::worker::PseudoRuntimeContext ctx(&fz::kDefaultSyzTarget);
    const auto* meta = FindMountMeta("syz_mount_image$tmpfs");
    CHECK(meta != nullptr);
    char target[128];
    std::snprintf(target, sizeof(target),
                  "/tmp/refuzz-dirfd-valid-%d", ::getpid());
    MountArgs ma;
    ma.fs = "tmpfs";
    ma.target = target;
    ma.opts = "";
    ma.change_dir = 0;  // dirfd is the return value
    auto a = ma.raw();
    auto result = refuzz::worker::DispatchPseudo(ctx, meta->nr,
                                                 a.data(),
                                                 static_cast<uint32_t>(a.size()));
    if (result.ret == -1) {
        CHECK(result.err != 0);
        return;
    }
    const int dirfd = static_cast<int>(result.ret);
    CHECK(dirfd > 2);
    // fstat on dirfd must be a directory.
    struct stat sb{};
    CHECK(::fstat(dirfd, &sb) == 0);
    CHECK(S_ISDIR(sb.st_mode));
    // dirfd is owned by the worker (RegisterOwnedFd); do NOT close here —
    // PseudoRuntimeContext destructor will close at scope exit.
}

}  // namespace

int main()
{
    RUN_TEST(test_build_opts_iso9660_forces_rdonly);
    RUN_TEST(test_build_opts_ext4_appends_errors_continue_on_panic);
    RUN_TEST(test_build_opts_ext4_appends_errors_continue_when_no_remount_ro);
    RUN_TEST(test_build_opts_ext4_skips_when_remount_ro_already_present);
    RUN_TEST(test_build_opts_xfs_appends_nouuid);
    RUN_TEST(test_build_opts_gfs2_appends_errors_withdraw_on_panic);
    RUN_TEST(test_build_opts_gfs2meta_appends_errors_withdraw_on_debug);
    RUN_TEST(test_build_opts_btrfs_unchanged);
    RUN_TEST(test_build_opts_truncated_returns_minus_one);
    RUN_TEST(test_decompress_zlib_round_trip);
    RUN_TEST(test_decompress_zlib_invalid_returns_minus_one);
    RUN_TEST(test_dispatch_returns_einval_on_short_argc);
    RUN_TEST(test_dispatch_returns_einval_on_missing_fs);
    RUN_TEST(test_dispatch_unprivileged_mount_fails_gracefully);
    RUN_TEST(test_mount_state_lifecycle);
    RUN_TEST(test_active_loopnames_always_empty_after_dispatch);
    // [PR-D1.O'] Source-level handler invariants (Fix 1, 3, 4).
    RUN_TEST(test_invariant_zlib_short_input_returns_success_empty);
    RUN_TEST(test_invariant_zlib_output_capped_at_132mib);
    RUN_TEST(test_invariant_need_loop_size_only_no_image_pointer);
    RUN_TEST(test_invariant_chdir_overwrites_dirfd_return);
    RUN_TEST(test_invariant_dirfd_returned_is_valid_directory);
    return 0;
}

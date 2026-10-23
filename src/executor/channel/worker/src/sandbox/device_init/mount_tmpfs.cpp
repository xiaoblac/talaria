// SandboxCommonMountTmpfs — 对齐 syzkaller `sandbox_common_mount_tmpfs`
// (executor/common_linux.h:3930-4003)。
//
// 目的:在 fuzz harness 与 host 文件系统之间立一道墙。
//   1) 挂一个新 tmpfs 当 staging dir (./syz-tmp)
//   2) 在 staging dir 里 bind-mount host 必需子树 (/dev /proc /sys /selinux
//      /sys/kernel/debug /sys/fs/smackfs /proc/sys/fs/binfmt_misc /syz-inputs)
//      到 newroot/
//   3) InitializeCgroups bind /syzcgroup/* 到 newroot/syzcgroup/*
//   4) pivot_root tmpfs → 老 root 落到 ./syz-tmp/pivot,然后 umount 之
//   5) chroot ./newroot,fuzz program 看到的根就只剩 bind 来的子树
//   6) chroot 后 setup_gadgetfs / setup_binderfs / setup_fusectl
//
// 与 upstream 一致，critical 步骤失败立即返回错误；ENOENT-tolerant 的可选
// bind mount 才允许跳过。错误由 loop startup ACK 交给 daemon 重试。
//
// 不做(deferred):
//   - SYZ_USE_TMP_DIR 路径(那是 binary-mode CLI 的语义,reFuzz exec-mode 不用)
//   - 给 ./binderfs 加 host-visible symlink(SYZ_USE_TMP_DIR 才需要)

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "worker/sandbox/device_init/device_init.hpp"

#include "worker/log/log_macros.hpp"

#include <errno.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>

#define DILOG(fmt, ...) \
    ::refuzz::worker::log::WorkerLog("[device_init] " fmt "\n", ##__VA_ARGS__)

namespace refuzz::worker::sandbox::device_init {

namespace {

// 与 syzkaller `write_file` 同等:open(O_WRONLY) + write,失败 debug log。
// 仅本文件内部用(其它 device_init 单元自带各自 helper)。
void WriteFile(const char* path, const char* value)
{
    const int fd = ::open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        DILOG("write_file: open(%s) errno=%d (%s) — skipped",
              path, errno, ::strerror(errno));
        return;
    }
    const size_t n = ::strlen(value);
    const ssize_t w = ::write(fd, value, n);
    if (w != static_cast<ssize_t>(n)) {
        DILOG("write_file: write(%s) rc=%zd errno=%d (%s)",
              path, w, errno, ::strerror(errno));
    }
    ::close(fd);
}

// mkdir + 既存 OK。dir_path 失败但非 EEXIST → log + negative errno。
int MkdirOrExisting(const char* path, mode_t mode)
{
    if (::mkdir(path, mode) == 0) return 0;
    if (errno == EEXIST) return 0;
    const int result = -(errno != 0 ? errno : EIO);
    DILOG("mkdir(%s, 0%o) errno=%d (%s)",
          path, (unsigned)mode, errno, ::strerror(errno));
    return result;
}

int CurrentFailure()
{
    return -(errno != 0 ? errno : EIO);
}

// 必需 bind mount —— failure 必然影响 fuzz harness 视图。
int BindMountRequired(const char* src, const char* tgt, unsigned flags)
{
    if (::mount(src, tgt, nullptr, flags, nullptr) == 0) {
        return 0;
    }
    const int result = CurrentFailure();
    DILOG("CRITICAL: bind mount(%s -> %s, flags=0x%x) errno=%d (%s)",
          src, tgt, flags, errno, ::strerror(errno));
    return result;
}

// 可选 bind mount —— upstream 用 `errno != ENOENT` 判定可跳过。
// 这里区分:ENOENT silent (kernel 没编出对应文件系统),其它 errno LOG。
int BindMountOptional(const char* src, const char* tgt, unsigned flags)
{
    if (::mount(src, tgt, nullptr, flags, nullptr) == 0) return 0;
    if (errno == ENOENT) return 0;
    const int result = CurrentFailure();
    DILOG("optional bind mount(%s -> %s) errno=%d (%s)",
          src, tgt, errno, ::strerror(errno));
    return result;
}

} // namespace

int SandboxCommonMountTmpfs()
{
    // 起点 cwd 由 launcher 决定(reFuzz daemon → ivshmem_worker inherited)。
    // chdir("/") 让后面所有相对路径 ./syz-tmp/* 都落到 root,可预测。
    if (::chdir("/") != 0) {
        const int result = CurrentFailure();
        DILOG("CRITICAL: chdir(/) errno=%d (%s) — abort mount_tmpfs",
              errno, ::strerror(errno));
        return result;
    }

    // Android 等 fs.mount-max 偏低,后面 8+ bind mount 会撞 ENOSPC。
    // upstream 注释 #4972,这里 byte-equal。
    WriteFile("/proc/sys/fs/mount-max", "100000");

    // ── ./syz-tmp = staging tmpfs ─────────────────────────────────
    if (const int rc = MkdirOrExisting("./syz-tmp", 0777); rc != 0) {
        DILOG("CRITICAL: cannot create ./syz-tmp — abort mount_tmpfs");
        return rc;
    }
    if (::mount("", "./syz-tmp", "tmpfs", 0, nullptr) != 0) {
        const int result = CurrentFailure();
        DILOG("CRITICAL: mount(tmpfs @ ./syz-tmp) errno=%d (%s) — "
              "startup rejected",
              errno, ::strerror(errno));
        return result;
    }

    // ── ./syz-tmp/newroot:fuzz program 最终的视图 ────────────────
    if (const int rc = MkdirOrExisting("./syz-tmp/newroot", 0777); rc != 0) {
        return rc;
    }

    // dev: bind host /dev (含 kcov / null / urandom / net/tun / vhci / ...).
    // 这一步 fail 几乎等于 fuzz 全废 —— 但 syzkaller 也只 fail();reFuzz
    // 这里 LOG loud + 继续,oracle 看到 ApplySandbox 后绝大多数 open 全 ENOENT。
    if (const int rc = MkdirOrExisting(
            "./syz-tmp/newroot/dev", 0700); rc != 0) {
        return rc;
    }
    const unsigned kBindRecPriv = MS_BIND | MS_REC | MS_PRIVATE;
    if (const int rc = BindMountRequired(
            "/dev", "./syz-tmp/newroot/dev", kBindRecPriv); rc != 0) {
        return rc;
    }

    // proc: 一个新 proc 实例 (不是 bind),反映当前 pid ns。
    if (const int rc = MkdirOrExisting(
            "./syz-tmp/newroot/proc", 0700); rc != 0) {
        return rc;
    }
    if (::mount("syz-proc", "./syz-tmp/newroot/proc", "proc", 0, nullptr) != 0) {
        const int result = CurrentFailure();
        DILOG("CRITICAL: mount(proc @ newroot/proc) errno=%d (%s)",
              errno, ::strerror(errno));
        return result;
    }

    // selinux: 优先尝试 /selinux (legacy),fallback /sys/fs/selinux。
    // 两条都 ENOENT 才完全跳。
    if (const int rc = MkdirOrExisting(
            "./syz-tmp/newroot/selinux", 0700); rc != 0) {
        return rc;
    }
    {
        const char* tgt = "./syz-tmp/newroot/selinux";
        if (::mount("/selinux", tgt, nullptr, kBindRecPriv, nullptr) != 0) {
            if (errno != ENOENT) {
                const int result = CurrentFailure();
                DILOG("optional bind mount(/selinux -> %s) errno=%d (%s)",
                      tgt, errno, ::strerror(errno));
                return result;
            }
            if (::mount("/sys/fs/selinux", tgt, nullptr, kBindRecPriv, nullptr) != 0
                && errno != ENOENT) {
                const int result = CurrentFailure();
                DILOG("optional bind mount(/sys/fs/selinux -> %s) errno=%d (%s)",
                      tgt, errno, ::strerror(errno));
                return result;
            }
        }
    }

    // sys: bind host /sys (含 /sys/class/net /sys/devices ...).
    if (const int rc = MkdirOrExisting(
            "./syz-tmp/newroot/sys", 0700); rc != 0) {
        return rc;
    }
    if (const int rc = BindMountRequired(
            "/sys", "./syz-tmp/newroot/sys", kBindRecPriv); rc != 0) {
        return rc;
    }

    // 其它可选 bind mount —— 不存在的 hosts (容器内 / 非 selinux distro / 没
    // 编 binfmt_misc) silent skip,upstream 行为一致。
    if (const int rc = BindMountOptional(
            "/sys/kernel/debug", "./syz-tmp/newroot/sys/kernel/debug",
            kBindRecPriv); rc != 0) {
        return rc;
    }
    if (const int rc = BindMountOptional(
            "/sys/fs/smackfs", "./syz-tmp/newroot/sys/fs/smackfs",
            kBindRecPriv); rc != 0) {
        return rc;
    }
    if (const int rc = BindMountOptional(
            "/proc/sys/fs/binfmt_misc",
            "./syz-tmp/newroot/proc/sys/fs/binfmt_misc",
            kBindRecPriv); rc != 0) {
        return rc;
    }

    // syz-inputs: host 上用户预放的 input corpus,挂只读。
    if (const int rc = MkdirOrExisting(
            "./syz-tmp/newroot/syz-inputs", 0700); rc != 0) {
        return rc;
    }
    if (::mount("/syz-inputs", "./syz-tmp/newroot/syz-inputs", nullptr,
                kBindRecPriv | MS_RDONLY, nullptr) != 0 && errno != ENOENT) {
        const int result = CurrentFailure();
        DILOG("optional bind mount(/syz-inputs) errno=%d (%s)",
              errno, ::strerror(errno));
        return result;
    }

    // ── cgroups bind (newroot/syzcgroup/{unified,cpu,net}) ─────────
    InitializeCgroups();

    // ── pivot_root + chroot ─────────────────────────────────────────
    // pivot_root("./syz-tmp", "./syz-tmp/pivot") 把当前 mount ns 的
    // root 切到 tmpfs,把原 root 落到 ./syz-tmp/pivot。
    if (const int rc = MkdirOrExisting("./syz-tmp/pivot", 0777); rc != 0) {
        return rc;
    }
    if (::syscall(SYS_pivot_root, "./syz-tmp", "./syz-tmp/pivot") != 0) {
        // upstream 用 debug() (不 fail),回退 chdir。reFuzz 同语义。
        DILOG("pivot_root errno=%d (%s) — fallback chdir(./syz-tmp), "
              "fuzz 将无 chroot 保护",
              errno, ::strerror(errno));
        if (::chdir("./syz-tmp") != 0) {
            const int result = CurrentFailure();
            DILOG("CRITICAL: fallback chdir(./syz-tmp) errno=%d (%s)",
                  errno, ::strerror(errno));
            return result;
        }
    } else {
        // pivot_root 成功:cwd handle 仍指向原老 dir,但 path 解析改新 root。
        // 用 chdir("/") 把 cwd 归位到新 root。
        if (::chdir("/") != 0) {
            const int result = CurrentFailure();
            DILOG("CRITICAL: post-pivot chdir(/) errno=%d (%s)",
                  errno, ::strerror(errno));
            return result;
        }
        if (::umount2("./pivot", MNT_DETACH) != 0) {
            const int result = CurrentFailure();
            DILOG("umount2(./pivot, MNT_DETACH) errno=%d (%s)",
                  errno, ::strerror(errno));
            return result;
        }
    }

    // chroot 到 newroot —— fuzz program 看见的根从此只剩 bind 子树。
    if (::chroot("./newroot") != 0) {
        const int result = CurrentFailure();
        DILOG("CRITICAL: chroot(./newroot) errno=%d (%s)",
              errno, ::strerror(errno));
        return result;
    }
    if (::chdir("/") != 0) {
        const int result = CurrentFailure();
        DILOG("post-chroot chdir(/) errno=%d (%s)",
              errno, ::strerror(errno));
        return result;
    }

    // ── pseudo fs mounts after chroot ──────────────────────────────
    SetupGadgetfs();
    SetupBinderfs();
    SetupFusectl();

    DILOG("mount_tmpfs: complete pid=%d cwd=/", (int)::getpid());
    return 0;
}

} // namespace refuzz::worker::sandbox::device_init

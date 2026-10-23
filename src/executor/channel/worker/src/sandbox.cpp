// worker/sandbox.cpp — SandboxMode 分派实现
//
// 与 syzkaller executor/common_linux.h 等价对齐（reference: syzkaller
// sandbox_common() + do_sandbox_setuid() + do_sandbox_none()）：
//
//   sandbox_common（三种模式共用）:
//     * prctl(PR_SET_PDEATHSIG, SIGKILL)
//     * setrlimit: AS / MEMLOCK / FSIZE / STACK / CORE / NOFILE
//     * unshare: NEWNS / NEWIPC / NEWUTS / SYSVSEM / NEWCGROUP
//       (NEWNS 失败为生产硬失败，其余保持 debug log)
//     * mount("/", MS_REC|MS_PRIVATE)
//     * 写 IPC sysctl（shmmax / msgmax / sem 等；发生在 NEWIPC 之后，
//       所以只影响本 namespace）
//
//   setuid 追加:
//     * setgroups(0, NULL)
//     * setresgid(nobody, nobody, nobody)
//     * setresuid(nobody, nobody, nobody)
//     * prctl(PR_SET_PDEATHSIG, SIGKILL)  // setresuid 清掉需补回
//     * prctl(PR_SET_DUMPABLE, 1)         // 否则 /proc/self/* 被 root 拥有
//
// 历史版本曾在 syzkaller 之上追加 NO_NEW_PRIVS / reverse-setuid 硬化。
// current-process parity 路径(none/setuid)不做这些 reFuzz-only 操作；
// namespace 近似模式仍保留自己的 NO_NEW_PRIVS,不作为 strict parity 依据。
//
//   namespace（Phase 2，对齐 do_sandbox_namespace）:
//     * unshare(CLONE_NEWUSER|CLONE_NEWPID)
//     * fork —— 中间进程 waitpid 孙子并以其状态退出（trampoline），孙子成
//       为新 pid ns 的 PID 1
//     * 孙子:
//        - /proc/self/setgroups = "deny"
//        - /proc/self/uid_map   = "0 <real_uid> 1"
//        - /proc/self/gid_map   = "0 <real_gid> 1"
//        - sandbox_common (rlimit + mount/ipc/uts/sysvsem/cgroup + mount priv)
//        - unshare(CLONE_NEWNET)
//        - drop_caps (capset with all-zero)
//        - prctl(PR_SET_NO_NEW_PRIVS, 1)
//        - 返回 0 → 进入 fuzz main loop
//
// ── TODO（与 syzkaller 仍存在的差距，按优先级列）────────────────────
//
// [DONE 2026-05-12 sandbox-device-init D1] pivot_root → tmpfs 最小 rootfs
//   完整对齐 syzkaller `sandbox_common_mount_tmpfs` (common_linux.h:3930)
//   见 worker/sandbox/device_init/mount_tmpfs.cpp。ApplyNone 末尾 single
//   entry SandboxCommonMountTmpfs() 内部完成 tmpfs + 8 bind mount + cgroups
//   + pivot_root + chroot + gadgetfs/binderfs/fusectl。仍未做(D2-D7):
//
// [TODO-2] initialize_tun / initialize_netdevices / initialize_wifi_devices
//   原因: 当前只 unshare(CLONE_NEWNET)——孙子进入空网络栈，没有 tun/tap
//         设备、没有路由表，所以绝大多数 network syscall 直接 ENODEV/EINVAL
//         返回，网络子系统的 fuzz 覆盖率基本为零。syzkaller 在进入 NEWNET
//         之后创建一组虚拟网卡（tun0 + 若干 netdev + wifi sim），使得
//         fuzz syscall 能产生真正的包路径。
//   做什么:
//     a) open /dev/net/tun, ioctl(TUNSETIFF, "syz0") 建 tun；
//     b) ip link add / bridge / bond / vlan 等若干模板（syzkaller 里是 C
//        代码，不依赖 iproute2）；
//     c) 可选：mac80211_hwsim netlink 注册虚拟 wifi。
//   参考: syzkaller `executor/common_linux.h`
//     - `initialize_tun()`             (SYZ_NET_INJECTION)
//     - `initialize_netdevices()`      (SYZ_NET_DEVICES)
//     - `initialize_netdevices_init()` (NEWUSER/NEWNET 之前的提前初始化)
//     - `initialize_wifi_devices()`    (SYZ_WIFI)
//
// [TODO-3] initialize_vhci
//   原因: Bluetooth/HCI syscall 需要一个 virtual HCI controller。syzkaller
//         在 sandbox_common 之前就注册 vhci（CAP_ADMIN 要求）。
//   做什么: open /dev/vhci，ioctl HCIDEVUP；完全 C 路径，见参考。
//   参考: syzkaller `executor/common_linux.h::initialize_vhci()` （SYZ_VHCI_INJECTION）
//
// [DONE 2026-05-12 sandbox-device-init D1] setup_binderfs / setup_fusectl /
//   setup_gadgetfs 现由 mount_tmpfs.cpp 在 chroot 之后一并 call,见
//   worker/sandbox/device_init/{binderfs,fusectl,gadgetfs}.cpp。
//
// 触发时机: 当 Phase 2 跑 soak 后 crash 集中在网络路径,说明没跑到 D3-D5,
//          或者 repro 报出 "跑不出来 because of XYZ"——才按优先级实现剩余 TODO。

#include "worker/sandbox.hpp"
#include "worker/coverage/kcov_collector.hpp"
#include "worker/coverage/remote_kcov_buffer.hpp"
#include "worker/log/log_macros.hpp"
#include "worker/sandbox/device_init/device_init.hpp"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <sched.h>    // CLONE_NEW* constants

#define SBXLOG(fmt, ...) ::refuzz::worker::log::WorkerLog("[Sandbox] " fmt "\n", ##__VA_ARGS__)

namespace refuzz::worker {

namespace {

// nobody / nogroup —— 与 syzkaller 同值。不依赖 /etc/passwd 解析。
constexpr uid_t kNobodyUid = 65534;
constexpr gid_t kNobodyGid = 65534;

// syzkaller exec-mode fixed fd layout:
//   201 = kInitNetNsFd
// SandboxCommon saves the pre-NEWNET namespace here so pseudo handlers such
// as syz_init_net_socket can temporarily setns back to it.
constexpr int kInitNetNsFd = 201;

// syzkaller 未导出 CLONE_NEWCGROUP（老 glibc 没定义），这里兜底。
#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP 0x02000000
#endif

// ── 小工具：把 "value" 写入 /proc/sys/* ───────────────────────────
// 失败 debug log 即可——VM 内 sysctl 写失败不致命。
static void WriteFile(const char* path, const char* value) {
    int fd = ::open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        SBXLOG("open(%s) for write failed: errno=%d", path, errno);
        return;
    }
    const size_t n = ::strlen(value);
    ssize_t w = ::write(fd, value, n);
    if (w != static_cast<ssize_t>(n)) {
        SBXLOG("write(%s) partial/fail: rc=%zd errno=%d", path, w, errno);
    }
    ::close(fd);
}

// ── SetResourceLimits / Unshare / IpcSysctl: 与 syzkaller sandbox_common 等价 ──

// syzkaller 08ab31164 的 RLIMIT_AS 由两块组成：200 MiB 非 KCOV 基线，
// 加上 32 个 local KCOV 和一个 1M-entry extra KCOV 的最坏预留。
// reFuzz 保留这个经验下限；若自身 window/scratch/coverage 更大，再动态上调。
static constexpr size_t kSyzkallerBaseAddressSpaceBytes =
    static_cast<size_t>(200) << 20;
static constexpr size_t kSyzkallerMaxThreads = 32;
static constexpr size_t kSyzkallerCoverageReserveBytes =
    (kSyzkallerMaxThreads * kDefaultKcovEntries +
     kSyzkallerExtraKcovEntries) * sizeof(void*);

// 超过 syzkaller 默认几何后用于动态扩展的 reFuzz 自身估算分量。
static constexpr size_t kFixedFootprintBytes =
    static_cast<size_t>(64) << 20; // binary + libstdc++ + vdso + 初始 heap
static constexpr size_t kFuzzHeadroomBytes   =
    static_cast<size_t>(64) << 20; // stack grow + fuzz 程序运行期 mmap

// 其它 rlimit 取 syzkaller 标准值（不随 ivshmem geometry 变，纯护栏性质）。
static void SetNonAsResourceLimits() {
    struct rlimit r;
    r.rlim_cur = r.rlim_max = (32UL << 20);           // MEMLOCK    ≈ 32 MiB
    ::setrlimit(RLIMIT_MEMLOCK, &r);
    r.rlim_cur = r.rlim_max = (136UL << 20);          // FSIZE      ≈ 136 MiB
    ::setrlimit(RLIMIT_FSIZE, &r);
    r.rlim_cur = r.rlim_max = (1UL << 20);            // STACK      ≈ 1 MiB
    ::setrlimit(RLIMIT_STACK, &r);
    r.rlim_cur = r.rlim_max = (128UL << 20);          // CORE       ≈ 128 MiB
    ::setrlimit(RLIMIT_CORE, &r);
    r.rlim_cur = r.rlim_max = 256;                    // NOFILE     = 256 (kMaxFd)
    ::setrlimit(RLIMIT_NOFILE, &r);
}

// RLIMIT_AS：基于 sizing 动态算，log 出分量便于事后排障。
// 顺序：① 先 log 入参 → ② 调用公式 → ③ setrlimit 并 log 最终值 + 当前 VmSize
// 对比，任何后续 mmap ENOMEM 都能用这几行 log 定位。
static void ApplyAddressSpaceLimit(const SandboxSizing& sizing) {
    const size_t as_bytes = ComputeAddressSpaceLimit(sizing);
    const size_t dynamic_base = sizing.ivshmem_bytes + sizing.scratch_bytes +
                                kFixedFootprintBytes + kFuzzHeadroomBytes;
    const size_t effective_base =
        dynamic_base < kSyzkallerBaseAddressSpaceBytes
            ? kSyzkallerBaseAddressSpaceBytes
            : dynamic_base;
    const size_t effective_coverage =
        sizing.coverage_bytes < kSyzkallerCoverageReserveBytes
            ? kSyzkallerCoverageReserveBytes
            : sizing.coverage_bytes;
    SBXLOG("rlimit_as compute: ivshmem=%zu scratch=%zu "
           "dynamic_base=%zu effective_base=%zu syz_base=%zu "
           "coverage_actual=%zu effective_coverage=%zu syz_coverage=%zu "
           "-> AS=%zu (%zuMiB)",
           sizing.ivshmem_bytes, sizing.scratch_bytes,
           dynamic_base, effective_base, kSyzkallerBaseAddressSpaceBytes,
           sizing.coverage_bytes, effective_coverage,
           kSyzkallerCoverageReserveBytes,
           as_bytes, as_bytes >> 20);
    struct rlimit r;
    r.rlim_cur = r.rlim_max = as_bytes;
    if (::setrlimit(RLIMIT_AS, &r) != 0) {
        SBXLOG("setrlimit(RLIMIT_AS=%zu) failed: errno=%d", as_bytes, errno);
    }
}

// syzkaller 逐个 unshare 而不是 OR，一条失败不拖累其余。reFuzz 额外将
// NEWNS + recursive MS_PRIVATE 设为生产不变式：每条 program 只删
// workdir，不再扫描整个 mount namespace 补偿隔离失败。
static int DoCommonUnshareAndMount(const SandboxSizing& sizing) {
    int mount_namespace_error = 0;
    if (::unshare(CLONE_NEWNS) != 0) {
        mount_namespace_error = errno;
        SBXLOG("unshare(CLONE_NEWNS) failed: errno=%d",
               mount_namespace_error);
    } else if (::mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) != 0) {
        mount_namespace_error = errno;
        SBXLOG("mount(/,MS_REC|MS_PRIVATE) failed: errno=%d",
               mount_namespace_error);
    }
    if (mount_namespace_error == 0) {
        SBXLOG("private mount namespace ready pid=%d (MS_REC|MS_PRIVATE)",
               static_cast<int>(::getpid()));
    }
    if (::unshare(CLONE_NEWIPC)    != 0) { SBXLOG("unshare(NEWIPC) errno=%d",    errno); }
    if (::unshare(CLONE_NEWCGROUP) != 0) { SBXLOG("unshare(NEWCGROUP) errno=%d", errno); }
    if (::unshare(CLONE_NEWUTS)    != 0) { SBXLOG("unshare(NEWUTS) errno=%d",    errno); }
    if (::unshare(CLONE_SYSVSEM)   != 0) { SBXLOG("unshare(SYSVSEM) errno=%d",   errno); }
    if (mount_namespace_error == 0) {
        return 0;
    }
    if (sizing.allow_no_private_mount_namespace_for_tests) {
        SBXLOG("private mount namespace unavailable: errno=%d "
               "(test-only degraded topology)",
               mount_namespace_error);
        return 0;
    }
    return -mount_namespace_error;
}

// syzkaller drop_caps 等价：capset(header{V3,pid=getpid()}, zero-data)。
// 清零 effective / permitted / inheritable 三组，同时 PR_CAPBSET_DROP 把
// bounding set 也扫一遍。capget/capset 是 Linux 原生 syscall，这里直接走
// syscall 号，避免拉 libcap 依赖。
// [v2 syzkaller-parity — drop_caps() 的 byte-equal 等价]
// syzkaller upstream drop_caps() 只清两个 cap：
//   - CAP_SYS_PTRACE: 阻止 fuzz program ptrace parent,
//     避免 loop 进程被 SIGSTOP 卡死(syzkaller 历史 bug)。
//   - CAP_SYS_NICE: 阻止 SCHED_DEADLINE 过高优先级把 rcu 等
//     kernel thread 饿死。
// 其它 cap (NET_ADMIN/SYS_ADMIN/...) **保留** —— 那些是
// fuzz program 行为的一部分。
//
// 注意 DropCaps()(全清) 不要用在 sandbox=none/setuid/namespace
// 三模式的 syzkaller-parity 路径上;只在测试或将来明确需要的
// 极端隔离场景调。
static void DropSyzkallerCaps() {
    struct __user_cap_header_struct hdr{};
    hdr.version = _LINUX_CAPABILITY_VERSION_3;
    hdr.pid = ::getpid();
    struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3]{};
    if (::syscall(SYS_capget, &hdr, &data) != 0) {
        SBXLOG("capget failed: errno=%d", errno);
        return;
    }
    const uint32_t drop = (1u << CAP_SYS_PTRACE) | (1u << CAP_SYS_NICE);
    data[0].effective   &= ~drop;
    data[0].permitted   &= ~drop;
    data[0].inheritable &= ~drop;
    if (::syscall(SYS_capset, &hdr, &data) != 0) {
        SBXLOG("capset(syzkaller-partial) failed: errno=%d", errno);
    }
}

// 写 IPC sysctl —— 必须在 NEWIPC 之后才只影响本 ns。syzkaller 等价。
static void WriteIpcSysctls() {
    struct Sysctl { const char* path; const char* value; };
    static const Sysctl kSysctls[] = {
        {"/proc/sys/kernel/shmmax", "16777216"},
        {"/proc/sys/kernel/shmall", "536870912"},
        {"/proc/sys/kernel/shmmni", "1024"},
        {"/proc/sys/kernel/msgmax", "8192"},
        {"/proc/sys/kernel/msgmni", "1024"},
        {"/proc/sys/kernel/msgmnb", "1024"},
        {"/proc/sys/kernel/sem",    "1024 1048576 500 1024"},
    };
    for (const auto& s : kSysctls) {
        WriteFile(s.path, s.value);
    }
}

// sandbox_common 等价体：rlimit + PDEATHSIG + unshare + mount + sysctl。
// NEWNS/MS_PRIVATE 在生产路径失败必须退出，不允许降级后继续 fuzz。
//
// sizing 用于 RLIMIT_AS 的动态计算；传入 {} 也不会崩，只是 AS 走兜底 128 MiB。
static int SandboxCommon(const SandboxSizing& sizing) {
    // Preserve the net namespace seen before sandbox NEWNET setup.
    // This must happen before DoCommonUnshareAndMount()/ApplyNone's NEWNET.
    // open(..., O_CLOEXEC) + dup2 mirrors the usual syzkaller pattern while
    // leaving fd 201 itself non-CLOEXEC after dup2.
    {
        const int netns = ::open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
        if (netns < 0) {
            SBXLOG("open(/proc/self/ns/net) failed: errno=%d (skip kInitNetNsFd)",
                   errno);
        } else if (netns == kInitNetNsFd) {
            const int flags = ::fcntl(netns, F_GETFD);
            if (flags >= 0) {
                (void)::fcntl(netns, F_SETFD, flags & ~FD_CLOEXEC);
            }
        } else if (::dup2(netns, kInitNetNsFd) < 0) {
            SBXLOG("dup2(netns=%d -> %d) failed: errno=%d",
                   netns, kInitNetNsFd, errno);
            ::close(netns);
        } else {
            ::close(netns);
        }
    }

    // 父死立即 SIGKILL：parent (watchdog) 挂了不要留僵 child。
    // 注意：后面 setresuid 会清掉这个设置，setuid 路径会在 drop 后再 prctl 一次。
    // [Brick 4a] snapshot top-level worker has no daemon watchdog parent — it is
    // launched via `nohup ... &` and reparented to init (getppid()==1) by design,
    // exactly like syz's `nohup executor exec snapshot &`. Skip PDEATHSIG + the
    // getppid()==1 guard there, else the worker exits before it can Register.
    if (!sizing.no_parent_watchdog) {
        ::prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
        // [byte-equal upstream sandbox_common() common_linux.h:4070]
        // PR_SET_PDEATHSIG 注册之后还要检 race: 若在 prctl() 调用前父就已死,
        // PDEATHSIG 不会触发,我们 ppid 已变为 1(init/systemd 接管)。 立即退,
        // 比一路 sandbox setup + 跑 fuzz 后才发现孤儿要 cheap 得多。
        if (::getppid() == 1) {
            SBXLOG("sandbox parent already dead (getppid()==1), exiting child");
            _exit(1);
        }
    }

    ApplyAddressSpaceLimit(sizing);
    SetNonAsResourceLimits();
    const int mount_namespace_rc = DoCommonUnshareAndMount(sizing);
    if (mount_namespace_rc != 0) {
        return mount_namespace_rc;
    }
    WriteIpcSysctls();
    return 0;
}

// [v2 PID-namespace trampoline — ROLLBACK: uncomment 整段,把 ApplyNone /
//  ApplySetuid 头部的 `if (int rc = DoSandboxPidTrampoline();...)` 一起恢复]
//
// 经 docs/plans/sandbox-syzkaller-parity.md(corrected version)review:
// 这段把 reFuzz 从 "daemon → engine child" 2 层悄悄变成 "daemon → engine
// child(middle) → grandchild" 3 层,违反 reFuzz 架构 invariant。NEWPID
// 这种**进程拓扑**改动只能在 engine/profile 显式设计点上做(stdio 入口
// daemon main 自己 unshare),不能藏在 sandbox helper 里。
//
// daemon-level unshare(CLONE_NEWPID) 也已 deferred:它和 stdio
// recycle_after=1 不兼容。第一轮 child(PID 1)退出后 pid namespace 进入
// dying 状态,daemon 的后续 fork 会失败(ENOMEM)。见
// docs/plans/exec-parity-stdio-scope.md 的 NEWPID isolation deferred 节。
//
// // [v2 syzkaller-parity — PID-namespace trampoline]
// // syzkaller do_sandbox_none() / do_sandbox_setuid() 的开头是:
// //     unshare(CLONE_NEWPID);
// //     pid = fork();
// //     if (pid != 0) return wait_for_loop(pid);
// // CLONE_NEWPID 不立刻生效:它只让**下一个 fork** 出来的 child 进入新
// // pid ns 作为 PID 1。所以 reFuzz 这边也要 fork 一次 — 当前进程(middle)
// // 等 grandchild,grandchild 拿到 PID=1,继续跑 engine 主循环。
// //
// // 返回值:
// //   0      → 当前已在 grandchild 进程,调用方应继续 sandbox 余下步骤
// //   -errno → fork/unshare 失败,致命错误
// //   永不返回的路径:middle 始终 _exit,不返回调用方
// //
// // 注意 PR_SET_PDEATHSIG 在 fork 后会被 kernel 清掉(per-task setting),
// // SandboxCommon() 头几行会重新 set,因此 daemon → kill(middle) →
// // kernel 给 grandchild 发 SIGKILL 的级联仍然成立。
// static int DoSandboxPidTrampoline() {
//     // syzkaller 把 unshare(NEWPID) 失败也只 debug-log 不 fail —— sandbox=none
//     // 历来要兼容 unpriv 跑 pkg/ipc 单测的情况。这里语义对齐:logging-only。
//     if (::unshare(CLONE_NEWPID) != 0) {
//         SBXLOG("unshare(NEWPID) failed: errno=%d (continuing without PID ns)",
//                errno);
//     }
//     const pid_t pid = ::fork();
//     if (pid < 0) {
//         const int err = errno;
//         SBXLOG("sandbox trampoline fork failed: errno=%d", err);
//         return -err;
//     }
//     if (pid > 0) {
//         // middle: 阻塞等 grandchild,传递 exit code 给 daemon 看。
//         int status = 0;
//         for (;;) {
//             pid_t w = ::waitpid(pid, &status, 0);
//             if (w == pid) break;
//             if (w < 0 && errno == EINTR) continue;
//             if (w < 0) {
//                 SBXLOG("sandbox trampoline: waitpid(%d) errno=%d",
//                        (int)pid, errno);
//                 _exit(1);
//             }
//         }
//         if (WIFEXITED(status))   _exit(WEXITSTATUS(status));
//         if (WIFSIGNALED(status)) _exit(128 + WTERMSIG(status));
//         _exit(1);
//     }
//     // grandchild: 继续走 sandbox 余下步骤,最终返回到 ChildMain 主循环。
//     return 0;
// }

// ── 三种模式的实际入口 ────────────────────────────────────────────

int RequiredSandboxSetupResult(int result,
                               const char* operation,
                               const SandboxSizing& sizing)
{
    if (result == 0) {
        return 0;
    }
    if (sizing.allow_no_private_mount_namespace_for_tests) {
        SBXLOG("%s failed rc=%d (test-only degraded sandbox)",
               operation, result);
        return 0;
    }
    return result;
}

// [v4 current-process parity — 当前版本]
// 对齐 docs/plans/sandbox-syzkaller-parity.md(corrected):ApplyNone 只做
// syzkaller-style **current-process** sandbox 操作,不在 sandbox 内部 fork。
// 进程拓扑改动(NEWPID + fork-per-program)由 engine/profile 层在显式设计
// 点上做,不藏进 sandbox helper。
//
// NEWPID 不在这里做,也不在 stdio daemon main 做。它和
// recycle_after=1 的 fork 生命周期耦合,需要 engine/profile 层显式设计。
//
// 仍未做(D2-D7,见 docs/plans/sandbox-device-init.md):initialize_vhci /
// netdevices / devlink / tun / wifi。
// 已完成(D1): sandbox_common_mount_tmpfs 完整序列见 mount_tmpfs.cpp。
int ApplyNone(const SandboxSizing& sizing) {
    // [当前版本 sandbox-device-init D6 pre-sandbox_common] 对齐 upstream
    // do_sandbox_none()(common_linux.h:4193):initialize_vhci() 在
    // sandbox_common 之前调,因为 open /dev/vhci 在 unshare(NEWNS) 后路径
    // 视图变化也仍 OK(已开 fd),且 hci_sock + pthread spawn 前 namespace
    // 完整方便。失败由 startup ACK 交给 daemon 重试。
    if (const int rc = RequiredSandboxSetupResult(
            ::refuzz::worker::sandbox::device_init::InitializeVhci(),
            "initialize_vhci", sizing);
        rc != 0) {
        return rc;
    }

    if (const int rc = SandboxCommon(sizing); rc != 0) {
        return rc;
    }
    DropSyzkallerCaps();

    // [当前版本 sandbox-device-init D3 pre-NEWNET] 操作 host netns 上的
    // NETROM / ROSE devices(必须在 NEWNET 之前 — 进入隔离 netns 后这些
    // 设备不可见)。 procid=0 — reFuzz single-worker oracle case。
    ::refuzz::worker::sandbox::device_init::InitializeNetdevicesInit(sizing.proc_id);

    if (::unshare(CLONE_NEWNET) != 0) {
        SBXLOG("none: unshare(NEWNET) failed: errno=%d", errno);
    }
    // ICMP socket 访问权(syzkaller upstream 等价行):必须在 NEWNET 后做,
    // 才只影响本 net ns。
    WriteFile("/proc/sys/net/ipv4/ping_group_range", "0 65535");

    // [当前版本 sandbox-device-init D7 post-NEWNET] setns 回 init netns,
    // devlink reload "pci/0000:00:10.0" 到 sandbox netns,然后 rename ports
    // 为 netpci0/1/...。 必须在 NEWNET 之后(才能 setns 回去)且 InitializeTun
    // 之前(upstream 序列 devlink_pci → tun → netdevices)。
    ::refuzz::worker::sandbox::device_init::InitializeDevlinkPci();

    // [当前版本 sandbox-device-init D3 post-NEWNET] open tun → fd 200 +
    // netlink add_addr / add_neigh / device up。 在 NEWNET 之后做,所有 tun
    // 配置只对本 netns 生效。详见 worker/src/sandbox/device_init/tun.cpp。
    if (const int rc = RequiredSandboxSetupResult(
            ::refuzz::worker::sandbox::device_init::InitializeTun(),
            "initialize_tun", sizing);
        rc != 0) {
        return rc;
    }

    // [当前版本 sandbox-device-init D4 post-NEWNET] 创建 50+ 虚拟 netdev:
    // bridge / bond / team / batadv / hsr / veth / wireguard / vlan / macvlan /
    // ipvlan / geneve / netdevsim / xfrm / virt_wifi / macvtap / macsec / ...
    // 加 IPv4/IPv6 地址 + MAC + up。详见 worker/src/sandbox/device_init/netdevices.cpp。
    // procid=0 — reFuzz single-worker oracle case (与 InitializeNetdevicesInit 同步)。
    ::refuzz::worker::sandbox::device_init::InitializeNetdevices(sizing.proc_id);

    // [当前版本 sandbox-device-init D5 post-NEWNET] mac80211_hwsim 2 radios +
    // wlan0/wlan1 join IBSS。给 syz_80211_inject_frame / syz_80211_join_ibss
    // fuzz pseudo 一个 ready 的无线栈,直接清掉 oracle 7 个 mismatch。
    // 详见 worker/src/sandbox/device_init/wifi.cpp。
    if (const int rc = RequiredSandboxSetupResult(
            ::refuzz::worker::sandbox::device_init::InitializeWifiDevices(),
            "initialize_wifi_devices", sizing);
        rc != 0) {
        return rc;
    }

    // [当前版本 sandbox-device-init D1] syzkaller `do_sandbox_none()` 末尾的
    // `sandbox_common_mount_tmpfs()` 完整序列:
    //   tmpfs ./syz-tmp + 8 bind mount + InitializeCgroups + pivot_root +
    //   chroot ./newroot + SetupGadgetfs + SetupBinderfs + SetupFusectl。
    // 完整对齐 common_linux.h:3930-4003。Critical 步骤失败拒绝 startup。
    if (const int rc = RequiredSandboxSetupResult(
            ::refuzz::worker::sandbox::device_init::SandboxCommonMountTmpfs(),
            "sandbox_common_mount_tmpfs", sizing);
        rc != 0) {
        return rc;
    }
    SBXLOG("none applied (current-process parity): pid=%d uid=%u",
           (int)::getpid(), (unsigned)::getuid());
    return 0;
}


// [v5 syzkaller-parity device init — 当前版本]
// 对齐 syzkaller upstream do_sandbox_setuid (common_linux.h:4245-4296)
// 序列(按上游字面顺序):
//   1) initialize_vhci()                  -- HCIDEVUP 需 CAP_ADMIN, 必须早
//   2) sandbox_common()                   -- rlimit + NEWNS|NEWIPC|NEWUTS|NEWCGROUP|SYSVSEM
//   3) initialize_netdevices_init()       -- 在 host netns 上配 NETROM/ROSE
//   4) unshare(CLONE_NEWNET)              -- 上游 debug-log 软失败,这里同
//   5) initialize_devlink_pci()           -- setns init netns → devlink reload → setns 回
//   6) initialize_tun()                   -- 在 NEWNET 内开 tun
//   7) initialize_netdevices()            -- 在 NEWNET 内建 50+ 虚拟网卡
//   8) initialize_wifi_devices()          -- mac80211_hwsim + wlan0/1
//   9) setup_binderfs()                   -- 在 sandbox NEWNS 内 mount /dev/binderfs
//  10) setup_fusectl()                    -- 在 sandbox NEWNS 内 mount /sys/fs/fuse/connections
//  11) setgroups/setresgid/setresuid → nobody
//  12) prctl(PDEATHSIG)/prctl(DUMPABLE)
//
// 与 do_sandbox_none 的差别:不做 sandbox_common_mount_tmpfs(上游也不在
// SETUID 路径里调它,见 4276-4277 没有 mount_tmpfs)。NEWPID + fork 由
// engine/profile 层在 DoubleFork topology 中处理(current-process parity)。
//
// Removed (从 v3 起):
//   - PR_SET_NO_NEW_PRIVS: syzkaller 不做这步
//   - reverse-setuid sanity check: syzkaller 不做
int ApplySetuid(const SandboxSizing& sizing) {
    // [v5 D6 pre-sandbox_common] HCIDEVUP 需 CAP_SYS_ADMIN;必须在 setresuid
    // 把权限降到 nobody 之前,且在 unshare(NEWNS) 之前(open /dev/vhci 在
    // NEWNS 后路径视图变化也仍 OK,但 hci_sock 创建在完整 ns 里方便)。
    // 缺 CONFIG_BT_HCIVHCI 时拒绝 startup。
    if (const int rc = RequiredSandboxSetupResult(
            ::refuzz::worker::sandbox::device_init::InitializeVhci(),
            "initialize_vhci", sizing);
        rc != 0) {
        return rc;
    }

    if (const int rc = SandboxCommon(sizing); rc != 0) {
        return rc;
    }

    // [v5 D3 pre-NEWNET] 配 host netns 的 NETROM/ROSE 设备(进入 NEWNET 后
    // 这些 host 设备就不可见了)。procid=0 — reFuzz single-worker oracle。
    ::refuzz::worker::sandbox::device_init::InitializeNetdevicesInit(sizing.proc_id);

    if (::unshare(CLONE_NEWNET) != 0) {
        SBXLOG("setuid: unshare(NEWNET) failed: errno=%d", errno);
    }

    // [v5 D7 post-NEWNET] setns 回 init netns → devlink reload pci/0000:00:10.0
    // 到 sandbox netns → 重命名 ports 为 netpci0/1/...。 必须在 NEWNET 之后
    // (才能 setns 回去)且 InitializeTun 之前(上游序列 devlink → tun → netdev)。
    ::refuzz::worker::sandbox::device_init::InitializeDevlinkPci();

    // [v5 D3 post-NEWNET] open tun → fd 200 + netlink add_addr / add_neigh /
    // device up。所有 tun 配置只对本 netns 生效。
    if (const int rc = RequiredSandboxSetupResult(
            ::refuzz::worker::sandbox::device_init::InitializeTun(),
            "initialize_tun", sizing);
        rc != 0) {
        return rc;
    }

    // [v5 D4 post-NEWNET] 50+ 虚拟 netdev(bridge/bond/team/batadv/hsr/veth/
    // wireguard/vlan/macvlan/ipvlan/geneve/netdevsim/xfrm/virt_wifi/macvtap/
    // macsec/...)+ IPv4/IPv6 地址 + MAC + up。procid=0。
    ::refuzz::worker::sandbox::device_init::InitializeNetdevices(sizing.proc_id);

    // [v5 D5 post-NEWNET] mac80211_hwsim 2 radios + wlan0/wlan1 join IBSS。
    // 给 syz_80211_inject_frame / syz_80211_join_ibss 一个 ready 的无线栈。
    if (const int rc = RequiredSandboxSetupResult(
            ::refuzz::worker::sandbox::device_init::InitializeWifiDevices(),
            "initialize_wifi_devices", sizing);
        rc != 0) {
        return rc;
    }

    // [v5 binderfs/fusectl] 上游 do_sandbox_setuid 在 setresuid 之前调,因为
    // mount 需要 CAP_SYS_ADMIN(在 NEWNS 内仍然要)。两个 mount 都只对 sandbox
    // 的 NEWNS 可见,不污染 host。缺对应 kernel CONFIG 时 silent skip。
    ::refuzz::worker::sandbox::device_init::SetupBinderfs();
    ::refuzz::worker::sandbox::device_init::SetupFusectl();

    if (::setgroups(0, nullptr) != 0) {
        const int err = errno;
        SBXLOG("setgroups(0) failed: errno=%d", err);
        return -err;
    }
    if (::syscall(SYS_setresgid, kNobodyGid, kNobodyGid, kNobodyGid) != 0) {
        const int err = errno;
        SBXLOG("setresgid(%u) failed: errno=%d", (unsigned)kNobodyGid, err);
        return -err;
    }
    if (::syscall(SYS_setresuid, kNobodyUid, kNobodyUid, kNobodyUid) != 0) {
        const int err = errno;
        SBXLOG("setresuid(%u) failed: errno=%d", (unsigned)kNobodyUid, err);
        return -err;
    }

    // setres* 会清 PDEATHSIG（kernel/cred.c commit_creds）；补回来。
    ::prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
    // 否则 /proc/self/* 的 owner 还是 root，drop 后 open 会 EACCES。
    ::prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);

    SBXLOG("setuid applied (syzkaller-parity v5 with full device init): "
           "uid=%u gid=%u pid=%d",
           (unsigned)::getuid(), (unsigned)::getgid(), (int)::getpid());
    return 0;
}

// [v3 syzkaller-parity full device init — 当前版本]
// 对齐 syzkaller upstream do_sandbox_namespace + namespace_sandbox_proc
// (common_linux.h:4308-4366)。
//
// 与上游 byte-equal 实现的主要差异:
//   - 上游用 clone(NEWUSER|NEWPID, sandbox_stack, ..., namespace_sandbox_proc)
//     一次性建 user+pid ns;reFuzz 用 unshare(NEWUSER|NEWPID) + fork 两步,
//     因 unshare(NEWPID) 只影响下一次 fork。 grandchild 成为新 pid ns PID 1。
//     语义等价(进入新 user/pid ns,middle 做 trampoline,grandchild 跑 fuzz 主循环),
//     不严格 byte-equal,但 D1-D7 device init + hard-fail NEWNET 已对齐。
//
// 序列(按上游 do_sandbox_namespace + namespace_sandbox_proc 顺序):
//   ── pre-clone (这里是 pre-unshare) ───────────────────────────────
//   1) initialize_vhci()                  -- HCIDEVUP 需 CAP_SYS_ADMIN
//   ── 进入 user+pid ns,grandchild 是 PID 1 ──────────────────────────
//   2) /proc/self/setgroups = deny + uid_map + gid_map
//   3) prctl(PR_SET_PDEATHSIG, SIGKILL)
//   4) sandbox_common()                   -- rlimit + NEWNS|NEWIPC|NEWUTS|NEWCGROUP|SYSVSEM
//   5) initialize_netdevices_init()       -- host netns 配 NETROM/ROSE
//                                            (上游 namespace_sandbox_proc 4319-4321)
//   6) unshare(CLONE_NEWNET)              -- 上游 fail() 硬失败,这里 _exit(1) 等价
//   7) ping_group_range = "0 65535"       -- 必须在 NEWNET 后(只影响本 netns)
//   8) initialize_devlink_pci()           -- setns init → devlink reload → setns 回
//   9) initialize_tun()                   -- 在 NEWNET 内开 tun
//  10) initialize_netdevices()            -- 50+ 虚拟 netdev
//  11) initialize_wifi_devices()          -- mac80211_hwsim + wlan0/1
//  12) sandbox_common_mount_tmpfs()       -- tmpfs + bind + pivot_root + chroot
//                                            + setup_binderfs + setup_fusectl
//                                            + setup_gadgetfs + InitializeCgroups
//  13) drop_caps()                        -- 上游 drop_caps == DropSyzkallerCaps (仅 PTRACE+NICE)
//  14) prctl(PR_SET_NO_NEW_PRIVS, 1)      -- 防 execve setuid 回提权
//
// 关键点:
//   - grandchild 沿用已打开的 kcov fd / ivshmem mmap / pipe fd(fork 继承)。
//   - 返回 0 代表"继续跑 fuzz 主循环",只有 grandchild 会回到 ChildMain 的 while。
//     middle 始终 _exit,不返回。
//   - unshare(NEWNET) hard-fail:沙箱被破坏不应继续 fuzz,否则 host netns 泄漏。
int ApplyNamespace(const SandboxSizing& sizing) {
    const int real_uid = static_cast<int>(::getuid());
    const int real_gid = static_cast<int>(::getgid());

    // [v3 D6 pre-unshare] HCIDEVUP 需 CAP_SYS_ADMIN;必须在进入 user ns
    // (uid map 之前 effective uid=0,但 cap 不含 SYS_ADMIN 在 namespace 内)
    // 之前调。上游 do_sandbox_namespace 4356-4359 也是 pre-clone。
    if (const int rc = RequiredSandboxSetupResult(
            ::refuzz::worker::sandbox::device_init::InitializeVhci(),
            "initialize_vhci", sizing);
        rc != 0) {
        return rc;
    }

    if (::unshare(CLONE_NEWUSER | CLONE_NEWPID) != 0) {
        const int err = errno;
        SBXLOG("unshare(NEWUSER|NEWPID) failed: errno=%d (kernel userns 被禁?)", err);
        return -err;
    }

    const pid_t pid = ::fork();
    if (pid < 0) {
        const int err = errno;
        SBXLOG("fork after unshare failed: errno=%d", err);
        return -err;
    }

    if (pid > 0) {
        // ── 中间进程：trampoline ──────────────────────────────────
        // 孙子是新 pid ns 的 PID 1；它自行进入 fuzz 主循环。我们在这里
        // 阻塞等它退出，然后用它的退出码退出——parent watchdog 看到的
        // 是原 fuzz child (middle) 的退出状态，语义与 syzkaller 一致。
        //
        // 不关闭 pipe fd：parent 的 NotifyChild/WaitChild 全部通过 pipe
        // 与 **孙子** 通信（fd 被 fork 继承给孙子），middle 持有同样的
        // fd 但不读不写。middle 退出时 kernel 自动 close 其 fd 副本；
        // 孙子的 fd 仍然活着，pipe 语义不受影响。
        int status = 0;
        for (;;) {
            pid_t w = ::waitpid(pid, &status, 0);
            if (w == pid) break;
            if (w < 0 && errno == EINTR) continue;
            if (w < 0) {
                SBXLOG("middle: waitpid(%d) errno=%d", (int)pid, errno);
                _exit(1);
            }
        }
        if (WIFEXITED(status))   _exit(WEXITSTATUS(status));
        if (WIFSIGNALED(status)) _exit(128 + WTERMSIG(status));
        _exit(1);
    }

    // ── 孙子（新 pid ns PID 1；新 user ns，需要立刻写 uid/gid map）──

    // setgroups=deny 必须在 gid_map 之前（否则 unprivileged user ns 不允许
    // 写 gid_map）。
    WriteFile("/proc/self/setgroups", "deny");

    char buf[64];
    ::snprintf(buf, sizeof(buf), "0 %d 1\n", real_uid);
    WriteFile("/proc/self/uid_map", buf);
    ::snprintf(buf, sizeof(buf), "0 %d 1\n", real_gid);
    WriteFile("/proc/self/gid_map", buf);

    // 父死即 SIGKILL（与 setuid 路径一致）。
    ::prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);

    // 复用 SandboxCommon：rlimit + NEWNS|NEWIPC|NEWUTS|NEWCGROUP|SYSVSEM
    // + mount("/", MS_REC|MS_PRIVATE) + IPC sysctl。
    // 注意：prctl(PDEATHSIG) 已经单独设好，SandboxCommon 里那条等价重复
    // 即可，不会冲突。
    if (const int rc = SandboxCommon(sizing); rc != 0) {
        return rc;
    }

    // [v3 D3 pre-NEWNET] 配 host netns 的 NETROM/ROSE 设备(必须在 NEWNET 之前;
    // 进入 sandbox netns 后这些 host 设备就不可见了)。procid=0。
    // 对齐上游 namespace_sandbox_proc 4319-4321。
    ::refuzz::worker::sandbox::device_init::InitializeNetdevicesInit(sizing.proc_id);

    // 网络 ns 隔离 — 上游 hard-fail (fail("unshare(NEWNET)")),沙箱被破坏不应
    // 继续 fuzz,否则 host netns 泄漏。这里 _exit(1) 等价 — middle 的 waitpid
    // 拿到 128+SIGKILL? 不,exit(1) → middle 拿到 WIFEXITED && WEXITSTATUS=1 →
    // middle _exit(1) → daemon watchdog → recovery → restart_single_worker。
    if (::unshare(CLONE_NEWNET) != 0) {
        const int error_number = errno;
        SBXLOG("namespace: unshare(NEWNET) failed: errno=%d", error_number);
        return -error_number;
    }
    // [Phase 1] ICMP socket 访问权,必须在 NEWNET 后做(对齐 syzkaller)。
    WriteFile("/proc/sys/net/ipv4/ping_group_range", "0 65535");

    // [v3 D7 post-NEWNET] setns init netns → devlink reload pci/0000:00:10.0
    // 到 sandbox netns → 重命名 ports 为 netpci0/1/...。必须在 NEWNET 之后
    // (能 setns 回去)且 InitializeTun 之前(上游序列 devlink → tun → netdev)。
    ::refuzz::worker::sandbox::device_init::InitializeDevlinkPci();

    // [v3 D3 post-NEWNET] open tun → fd 200 + netlink add_addr / add_neigh /
    // device up。所有 tun 配置只对本 netns 生效。
    if (const int rc = RequiredSandboxSetupResult(
            ::refuzz::worker::sandbox::device_init::InitializeTun(),
            "initialize_tun", sizing);
        rc != 0) {
        return rc;
    }

    // [v3 D4 post-NEWNET] 50+ 虚拟 netdev(bridge/bond/team/batadv/hsr/veth/
    // wireguard/vlan/macvlan/ipvlan/geneve/netdevsim/xfrm/virt_wifi/macvtap/
    // macsec/...) + IPv4/IPv6 + MAC + up。procid=0。
    ::refuzz::worker::sandbox::device_init::InitializeNetdevices(sizing.proc_id);

    // [v3 D5 post-NEWNET] mac80211_hwsim 2 radios + wlan0/wlan1 join IBSS。
    // 给 syz_80211_inject_frame / syz_80211_join_ibss 一个 ready 的无线栈。
    if (const int rc = RequiredSandboxSetupResult(
            ::refuzz::worker::sandbox::device_init::InitializeWifiDevices(),
            "initialize_wifi_devices", sizing);
        rc != 0) {
        return rc;
    }

    // [v3 D1] sandbox_common_mount_tmpfs 完整序列(对齐上游 4346):
    //   tmpfs ./syz-tmp + 8 bind mount + InitializeCgroups + pivot_root +
    //   chroot ./newroot + SetupGadgetfs + SetupBinderfs + SetupFusectl。
    // 上游在 namespace_sandbox_proc 末尾 drop_caps 之前调。
    if (const int rc = RequiredSandboxSetupResult(
            ::refuzz::worker::sandbox::device_init::SandboxCommonMountTmpfs(),
            "sandbox_common_mount_tmpfs", sizing);
        rc != 0) {
        return rc;
    }

    // [v3 syzkaller-parity DropSyzkallerCaps]
    // user ns 内即便 effective uid=0,DropSyzkallerCaps 后 CAP_SYS_PTRACE
    // / CAP_SYS_NICE 被剥(等价上游 drop_caps()),其它 caps 保留,
    // fuzz program 测试它们与 kernel 的交互。
    DropSyzkallerCaps();

    // NO_NEW_PRIVS 阻止 execve setuid binary 回提权（与 setuid 路径一致）。
    if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        SBXLOG("prctl(PR_SET_NO_NEW_PRIVS) failed: errno=%d", errno);
    }

    SBXLOG("namespace applied (syzkaller-parity v3 with full device init): "
           "inner_pid=%d inner_uid=%d outer_uid=%d outer_gid=%d",
           (int)::getpid(), (int)::getuid(), real_uid, real_gid);
    return 0;
}

enum class IsolationProbeStage : int32_t {
    kOk = 0,
    kUserNamespace = 1,
    kMountNamespace = 2,
    kPrivatePropagation = 3,
};

struct IsolationProbeResult {
    IsolationProbeStage stage = IsolationProbeStage::kOk;
    int32_t error_number = 0;
};

bool ProbePrivateMountNamespace(bool enter_user_namespace,
                                char* err_detail,
                                size_t cap)
{
    int result_pipe[2] = {-1, -1};
    if (::pipe(result_pipe) != 0) {
        if (err_detail != nullptr && cap > 0) {
            ::snprintf(err_detail, cap, "probe pipe() errno=%d", errno);
        }
        return false;
    }

    const pid_t pid = ::fork();
    if (pid < 0) {
        const int err = errno;
        ::close(result_pipe[0]);
        ::close(result_pipe[1]);
        if (err_detail != nullptr && cap > 0) {
            ::snprintf(err_detail, cap, "probe fork() errno=%d", err);
        }
        return false;
    }
    if (pid == 0) {
        ::close(result_pipe[0]);
        IsolationProbeResult result{};
        if (enter_user_namespace && ::unshare(CLONE_NEWUSER) != 0) {
            result.stage = IsolationProbeStage::kUserNamespace;
            result.error_number = errno;
        } else if (::unshare(CLONE_NEWNS) != 0) {
            result.stage = IsolationProbeStage::kMountNamespace;
            result.error_number = errno;
        } else if (::mount(nullptr, "/", nullptr,
                           MS_REC | MS_PRIVATE, nullptr) != 0) {
            result.stage = IsolationProbeStage::kPrivatePropagation;
            result.error_number = errno;
        }
        ssize_t written;
        do {
            written = ::write(result_pipe[1], &result, sizeof(result));
        } while (written < 0 && errno == EINTR);
        ::close(result_pipe[1]);
        _exit(written == static_cast<ssize_t>(sizeof(result)) ? 0 : 1);
    }

    ::close(result_pipe[1]);
    IsolationProbeResult result{};
    size_t received = 0;
    while (received < sizeof(result)) {
        const ssize_t n = ::read(
            result_pipe[0],
            reinterpret_cast<char*>(&result) + received,
            sizeof(result) - received);
        if (n > 0) {
            received += static_cast<size_t>(n);
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        break;
    }
    ::close(result_pipe[0]);

    int status = 0;
    pid_t waited;
    do {
        waited = ::waitpid(pid, &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited != pid || received != sizeof(result) ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        if (err_detail != nullptr && cap > 0) {
            ::snprintf(err_detail, cap,
                       "private mount namespace probe failed status=0x%x",
                       status);
        }
        return false;
    }
    if (result.stage == IsolationProbeStage::kOk) {
        return true;
    }

    const char* operation = "mount propagation";
    switch (result.stage) {
    case IsolationProbeStage::kUserNamespace:
        operation = "unshare(CLONE_NEWUSER)";
        break;
    case IsolationProbeStage::kMountNamespace:
        operation = "unshare(CLONE_NEWNS)";
        break;
    case IsolationProbeStage::kPrivatePropagation:
        operation = "mount(/,MS_REC|MS_PRIVATE)";
        break;
    case IsolationProbeStage::kOk:
        break;
    }
    if (err_detail != nullptr && cap > 0) {
        ::snprintf(err_detail, cap, "%s errno=%d",
                   operation, result.error_number);
    }
    return false;
}

} // namespace

bool ProbeSandboxMode(SandboxMode mode, char* err_detail, size_t cap) {
    if (err_detail != nullptr && cap > 0) {
        err_detail[0] = '\0';
    }
    switch (mode) {
    case SandboxMode::kNone:
    case SandboxMode::kSetuid:
        return ProbePrivateMountNamespace(false, err_detail, cap);
    case SandboxMode::kNamespace:
        return ProbePrivateMountNamespace(true, err_detail, cap);
    }
    if (err_detail != nullptr && cap > 0) {
        ::snprintf(err_detail, cap, "unknown sandbox mode=%d",
                   static_cast<int>(mode));
    }
    return false;
}

bool ParseSandboxMode(std::string_view s, SandboxMode* out) {
    if (out == nullptr) return false;
    if (s == "none")      { *out = SandboxMode::kNone;      return true; }
    if (s == "setuid")    { *out = SandboxMode::kSetuid;    return true; }
    if (s == "namespace") { *out = SandboxMode::kNamespace; return true; }
    return false;
}

const char* SandboxModeName(SandboxMode m) {
    switch (m) {
    case SandboxMode::kNone:      return "none";
    case SandboxMode::kSetuid:    return "setuid";
    case SandboxMode::kNamespace: return "namespace";
    }
    return "unknown";
}

size_t ComputeAddressSpaceLimit(const SandboxSizing& sizing) {
    const size_t dynamic_base =
        sizing.ivshmem_bytes +
        sizing.scratch_bytes +
        kFixedFootprintBytes +
        kFuzzHeadroomBytes;
    const size_t base = dynamic_base < kSyzkallerBaseAddressSpaceBytes
        ? kSyzkallerBaseAddressSpaceBytes
        : dynamic_base;
    const size_t coverage = sizing.coverage_bytes < kSyzkallerCoverageReserveBytes
        ? kSyzkallerCoverageReserveBytes
        : sizing.coverage_bytes;
    return base + coverage;
}

int ApplySandbox(SandboxMode mode, const SandboxSizing& sizing) {
    switch (mode) {
    case SandboxMode::kNone:      return ApplyNone(sizing);
    case SandboxMode::kSetuid:    return ApplySetuid(sizing);
    case SandboxMode::kNamespace: return ApplyNamespace(sizing);
    }
    return -EINVAL;
}

} // namespace refuzz::worker

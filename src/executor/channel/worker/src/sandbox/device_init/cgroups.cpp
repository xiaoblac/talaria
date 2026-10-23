// InitializeCgroups — 对齐 syzkaller `initialize_cgroups`
// (executor/common_linux.h:3893-3918)。
//
// 前提:host 已 mount /syzcgroup/unified (cgroup2) / /syzcgroup/cpu /
// /syzcgroup/net (cgroup v1 controllers)。reFuzz VM image setup 时由
// boot 脚本挂好(syzkaller VM image 也是这套约定)。
//
// 步骤:
//   mkdir ./syz-tmp/newroot/syzcgroup{,/unified,/cpu,/net}
//   bind-mount host /syzcgroup/{unified,cpu,net} 到 newroot 对应位置
//
// 失败:
//   mkdir 失败 (newroot 不在?) → CRITICAL log,return (上层 mount_tmpfs
//   已挂了 tmpfs,理论不会失败;若失败说明前面 mkdir newroot 也 fail 过,
//   整条 sandbox 路径已严重出问题)
//   bind 失败 → DEBUG log,continue;host 没挂 /syzcgroup/* 时 cgroup
//   类 fuzz syscall 会 ENOENT,但不影响其它 syscall。

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "worker/sandbox/device_init/device_init.hpp"

#include "worker/log/log_macros.hpp"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#define DILOG(fmt, ...) \
    ::refuzz::worker::log::WorkerLog("[device_init] " fmt "\n", ##__VA_ARGS__)

namespace refuzz::worker::sandbox::device_init {

namespace {

bool MkdirOrExisting(const char* path, mode_t mode)
{
    if (::mkdir(path, mode) == 0) return true;
    if (errno == EEXIST) return true;
    DILOG("cgroups: mkdir(%s, 0%o) errno=%d (%s)",
          path, (unsigned)mode, errno, ::strerror(errno));
    return false;
}

void WriteFile(const char* path, const char* value)
{
    const int fd = ::open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        DILOG("cgroups: open(%s) errno=%d (%s) — skipped",
              path, errno, ::strerror(errno));
        return;
    }
    const size_t n = ::strlen(value);
    const ssize_t w = ::write(fd, value, n);
    if (w != static_cast<ssize_t>(n)) {
        DILOG("cgroups: write(%s) rc=%zd errno=%d (%s)",
              path, w, errno, ::strerror(errno));
    }
    ::close(fd);
}

// [当前版本 setup-cgroups-loop-test] 对齐 syzkaller `mount_cgroups`
// (common_linux.h:3725-3760)。先按 controller 逐个探测能挂的,然后一次性
// 全部挂上去。失败 silent log + rmdir 清理。
void MountCgroupV1(const char* dir, const char* const* controllers, int count)
{
    if (::mkdir(dir, 0777) != 0 && errno != EEXIST) {
        DILOG("mount_cgroups: mkdir(%s) errno=%d (%s) — skip",
              dir, errno, ::strerror(errno));
        return;
    }
    char enabled[128] = {0};
    for (int i = 0; i < count; i++) {
        if (::mount("none", dir, "cgroup", 0, controllers[i]) != 0) {
            DILOG("mount_cgroups: mount(%s, %s) probe errno=%d",
                  dir, controllers[i], errno);
            continue;
        }
        ::umount(dir);
        ::strcat(enabled, ",");
        ::strcat(enabled, controllers[i]);
    }
    if (enabled[0] == 0) {
        if (::rmdir(dir) != 0 && errno != EBUSY) {
            DILOG("mount_cgroups: rmdir(%s) errno=%d after empty probe",
                  dir, errno);
        }
        return;
    }
    if (::mount("none", dir, "cgroup", 0, enabled + 1) != 0) {
        DILOG("mount_cgroups: mount(%s, %s) errno=%d (likely EBUSY systemd)",
              dir, enabled + 1, errno);
        if (::rmdir(dir) != 0 && errno != EBUSY) {
            DILOG("mount_cgroups: rmdir(%s) errno=%d after combined fail",
                  dir, errno);
        }
    }
    if (::chmod(dir, 0777) != 0) {
        DILOG("mount_cgroups: chmod(%s,0777) errno=%d", dir, errno);
    }
}

// [当前版本 setup-cgroups-loop-test] 对齐 syzkaller `mount_cgroups2`
// (common_linux.h:3762-3793)。挂 cgroup2 unified hierarchy,然后通过
// cgroup.subtree_control 启用 +cpu/+io/+pids 子树控制器。
void MountCgroupV2Unified(const char* const* controllers, int count)
{
    if (::mkdir("/syzcgroup/unified", 0777) != 0 && errno != EEXIST) {
        DILOG("mount_cgroups2: mkdir(/syzcgroup/unified) errno=%d", errno);
        return;
    }
    // [当前版本 cgroup2-EBUSY-still-enable-io] mount(cgroup2) 失败要分两种:
    //   · errno==EBUSY → /syzcgroup/unified **已经是 cgroup2 挂点**(image boot
    //     脚本或上一次 boot 挂的)。这时**不能 return** —— 必须继续往
    //     cgroup.subtree_control 写 +cpu/+io/+pids,否则 per-procid cgroup 没有 io
    //     控制器,program-child 落 root blkcg,blkcg_css/blk_cgroup_congested 全
    //     短路。**这是 reFuzz vs syz blkcg 100% vs 0% 分歧的根因**(syz 环境里
    //     /syzcgroup/unified 没被预挂,mount 成功→直接到 subtree_control;reFuzz
    //     环境预挂了→撞 EBUSY→旧代码 return→+io 从未启用)。
    //   · 其它 errno → 真失败,rmdir 清理(否则 fuzzer 在普通目录里写大文件)后退出。
    if (::mount("none", "/syzcgroup/unified", "cgroup2", 0, nullptr) != 0) {
        if (errno != EBUSY) {
            DILOG("mount_cgroups2: mount(cgroup2) errno=%d — abort", errno);
            if (::rmdir("/syzcgroup/unified") != 0 && errno != EBUSY) {
                DILOG("mount_cgroups2: rmdir(/syzcgroup/unified) errno=%d", errno);
            }
            return;
        }
        DILOG("mount_cgroups2: cgroup2 already mounted (EBUSY) — 复用挂点,仍启用 subtree_control");
    }
    if (::chmod("/syzcgroup/unified", 0777) != 0) {
        DILOG("mount_cgroups2: chmod(/syzcgroup/unified) errno=%d", errno);
    }
    const int ctl = ::open("/syzcgroup/unified/cgroup.subtree_control",
                           O_WRONLY | O_CLOEXEC);
    if (ctl < 0) {
        DILOG("mount_cgroups2: open(subtree_control) errno=%d", errno);
        return;
    }
    for (int i = 0; i < count; i++) {
        const size_t n = ::strlen(controllers[i]);
        if (::write(ctl, controllers[i], n) != static_cast<ssize_t>(n)) {
            DILOG("mount_cgroups2: write(subtree_control,%s) errno=%d",
                  controllers[i], errno);
        }
    }
    ::close(ctl);
}

} // namespace

// [当前版本 setup-cgroups-loop-test] 对齐 syzkaller `setup_cgroups`
// (common_linux.h:3795-3818)。worker 0 在 Register() 发布 daemon heartbeat
// 后、domain sandbox 前调一次,把 cgroup v1/v2 hierarchies 挂到 host
// /syzcgroup/{unified,cpu,net}。**没有这一步,后续 InitializeCgroups bind
// mount、SetupCgroupsLoop mkdir 全部 ENOENT 空转。**
//
// 三个 controller 分组对齐上游:
//   unified (cgroup2): +cpu, +io, +pids
//   cpu (v1):          cpuset, cpuacct, hugetlb, rlimit, memory
//   net (v1):          net, net_prio, devices, blkio, freezer
//
// EBUSY(已挂载,例如 systemd 抢先 attach memory)debug log + continue,
// 不视为错误。reFuzz qemu snapshot=true 模式每次 boot reset,通常 clean。
void MountCgroupsHost()
{
    if (::mkdir("/syzcgroup", 0777) != 0 && errno != EEXIST) {
        DILOG("setup_cgroups: mkdir(/syzcgroup) errno=%d (%s) — abort",
              errno, ::strerror(errno));
        return;
    }
    static const char* const kUnified[] = {"+cpu", "+io", "+pids"};
    static const char* const kCpu[]     = {"cpuset", "cpuacct", "hugetlb",
                                            "rlimit", "memory"};
    static const char* const kNet[]     = {"net", "net_prio", "devices",
                                            "blkio", "freezer"};
    MountCgroupV2Unified(kUnified, 3);
    MountCgroupV1("/syzcgroup/net", kNet, 5);
    MountCgroupV1("/syzcgroup/cpu", kCpu, 5);
    WriteFile("/syzcgroup/cpu/cgroup.clone_children", "1");
    WriteFile("/syzcgroup/cpu/cpuset.memory_pressure_enabled", "1");
    DILOG("setup_cgroups: host /syzcgroup/{unified,cpu,net} ready");
}

void InitializeCgroups()
{
    if (!MkdirOrExisting("./syz-tmp/newroot/syzcgroup", 0700)) {
        DILOG("CRITICAL: cgroups: cannot create newroot/syzcgroup — skip");
        return;
    }
    // 三个 controller 目录;单个 mkdir 失败仍尝试后续 bind(host 上可能只
    // 挂部分 controller)。
    MkdirOrExisting("./syz-tmp/newroot/syzcgroup/unified", 0700);
    MkdirOrExisting("./syz-tmp/newroot/syzcgroup/cpu", 0700);
    MkdirOrExisting("./syz-tmp/newroot/syzcgroup/net", 0700);

    const unsigned kBindRecPriv = MS_BIND | MS_REC | MS_PRIVATE;
    if (::mount("/syzcgroup/unified", "./syz-tmp/newroot/syzcgroup/unified",
                nullptr, kBindRecPriv, nullptr) != 0) {
        DILOG("cgroups: bind(/syzcgroup/unified) errno=%d (%s) — "
              "host 没挂 cgroup2 控制器,cgroup2 fuzz 类 corpus 走 ENOENT",
              errno, ::strerror(errno));
    }
    if (::mount("/syzcgroup/cpu", "./syz-tmp/newroot/syzcgroup/cpu",
                nullptr, kBindRecPriv, nullptr) != 0) {
        DILOG("cgroups: bind(/syzcgroup/cpu) errno=%d (%s)",
              errno, ::strerror(errno));
    }
    if (::mount("/syzcgroup/net", "./syz-tmp/newroot/syzcgroup/net",
                nullptr, kBindRecPriv, nullptr) != 0) {
        DILOG("cgroups: bind(/syzcgroup/net) errno=%d (%s)",
              errno, ::strerror(errno));
    }
}

// [当前版本 setup-cgroups-loop-test] 对齐 syzkaller `setup_cgroups_loop`
// (common_linux.h:3821-3869)。loop_child 进 main loop 之前调一次:
//   1) /syzcgroup/unified/syz<procid>:pids.max=32,把自己写入 cgroup.procs。
//      cgroup 是继承的,后续 fork 出来的 program-child 全在同 cgroup —
//      累积 task 数超 32 时 fork(2) 返 EAGAIN,跟上游"fork-bomb 防护"对齐。
//   2) /syzcgroup/cpu/syz<procid>:cgroup.procs + memory.{soft_limit,limit}
//      _in_bytes(300 MB)逐步收紧内存。
//   3) /syzcgroup/net/syz<procid>:cgroup.procs(给 net_prio / net_cls 类
//      fuzz target 一个可写位置)。
//
// procid is the execution-domain resource identity. It changes after an
// uncertain recovery while the stable worker slot does not.
//
// pid: 用 getpid() —— loop_child 在新 PID NS 内是 pid=2(ns_runner_child 占
// pid=1),kernel cgroup.procs 写入按 caller PID NS 解释,写"自己的视角 pid"
// 即可。
void SetupCgroupsLoop(std::uint64_t procid)
{
    const int pid = ::getpid();
    char cgroupdir[64];
    char file[128];

    snprintf(cgroupdir, sizeof(cgroupdir),
             "/syzcgroup/unified/syz%llu", (unsigned long long)procid);
    if (!MkdirOrExisting(cgroupdir, 0777)) {
        DILOG("setup_cgroups_loop: skip (unified syz%llu unavailable)",
              (unsigned long long)procid);
        return;
    }
    snprintf(file, sizeof(file), "%s/pids.max", cgroupdir);
    WriteFile(file, "32");
    snprintf(file, sizeof(file), "%s/cgroup.procs", cgroupdir);
    {
        char buf[16];
        snprintf(buf, sizeof(buf), "%d", pid);
        WriteFile(file, buf);
    }

    snprintf(cgroupdir, sizeof(cgroupdir),
             "/syzcgroup/cpu/syz%llu", (unsigned long long)procid);
    MkdirOrExisting(cgroupdir, 0777);
    snprintf(file, sizeof(file), "%s/cgroup.procs", cgroupdir);
    {
        char buf[16];
        snprintf(buf, sizeof(buf), "%d", pid);
        WriteFile(file, buf);
    }
    snprintf(file, sizeof(file), "%s/memory.soft_limit_in_bytes", cgroupdir);
    WriteFile(file, "313524224");  // 299 << 20
    snprintf(file, sizeof(file), "%s/memory.limit_in_bytes", cgroupdir);
    WriteFile(file, "314572800");  // 300 << 20

    snprintf(cgroupdir, sizeof(cgroupdir),
             "/syzcgroup/net/syz%llu", (unsigned long long)procid);
    MkdirOrExisting(cgroupdir, 0777);
    snprintf(file, sizeof(file), "%s/cgroup.procs", cgroupdir);
    {
        char buf[16];
        snprintf(buf, sizeof(buf), "%d", pid);
        WriteFile(file, buf);
    }

    DILOG("setup_cgroups_loop: pid=%d procid=%llu cgroups attached "
          "(unified pids.max=32, cpu memory<=300MB, net)",
          pid, (unsigned long long)procid);
}

// [当前版本 setup-cgroups-loop-test] 对齐 syzkaller `setup_cgroups_test`
// (common_linux.h:3871-3890)。每个 program-child fork 之后,chdir(workdir)
// 之后调一次:在当前 cwd 创 ./cgroup / ./cgroup.cpu / ./cgroup.net symlink
// 指向 host /syzcgroup/.../syz<procid>。给 corpus 里 mount$cgroup /
// setxattr$trusted_overlay 等需要 cgroup path 的 fuzz target 一个稳定路径。
//
// symlink 已存在(同 workdir 跨 program 复用)返 EEXIST,debug log + 忽略,
// 跟上游 `debug()` 行为一致。
void SetupCgroupsTest(std::uint64_t procid)
{
    char cgroupdir[64];

    snprintf(cgroupdir, sizeof(cgroupdir),
             "/syzcgroup/unified/syz%llu", (unsigned long long)procid);
    if (::symlink(cgroupdir, "./cgroup") != 0 && errno != EEXIST) {
        DILOG("setup_cgroups_test: symlink(%s, ./cgroup) errno=%d (%s)",
              cgroupdir, errno, ::strerror(errno));
    }
    snprintf(cgroupdir, sizeof(cgroupdir),
             "/syzcgroup/cpu/syz%llu", (unsigned long long)procid);
    if (::symlink(cgroupdir, "./cgroup.cpu") != 0 && errno != EEXIST) {
        DILOG("setup_cgroups_test: symlink(%s, ./cgroup.cpu) errno=%d (%s)",
              cgroupdir, errno, ::strerror(errno));
    }
    snprintf(cgroupdir, sizeof(cgroupdir),
             "/syzcgroup/net/syz%llu", (unsigned long long)procid);
    if (::symlink(cgroupdir, "./cgroup.net") != 0 && errno != EEXIST) {
        DILOG("setup_cgroups_test: symlink(%s, ./cgroup.net) errno=%d (%s)",
              cgroupdir, errno, ::strerror(errno));
    }
}

// [当前版本 setup-cgroups-loop-test] 对齐 syzkaller `setup_test`
// (common_linux.h:4881-4904)。每个 forked program-child 无条件执行:
//   1) prctl(PR_SET_PDEATHSIG, SIGKILL):loop_parent 死时 program-child
//      跟着自动 SIGKILL,避免漏跑泄漏。
//   2) setpgrp():**核心** — program-child 成 process group leader (PGID =
//      自己 pid)。后续 syz_clone fork 出的 grand-child 继承同 PGID。
//      program-child _exit(0) 后整个 group 变 "orphaned process group";
//      POSIX 规定 orphaned group 内若有 stopped 进程(被 ptrace 截停)
//      kernel 自动发 SIGHUP + SIGCONT,SIGHUP 默认 terminate → stopped
//      grand-child 自动死,cgroup pids 自动释放。
//      **没这一步:**stopped grand-child 永生,cgroup pids.max=32 撑爆 → 后续
//      syz_clone EAGAIN(snapshot 实测 11 个 stopped child 占满 cgroup)。
//   3) write_file("/proc/self/oom_score_adj", "1000"):leaf 进程优先 OOM
//      kill,保护 loop_parent / ns_runner_child 在 OOM 时存活。
void SetupTestProcess()
{
    ::prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
    ::setpgrp();
    WriteFile("/proc/self/oom_score_adj", "1000");
}

void CloseProgramFds()
{
#ifdef SYS_close_range
    if (::syscall(SYS_close_range, 3u, 30u, 0u) == 0) {
        return;
    }
#endif
    for (int fd = 3; fd <= 30; ++fd) {
        ::close(fd);
    }
}

void SetupTestWorkdir(std::uint64_t procid)
{
    SetupCgroupsTest(procid);
    // [当前版本 binderfs symlink — 2026-05-22]
    // 上游 setup_test (common_linux.h:4898-4903) 在每个 test workdir 创
    // ./binderfs symlink → /dev/binderfs。syzlang corpus 路径用相对
    // ./binderfs/binder0 / ./binderfs/binder-control 等(dev_binderfs.txt:10),
    // 没这 symlink → openat$binderfs ENOENT(6 mismatch)+ mmap$binder
    // EBADF cascade(6 mismatch)。errno = EEXIST 时静默(下一个 program
    // 在同 workdir 再 setup,符号链接已存在)。
    if (::symlink("/dev/binderfs", "./binderfs") != 0 && errno != EEXIST) {
        // silent — match upstream debug() behavior on failure
    }
    // [当前版本 close_fds — 2026-05-22]
    // 上游 close_fds (common_linux.h:4910-4926) 用 close_range(3, 30, 0)
    // 关掉 fd 3-30,确保 program-child 起步 fd table 干净。reFuzz worker daemon
    // 持有 fd 200+(TUN/init_netns/vhci/devlink),不在 3-30 范围,close_range
    // 不影响。
    //
    // 没这一步:program-child 从 worker fork 时继承 fd 3-29(LOG/IPC/etc),
    // corpus 调 close(N) literal 时 reFuzz 关掉 worker 的 fd → 成功,upstream
    // 同位置 close 返 EBADF。close 6 个 actionable (syz=9, ref=0) 的根因。
    CloseProgramFds();
}

namespace {

long ReadLongFromFile(const char* path)
{
    const int fd = ::open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    char buf[64] = {0};
    const ssize_t n = ::read(fd, buf, sizeof(buf) - 1);
    ::close(fd);
    if (n <= 0) return -1;
    return ::atol(buf);
}

int CountFileLines(const char* path)
{
    const int fd = ::open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    int lines = 0;
    char buf[256];
    ssize_t n;
    while ((n = ::read(fd, buf, sizeof(buf))) > 0) {
        for (ssize_t i = 0; i < n; ++i) {
            if (buf[i] == '\n') ++lines;
        }
    }
    ::close(fd);
    return lines;
}

// 解 /proc/<pid>/stat 一次拿 state/ppid/pgrp/session。format:
//   pid (comm) state ppid pgrp session tty_pgrp ...
// comm 含空格 / ')' → 从最后一个 ')' 之后开始 parse。
// state 'T' = SIGSTOP/job-control stop;'t' = ptrace stop (Linux 2.6.33+)。
bool ReadProcStatBrief(int pid, char* out_state, int* out_ppid,
                       int* out_pgid, int* out_sid)
{
    if (out_state) *out_state = '?';
    if (out_ppid)  *out_ppid  = -1;
    if (out_pgid)  *out_pgid  = -1;
    if (out_sid)   *out_sid   = -1;
    char path[64];
    ::snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    const int fd = ::open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    char buf[1024] = {0};
    const ssize_t n = ::read(fd, buf, sizeof(buf) - 1);
    ::close(fd);
    if (n <= 0) return false;
    const char* rp = ::strrchr(buf, ')');
    if (rp == nullptr) return false;
    char state = '?';
    int ppid = -1, pgrp = -1, session = -1;
    if (::sscanf(rp + 1, " %c %d %d %d", &state, &ppid, &pgrp, &session) == 4) {
        if (out_state) *out_state = state;
        if (out_ppid)  *out_ppid  = ppid;
        if (out_pgid)  *out_pgid  = pgrp;
        if (out_sid)   *out_sid   = session;
        return true;
    }
    return false;
}

} // namespace

// loop_parent 在每个 program-child waitpid 收尸完成之后调一次,dump 当前
// /syzcgroup/unified/syz<procid>/cgroup.procs 占用快照,逐 pid 一行
// (state/pgid/sid/ppid)。给 over-EAGAIN diag 用,看 setpgrp 是否生效
// (stopped child 的 pgid 应该 == 它 fork 出来时 program-child 的 pid;
//  累积 == orphaned-pgrp cleanup 未触发,即 task_session(real_parent) ==
//  task_session(p) 命中)。
//
// 频率控制:env REFUZZ_DUMP_POST_EXIT=1 主开关 (默认关闭,生产路径零开销),
// 开启后用 file-static counter,前 N=256 次 program 全部 dump,之后只
// 在 pids.current >= warn_threshold (默认 24,接近 32 cap) 时 dump,
// 避免 ttyS0 burst。
//
// prog_seq 从 caller 传 (program_runtime 内 thread_local atomic counter),
// 主要给 log 关联用 — 不同 program 的 snapshot 行能按 seq 排序。
void DumpCgroupSnapshotPostExit(std::uint32_t proc_id, std::uint64_t prog_seq)
{
    static const bool kEnabled = []() {
        const char* env = ::getenv("REFUZZ_DUMP_POST_EXIT");
        return env != nullptr && env[0] != '0' && env[0] != '\0';
    }();
    if (!kEnabled) return;

    static int kRemainingFull = 256;
    constexpr long kWarnThreshold = 24;

    char pids_current_path[128];
    char procs_path[128];
    ::snprintf(pids_current_path, sizeof(pids_current_path),
               "/syzcgroup/unified/syz%u/pids.current", proc_id);
    ::snprintf(procs_path, sizeof(procs_path),
               "/syzcgroup/unified/syz%u/cgroup.procs", proc_id);

    const long pids_current = ReadLongFromFile(pids_current_path);
    const int  procs_lines  = CountFileLines(procs_path);

    bool do_full = false;
    if (kRemainingFull > 0) {
        --kRemainingFull;
        do_full = true;
    } else if (pids_current >= kWarnThreshold) {
        do_full = true;
    }
    if (!do_full) return;

    DILOG("[post-exit-snap-begin] wid=%u seq=%llu pids.current=%ld procs_lines=%d",
          proc_id, static_cast<unsigned long long>(prog_seq),
          pids_current, procs_lines);

    const int fd = ::open(procs_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        DILOG("[post-exit-snap-end] cgroup.procs open errno=%d", errno);
        return;
    }
    char buf[8192] = {0};
    const ssize_t n = ::read(fd, buf, sizeof(buf) - 1);
    ::close(fd);
    if (n <= 0) {
        DILOG("[post-exit-snap-end] cgroup.procs empty");
        return;
    }
    const char* p = buf;
    int dumped = 0;
    while (*p) {
        const char* eol = ::strchr(p, '\n');
        char pid_str[32] = {0};
        const size_t line_len = eol ? static_cast<size_t>(eol - p) : ::strlen(p);
        const size_t copy = line_len < sizeof(pid_str) - 1 ? line_len
                                                            : sizeof(pid_str) - 1;
        ::memcpy(pid_str, p, copy);
        pid_str[copy] = '\0';
        const int proc_pid = ::atoi(pid_str);
        if (proc_pid > 0) {
            char state = '?';
            int ppid = -1, pgid = -1, sid = -1;
            ReadProcStatBrief(proc_pid, &state, &ppid, &pgid, &sid);
            DILOG("[post-exit-snap-proc] proc=%d state=%c ppid=%d pgid=%d sid=%d",
                  proc_pid, state, ppid, pgid, sid);
            ++dumped;
        }
        if (!eol) break;
        p = eol + 1;
    }
    DILOG("[post-exit-snap-end] wid=%u seq=%llu dumped=%d",
          proc_id, static_cast<unsigned long long>(prog_seq), dumped);
}

} // namespace refuzz::worker::sandbox::device_init

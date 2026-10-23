#include "worker/backend/pseudo/pseudo_context.hpp"
#include "worker/backend/pseudo/pseudo_result.hpp"
#include "worker/log/log_macros.hpp"

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <linux/btf.h>
#include <linux/io_uring.h>
#include <linux/time_types.h>   // __kernel_timespec — syz_ublk_process_io ext_arg
#include <sched.h>
#include <signal.h>             // _NSIG — io_uring_enter sigsetsize (ublk)
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace refuzz::worker::pseudo {
namespace {

// [EAGAIN diag] 读 cgroup 文件 / /proc/<pid>/* 定位 syz_clone EAGAIN
// 时 cgroup pids 撑爆的真实占用结构。raw open/read 避免 stdio buffer +
// malloc 在 fork-bomb edge 路径副作用。
long ReadIntFile(const char* path)
{
    const int fd = ::open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    char buf[64] = {0};
    const ssize_t n = ::read(fd, buf, sizeof(buf) - 1);
    ::close(fd);
    if (n <= 0) return -1;
    return ::atol(buf);
}

void ReadLimitTextFile(const char* path, char* out_buf, size_t cap)
{
    if (out_buf == nullptr || cap == 0) return;
    out_buf[0] = '\0';
    const int fd = ::open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        std::snprintf(out_buf, cap, "err:%d", errno);
        return;
    }
    const ssize_t n = ::read(fd, out_buf, cap - 1);
    const int read_errno = errno;
    ::close(fd);
    if (n <= 0) {
        std::snprintf(out_buf, cap, "err:%d", read_errno);
        return;
    }
    size_t len = static_cast<size_t>(n);
    while (len > 0 && (out_buf[len - 1] == '\n' || out_buf[len - 1] == '\r')) --len;
    out_buf[len] = '\0';
}

int CountLines(const char* path)
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

bool IsNumericName(const char* name)
{
    if (name == nullptr || *name == '\0') return false;
    for (const char* p = name; *p != '\0'; ++p) {
        if (*p < '0' || *p > '9') return false;
    }
    return true;
}

int CountDirEntries(const char* path)
{
    DIR* d = ::opendir(path);
    if (d == nullptr) return -1;
    int count = 0;
    struct dirent* ent;
    while ((ent = ::readdir(d)) != nullptr) {
        if (ent->d_name[0] == '.') continue;
        ++count;
    }
    ::closedir(d);
    return count;
}

void CountProcAndThreads(int* out_procs, int* out_threads)
{
    if (out_procs) *out_procs = -1;
    if (out_threads) *out_threads = -1;
    DIR* d = ::opendir("/proc");
    if (d == nullptr) return;
    int procs = 0;
    int threads = 0;
    struct dirent* ent;
    while ((ent = ::readdir(d)) != nullptr) {
        if (!IsNumericName(ent->d_name)) continue;
        ++procs;
        char path[96];
        std::snprintf(path, sizeof(path), "/proc/%s/task", ent->d_name);
        const int task_count = CountDirEntries(path);
        if (task_count > 0) threads += task_count;
    }
    ::closedir(d);
    if (out_procs) *out_procs = procs;
    if (out_threads) *out_threads = threads;
}

const char* FormatRlim(rlim_t value, char* buf, size_t cap)
{
    if (buf == nullptr || cap == 0) return "";
    if (value == RLIM_INFINITY) {
        std::snprintf(buf, cap, "infinity");
    } else {
        std::snprintf(buf, cap, "%llu",
                      static_cast<unsigned long long>(value));
    }
    return buf;
}

// Read trimmed single-line file (e.g. /proc/<pid>/comm). Strips trailing
// '\n'. out_buf zero-terminated. Returns true on success.
bool ReadTrimmedLine(const char* path, char* out_buf, size_t cap)
{
    if (out_buf == nullptr || cap == 0) return false;
    out_buf[0] = '\0';
    const int fd = ::open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    const ssize_t n = ::read(fd, out_buf, cap - 1);
    ::close(fd);
    if (n <= 0) { out_buf[0] = '\0'; return false; }
    size_t len = static_cast<size_t>(n);
    while (len > 0 && (out_buf[len - 1] == '\n' || out_buf[len - 1] == '\r')) --len;
    out_buf[len] = '\0';
    return true;
}

// Parse /proc/<pid>/status (or /proc/<pid>/task/<tid>/status). Fills given
// fields if found (-1 / 'X' if missing). state is the single-char State letter
// — 'T' = SIGSTOP/job-control stop, 't' = ptrace stop (Linux 2.6.33+).
// pgid/sid 不在 /status,补一次 /proc/<pid>/stat 解析(第 5、6 列)。
struct ProcStatusFields {
    char state = '?';
    int  tgid = -1;
    int  pid = -1;
    int  ppid = -1;
    int  tracer_pid = -1;
    int  threads = -1;
    int  pgid = -1;
    int  sid = -1;
};

// 解 /proc/<pid>/stat 第 5、6 列 (pgrp, session)。格式:
//   pid (comm) state ppid pgrp session tty ...
// comm 可含空格 / ')' — 从最后一个 ')' 开始 parse 避坑。
void ReadProcStatPgidSid(int pid, int* out_pgid, int* out_sid)
{
    if (out_pgid) *out_pgid = -1;
    if (out_sid)  *out_sid  = -1;
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    const int fd = ::open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    char buf[1024] = {0};
    const ssize_t n = ::read(fd, buf, sizeof(buf) - 1);
    ::close(fd);
    if (n <= 0) return;
    const char* rp = ::strrchr(buf, ')');
    if (rp == nullptr) return;
    // rp 指向 ")"。skip ") " 进入 state 字段。
    const char* p = rp + 1;
    // skip whitespace + state (1 char) + whitespace + ppid (int) + whitespace.
    // 直接按 sscanf。
    int state_c = 0, ppid = 0, pgrp = 0, session = 0;
    if (std::sscanf(p, " %c %d %d %d", reinterpret_cast<char*>(&state_c), &ppid,
                    &pgrp, &session) == 4) {
        if (out_pgid) *out_pgid = pgrp;
        if (out_sid)  *out_sid  = session;
    }
}

bool ReadProcStatus(const char* path, ProcStatusFields* out)
{
    if (out == nullptr) return false;
    const int fd = ::open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    char buf[4096] = {0};
    const ssize_t n = ::read(fd, buf, sizeof(buf) - 1);
    ::close(fd);
    if (n <= 0) return false;
    const char* p = buf;
    while (*p) {
        const char* eol = ::strchr(p, '\n');
        const size_t line_len = eol ? static_cast<size_t>(eol - p) : ::strlen(p);
        if (line_len >= 6 && ::strncmp(p, "State:", 6) == 0) {
            // State: X (text...)
            const char* q = p + 6;
            while (*q == ' ' || *q == '\t') ++q;
            if (q < p + line_len) out->state = *q;
        } else if (line_len >= 5 && ::strncmp(p, "Tgid:", 5) == 0) {
            out->tgid = ::atoi(p + 5);
        } else if (line_len >= 4 && ::strncmp(p, "Pid:", 4) == 0) {
            out->pid = ::atoi(p + 4);
        } else if (line_len >= 5 && ::strncmp(p, "PPid:", 5) == 0) {
            out->ppid = ::atoi(p + 5);
        } else if (line_len >= 10 && ::strncmp(p, "TracerPid:", 10) == 0) {
            out->tracer_pid = ::atoi(p + 10);
        } else if (line_len >= 8 && ::strncmp(p, "Threads:", 8) == 0) {
            out->threads = ::atoi(p + 8);
        }
        if (!eol) break;
        p = eol + 1;
    }
    // /status 不带 pgrp/session,补一次 /stat。
    if (out->pid > 0) {
        ReadProcStatPgidSid(out->pid, &out->pgid, &out->sid);
    }
    return true;
}

// Dump per-task lines for one process: each tid's comm + state.
void DumpProcessTasks(int proc_pid)
{
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/%d/task", proc_pid);
    DIR* d = ::opendir(path);
    if (d == nullptr) return;
    struct dirent* ent;
    while ((ent = ::readdir(d)) != nullptr) {
        if (ent->d_name[0] == '.') continue;
        char tid_str[32];
        std::snprintf(tid_str, sizeof(tid_str), "%s", ent->d_name);
        char comm_path[96], stat_path[96];
        std::snprintf(comm_path, sizeof(comm_path),
                      "/proc/%d/task/%s/comm", proc_pid, tid_str);
        std::snprintf(stat_path, sizeof(stat_path),
                      "/proc/%d/task/%s/status", proc_pid, tid_str);
        char tcomm[64] = {0};
        ReadTrimmedLine(comm_path, tcomm, sizeof(tcomm));
        ProcStatusFields tf;
        ReadProcStatus(stat_path, &tf);
        ::refuzz::worker::log::WorkerLog(
            "[eagain-snap-task] proc=%d tid=%s comm=%s state=%c\n",
            proc_pid, tid_str, tcomm, tf.state);
    }
    ::closedir(d);
}

// Dump cgroup snapshot for proc_slot=wid. Reads pids.current, cgroup.procs
// lines and per-pid status / task table. Caps total invocations via static
// counter to keep ttyS0 burst manageable.
void DumpEagainCgroupSnapshot(const char* call_name,
                              uint32_t wid,
                              uint64_t eid,
                              long flags)
{
    static int kRemaining = 20;
    if (kRemaining <= 0) return;
    --kRemaining;

    char pids_current_path[128];
    char pids_max_path[128];
    char procs_path[128];
    char threads_path[128];
    std::snprintf(pids_current_path, sizeof(pids_current_path),
                  "/syzcgroup/unified/syz%u/pids.current", wid);
    std::snprintf(pids_max_path, sizeof(pids_max_path),
                  "/syzcgroup/unified/syz%u/pids.max", wid);
    std::snprintf(procs_path, sizeof(procs_path),
                  "/syzcgroup/unified/syz%u/cgroup.procs", wid);
    std::snprintf(threads_path, sizeof(threads_path),
                  "/syzcgroup/unified/syz%u/cgroup.threads", wid);

    const long pids_current = ReadIntFile(pids_current_path);
    char pids_max[32] = {0};
    ReadLimitTextFile(pids_max_path, pids_max, sizeof(pids_max));
    const int  procs_lines  = CountLines(procs_path);
    const int  threads_lines = CountLines(threads_path);
    const long kernel_pid_max = ReadIntFile("/proc/sys/kernel/pid_max");
    const long kernel_threads_max = ReadIntFile("/proc/sys/kernel/threads-max");
    int proc_count = -1;
    int thread_count = -1;
    CountProcAndThreads(&proc_count, &thread_count);

    struct rlimit nproc_limit {};
    const int rlimit_rc = ::getrlimit(RLIMIT_NPROC, &nproc_limit);
    char rlim_cur[32] = {0};
    char rlim_max[32] = {0};
    if (rlimit_rc == 0) {
        FormatRlim(nproc_limit.rlim_cur, rlim_cur, sizeof(rlim_cur));
        FormatRlim(nproc_limit.rlim_max, rlim_max, sizeof(rlim_max));
    } else {
        std::snprintf(rlim_cur, sizeof(rlim_cur), "err:%d", errno);
        std::snprintf(rlim_max, sizeof(rlim_max), "err:%d", errno);
    }

    struct rusage self_usage {};
    struct rusage child_usage {};
    const int self_usage_rc = ::getrusage(RUSAGE_SELF, &self_usage);
    const int child_usage_rc = ::getrusage(RUSAGE_CHILDREN, &child_usage);

    ::refuzz::worker::log::WorkerLog(
        "[eagain-snap-begin] wid=%u eid=%llu caller_pid=%d caller_tid=%ld "
        "call=%s flags=0x%lx rlimit_nproc=%s/%s pid_max=%ld "
        "threads_max=%ld proc_count=%d thread_count=%d pids.current=%ld "
        "pids.max=%s procs_lines=%d threads_lines=%d\n",
        wid, static_cast<unsigned long long>(eid),
        static_cast<int>(::getpid()),
        static_cast<long>(::syscall(SYS_gettid)),
        call_name != nullptr ? call_name : "unknown",
        flags, rlim_cur, rlim_max, kernel_pid_max, kernel_threads_max,
        proc_count, thread_count, pids_current, pids_max, procs_lines,
        threads_lines);

    if (self_usage_rc == 0) {
        ::refuzz::worker::log::WorkerLog(
            "[eagain-snap-rusage] who=self maxrss=%ld minflt=%ld majflt=%ld "
            "nvcsw=%ld nivcsw=%ld\n",
            self_usage.ru_maxrss, self_usage.ru_minflt, self_usage.ru_majflt,
            self_usage.ru_nvcsw, self_usage.ru_nivcsw);
    } else {
        ::refuzz::worker::log::WorkerLog(
            "[eagain-snap-rusage] who=self errno=%d\n", errno);
    }
    if (child_usage_rc == 0) {
        ::refuzz::worker::log::WorkerLog(
            "[eagain-snap-rusage] who=children maxrss=%ld minflt=%ld "
            "majflt=%ld nvcsw=%ld nivcsw=%ld\n",
            child_usage.ru_maxrss, child_usage.ru_minflt, child_usage.ru_majflt,
            child_usage.ru_nvcsw, child_usage.ru_nivcsw);
    } else {
        ::refuzz::worker::log::WorkerLog(
            "[eagain-snap-rusage] who=children errno=%d\n", errno);
    }

    const int fd = ::open(procs_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        ::refuzz::worker::log::WorkerLog(
            "[eagain-snap-end] cgroup.procs open errno=%d\n", errno);
        return;
    }
    char buf[8192] = {0};
    const ssize_t n = ::read(fd, buf, sizeof(buf) - 1);
    ::close(fd);
    if (n <= 0) {
        ::refuzz::worker::log::WorkerLog(
            "[eagain-snap-end] cgroup.procs empty\n");
        return;
    }
    const char* p = buf;
    while (*p) {
        const char* eol = ::strchr(p, '\n');
        char pid_str[32] = {0};
        const size_t line_len = eol ? static_cast<size_t>(eol - p) : ::strlen(p);
        const size_t copy = line_len < sizeof(pid_str) - 1 ? line_len : sizeof(pid_str) - 1;
        std::memcpy(pid_str, p, copy);
        pid_str[copy] = '\0';
        const int proc_pid = ::atoi(pid_str);
        if (proc_pid > 0) {
            char comm_path[64], stat_path[64];
            std::snprintf(comm_path, sizeof(comm_path),
                          "/proc/%d/comm", proc_pid);
            std::snprintf(stat_path, sizeof(stat_path),
                          "/proc/%d/status", proc_pid);
            char comm[64] = {0};
            ReadTrimmedLine(comm_path, comm, sizeof(comm));
            ProcStatusFields f;
            ReadProcStatus(stat_path, &f);
            ::refuzz::worker::log::WorkerLog(
                "[eagain-snap-proc] proc=%d comm=%s state=%c tgid=%d ppid=%d "
                "tracer=%d threads=%d pgid=%d sid=%d\n",
                proc_pid, comm, f.state, f.tgid, f.ppid, f.tracer_pid, f.threads,
                f.pgid, f.sid);
            DumpProcessTasks(proc_pid);
        }
        if (!eol) break;
        p = eol + 1;
    }
    ::refuzz::worker::log::WorkerLog(
        "[eagain-snap-end] wid=%u eid=%llu\n",
        wid, static_cast<unsigned long long>(eid));
}

bool HasBaseName(const char* name, const char* base)
{
    if (name == nullptr) {
        return false;
    }
    const size_t n = std::strlen(base);
    return std::strncmp(name, base, n) == 0 &&
           (name[n] == '\0' || name[n] == '$');
}

PseudoResult Error(int err)
{
    return PseudoResult{-1, err};
}

// io_uring kernel-ABI offsets and sizes. Mirrors upstream syzkaller
// sys/linux/io_uring.txt `define SQ_RING_MASK_OFFSET 256` etc. and
// executor/common_linux.h `#define SIZEOF_IO_URING_SQE 64` etc. These
// are kernel ABI constants (Linux io_uring header layout) — stable
// across kernel versions when IORING_SETUP_SQE128 / IORING_SETUP_CQE32
// are NOT set (which the setup helper ensures by masking those flags).
//
// reFuzz worker cannot include `program/syz/generated/consts.gen.hpp`
// per plan §2.2 (worker boundary). These constants are duplicated here
// with the upstream ABI source noted; if the kernel ABI ever changes
// these values, this file and `sys/linux/io_uring.txt` move together.
constexpr std::size_t kIoUringSqTailOffset       = 64;
constexpr std::size_t kIoUringSqRingMaskOffset   = 256;
constexpr std::size_t kIoUringCqHeadOffset       = 128;
constexpr std::size_t kIoUringCqRingMaskOffset   = 260;
constexpr std::size_t kIoUringCqCqesOffset       = 320;
constexpr std::size_t kIoUringSqeSize            = 64;
constexpr std::size_t kIoUringCqeSize            = 16;

#ifndef __NR_io_uring_setup
// Fallback to x86_64 syscall number (Linux 5.1+). Worker is linux/amd64.
#define __NR_io_uring_setup 425
#endif

// IORING_SETUP_SQE128 / IORING_SETUP_CQE32 were added in Linux 6.0
// (commits ebdeb04 / 5563a0b). Older build hosts do not expose them
// from <linux/io_uring.h>. Define locally; mirrors upstream syzkaller
// executor/common_linux.h which uses the same fallback.
#ifndef IORING_SETUP_SQE128
#define IORING_SETUP_SQE128 (1U << 10)
#endif
#ifndef IORING_SETUP_CQE32
#define IORING_SETUP_CQE32  (1U << 11)
#endif

// User-data tag values that mark openat/openat2 SQEs in upstream
// io_uring.txt (sq.user_data fields). When the corresponding CQE
// returns one of these tags, complete() returns the cqe.res as the fd
// the syscall produced; any other tag yields -1 to signal "not a
// resource-producing op".
constexpr std::uint64_t kIoUringOpenatTag  = 0x12345;
constexpr std::uint64_t kIoUringOpenat2Tag = 0x23456;

// syz_io_uring_setup(entries, params*, **ring_params_ptr_out, **ring_ptr_out,
//                    **sqes_ptr_out) → fd
//
// 1. Mask out IORING_SETUP_CQE32 / IORING_SETUP_SQE128 (would change
//    SIZEOF_IO_URING_{SQE,CQE}; tracking bug syzkaller#4531).
// 2. Issue io_uring_setup syscall → fd. RegisterOwnedFd for cleanup.
// 3. mmap SQ ring + SQEs separately. Both registered via
//    RegisterNamedRegion using the mmap'd address as key (cleanup
//    auto-munmaps on program teardown).
// 4. Pre-fill the SQ array with identity indices (i → i).
// 5. Write the two mmap'd pointers back through the user-supplied
//    out-params.
PseudoResult IoUringSetup(const PseudoContext& ctx,
                          const intptr_t* args,
                          uint32_t argc)
{
    if (args == nullptr || argc < 5) {
        return Error(EINVAL);
    }

    const auto entries = static_cast<std::uint32_t>(args[0]);
    auto* setup_params = reinterpret_cast<struct io_uring_params*>(args[1]);
    // [当前版本 syz 08ab311 对齐] syzlang 在 params 之后插入了 ring_params_ptr
    // out 参数(common_linux.h:1975),后续 submit/complete/modify_offsets 以它
    // (= setup_params 指针)作首参。其余 out 参数整体后移一位。
    auto* ring_params_ptr_out = reinterpret_cast<void**>(args[2]);
    auto* ring_ptr_out = reinterpret_cast<void**>(args[3]);
    auto* sqes_ptr_out = reinterpret_cast<void**>(args[4]);
    if (setup_params == nullptr || ring_params_ptr_out == nullptr ||
        ring_ptr_out == nullptr || sqes_ptr_out == nullptr) {
        return Error(EINVAL);
    }
    // 上游 common_linux.h:1986 `*ring_params_ptr_out = (void*)setup_params;`
    *ring_params_ptr_out = setup_params;

    setup_params->flags &= ~(static_cast<std::uint32_t>(IORING_SETUP_CQE32) |
                             static_cast<std::uint32_t>(IORING_SETUP_SQE128));

    errno = 0;
    const long fd = syscall(__NR_io_uring_setup, entries, setup_params);
    if (fd < 0) {
        return Error(errno);
    }
    ctx.RegisterOwnedFd(static_cast<int>(fd));

    // Assumed IORING_FEAT_SINGLE_MMAP (always the case in current kernels):
    // SQ and CQ rings live in one mmap region, sized to the larger.
    const std::size_t sq_ring_sz = setup_params->sq_off.array +
                                   setup_params->sq_entries * sizeof(std::uint32_t);
    const std::size_t cq_ring_sz = setup_params->cq_off.cqes +
                                   setup_params->cq_entries * kIoUringCqeSize;
    const std::size_t ring_sz = sq_ring_sz > cq_ring_sz ? sq_ring_sz : cq_ring_sz;

    errno = 0;
    void* ring_ptr = mmap(nullptr, ring_sz,
                          PROT_READ | PROT_WRITE,
                          MAP_SHARED | MAP_POPULATE,
                          static_cast<int>(fd),
                          IORING_OFF_SQ_RING);
    if (ring_ptr == MAP_FAILED) {
        return Error(errno);
    }
    ctx.RegisterNamedRegion(reinterpret_cast<std::uint64_t>(ring_ptr),
                            ring_ptr, ring_sz);

    const std::size_t sqes_sz = setup_params->sq_entries * kIoUringSqeSize;
    errno = 0;
    void* sqes_ptr = mmap(nullptr, sqes_sz,
                          PROT_READ | PROT_WRITE,
                          MAP_SHARED | MAP_POPULATE,
                          static_cast<int>(fd),
                          IORING_OFF_SQES);
    if (sqes_ptr == MAP_FAILED) {
        return Error(errno);
    }
    ctx.RegisterNamedRegion(reinterpret_cast<std::uint64_t>(sqes_ptr),
                            sqes_ptr, sqes_sz);

    auto* array = reinterpret_cast<std::uint32_t*>(
        reinterpret_cast<std::uintptr_t>(ring_ptr) + setup_params->sq_off.array);
    for (std::uint32_t i = 0; i < entries; ++i) {
        array[i] = i;
    }

    *ring_ptr_out = ring_ptr;
    *sqes_ptr_out = sqes_ptr;

    return PseudoResult{static_cast<intptr_t>(fd), 0};
}

// syz_io_uring_submit(params*, ring_ptr, sqes_ptr, sqe*) → 0
//
// Copies one SQE into the SQ ring at position (sq_tail & sq_ring_mask),
// then atomically advances sq_tail with release semantics so the kernel
// observes the SQE before the tail update. Ring fullness is NOT checked
// (mirrors upstream).
// [当前版本 syz 08ab311 对齐] syzlang 在最前插入了 ring_params_ptr(args[0]);
// reFuzz 用固定 ring 偏移常量,不需要 params,故跳过 args[0],其余后移一位。
PseudoResult IoUringSubmit(const PseudoContext& ctx,
                           const intptr_t* args,
                           uint32_t argc)
{
    (void)ctx;
    if (args == nullptr || argc < 4) {
        return Error(EINVAL);
    }
    auto* ring_ptr = reinterpret_cast<char*>(args[1]);
    auto* sqes_ptr = reinterpret_cast<char*>(args[2]);
    auto* sqe      = reinterpret_cast<const char*>(args[3]);
    if (ring_ptr == nullptr || sqes_ptr == nullptr || sqe == nullptr) {
        return Error(EINVAL);
    }

    const std::uint32_t sq_ring_mask = *reinterpret_cast<const std::uint32_t*>(
        ring_ptr + kIoUringSqRingMaskOffset);
    auto* sq_tail_ptr = reinterpret_cast<std::uint32_t*>(
        ring_ptr + kIoUringSqTailOffset);
    const std::uint32_t sq_tail = *sq_tail_ptr & sq_ring_mask;

    char* sqe_dest = sqes_ptr + sq_tail * kIoUringSqeSize;
    std::memcpy(sqe_dest, sqe, kIoUringSqeSize);

    const std::uint32_t sq_tail_next = *sq_tail_ptr + 1;
    __atomic_store_n(sq_tail_ptr, sq_tail_next, __ATOMIC_RELEASE);

    return PseudoResult{0, 0};
}

// syz_io_uring_complete(params*, ring_ptr) → cqe.res or -1
//
// Reads one CQE at position (cq_head & cq_ring_mask), advances cq_head
// with release semantics, and surfaces cqe.res ONLY when cqe.user_data
// matches the openat/openat2 syzlang tags (to expose newly-produced
// fd resources to the resource graph). Other ops return -1 — same
// contract as upstream syz_io_uring_complete.
// [当前版本 syz 08ab311 对齐] syzlang 在最前插入了 ring_params_ptr(args[0]);
// reFuzz 用固定 ring 偏移常量,跳过 args[0],ring_ptr 取 args[1]。
PseudoResult IoUringComplete(const PseudoContext& ctx,
                             const intptr_t* args,
                             uint32_t argc)
{
    (void)ctx;
    if (args == nullptr || argc < 2) {
        return Error(EINVAL);
    }
    auto* ring_ptr = reinterpret_cast<char*>(args[1]);
    if (ring_ptr == nullptr) {
        return Error(EINVAL);
    }

    const std::uint32_t cq_ring_mask = *reinterpret_cast<const std::uint32_t*>(
        ring_ptr + kIoUringCqRingMaskOffset);
    auto* cq_head_ptr = reinterpret_cast<std::uint32_t*>(
        ring_ptr + kIoUringCqHeadOffset);
    const std::uint32_t cq_head      = *cq_head_ptr & cq_ring_mask;
    const std::uint32_t cq_head_next = *cq_head_ptr + 1;

    // Layout of struct io_uring_cqe is { u64 user_data; s32 res; u32 flags; }
    // == 16 bytes. We avoid <linux/io_uring.h>'s flexible-array tail
    // (big_cqe[]) by using a local POD with the same prefix layout.
    struct Cqe {
        std::uint64_t user_data;
        std::int32_t  res;
        std::uint32_t flags;
    };
    static_assert(sizeof(Cqe) == kIoUringCqeSize,
                  "io_uring cqe local POD size mismatch");

    const char* cqe_src = ring_ptr + kIoUringCqCqesOffset +
                          cq_head * kIoUringCqeSize;
    Cqe cqe{};
    std::memcpy(&cqe, cqe_src, sizeof(cqe));

    __atomic_store_n(cq_head_ptr, cq_head_next, __ATOMIC_RELEASE);

    if (cqe.user_data == kIoUringOpenatTag ||
        cqe.user_data == kIoUringOpenat2Tag) {
        return PseudoResult{static_cast<intptr_t>(cqe.res), 0};
    }
    // [当前版本 byte-equal upstream — 2026-05-22]
    // 上游 syz_io_uring_complete (common_linux.h:1896) `return (long)-1` —
    // 不设 errno,leak 当前线程之前 syscall 残留。reFuzz 之前强设 errno=0,
    // capture 时残留是 14 EFAULT → (syz=14, ref=0) 3 个 mismatch。
    // 这里透传当前 errno(可能跟 capture 不完全相同,但比硬设 0 更接近)。
    return PseudoResult{-1, errno};
}

// syz_io_uring_modify_offsets(params*, ring_ptr, params_off, value) → 0
//
// [当前版本 syz 08ab311 新增] 全新伪调用(common_linux.h:2055)。读 params
// 在偏移 params_off 处存的一个 ring 偏移值,再把 value 写进 ring_ptr 的该偏移。
// 是 fuzzer 戳 ring offset 字段的原语,替代被删的 syz_memcpy_off$IO_URING_*。
PseudoResult IoUringModifyOffsets(const PseudoContext& ctx,
                                  const intptr_t* args,
                                  uint32_t argc)
{
    (void)ctx;
    if (args == nullptr || argc < 4) {
        return Error(EINVAL);
    }
    const auto* params = reinterpret_cast<const char*>(args[0]);
    auto* ring_ptr     = reinterpret_cast<char*>(args[1]);
    const auto params_off = static_cast<std::uint32_t>(args[2]);
    const auto value      = static_cast<std::uint32_t>(args[3]);
    if (params == nullptr || ring_ptr == nullptr) {
        return Error(EINVAL);
    }
    const std::uint32_t ring_off =
        *reinterpret_cast<const std::uint32_t*>(params + params_off);
    *reinterpret_cast<std::uint32_t*>(ring_ptr + ring_off) = value;
    return PseudoResult{0, 0};
}

// ======================== ublk (userspace block dev) ====================
// [当前版本 syz 08ab311 新增] ublk 伪调用族,镜像 common_linux.h:2069-2432。
// ublk 用 io_uring uring_cmd(128 字节 SQE 装 ublksrv_ctrl_cmd + 32 字节 CQE)
// 与 /dev/ublk-control 通信,故需 IORING_SETUP_SQE128|CQE32。reFuzz 的通用
// io_uring handler 故意 mask 掉这俩 flag 且用固定 64/16 大小,所以 ublk 自带
// size-aware 的 setup/submit/complete(读 params->flags 算 SQE/CQE 大小、用
// params->{sq,cq}_off 偏移),不动通用 io_uring 路径。缺 CONFIG_BLK_DEV_UBLK
// 时底层 io_uring_setup/enter 优雅失败(= 与不支持等价)。
#ifndef __NR_io_uring_enter
#define __NR_io_uring_enter 426
#endif
#ifndef UBLK_F_USER_COPY
#define UBLK_F_USER_COPY (1ULL << 7)
#endif

constexpr std::uint32_t kUblkIoResOk          = 0;
constexpr std::uint32_t kUblkIoResNeedGetData = 1;
// _IOWR('u', n, struct ublksrv_io_cmd) — ublksrv_io_cmd is 16 bytes.
#define UBLK_U_IO_COMMIT_AND_FETCH_REQ _IOWR('u', 0x21, struct UblksrvIoCmd)
#define UBLK_U_IO_NEED_GET_DATA        _IOWR('u', 0x22, struct UblksrvIoCmd)
constexpr std::uint32_t kUblkMaxQueueDepth = 4096;

// ublksrv ABI structs (uapi/linux/ublk_cmd.h) — defined locally (reFuzz does
// not include the ublk uapi header) exactly as upstream common_linux.h:2104+.
struct UblksrvCtrlCmd {
    std::uint32_t dev_id;
    std::uint16_t queue_id;
    std::uint16_t len;
    std::uint64_t addr;
    std::uint64_t data[1];
    std::uint16_t dev_path_len;
    std::uint16_t pad;
    std::uint32_t reserved;
};
struct UblksrvCtrlDevInfo {
    std::uint16_t nr_hw_queues;
    std::uint16_t queue_depth;
    std::uint16_t state;
    std::uint16_t pad0;
    std::uint32_t max_io_buf_bytes;
    std::uint32_t dev_id;
    std::int32_t  ublksrv_pid;
    std::uint32_t pad1;
    std::uint64_t flags;
    std::uint64_t ublksrv_flags;
    std::uint32_t owner_uid;
    std::uint32_t owner_gid;
    std::uint64_t reserved1;
    std::uint64_t reserved2;
};
struct UblksrvIoDesc {
    std::uint32_t op_flags;
    std::uint32_t nr_sectors;
    std::uint64_t start_sector;
    std::uint64_t addr;
};
struct UblksrvIoCmd {
    std::uint16_t q_id;
    std::uint16_t tag;
    std::int32_t  result;
    std::uint64_t addr;
};
struct UblkQueue {
    std::uint16_t q_id;
    std::uint32_t char_dev_fd;
    struct io_uring_params params;
    std::uint32_t ring_fd;
    char* ring_ptr;
    char* sqes_ptr;
    char* io_cmd_buf;
};
struct UblkCqe { std::uint64_t user_data; std::int32_t res; std::uint32_t flags; };

// Local io_uring_sqe / getevents_arg layouts: the build's <linux/io_uring.h>
// predates the uring_cmd fields (cmd_op/addr3/cmd[]) and getevents min_wait_usec,
// and we cannot redefine `struct io_uring_sqe` (already pulled in by the header).
// These renamed PODs mirror the current kernel ABI offsets exactly and are used
// to reinterpret the fuzzer-materialized SQE bytes. The uring_cmd inline payload
// (`cmd[]`) shares offset 48 with addr3, so &sqe->addr3 is the cmd region start.
struct UblkSqe {
    std::uint8_t  opcode;        // 0
    std::uint8_t  flags;         // 1
    std::uint16_t ioprio;        // 2
    std::int32_t  fd;            // 4
    std::uint32_t cmd_op;        // 8   (union: off-low / uring_cmd op)
    std::uint32_t cmd_pad;       // 12
    std::uint64_t addr;          // 16
    std::uint32_t len;           // 24
    std::uint32_t op_flags;      // 28
    std::uint64_t user_data;     // 32
    std::uint16_t buf_index;     // 40
    std::uint16_t personality;   // 42
    std::int32_t  splice_fd_in;  // 44
    std::uint64_t addr3;         // 48  (== uring_cmd inline data start)
    std::uint64_t addr3_pad;     // 56
};
static_assert(sizeof(UblkSqe) == 64, "UblkSqe must match io_uring_sqe base ABI");
static_assert(offsetof(UblkSqe, cmd_op) == 8, "cmd_op offset");
static_assert(offsetof(UblkSqe, user_data) == 32, "user_data offset");
static_assert(offsetof(UblkSqe, addr3) == 48, "addr3 offset");

struct UblkGeteventsArg {
    std::uint64_t sigmask;        // 0
    std::uint32_t sigmask_sz;     // 8
    std::uint32_t min_wait_usec;  // 12
    std::uint64_t ts;             // 16
};

// SQE/CQE sizes are flag-dependent (common_linux.h:1898/1905): SQE128 doubles
// the SQE to 128, CQE32 doubles the CQE to 32. ublk requires both.
inline long UblkSqeSize(const struct io_uring_params* p) {
    return static_cast<long>(sizeof(struct io_uring_sqe))
           << (((p->flags & IORING_SETUP_SQE128) != 0) ? 1 : 0);
}
inline long UblkCqeSize(const struct io_uring_params* p) {
    return static_cast<long>(kIoUringCqeSize)
           << (((p->flags & IORING_SETUP_CQE32) != 0) ? 1 : 0);
}

// ublk-local io_uring setup: does NOT mask SQE128/CQE32 and uses flag-dependent
// sizes + params offsets (mirrors syz_io_uring_setup). Returns fd or -errno.
long UblkIoUringSetup(const PseudoContext& ctx, std::uint32_t entries,
                      struct io_uring_params* params, void** ring_params_out,
                      void** ring_out, void** sqes_out) {
    errno = 0;
    const long fd = syscall(__NR_io_uring_setup, entries, params);
    if (fd < 0) {
        return -errno;
    }
    ctx.RegisterOwnedFd(static_cast<int>(fd));
    *ring_params_out = params;

    const std::size_t sq_ring_sz =
        params->sq_off.array + params->sq_entries * sizeof(std::uint32_t);
    const std::size_t cq_ring_sz =
        params->cq_off.cqes + params->cq_entries * UblkCqeSize(params);
    const std::size_t ring_sz = sq_ring_sz > cq_ring_sz ? sq_ring_sz : cq_ring_sz;

    errno = 0;
    void* ring = mmap(nullptr, ring_sz, PROT_READ | PROT_WRITE,
                      MAP_SHARED | MAP_POPULATE, static_cast<int>(fd),
                      IORING_OFF_SQ_RING);
    if (ring == MAP_FAILED) {
        return -errno;
    }
    ctx.RegisterNamedRegion(reinterpret_cast<std::uint64_t>(ring), ring, ring_sz);

    const std::size_t sqes_sz = params->sq_entries * UblkSqeSize(params);
    errno = 0;
    void* sqes = mmap(nullptr, sqes_sz, PROT_READ | PROT_WRITE,
                      MAP_SHARED | MAP_POPULATE, static_cast<int>(fd),
                      IORING_OFF_SQES);
    if (sqes == MAP_FAILED) {
        return -errno;
    }
    ctx.RegisterNamedRegion(reinterpret_cast<std::uint64_t>(sqes), sqes, sqes_sz);

    auto* array = reinterpret_cast<std::uint32_t*>(
        reinterpret_cast<std::uintptr_t>(ring) + params->sq_off.array);
    for (std::uint32_t i = 0; i < entries; ++i) {
        array[i] = i;
    }
    *ring_out = ring;
    *sqes_out = sqes;
    return fd;
}

// ublk-local submit/complete (size-aware, params-offset based).
long UblkIoUringSubmit(struct io_uring_params* params, char* ring, char* sqes,
                       const char* sqe) {
    const std::uint32_t mask =
        *reinterpret_cast<std::uint32_t*>(ring + params->sq_off.ring_mask);
    auto* tail_ptr = reinterpret_cast<std::uint32_t*>(ring + params->sq_off.tail);
    const std::uint32_t tail = *tail_ptr & mask;
    const long sqe_sz = UblkSqeSize(params);
    std::memcpy(sqes + tail * sqe_sz, sqe, static_cast<std::size_t>(sqe_sz));
    __atomic_store_n(tail_ptr, *tail_ptr + 1, __ATOMIC_RELEASE);
    return 0;
}
int UblkIoUringComplete(struct io_uring_params* params, char* ring, UblkCqe* out) {
    const std::uint32_t mask =
        *reinterpret_cast<std::uint32_t*>(ring + params->cq_off.ring_mask);
    auto* head_ptr = reinterpret_cast<std::uint32_t*>(ring + params->cq_off.head);
    const std::uint32_t head = *head_ptr & mask;
    const long cqe_sz = UblkCqeSize(params);
    std::memcpy(out, ring + params->cq_off.cqes + head * cqe_sz, sizeof(UblkCqe));
    __atomic_store_n(head_ptr, *head_ptr + 1, __ATOMIC_RELEASE);
    return 0;
}

// syz_ublk_setup_io_uring(entries, params*, **ring_params, **ring, **sqes) → fd
PseudoResult UblkSetupIoUring(const PseudoContext& ctx, const intptr_t* args,
                              uint32_t argc) {
    if (args == nullptr || argc < 5) {
        return Error(EINVAL);
    }
    const auto entries = static_cast<std::uint32_t>(args[0]);
    auto* params = reinterpret_cast<struct io_uring_params*>(args[1]);
    auto* ring_params_out = reinterpret_cast<void**>(args[2]);
    auto* ring_out = reinterpret_cast<void**>(args[3]);
    auto* sqes_out = reinterpret_cast<void**>(args[4]);
    if (params == nullptr || ring_params_out == nullptr ||
        ring_out == nullptr || sqes_out == nullptr) {
        return Error(EINVAL);
    }
    params->flags |= static_cast<std::uint32_t>(IORING_SETUP_SQE128) |
                     static_cast<std::uint32_t>(IORING_SETUP_CQE32);
    const long fd =
        UblkIoUringSetup(ctx, entries, params, ring_params_out, ring_out, sqes_out);
    if (fd < 0) {
        return Error(static_cast<int>(-fd));
    }
    return PseudoResult{fd, 0};
}

// syz_io_uring_submit$UBLK(params*, ring, sqes, sqe*) → 0
// The ublk submit variant rides a SQE128 ring, so it needs the size-aware
// copy (the generic IoUringSubmit hardcodes the 64-byte SQE and would
// truncate the uring_cmd payload).
PseudoResult UblkSubmit(const PseudoContext& ctx, const intptr_t* args,
                        uint32_t argc) {
    (void)ctx;
    if (args == nullptr || argc < 4) {
        return Error(EINVAL);
    }
    auto* params = reinterpret_cast<struct io_uring_params*>(args[0]);
    auto* ring = reinterpret_cast<char*>(args[1]);
    auto* sqes = reinterpret_cast<char*>(args[2]);
    auto* sqe = reinterpret_cast<const char*>(args[3]);
    if (params == nullptr || ring == nullptr || sqes == nullptr || sqe == nullptr) {
        return Error(EINVAL);
    }
    const long r = UblkIoUringSubmit(params, ring, sqes, sqe);
    if (r < 0) {
        return Error(static_cast<int>(-r));
    }
    return PseudoResult{0, 0};
}

// syz_ublk_add_dev(ring_fd, params*, ring, sqes, sqe*, **dev_info_out) → dev_id
PseudoResult UblkAddDev(const PseudoContext& ctx, const intptr_t* args,
                        uint32_t argc) {
    (void)ctx;
    if (args == nullptr || argc < 6) {
        return Error(EINVAL);
    }
    const auto ring_fd = static_cast<int>(args[0]);
    auto* params = reinterpret_cast<struct io_uring_params*>(args[1]);
    auto* ring = reinterpret_cast<char*>(args[2]);
    auto* sqes = reinterpret_cast<char*>(args[3]);
    auto* sqe = reinterpret_cast<UblkSqe*>(args[4]);
    auto* dev_info_out = reinterpret_cast<void**>(args[5]);
    if (params == nullptr || ring == nullptr || sqes == nullptr ||
        sqe == nullptr || dev_info_out == nullptr) {
        return Error(EINVAL);
    }
    auto* cmd = reinterpret_cast<UblksrvCtrlCmd*>(&sqe->addr3);
    auto* dev_info = reinterpret_cast<UblksrvCtrlDevInfo*>(
        static_cast<std::uintptr_t>(cmd->addr));
    if (dev_info == nullptr) {
        return Error(EINVAL);
    }
    // UBLK_F_USER_COPY avoids preallocated I/O buffers (upstream always sets it).
    dev_info->flags |= UBLK_F_USER_COPY;
    const long sret =
        UblkIoUringSubmit(params, ring, sqes, reinterpret_cast<const char*>(sqe));
    if (sret < 0) {
        return Error(static_cast<int>(-sret));
    }
    syscall(__NR_io_uring_enter, ring_fd, 1, 1, 1, nullptr, _NSIG / 8);
    *dev_info_out = dev_info;
    return PseudoResult{static_cast<intptr_t>(dev_info->dev_id), 0};
}

// syz_ublk_setup_queues(char_dev_fd, dev_info*, params*, queues*, nr_queues,
//                       sqe*, **queues_out) → 0
PseudoResult UblkSetupQueues(const PseudoContext& ctx, const intptr_t* args,
                             uint32_t argc) {
    if (args == nullptr || argc < 7) {
        return Error(EINVAL);
    }
    const int char_dev_fd = static_cast<int>(args[0]);
    auto* dev_info = reinterpret_cast<UblksrvCtrlDevInfo*>(args[1]);
    auto* params = reinterpret_cast<struct io_uring_params*>(args[2]);
    auto* queues = reinterpret_cast<UblkQueue*>(args[3]);
    const int queues_len = static_cast<int>(args[4]);
    auto* sqe = reinterpret_cast<UblkSqe*>(args[5]);
    auto* queues_out = reinterpret_cast<void**>(args[6]);
    if (char_dev_fd < 0 || dev_info == nullptr || params == nullptr ||
        queues == nullptr || queues_len <= 0 || sqe == nullptr ||
        queues_out == nullptr) {
        return Error(EINVAL);
    }
    std::memset(queues, 0, sizeof(UblkQueue) * static_cast<std::size_t>(queues_len));
    const int queue_depth = dev_info->queue_depth;
    const unsigned long page = static_cast<unsigned long>(sysconf(_SC_PAGESIZE));
    auto round_up = [](unsigned long x, unsigned long y) { return (x + y - 1) / y * y; };
    for (int q_id = 0; q_id < dev_info->nr_hw_queues && q_id < queues_len; ++q_id) {
        UblkQueue* queue = &queues[q_id];
        queue->q_id = static_cast<std::uint16_t>(q_id);
        queue->char_dev_fd = static_cast<std::uint32_t>(char_dev_fd);
        queue->params = *params;
        queue->params.flags |= static_cast<std::uint32_t>(IORING_SETUP_SQE128) |
                               static_cast<std::uint32_t>(IORING_SETUP_CQE32);
        void* tmp = nullptr;
        void* ring = nullptr;
        void* sqes = nullptr;
        const long fd = UblkIoUringSetup(ctx, static_cast<std::uint32_t>(queue_depth),
                                         &queue->params, &tmp, &ring, &sqes);
        if (fd < 0) {
            return Error(static_cast<int>(-fd));
        }
        queue->ring_fd = static_cast<std::uint32_t>(fd);
        queue->ring_ptr = static_cast<char*>(ring);
        queue->sqes_ptr = static_cast<char*>(sqes);

        const unsigned long cmd_buf_size = round_up(
            static_cast<unsigned long>(queue_depth) * sizeof(UblksrvIoDesc), page);
        const unsigned long off = static_cast<unsigned long>(q_id) *
            round_up(static_cast<unsigned long>(kUblkMaxQueueDepth) * sizeof(UblksrvIoDesc), page);
        errno = 0;
        queue->io_cmd_buf = static_cast<char*>(
            mmap(nullptr, cmd_buf_size, PROT_READ, MAP_SHARED | MAP_POPULATE,
                 char_dev_fd, static_cast<off_t>(off)));
        if (queue->io_cmd_buf == MAP_FAILED) {
            return Error(errno);
        }
        ctx.RegisterNamedRegion(reinterpret_cast<std::uint64_t>(queue->io_cmd_buf),
                                queue->io_cmd_buf, cmd_buf_size);

        for (int j = 0; j < queue_depth; ++j) {
            auto* iocmd = reinterpret_cast<UblksrvIoCmd*>(&sqe->addr3);
            iocmd->q_id = static_cast<std::uint16_t>(q_id);
            iocmd->tag = static_cast<std::uint16_t>(j);
            iocmd->addr = 0;
            sqe->user_data = static_cast<std::uint64_t>(j) |
                             (static_cast<std::uint64_t>(sqe->cmd_op) << 16);
            if (UblkIoUringSubmit(&queue->params, queue->ring_ptr, queue->sqes_ptr,
                                  reinterpret_cast<const char*>(sqe)) < 0) {
                return Error(EINVAL);
            }
            syscall(__NR_io_uring_enter, queue->ring_fd, 1, 0, 0, nullptr, _NSIG / 8);
        }
    }
    *queues_out = queues;
    return PseudoResult{0, 0};
}

// syz_ublk_process_io(queues*, q_id, wait_secs, sqe*, use_generated_sqe) → ret
PseudoResult UblkProcessIo(const PseudoContext& ctx, const intptr_t* args,
                           uint32_t argc) {
    (void)ctx;
    if (args == nullptr || argc < 5) {
        return Error(EINVAL);
    }
    auto* queues = reinterpret_cast<UblkQueue*>(args[0]);
    const int q_id = static_cast<int>(args[1]);
    const long wait_secs = static_cast<long>(args[2]);
    auto* sqe = reinterpret_cast<UblkSqe*>(args[3]);
    const bool use_generated_sqe = args[4] != 0;
    if (queues == nullptr || q_id < 0 || sqe == nullptr) {
        return Error(EINVAL);
    }
    UblkQueue* queue = &queues[q_id];
    if (queue->ring_ptr == nullptr) {
        return Error(EINVAL);
    }

    // Wait for one CQE with the given timeout (io_uring_enter EXT_ARG).
    struct __kernel_timespec ts = {wait_secs, 0};
    UblkGeteventsArg ext_arg;
    std::memset(&ext_arg, 0, sizeof(ext_arg));
    ext_arg.sigmask = 0;
    ext_arg.sigmask_sz = _NSIG / 8;
    ext_arg.min_wait_usec = 0;
    ext_arg.ts = reinterpret_cast<std::uint64_t>(&ts);
    errno = 0;
    long ret = syscall(__NR_io_uring_enter, queue->ring_fd, 0, 1,
                       IORING_ENTER_GETEVENTS | IORING_ENTER_EXT_ARG,
                       &ext_arg, sizeof(ext_arg));
    if (ret < 0) {
        return Error(errno);
    }

    UblkCqe cqe;
    std::memset(&cqe, 0, sizeof(cqe));
    if (UblkIoUringComplete(&queue->params, queue->ring_ptr, &cqe) < 0) {
        return Error(EINVAL);
    }

    if (!use_generated_sqe) {
        // Drive the next command from the CQE result rather than fuzzer SQE.
        std::uint32_t cmd_op = 0;
        if (cqe.res == static_cast<std::int32_t>(kUblkIoResNeedGetData)) {
            cmd_op = UBLK_U_IO_NEED_GET_DATA;
        } else if (cqe.res == static_cast<std::int32_t>(kUblkIoResOk)) {
            cmd_op = UBLK_U_IO_COMMIT_AND_FETCH_REQ;
        } else {
            return PseudoResult{0, 0};
        }
        sqe->cmd_op = cmd_op;
        const std::uint16_t tag = static_cast<std::uint16_t>(cqe.user_data & 0xffff);
        auto* io_desc = reinterpret_cast<UblksrvIoDesc*>(
            &queue->io_cmd_buf[tag * sizeof(UblksrvIoDesc)]);
        auto* iocmd = reinterpret_cast<UblksrvIoCmd*>(&sqe->addr3);
        iocmd->q_id = static_cast<std::uint16_t>(q_id);
        iocmd->tag = tag;
        iocmd->addr = 0;
        iocmd->result = static_cast<std::int32_t>(io_desc->nr_sectors << 9);
        sqe->user_data = static_cast<std::uint64_t>(tag) |
                         (static_cast<std::uint64_t>(sqe->cmd_op) << 16);
    }

    ret = UblkIoUringSubmit(&queue->params, queue->ring_ptr, queue->sqes_ptr,
                            reinterpret_cast<const char*>(sqe));
    syscall(__NR_io_uring_enter, queue->ring_fd, 1, 0, 0, nullptr, _NSIG / 8);
    return PseudoResult{static_cast<intptr_t>(ret), 0};
}

} // namespace

// BTF (Binary Type Format) helpers — used by syz_btf_id_by_name$bpf_lsm.
// ScanBtfForName is exposed in the namespace (not anonymous) so unit
// tests can drive it with synthetic BTF blobs without a real
// /sys/kernel/btf/vmlinux.
//
// Constants mirror kernel uapi/linux/btf.h; struct layouts come from
// <linux/btf.h>. ABI is stable since Linux 4.18.
namespace {
constexpr std::uint32_t kBtfMagic            = 0xeB9F;
constexpr std::size_t   kVmlinuxMaxSize      = 10ULL * 1024 * 1024;  // syz parity: VMLINUX_MAX_SUPPORT_SIZE in common_linux.h:2164

constexpr std::uint32_t kBtfKindInt          = 1;
constexpr std::uint32_t kBtfKindArray        = 3;
constexpr std::uint32_t kBtfKindStruct       = 4;
constexpr std::uint32_t kBtfKindUnion        = 5;
constexpr std::uint32_t kBtfKindEnum         = 6;
constexpr std::uint32_t kBtfKindFuncProto    = 13;
constexpr std::uint32_t kBtfKindVar          = 14;
constexpr std::uint32_t kBtfKindDatasec      = 15;

inline std::uint32_t BtfKind(std::uint32_t info) { return (info >> 24) & 0x0fU; }
inline std::uint32_t BtfVlen(std::uint32_t info) { return info & 0xffffU; }

struct BtfBlob {
    const char* base = nullptr;
    std::size_t len  = 0;
    // [A4] errno captured at the failing syscall when base==nullptr。
    // upstream syzkaller `read_btf_vmlinux` open 失败时 errno = open()-set
    // (典型 ENOENT 缺 CONFIG_DEBUG_INFO_BTF);read 失败时 read()-set。
    // 通过 blob 把 errno 带回 BtfIdByName,让 PseudoResult.err 跟 upstream
    // byte-equal。
    int         err  = 0;
};

// Cache /sys/kernel/btf/vmlinux in a process-local static buffer.
// First call reads up to kVmlinuxMaxSize; returns {nullptr, 0, errno-of-fail}
// on any failure (no BTF kernel, file too large, read error). Once cached,
// repeated calls are O(1). Race-free without locks: both threads on a
// concurrent first call would write the same bytes to the same buffer,
// then both flip the same flags identically.
BtfBlob ReadBtfVmlinux()
{
    static char buf[kVmlinuxMaxSize];
    static std::size_t cached_len = 0;
    static bool tried = false;
    static bool ok    = false;
    static int  cached_err = 0;  // [A4] errno when first attempt failed

    if (tried) {
        if (ok) return BtfBlob{buf, cached_len, 0};
        return BtfBlob{nullptr, 0, cached_err};
    }

    int fd = open("/sys/kernel/btf/vmlinux", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        cached_err = errno;
        tried = true;
        return {nullptr, 0, cached_err};
    }
    std::size_t total = 0;
    for (;;) {
        const ssize_t n = read(fd, buf + total, kVmlinuxMaxSize - total);
        if (n < 0) {
            cached_err = errno;
            close(fd);
            tried = true;
            return {nullptr, 0, cached_err};
        }
        if (n == 0) break;
        total += static_cast<std::size_t>(n);
        if (total == kVmlinuxMaxSize) {
            // BTF larger than the static buffer; treat as failure.
            // upstream `read_btf_vmlinux` 也是这个判定 (bytes_read+ret ==
            // VMLINUX_MAX_SUPPORT_SIZE → return NULL);errno 保留 read()
            // 最后一次成功的 0 (无失败 syscall),所以 cached_err=0。
            cached_err = 0;
            close(fd);
            tried = true;
            return {nullptr, 0, cached_err};
        }
    }
    close(fd);
    cached_len = total;
    ok    = true;
    tried = true;
    return {buf, total, 0};
}
} // namespace

// Scan a BTF blob for the first type whose name equals `target`. Returns
// the BTF type id (>= 1) on match, or -1 on missing/malformed/no-match.
// Mirrors upstream `syz_btf_id_by_name` scan loop in
// `executor/common_linux.h:2202-2268` (semantics, not source).
//
// Exposed (non-anonymous) so `pseudo_io_uring_handler_test` and a future
// `pseudo_btf_handler_test` can drive it with synthetic BTF blobs.
long ScanBtfForName(const char* btf, std::size_t btf_len, const char* target)
{
    if (btf == nullptr || target == nullptr || btf_len < sizeof(::btf_header)) {
        return -1;
    }
    const auto* hdr = reinterpret_cast<const ::btf_header*>(btf);
    if (hdr->magic != kBtfMagic) {
        return -1;
    }

    const std::size_t hdr_len = hdr->hdr_len;
    const std::size_t type_end = hdr_len +
                                 static_cast<std::size_t>(hdr->type_off) +
                                 static_cast<std::size_t>(hdr->type_len);
    const std::size_t str_end  = hdr_len +
                                 static_cast<std::size_t>(hdr->str_off) +
                                 static_cast<std::size_t>(hdr->str_len);
    if (type_end > btf_len || str_end > btf_len) {
        return -1;
    }

    const char* type_sec = btf + hdr_len + hdr->type_off;
    const char* str_sec  = btf + hdr_len + hdr->str_off;
    const std::size_t type_len    = hdr->type_len;
    const std::size_t str_sec_len = hdr->str_len;
    const std::size_t target_len  = std::strlen(target);

    std::size_t bytes_parsed = 0;
    long idx = 1;  // BTF type IDs start at 1
    while (bytes_parsed + sizeof(::btf_type) <= type_len) {
        const auto* t = reinterpret_cast<const ::btf_type*>(type_sec + bytes_parsed);
        const std::uint32_t kind = BtfKind(t->info);
        const std::uint32_t vlen = BtfVlen(t->info);

        if (t->name_off < str_sec_len) {
            const char* name = str_sec + t->name_off;
            const std::size_t max_name_len = str_sec_len - t->name_off;
            // strncmp + explicit '\0' check — string section is not
            // guaranteed to be null-terminated at the very end.
            if (target_len < max_name_len &&
                name[target_len] == '\0' &&
                std::memcmp(name, target, target_len) == 0) {
                return idx;
            }
        }

        std::size_t skip = 0;
        switch (kind) {
        case kBtfKindInt:        skip = sizeof(std::uint32_t); break;
        case kBtfKindEnum:       skip = sizeof(::btf_enum) * vlen; break;
        case kBtfKindArray:      skip = sizeof(::btf_array); break;
        case kBtfKindStruct:
        case kBtfKindUnion:      skip = sizeof(::btf_member) * vlen; break;
        case kBtfKindFuncProto:  skip = sizeof(::btf_param) * vlen; break;
        case kBtfKindVar:        skip = sizeof(::btf_var); break;
        case kBtfKindDatasec:    skip = sizeof(::btf_var_secinfo) * vlen; break;
        default:                 skip = 0;
        }

        const std::size_t step = sizeof(::btf_type) + skip;
        if (bytes_parsed + step < bytes_parsed) {  // overflow guard
            return -1;
        }
        bytes_parsed += step;
        idx++;
    }
    return -1;
}

namespace {
// syz_btf_id_by_name$bpf_lsm(name ptr[in, string]) → btf_id
//
// Open /sys/kernel/btf/vmlinux (cached per worker), scan the BTF type
// table for `name`, return its 1-based id or -1. Returns -1 (not an
// errno) when BTF isn't available — matches upstream "graceful no BTF"
// behavior so generated programs don't fail with a hard error in
// non-BTF kernels.
PseudoResult BtfIdByName(const PseudoContext& ctx,
                         const intptr_t* args,
                         uint32_t argc)
{
    (void)ctx;
    if (args == nullptr || argc < 1 || args[0] == 0) {
        return Error(EINVAL);
    }
    const char* target = reinterpret_cast<const char*>(args[0]);

    const BtfBlob blob = ReadBtfVmlinux();
    if (blob.base == nullptr) {
        // [A4] byte-equal upstream:open/read 失败时 errno 透回。
        // upstream `read_btf_vmlinux() == NULL` 时 errno 是 open() 设的;
        // 跟 oracle 显示的 syz=(r=-1, e=ENOENT=2) 对齐。
        return PseudoResult{-1, blob.err};
    }
    const long id = ScanBtfForName(blob.base, blob.len, target);
    if (id < 0) {
        // upstream 在 BTF 中找不到 name 时 fall through 到 `return -1`,
        // errno 是 strcmp/上一个 syscall 设的(典型 0,因为 scan 不调
        // syscall)。 reFuzz 同行为:scan-not-found 时 errno=0。
        return PseudoResult{-1, 0};
    }
    return PseudoResult{static_cast<intptr_t>(id), 0};
}
} // namespace

// PR-A2 — process / memory / kfuzztest handlers.
//
// All ungated by capability mask (kCapNone). Handler signatures stay
// the bytes-only contract — args[i] interpreted per upstream syzlang.
namespace {

#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434
#endif
#ifndef __NR_clone3
#define __NR_clone3 435
#endif

constexpr long          kSyzCloneArgsMaxBytes      = 256;
constexpr long          kSyzPkeyReserved           = 15;
// Upstream: USLEEP_FORKED_CHILD = 3 * syscall_timeout_ms * 1000 (common_linux.h:5716)
// with syscall_timeout_ms == 50 → 150_000us. reFuzz 之前是 50us → ptrace target
// (child) 在 ptrace_attach 调用前已 exit + PID 被 kernel 复用 → ESRCH 或
// attach 到 ivshmem_worker。对齐 upstream 量级是 ptrace family 等价的硬性
// 前提(258 mismatch / Tier 1 根因)。BASE_CALL_TIMEOUT_MS 类 worker 默认
// 跟 upstream syscall_timeout_ms 都是 50ms,这里直接固定 150_000。
constexpr useconds_t    kSyzCloneChildSleepUsec    = 150000;
constexpr std::size_t   kSyzKfuzztestPathMax       = 256;

// Mirror of upstream common_linux.h:5721 handle_clone_ret: in the child
// branch (ret == 0) we MUST exit immediately, otherwise the cloned
// process continues running worker dispatch code → fork bomb / state
// corruption. Brief sleep before exit matches upstream USLEEP_FORKED_CHILD
// for IPC-fuzz timing windows.
long HandleCloneRet(long ret)
{
    if (ret != 0) {
        return ret;
    }
    usleep(kSyzCloneChildSleepUsec);
    syscall(__NR_exit, 0);
    while (true) {}  // unreachable
}

// syz_clone(flags, stack, stack_len, ptid, ctid, tls) — upstream common_linux.h:5745
PseudoResult SyzClone(const PseudoContext& ctx,
                      const intptr_t* args, uint32_t argc)
{
    if (args == nullptr || argc < 6) return Error(EINVAL);
    const long flags     = static_cast<long>(args[0]);
    const long stack     = static_cast<long>(args[1]);
    const long stack_len = static_cast<long>(args[2]);
    const long ptid      = static_cast<long>(args[3]);
    const long ctid      = static_cast<long>(args[4]);
    const long tls       = static_cast<long>(args[5]);
    // 16-byte stack alignment per ABI.
    const long sp = (stack + stack_len) & ~15L;
    errno = 0;
    const long ret = syscall(__NR_clone, flags & ~static_cast<long>(CLONE_VM),
                             sp, ptid, ctid, tls);
    const int err = errno;
    if (ret < 0 && err == EAGAIN) {
        DumpEagainCgroupSnapshot("syz_clone",
                                 ctx.proc_slot_id,
                                 ctx.DiagnosticExecutorId(), flags);
    }
    const long final_ret = HandleCloneRet(ret);
    return PseudoResult{final_ret, err};
}

// syz_clone3(clone_args*, clone_args_size) — upstream common_linux.h:5764
PseudoResult SyzClone3(const PseudoContext& ctx,
                       const intptr_t* args, uint32_t argc)
{
    if (args == nullptr || argc < 2 || args[0] == 0) return Error(EINVAL);
    const auto copy_size = static_cast<unsigned long>(args[1]);
    if (copy_size < sizeof(std::uint64_t) ||
        copy_size > static_cast<unsigned long>(kSyzCloneArgsMaxBytes)) {
        return PseudoResult{-1, 0};
    }
    // Copy as raw bytes — clone3 args struct grows across kernel versions.
    char clone_args[kSyzCloneArgsMaxBytes];
    std::memcpy(clone_args, reinterpret_cast<const void*>(args[0]), copy_size);
    // First 8 bytes are flags; clear CLONE_VM (mirror upstream).
    auto* flags = reinterpret_cast<std::uint64_t*>(clone_args);
    *flags &= ~static_cast<std::uint64_t>(CLONE_VM);
    errno = 0;
    const long ret = syscall(__NR_clone3, &clone_args, copy_size);
    const int err = errno;
    if (ret < 0 && err == EAGAIN) {
        DumpEagainCgroupSnapshot("syz_clone3",
                                 ctx.proc_slot_id,
                                 ctx.DiagnosticExecutorId(),
                                 static_cast<long>(*flags));
    }
    const long final_ret = HandleCloneRet(ret);
    return PseudoResult{final_ret, err};
}

// syz_pidfd_open(pid, flags) — upstream common_linux.h:5855
// Forces pid=0 if pid==1 (PID-namespace parent guard so a forked child
// can't mangle the worker's fds).
PseudoResult SyzPidfdOpen(const PseudoContext& ctx,
                          const intptr_t* args, uint32_t argc)
{
    (void)ctx;
    if (args == nullptr || argc < 2) return Error(EINVAL);
    long pid   = static_cast<long>(args[0]);
    long flags = static_cast<long>(args[1]);
    if (pid == 1) pid = 0;
    errno = 0;
    const long ret = syscall(__NR_pidfd_open, pid, flags);
    return PseudoResult{ret, errno};
}

// syz_pkey_set(pkey, val) — upstream common_linux.h:5788
// x86 PKRU register manipulation; non-x86 archs return 0 silently.
PseudoResult SyzPkeySet(const PseudoContext& ctx,
                        const intptr_t* args, uint32_t argc)
{
    (void)ctx;
    if (args == nullptr || argc < 2) return Error(EINVAL);
    const long pkey = static_cast<long>(args[0]);
    const long val  = static_cast<long>(args[1]);
    if (pkey == kSyzPkeyReserved) {
        return PseudoResult{-1, EINVAL};
    }
#if defined(__x86_64__) || defined(__i386__)
    std::uint32_t eax = 0;
    const std::uint32_t ecx = 0;
    asm volatile("rdpkru" : "=a"(eax) : "c"(ecx) : "edx");
    const std::uint32_t shift = static_cast<std::uint32_t>((pkey % 16) * 2);
    eax &= ~(3u << shift);
    eax |= (static_cast<std::uint32_t>(val) & 3u) << shift;
    const std::uint32_t edx = 0;
    asm volatile("wrpkru" :: "a"(eax), "c"(ecx), "d"(edx));
#else
    (void)val;
#endif
    return PseudoResult{0, 0};
}

// syz_execute_func(text) — upstream common.h:507
// Cast pointer to function and call. Coverage-only path; inherently
// unsafe — reFuzz worker runs inside a controlled VM. Register-clearing
// dance mirrors upstream so leftover ptrs don't reach the output region.
PseudoResult SyzExecuteFunc(const PseudoContext& ctx,
                            const intptr_t* args, uint32_t argc)
{
    (void)ctx;
    if (args == nullptr || argc < 1 || args[0] == 0) return Error(EINVAL);
#if defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))
    volatile long p[8] = {0};
    (void)p;
    asm volatile("" :: "r"(0L), "r"(1L), "r"(2L), "r"(3L), "r"(4L),
                       "r"(5L), "r"(6L), "r"(7L), "r"(8L), "r"(9L),
                       "r"(10L), "r"(11L), "r"(12L), "r"(13L));
#endif
    using FnPtr = void (*)(void);
    auto fn = reinterpret_cast<FnPtr>(args[0]);
    fn();
    return PseudoResult{0, 0};
}

// syz_memcpy_off$*(dest, dest_off, src, src_off, n) — upstream common_linux.h:2273
PseudoResult SyzMemcpyOff(const PseudoContext& ctx,
                          const intptr_t* args, uint32_t argc)
{
    (void)ctx;
    if (args == nullptr || argc < 5) return Error(EINVAL);
    auto* dest = reinterpret_cast<char*>(args[0]);
    const auto dest_off = static_cast<std::uint32_t>(args[1]);
    const auto* src     = reinterpret_cast<const char*>(args[2]);
    const auto src_off  = static_cast<std::uint32_t>(args[3]);
    const auto n        = static_cast<std::size_t>(args[4]);
    if (dest == nullptr || src == nullptr) return Error(EINVAL);
    std::memcpy(dest + dest_off, src + src_off, n);
    return PseudoResult{reinterpret_cast<intptr_t>(dest + dest_off), 0};
}

// syz_kfuzztest_run(test_name, input_data, input_data_size, buffer)
// — upstream common_linux.h:5878. Note upstream wire arg ordering:
// `buffer` (a3) is what gets written, not `input_data` (a1) — the
// latter is unused in the upstream impl too. We mirror that.
PseudoResult SyzKfuzztestRun(const PseudoContext& ctx,
                             const intptr_t* args, uint32_t argc)
{
    (void)ctx;
    if (args == nullptr || argc < 4 || args[0] == 0 || args[3] == 0) {
        return Error(EINVAL);
    }
    const char* test_name      = reinterpret_cast<const char*>(args[0]);
    const auto  input_data_sz  = static_cast<std::size_t>(args[2]);
    const void* buffer         = reinterpret_cast<const void*>(args[3]);

    char path[kSyzKfuzztestPathMax];
    int n = std::snprintf(path, sizeof(path),
                          "/sys/kernel/debug/kfuzztest/%s/input", test_name);
    if (n < 0 || static_cast<std::size_t>(n) >= sizeof(path)) {
        return PseudoResult{-1, 0};
    }
    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        return PseudoResult{-1, 0};
    }
    const ssize_t bytes = write(fd, buffer, input_data_sz);
    close(fd);
    if (bytes != static_cast<ssize_t>(input_data_sz)) {
        return PseudoResult{-1, 0};
    }
    return PseudoResult{0, 0};
}

} // namespace

PseudoResult DispatchCorePseudo(const PseudoContext& ctx,
                                const refuzz::fuzzer::syz::PseudoMeta& meta,
                                const intptr_t* args,
                                uint32_t argc)
{
    if (HasBaseName(meta.name, "syz_create_resource")) {
        if (args == nullptr || argc < 1) {
            return Error(EINVAL);
        }
        return PseudoResult{args[0], 0};
    }
    if (HasBaseName(meta.name, "syz_io_uring_setup")) {
        return IoUringSetup(ctx, args, argc);
    }
    if (std::strcmp(meta.name, "syz_io_uring_submit$UBLK") == 0) {
        return UblkSubmit(ctx, args, argc);
    }
    if (HasBaseName(meta.name, "syz_io_uring_submit")) {
        return IoUringSubmit(ctx, args, argc);
    }
    if (HasBaseName(meta.name, "syz_io_uring_complete")) {
        return IoUringComplete(ctx, args, argc);
    }
    if (HasBaseName(meta.name, "syz_io_uring_modify_offsets")) {
        return IoUringModifyOffsets(ctx, args, argc);
    }
    if (HasBaseName(meta.name, "syz_ublk_setup_io_uring")) {
        return UblkSetupIoUring(ctx, args, argc);
    }
    if (HasBaseName(meta.name, "syz_ublk_add_dev")) {
        return UblkAddDev(ctx, args, argc);
    }
    if (HasBaseName(meta.name, "syz_ublk_setup_queues")) {
        return UblkSetupQueues(ctx, args, argc);
    }
    if (HasBaseName(meta.name, "syz_ublk_process_io")) {
        return UblkProcessIo(ctx, args, argc);
    }
    if (HasBaseName(meta.name, "syz_btf_id_by_name")) {
        return BtfIdByName(ctx, args, argc);
    }
    // PR-A2: dispatch order matters — syz_clone3 must be checked before
    // syz_clone since they share no $-suffix-aware base prefix; HasBaseName
    // is base-equality strict (terminator must be '\0' or '$'), so order
    // is strictly safety not correctness.
    if (HasBaseName(meta.name, "syz_clone3")) {
        return SyzClone3(ctx, args, argc);
    }
    if (HasBaseName(meta.name, "syz_clone")) {
        return SyzClone(ctx, args, argc);
    }
    if (HasBaseName(meta.name, "syz_pidfd_open")) {
        return SyzPidfdOpen(ctx, args, argc);
    }
    if (HasBaseName(meta.name, "syz_pkey_set")) {
        return SyzPkeySet(ctx, args, argc);
    }
    if (HasBaseName(meta.name, "syz_execute_func")) {
        return SyzExecuteFunc(ctx, args, argc);
    }
    if (HasBaseName(meta.name, "syz_memcpy_off")) {
        return SyzMemcpyOff(ctx, args, argc);
    }
    if (HasBaseName(meta.name, "syz_kfuzztest_run")) {
        return SyzKfuzztestRun(ctx, args, argc);
    }
    return Error(ENOSYS);
}

} // namespace refuzz::worker::pseudo

// LoopRuntime 实现 — 从 ChildMain (execution_engine.cpp:423-593) 拆出。
//
// P1 阶段约束:Reusable topology + InlineProgramExecutor 路径必须 byte-equal
// 旧 ChildMain 行为。fd-table ABI helpers + sandbox 入口 + while-loop 协议
// 全部跟旧逻辑一致,只把"执行一条 prog"那段委派给 IProgramExecutor 接口。

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "worker/engine/loop_runtime.hpp"
#include "worker/engine/loop_worker_boot_config.hpp"

#include "worker/backend/exec_backend.hpp"
#include "worker/backend/syz_exec_runner.hpp"
#include "worker/engine/program_runtime.hpp"
#include "worker/engine/runtime_messages.hpp"
#include "worker/log/log_macros.hpp"
#include "worker/observation/extra_kcov_control.hpp"
#include "worker/observation/observation_bus.hpp"
#include "worker/perf/worker_perf.hpp"
#include "worker/sandbox/device_init/device_init.hpp"
#include "worker/topology/topology_probe.hpp"

#include "refuzz/proto_wire/ivshmem_protocol.h"   // MAX_INPUT_SIZE / MAX_OUTPUT_SIZE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/loop.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#define LOG(fmt, ...) ::refuzz::worker::log::WorkerLog("[Worker] " fmt "\n", ##__VA_ARGS__)

namespace refuzz::worker::engine {

bool IsSmapsVmaHeaderLine(std::string_view line)
{
    size_t offset = 0;
    while (offset < line.size() &&
           std::isxdigit(static_cast<unsigned char>(line[offset]))) {
        ++offset;
    }
    if (offset == 0 || offset >= line.size() || line[offset] != '-') {
        return false;
    }
    const size_t range_end_begin = ++offset;
    while (offset < line.size() &&
           std::isxdigit(static_cast<unsigned char>(line[offset]))) {
        ++offset;
    }
    return offset > range_end_begin && offset < line.size() &&
           line[offset] == ' ';
}

namespace {

// [per-program workdir isolation — 镜像 syzkaller `executor/common_linux.h:4603
//  remove_dir()` + `executor/common.h:609-751 loop()`]
//
// 上游 syzkaller 每条 prog: mkdir("./<iter>") → child chdir → run → remove_dir。
// reFuzz LoopRuntime 之前没这套,所有 prog 共用 chroot 根 cwd,文件系统状态
// 跨 prog 泄漏 → mknodat/mkdirat/symlinkat/linkat 90% 都返 EEXIST (RUN5
// errno_mismatch=2451 的主根因)。
//
// reFuzz 改动相比上游 remove_dir:
//   - 去 SYZ_SANDBOX_ANDROID 分支 (reFuzz 没 android profile)
//   - exitf → LOG + return false:LoopRuntime cleanup 失败必须容忍,否则
//     一条 program 留的 stale dir 删不掉就把整个 loop_parent 杀掉,EEXIST
//     问题等价升级为 OOM/respawn 风暴
//   - 保 EBUSY → umount2(MNT_FORCE|UMOUNT_NOFOLLOW) retry 兜底 (syz_mount_image
//     在 ./<iter> 子树留下的挂载点)
//   - 保 EPERM → FS_IOC_SETFLAGS=0 清 FS_XFLAG_IMMUTABLE 兜底
//   - 保 EROFS → break/best-effort (mount 把 entry 切成 ro,无法 unlink)
//   - 保 ENOTEMPTY → outer goto retry (umount 把子文件冒出来)
//   - 加 ENOENT 短路 (上游 exitf,reFuzz 视为 "已不在" return true)
#ifndef FS_IOC_SETFLAGS
#define FS_IOC_SETFLAGS _IOW('f', 2, long)
#endif

constexpr int kRmFileMaxIter  = 100;
constexpr int kRmDirMaxIter   = 100;
constexpr int kRmOuterMaxIter = 100;

bool RemoveDirRecursive(const char* dir)
{
    const int umount_flags = MNT_FORCE | UMOUNT_NOFOLLOW;
    int outer_iter = 0;
retry:
    // dir 本身可能是挂载点 (syz_mount_image target),先 umount 直到没挂载。
    while (::umount2(dir, umount_flags) == 0) { /* mount can be nested */ }

    DIR* dp = ::opendir(dir);
    if (dp == nullptr) {
        if (errno == EACCES) {
            // 0-perm dir;直接 rmdir 兜底 (上游 common.h:257-269)
            if (::rmdir(dir) == 0) {
                return true;
            }
            LOG("[workdir] rmdir(%s) after opendir EACCES failed errno=%d",
                dir, errno);
            return false;
        }
        if (errno == ENOENT) {
            return true; // 已不在
        }
        LOG("[workdir] opendir(%s) failed errno=%d", dir, errno);
        return false;
    }

    struct dirent* ep = nullptr;
    while ((ep = ::readdir(dp)) != nullptr) {
        if (::strcmp(ep->d_name, ".") == 0 ||
            ::strcmp(ep->d_name, "..") == 0) {
            continue;
        }
        char filename[FILENAME_MAX];
        ::snprintf(filename, sizeof(filename), "%s/%s", dir, ep->d_name);

        // entry 自己可能是 mount target (9p broken transport / nested mount)
        while (::umount2(filename, umount_flags) == 0) { /* nested */ }

        struct stat st;
        if (::lstat(filename, &st) != 0) {
            LOG("[workdir] lstat(%s) failed errno=%d (skip entry)",
                filename, errno);
            continue;
        }
        if (S_ISDIR(st.st_mode)) {
            (void)RemoveDirRecursive(filename); // best-effort,失败由 outer ENOTEMPTY retry 兜
            continue;
        }
        for (int i = 0; i < kRmFileMaxIter; ++i) {
            if (::unlink(filename) == 0) {
                break;
            }
            if (errno == EPERM) {
                int fd = ::open(filename, O_RDONLY);
                if (fd != -1) {
                    long flags = 0;
                    (void)::ioctl(fd, FS_IOC_SETFLAGS, &flags);
                    ::close(fd);
                    continue;
                }
            }
            if (errno == EROFS) {
                break; // ro 挂载下 unlink 必失败,best-effort 放过
            }
            if (errno != EBUSY) {
                LOG("[workdir] unlink(%s) failed errno=%d after %d iters",
                    filename, errno, i);
                break;
            }
            // EBUSY → 可能是 mount 在用,umount 再 retry
            if (::umount2(filename, umount_flags) != 0 && errno != EINVAL) {
                LOG("[workdir] unlink(%s) EBUSY + umount fail errno=%d",
                    filename, errno);
                break;
            }
        }
    }
    ::closedir(dp);

    for (int i = 0; i < kRmDirMaxIter; ++i) {
        if (::rmdir(dir) == 0) {
            return true;
        }
        if (errno == EPERM) {
            int fd = ::open(dir, O_RDONLY);
            if (fd != -1) {
                long flags = 0;
                (void)::ioctl(fd, FS_IOC_SETFLAGS, &flags);
                ::close(fd);
                continue;
            }
        }
        if (errno == EROFS) {
            LOG("[workdir] rmdir(%s) failed on read-only filesystem", dir);
            return false;
        }
        if (errno == EBUSY) {
            if (::umount2(dir, umount_flags) != 0 && errno != EINVAL) {
                LOG("[workdir] rmdir(%s) EBUSY + umount fail errno=%d",
                    dir, errno);
                return false;
            }
            continue;
        }
        if (errno == ENOTEMPTY) {
            if (outer_iter < kRmOuterMaxIter) {
                ++outer_iter;
                goto retry;
            }
            LOG("[workdir] rmdir(%s) ENOTEMPTY after %d outer retries",
                dir, outer_iter);
            return false;
        }
        if (errno == ENOENT) {
            return true;
        }
        LOG("[workdir] rmdir(%s) failed errno=%d", dir, errno);
        return false;
    }
    LOG("[workdir] rmdir(%s) hit max inner iters", dir);
    return false;
}

// Match syzkaller reset_loop(): every executor proc owns exactly
// /dev/loop<procid>, and the fork server issues one best-effort LOOP_CLR_FD at
// the start of each iteration. Mount/workdir cleanup from the previous program
// has already completed before the loop reaches this point.
void ClearLoopDevice(uint32_t proc_slot_id)
{
    char path[32];
    ::snprintf(path, sizeof(path), "/dev/loop%u", proc_slot_id);
    const int fd = ::open(path, O_RDWR | O_CLOEXEC);
    if (fd >= 0) {
        (void)::ioctl(fd, LOOP_CLR_FD, 0);
        ::close(fd);
    }
}

void AddLoopElapsed(::refuzz::worker::perf::LoopPerfSample* sample,
                    ::refuzz::worker::perf::LoopStage stage,
                    uint64_t start_us)
{
    if (sample != nullptr && start_us != 0) {
        ::refuzz::worker::perf::AddStage(
            sample,
            stage,
            ::refuzz::worker::perf::NowUs() - start_us);
    }
}

// [debug instrumentation] env-gated diagnostics dump,定位 fork_avg / exit_gap
// 的 floor 在哪。仅在 LoopRuntime 启动稳态调一次,主循环不重复跑。
//
// REFUZZ_DEBUG_SMAPS=1 → dump /proc/self/smaps 紧凑摘要 (一行一个 VMA) +
// 当前 fd 数,落到 ttyS0 给 host serial.log。看每个 VMA 的 Size / Rss /
// VmFlags,定位 fork copy_page_range 的成本来源。

bool ShouldDumpStartupSmaps()
{
    const char* v = std::getenv("REFUZZ_DEBUG_SMAPS");
    return v != nullptr && v[0] == '1' && v[1] == '\0';
}

// 把 smaps 一个 VMA 块(从 addr 行到下一个 addr 行)压成一行 log。
// smaps 块格式(示例):
//   7f5431e00000-7f5432200000 rw-p 00000000 00:01 12345  /memfd:foo (deleted)
//   Size:               4096 kB
//   KernelPageSize:        4 kB
//   MMUPageSize:           4 kB
//   Rss:                  16 kB
//   Pss:                  16 kB
//   ...
//   VmFlags: rd wr mr mw me sd
void EmitVmaSummary(const std::string& head,
                    size_t size_kb, size_t rss_kb,
                    const std::string& vmflags)
{
    LOG("[smaps] %s size=%zuk rss=%zuk vmflags=%s",
        head.c_str(), size_kb, rss_kb, vmflags.c_str());
}

void DumpStartupSmaps()
{
    FILE* f = std::fopen("/proc/self/smaps", "r");
    if (f == nullptr) {
        LOG("[smaps] open failed: %s", strerror(errno));
        return;
    }

    char line[1024];
    std::string head;
    size_t size_kb = 0;
    size_t rss_kb = 0;
    std::string vmflags;
    bool in_block = false;
    size_t vma_count = 0;

    auto flush = [&]() {
        if (in_block) {
            EmitVmaSummary(head, size_kb, rss_kb, vmflags);
            ++vma_count;
        }
        head.clear();
        size_kb = 0;
        rss_kb = 0;
        vmflags.clear();
        in_block = false;
    };

    while (std::fgets(line, sizeof(line), f) != nullptr) {
        size_t len = std::strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = '\0';
        }
        if (IsSmapsVmaHeaderLine(std::string_view(line, len))) {
            // 找到新块,先 flush 上一个
            flush();
            head = line;
            in_block = true;
            continue;
        }
        if (!in_block) continue;
        if (std::strncmp(line, "Size:", 5) == 0) {
            size_kb = static_cast<size_t>(std::strtoul(line + 5, nullptr, 10));
        } else if (std::strncmp(line, "Rss:", 4) == 0) {
            rss_kb = static_cast<size_t>(std::strtoul(line + 4, nullptr, 10));
        } else if (std::strncmp(line, "VmFlags:", 8) == 0) {
            // 跳过 "VmFlags:" 前缀 + 可能的空格
            const char* p = line + 8;
            while (*p == ' ' || *p == '\t') ++p;
            vmflags = p;
        }
    }
    flush();
    std::fclose(f);

    LOG("[smaps] total_vmas=%zu", vma_count);

    // fd 计数:遍历 /proc/self/fd 目录
    DIR* dir = ::opendir("/proc/self/fd");
    if (dir != nullptr) {
        size_t fd_count = 0;
        int max_fd = -1;
        struct dirent* ent;
        while ((ent = ::readdir(dir)) != nullptr) {
            if (ent->d_name[0] == '.') continue;
            ++fd_count;
            const int fd = std::atoi(ent->d_name);
            if (fd > max_fd) max_fd = fd;
        }
        ::closedir(dir);
        LOG("[smaps] open_fd_count=%zu max_fd=%d", fd_count, max_fd);
    }
}

// fd-table ABI layout(对齐 syzkaller `executor.cc` kTunFd/kInitNetNsFd/kVhciFd):
//   200 = kTunFd          ← syzkaller, init_tun() 时占
//   201 = kInitNetNsFd    ← SandboxCommon 顶部 dup2 占
//   202 = kVhciFd         ← syzkaller, init_vhci() 时占
//   203-205 = reFuzz internals(ready/done/log)
//   206-214 = reFuzz reserved
//   215     = kExtraCoverFd (optional)
//   216-247 = per-thread KCOV
// 详见 docs/plans/exec-parity-stdio-scope.md。
[[maybe_unused]] constexpr int kChildReadyPipeFd = 203;
[[maybe_unused]] constexpr int kChildDonePipeFd  = 204;
[[maybe_unused]] constexpr int kChildLogFd       = 205;
constexpr int kChildInternalFdBase = kChildReadyPipeFd;
constexpr int kChildKcovFdBase     = 216;
constexpr int kFallbackCloseFdLimit = 1 << 20;

void AppendPreservedFd(std::vector<int>* preserved_fds, int fd)
{
    if (preserved_fds == nullptr || fd < 0) {
        return;
    }
    for (int existing : *preserved_fds) {
        if (existing == fd) {
            return;
        }
    }
    preserved_fds->push_back(fd);
}

bool IsPreservedFd(const std::vector<int>& preserved_fds, int fd)
{
    if (fd < 3) {
        return true;
    }
    for (int preserved : preserved_fds) {
        if (preserved == fd) {
            return true;
        }
    }
    return false;
}

bool ParseFdName(const char* name, int* out_fd)
{
    if (name == nullptr || out_fd == nullptr || name[0] == '.') {
        return false;
    }
    char* end = nullptr;
    errno = 0;
    const long parsed = ::strtol(name, &end, 10);
    if (errno != 0 || end == name || *end != '\0' ||
        parsed < 0 || parsed > INT_MAX) {
        return false;
    }
    *out_fd = static_cast<int>(parsed);
    return true;
}

bool MoveFdAtOrAbove(int* fd, int* next_fd)
{
    if (fd == nullptr || next_fd == nullptr) {
        return false;
    }
    if (*fd < 0) {
        return true;
    }
    if (*fd >= *next_fd) {
        *next_fd = *fd + 1;
        return true;
    }
    const int new_fd = ::fcntl(*fd, F_DUPFD_CLOEXEC, *next_fd);
    if (new_fd < 0) {
        return false;
    }
    ::close(*fd);
    *fd = new_fd;
    *next_fd = new_fd + 1;
    return true;
}

void CloseUnpreservedFdsFallback(const std::vector<int>& preserved_fds)
{
#ifdef SYS_close_range
    std::vector<int> sorted_fds;
    sorted_fds.reserve(preserved_fds.size());
    for (int fd : preserved_fds) {
        if (fd >= 3) {
            sorted_fds.push_back(fd);
        }
    }
    std::sort(sorted_fds.begin(), sorted_fds.end());
    sorted_fds.erase(std::unique(sorted_fds.begin(), sorted_fds.end()),
                     sorted_fds.end());

    unsigned int range_begin = 3;
    bool close_range_ok = true;
    for (int preserved_fd : sorted_fds) {
        const unsigned int preserved = static_cast<unsigned int>(preserved_fd);
        if (range_begin < preserved &&
            ::syscall(SYS_close_range, range_begin, preserved - 1u, 0u) != 0) {
            close_range_ok = false;
            break;
        }
        range_begin = preserved + 1u;
    }
    if (close_range_ok &&
        ::syscall(SYS_close_range, range_begin, ~0u, 0u) == 0) {
        return;
    }
#endif

    int max_fd = kFallbackCloseFdLimit;
    struct rlimit lim {};
    if (::getrlimit(RLIMIT_NOFILE, &lim) == 0 && lim.rlim_cur != RLIM_INFINITY) {
        max_fd = lim.rlim_cur > static_cast<rlim_t>(INT_MAX)
            ? INT_MAX : static_cast<int>(lim.rlim_cur);
    }
    for (int fd = 3; fd < max_fd; ++fd) {
        if (!IsPreservedFd(preserved_fds, fd)) {
            ::close(fd);
        }
    }
}

void CloseUnpreservedFds(const std::vector<int>& preserved_fds)
{
    DIR* dir = ::opendir("/proc/self/fd");
    if (dir == nullptr) {
        CloseUnpreservedFdsFallback(preserved_fds);
        return;
    }

    const int dir_fd = ::dirfd(dir);
    while (dirent* ent = ::readdir(dir)) {
        int fd = -1;
        if (!ParseFdName(ent->d_name, &fd)) {
            continue;
        }
        if (fd < 3 || fd == dir_fd || IsPreservedFd(preserved_fds, fd)) {
            continue;
        }
        ::close(fd);
    }
    ::closedir(dir);
}

bool PrepareChildFdTableAbi(int* ready_pipe_r, int* done_pipe_w,
                            int* startup_ack_fd,
                            ::refuzz::worker::IObservationBus& bus)
{
    int next_fd = kChildInternalFdBase;
    std::vector<int> preserved_fds;
    preserved_fds.reserve(40);

    if (!MoveFdAtOrAbove(ready_pipe_r, &next_fd)) {
        return false;
    }
    AppendPreservedFd(&preserved_fds, *ready_pipe_r);

    if (!MoveFdAtOrAbove(done_pipe_w, &next_fd)) {
        return false;
    }
    AppendPreservedFd(&preserved_fds, *done_pipe_w);

    if (startup_ack_fd != nullptr && *startup_ack_fd >= 0) {
        if (!MoveFdAtOrAbove(startup_ack_fd, &next_fd)) {
            return false;
        }
        AppendPreservedFd(&preserved_fds, *startup_ack_fd);
    }

    if (!::refuzz::worker::log::MoveWorkerLogFdAtOrAbove(&next_fd)) {
        return false;
    }
    const int log_fd = ::refuzz::worker::log::WorkerLogFd();
    if (log_fd >= 0 && log_fd != STDERR_FILENO) {
        (void)::dup2(log_fd, STDERR_FILENO);
        AppendPreservedFd(&preserved_fds, log_fd);
    }

    if (next_fd < kChildKcovFdBase) {
        next_fd = kChildKcovFdBase;
    }
    if (!bus.RemapInternalFds(&next_fd, &preserved_fds)) {
        return false;
    }

    CloseUnpreservedFds(preserved_fds);
    return true;
}

void ReportLoopStartup(int* startup_ack_fd,
                       bool ready,
                       uint32_t proc_id,
                       LoopStartupStage stage,
                       int error_number)
{
    if (startup_ack_fd == nullptr || *startup_ack_fd < 0) {
        return;
    }
    LoopStartupStatus status = MakeLoopStartupStatus();
    status.ready = ready ? 1u : 0u;
    status.proc_id = proc_id;
    status.stage = stage;
    status.error_number = error_number;
    const uint8_t* data = reinterpret_cast<const uint8_t*>(&status);
    size_t offset = 0;
    while (offset < sizeof(status)) {
        const ssize_t written = ::write(*startup_ack_fd,
                                        data + offset,
                                        sizeof(status) - offset);
        if (written > 0) {
            offset += static_cast<size_t>(written);
            continue;
        }
        if (written < 0 && errno == EINTR) {
            continue;
        }
        break;
    }
    ::close(*startup_ack_fd);
    *startup_ack_fd = -1;
}

} // namespace

// V3 fork mapping policy — worker-local 继承。
//
// 在 loop child 进 main loop 前调一次，把 BAR2 内 *只属于其他 worker / 全局*
// 的子区段全部 MADV_DONTFORK；只保留本 worker 的 data window 在 program child
// 的 VA 里。
//
// 切片(基于 ShmHeader V3 显式 region 字段)：
//   [0, data_region_offset)                       DONTFORK  header + 所有 worker control
//   [data_region_offset, my_data_offset)          DONTFORK  worker 0..N-1 data
//   [my_data_offset, my_data_offset + my_stride)  inherit   本 worker data window
//   [my_data_offset + my_stride, step_ring_offset)DONTFORK  worker N+1..end data
//   [step_ring_offset, total_size)                DONTFORK  step ring + tail
//
// 任一 madvise 失败 = 致命；caller _exit。production 不允许任何 fallback /
// 降级到 multi-region transport：DONTFORK 不生效就是 V3 唯一提交边的硬前提
// 不成立，必须修配置/内核/驱动，再起一遍。
bool ApplyV3ForkMappingPolicy(void* transport_shm_base,
                              size_t transport_shm_size,
                              uint32_t worker_id)
{
    if (transport_shm_base == nullptr || transport_shm_size == 0) {
        return true;
    }
    auto* hdr = static_cast<ShmHeader*>(transport_shm_base);
    if (hdr->magic != IVSHMEM_MAGIC || hdr->version != PROTOCOL_VERSION ||
        !shm_header_has_v3_layout(hdr)) {
        LOG("child[%d]: invalid V3 shm header for direct data window "
            "(magic=0x%x version=%u)",
            getpid(), hdr->magic, hdr->version);
        return false;
    }
    if (worker_id >= hdr->n_workers) {
        LOG("child[%d]: worker_id %u out of range (n_workers=%u)",
            getpid(), worker_id, hdr->n_workers);
        return false;
    }
    const size_t data_off    = static_cast<size_t>(hdr->data_region_offset);
    const size_t data_size   = static_cast<size_t>(hdr->data_region_size);
    const size_t data_stride = static_cast<size_t>(hdr->per_worker_data_stride);
    const size_t step_off    = static_cast<size_t>(hdr->step_ring_offset);
    if (data_stride == 0 || data_off > transport_shm_size ||
        step_off > transport_shm_size ||
        step_off < data_off + data_size ||
        data_size != data_stride * hdr->n_workers) {
        LOG("child[%d]: invalid V3 region bounds data_off=%zu data_size=%zu "
            "stride=%zu step_off=%zu shm_size=%zu n_workers=%u",
            getpid(), data_off, data_size, data_stride, step_off,
            transport_shm_size, hdr->n_workers);
        return false;
    }
    const size_t my_data_off = data_off + static_cast<size_t>(worker_id) * data_stride;
    const size_t my_data_end = my_data_off + data_stride;

    auto* base = static_cast<uint8_t*>(transport_shm_base);

    struct Slice { size_t off; size_t len; const char* label; };
    const Slice slices[] = {
        // Region 1: header + 全局 control region(所有 worker 的 ctrl/task/completion)
        { 0, data_off, "header+control" },
        // Region 2: 比本 worker 编号小的所有 worker 的 data window
        { data_off, my_data_off - data_off, "lower-workers-data" },
        // Region 3: 比本 worker 编号大的所有 worker 的 data window
        { my_data_end, step_off - my_data_end, "higher-workers-data" },
        // Region 4: step event ring + 末尾 padding
        { step_off, transport_shm_size - step_off, "step-ring+tail" },
    };

    for (const auto& s : slices) {
        if (s.len == 0) continue;
        if (::madvise(base + s.off, s.len, MADV_DONTFORK) != 0) {
            LOG("child[%d]: madvise MADV_DONTFORK failed for %s "
                "off=%zu len=%zu errno=%d",
                getpid(), s.label, s.off, s.len, errno);
            return false;
        }
    }

    LOG("child[%d]: V3 fork mapping policy ready (worker-local): "
        "wid=%u inherited [%zu, %zu) total=%zu",
        getpid(), worker_id, my_data_off, my_data_end, data_stride);
    return true;
}

// Startup feasibility probe — verify MADV_DONTFORK is not a silent no-op.
//
// 部分内核 / UIO 驱动配合下，VM_PFNMAP/VM_IO 类型 VMA 的 madvise(MADV_DONTFORK)
// 会被忽略（不报错也不打 VM_DONTCOPY 位）；那样的话 program child 仍然继承
// 整段 BAR，"唯一提交边" 完全失守。这里 fork 一个探针子进程，重置 SIGSEGV/SIGBUS
// 为 SIG_DFL，然后读 base 偏移 0（属于 header，刚被 DONTFORK）。
//
// 预期：probe child 被 SIGSEGV / SIGBUS 杀掉 → DONTFORK 有效，返回 true。
// 否则（probe child 读成功 exit 0 / 被其它信号杀 / waitpid 出错）→ 返回 false。
// caller 必须 _exit 致命；production 不容降级。
bool ProbeV3ForkMappingDontFork(void* transport_shm_base)
{
    if (transport_shm_base == nullptr) {
        return true;
    }
    pid_t probe = ::fork();
    if (probe < 0) {
        LOG("child[%d]: V3 fork mapping probe: fork failed errno=%d",
            getpid(), errno);
        return false;
    }
    if (probe == 0) {
        // Probe child：重置 5 个 crash 信号到 SIG_DFL，让 SIGSEGV 直接由内核
        // 终止本进程，避免 engine_child_crash_handler 把 exit 转成 128+sig
        // 让 parent 难以辨别。
        struct sigaction dfl{};
        dfl.sa_handler = SIG_DFL;
        sigemptyset(&dfl.sa_mask);
        ::sigaction(SIGSEGV, &dfl, nullptr);
        ::sigaction(SIGBUS,  &dfl, nullptr);
        ::sigaction(SIGABRT, &dfl, nullptr);
        ::sigaction(SIGILL,  &dfl, nullptr);
        ::sigaction(SIGFPE,  &dfl, nullptr);

        // Probe read。volatile 防 compiler 把整个读优化掉。读 base+0：
        //   - DONTFORK 生效 → VMA 不在本 child 地址空间 → SIGSEGV
        //   - DONTFORK 是 silent no-op → 读到 magic 字节 → exit 0
        volatile const uint8_t* p =
            static_cast<volatile const uint8_t*>(transport_shm_base);
        const uint8_t v = *p;
        (void)v;
        _exit(0);
    }
    int wstatus = 0;
    if (::waitpid(probe, &wstatus, 0) < 0) {
        LOG("child[%d]: V3 fork mapping probe: waitpid failed errno=%d",
            getpid(), errno);
        return false;
    }
    if (WIFSIGNALED(wstatus)) {
        const int s = WTERMSIG(wstatus);
        if (s == SIGSEGV || s == SIGBUS) {
            LOG("child[%d]: V3 fork mapping probe ok: header unreachable "
                "in probe child (signal=%d)",
                getpid(), s);
            return true;
        }
        LOG("child[%d]: V3 fork mapping probe: probe killed by unexpected "
            "signal %d wstatus=0x%x", getpid(), s, wstatus);
        return false;
    }
    LOG("child[%d]: V3 fork mapping probe FAILED — MADV_DONTFORK is silent "
        "no-op on this kernel/driver (probe child survived; wstatus=0x%x). "
        "Unique commit edge cannot hold; aborting (no fallback in production).",
        getpid(), wstatus);
    return false;
}

// [early-publish + full staging] state threaded into
// ProgramRuntimeInput::publish_result_ctx. The forking executor invokes
// PublishDoneToDaemon the instant the program child commits its result (before
// reap); the loop owns the done pipe + the staging→BAR transcribe + error
// handling. `published` lets the loop fall back to a post-return publish for the
// inline executor (which never calls the hook); `ok` fails the loop closed on a
// broken done pipe.
struct EarlyPublishState {
    int done_pipe_w;
    // [full staging] transcribe targets. Non-null only on the ivshmem path:
    // the child wrote output (+ crash bytes) into `staging_output` and crash_len
    // into `staging_result_page`; the host reads them from the BAR, so we copy
    // staging → BAR before signalling completion. Null on stdio (no BAR, the
    // child wrote the delivery buffers directly — nothing to transcribe).
    const uint8_t* staging_output = nullptr;
    uint8_t* deliver_output = nullptr;
    uint32_t output_cap = 0;
    const ProgramResultPageV3* staging_result_page = nullptr;
    ProgramResultPageV3* deliver_result_page = nullptr;
    bool published = false;
    bool ok = true;
    // [ExecTL delivery] cost of the publish itself (staging->BAR transcribe +
    // done-pipe write), sampled INSIDE PublishDoneToDaemon so both paths are
    // measured. Previously only the post-return fallback was bracketed, so on
    // the early-publish fast path (the common case) delivery read as ~0 while
    // the work silently landed in kExecutor -- which, next to syzkaller's
    // always-measured perf_t4-perf_t3, made reFuzz's result delivery look free.
    // The loop subtracts delivery_us from the executor stage so the four
    // stages stay mutually exclusive, matching syzkaller's disjoint t-deltas.
    bool collect = false;
    uint64_t delivery_us = 0;
    uint64_t transcribe_cpu_us = 0;
};

// Thread CPU consumed, microseconds. vDSO clock_gettime, no file I/O -- safe on
// the per-program publish path (unlike SampleParentTimelinePoint below, which
// also opens /proc/self/schedstat).
static uint64_t ThreadCpuUs()
{
    struct timespec ts {};
    if (::clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts) != 0) {
        return 0;
    }
    return static_cast<uint64_t>(ts.tv_sec) * 1000000ULL +
           static_cast<uint64_t>(ts.tv_nsec) / 1000ULL;
}

// Captureless (stored as a plain function pointer): transcribe the child's
// staged output into the BAR the host reads, then deliver one DoneMsg to the
// daemon's done pipe and record the outcome. Callable from inside the executor's
// reap loop so D no longer waits for child teardown.
static bool PublishDoneToDaemon(void* ctx, const DoneMsg& done)
{
    auto* state = static_cast<EarlyPublishState*>(ctx);
    // [ExecTL delivery] bracket the transcribe + pipe write. The transcribe is
    // the cost this staging design newly introduced (the parent now does a
    // memcpy it never used to); without this sample there is no way to check
    // whether that trade paid off.
    const uint64_t deliver_wall_start =
        state->collect ? ::refuzz::worker::perf::NowUs() : 0;
    const uint64_t deliver_cpu_start = state->collect ? ThreadCpuUs() : 0;
    // [full staging] copy the actually-produced bytes staging → BAR output_pool
    // before completion is visible to the host. `done` was read from the
    // committed staging result page (or the post-reap crash/partial
    // classification), so output_len is final and the staging writes
    // happened-before this point (commit release-store / child death).
    if (state->staging_output != nullptr && state->deliver_output != nullptr) {
        uint32_t n = done.output_len;
        if (n > state->output_cap) {
            n = state->output_cap;
        }
        if (n > 0) {
            std::memcpy(state->deliver_output, state->staging_output, n);
        }
    }
    // crash_len is read from the BAR result page by the adapter
    // (IvshmemWorkerAdapter::GetCrashOutputLen); mirror it from staging.
    if (state->staging_result_page != nullptr &&
        state->deliver_result_page != nullptr) {
        __atomic_store_n(
            &state->deliver_result_page->crash_len,
            __atomic_load_n(&state->staging_result_page->crash_len,
                            __ATOMIC_ACQUIRE),
            __ATOMIC_RELEASE);
    }
    const ssize_t w = ::write(state->done_pipe_w, &done, sizeof(done));
    state->published = true;
    state->ok = (w == static_cast<ssize_t>(sizeof(done)));
    if (state->collect) {
        const uint64_t wall_end = ::refuzz::worker::perf::NowUs();
        const uint64_t cpu_end = ThreadCpuUs();
        if (wall_end >= deliver_wall_start) {
            state->delivery_us += wall_end - deliver_wall_start;
        }
        if (cpu_end >= deliver_cpu_start) {
            state->transcribe_cpu_us += cpu_end - deliver_cpu_start;
        }
    }
    return state->ok;
}

// [ExecTL] round-1 execution-timeline, loop-child side: one line per sampled
// request carrying the child stamps B/C plus this process's R (ready point
// before the blocking ReadyMsg read) and A2 (next-request arrival). Written
// straight to the worker diagnostic fd, bypassing the WorkerLog enable gate.
// The worker_perf switch is therefore the explicit gate for both collection
// and output. Keep this predicate identical to domain_supervisor.cpp so the
// two half-rows remain paired.
static bool ExecTimelineSampled(uint64_t executor_id)
{
    (void)executor_id;
    return ::refuzz::worker::perf::Enabled();
}

struct ParentTimelinePoint {
    uint64_t cpu_us = 0;
    uint64_t rq_us = 0;
    bool cpu_valid = false;
    bool rq_valid = false;
};

struct ParentTimelineDelta {
    uint64_t cpu_us = 0;
    uint64_t rq_us = 0;
    bool cpu_valid = false;
    bool rq_valid = false;
};

struct ParentTimelineCosts {
    ParentTimelineDelta pre;
    ParentTimelineDelta engine;
    ParentTimelineDelta post;
    ParentTimelineDelta idle;
};

// The loop parent owns at most one request, so deltas of these thread-local
// counters can be charged to that request. schedstat field 2 is cumulative
// runqueue wait in ns; an unavailable sample leaves only that rq delta at zero.
static ParentTimelinePoint SampleParentTimelinePoint()
{
    ParentTimelinePoint point{};
    struct timespec ts {};
    if (::clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts) == 0) {
        point.cpu_us = static_cast<uint64_t>(ts.tv_sec) * 1000000ULL +
                       static_cast<uint64_t>(ts.tv_nsec) / 1000ULL;
        point.cpu_valid = true;
    }

    const int fd = ::open("/proc/self/schedstat", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return point;
    }
    char buf[96] = {};
    const ssize_t n = ::read(fd, buf, sizeof(buf) - 1);
    ::close(fd);
    if (n <= 0) {
        return point;
    }
    unsigned long long runtime_ns = 0;
    unsigned long long wait_ns = 0;
    if (::sscanf(buf, "%llu %llu", &runtime_ns, &wait_ns) == 2) {
        point.rq_us = wait_ns / 1000ULL;
        point.rq_valid = true;
    }
    return point;
}

static ParentTimelineDelta ParentTimelineDiff(const ParentTimelinePoint& begin,
                                              const ParentTimelinePoint& end)
{
    ParentTimelineDelta delta{};
    if (begin.cpu_valid && end.cpu_valid && end.cpu_us >= begin.cpu_us) {
        delta.cpu_us = end.cpu_us - begin.cpu_us;
        delta.cpu_valid = true;
    }
    if (begin.rq_valid && end.rq_valid && end.rq_us >= begin.rq_us) {
        delta.rq_us = end.rq_us - begin.rq_us;
        delta.rq_valid = true;
    }
    return delta;
}

struct ExecCpuAccumulator {
    uint64_t done = 0;
    uint64_t execution_cpu_us = 0;
    uint64_t parent_active_cpu_us = 0;
    uint64_t parent_idle_cpu_us = 0;
    uint64_t missing = 0;
    uint64_t last_emit_us = 0;
};

static bool ProcessCpuUs(uint64_t* out)
{
    struct timespec ts {};
    if (out == nullptr || ::clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts) != 0) {
        return false;
    }
    *out = static_cast<uint64_t>(ts.tv_sec) * 1000000ULL +
           static_cast<uint64_t>(ts.tv_nsec) / 1000ULL;
    return true;
}

static bool ReapedChildrenCpuUs(uint64_t* out)
{
    struct rusage usage {};
    if (out == nullptr || ::getrusage(RUSAGE_CHILDREN, &usage) != 0) {
        return false;
    }
    *out = static_cast<uint64_t>(usage.ru_utime.tv_sec) * 1000000ULL +
           static_cast<uint64_t>(usage.ru_utime.tv_usec) +
           static_cast<uint64_t>(usage.ru_stime.tv_sec) * 1000000ULL +
           static_cast<uint64_t>(usage.ru_stime.tv_usec);
    return true;
}

static void AccumulateExecCpuRequest(ExecCpuAccumulator* accumulator,
                                     const DoneMsg& done,
                                     const ParentTimelineCosts& parent)
{
    if (!::refuzz::worker::perf::Enabled() || accumulator == nullptr) {
        return;
    }
    bool missing = false;
    if (done.tl_b_ts_us != 0 && done.tl_c_ts_us >= done.tl_b_ts_us &&
        done.tl_c_cpu_us >= done.tl_b_cpu_us) {
        accumulator->execution_cpu_us +=
            done.tl_c_cpu_us - done.tl_b_cpu_us;
    } else {
        missing = true;
    }

    if (parent.pre.cpu_valid && parent.engine.cpu_valid &&
        parent.post.cpu_valid) {
        accumulator->parent_active_cpu_us +=
            parent.pre.cpu_us + parent.engine.cpu_us + parent.post.cpu_us;
    } else {
        missing = true;
    }
    if (parent.idle.cpu_valid) {
        accumulator->parent_idle_cpu_us += parent.idle.cpu_us;
    } else {
        missing = true;
    }
    if (done.reap_ts_us == 0) {
        missing = true;
    }
    ++accumulator->done;
    if (missing) {
        ++accumulator->missing;
    }
}

static void MaybeEmitExecCpuLine(uint32_t worker_id,
                                 ExecCpuAccumulator* accumulator,
                                 bool force)
{
    constexpr uint64_t kReportIntervalUs = 5000000ULL;
    if (accumulator == nullptr) {
        return;
    }
    const uint64_t now = now_us();
    if (!force && accumulator->last_emit_us != 0 &&
        now - accumulator->last_emit_us < kReportIntervalUs) {
        return;
    }
    uint64_t process_cpu_us = 0;
    uint64_t children_cpu_us = 0;
    if (!ProcessCpuUs(&process_cpu_us) ||
        !ReapedChildrenCpuUs(&children_cpu_us)) {
        return;
    }

    char buf[384];
    const int n = ::snprintf(
        buf, sizeof(buf),
        "[WORKER][RfzExecCPU] w=%u t=%llu done=%llu pc=%llu ch=%llu"
        " ex=%llu pa=%llu pi=%llu miss=%llu\n",
        worker_id,
        static_cast<unsigned long long>(now),
        static_cast<unsigned long long>(accumulator->done),
        static_cast<unsigned long long>(process_cpu_us),
        static_cast<unsigned long long>(children_cpu_us),
        static_cast<unsigned long long>(accumulator->execution_cpu_us),
        static_cast<unsigned long long>(accumulator->parent_active_cpu_us),
        static_cast<unsigned long long>(accumulator->parent_idle_cpu_us),
        static_cast<unsigned long long>(accumulator->missing));
    if (n > 0) {
        ::refuzz::worker::log::WriteWorkerLogBytes(buf, static_cast<size_t>(n));
        accumulator->last_emit_us = now;
    }
}

static void EmitExecTimelineLoopLine(uint32_t worker_id, uint64_t executor_id,
                                     const DoneMsg& done,
                                     uint64_t r_us, uint64_t a2_us,
                                     const ParentTimelineCosts& parent,
                                     uint64_t transcribe_cpu_us)
{
    // Extra fields carry the round-2 CPU dimension: bc/bq and cc/cq are the
    // child's process-CPU and main-thread runqueue wait at B and C, fw/fc the
    // parent fork wall/CPU, rp the absolute reap stamp (rp-C = child death +
    // parent notice), ru/iv/mf the child's rusage CPU / involuntary context
    // switches / minor faults.
    //
    // tc = parent thread CPU spent inside the publish (staging->BAR transcribe
    // + done-pipe write); ob = bytes actually produced. tc alone is not
    // interpretable across programs -- ob normalizes it, which is what makes
    // the staging transcribe cost checkable (it should scale with ob).
    // Careful: pec/peq and the worker-perf kExecutor stage have DIFFERENT
    // boundaries and must not be mixed. pec/peq is the parent CPU/runqueue
    // delta sampled around ExecuteProgram entry->return, so on the fast path it
    // still CONTAINS the publish (the publish hook runs inside ExecuteProgram)
    // -- which is what makes it the resource-side evidence for publish(C->D).
    // The kExecutor stage, by contrast, has delivery subtracted out so the four
    // loop stages stay mutually exclusive. Same code region, two deliberately
    // different accounting boundaries.
    char buf[768];
    const int n = ::snprintf(
        buf, sizeof(buf),
        "[WORKER][RfzTL] w=%u id=%llu B=%llu C=%llu R=%llu A2=%llu"
        " bc=%llu bq=%llu cc=%llu cq=%llu fw=%llu fc=%llu"
        " rp=%llu ru=%llu iv=%llu mf=%llu"
        " ppc=%llu ppq=%llu pec=%llu peq=%llu"
        " poc=%llu poq=%llu pic=%llu piq=%llu"
        " tc=%llu ob=%llu\n",
        worker_id,
        static_cast<unsigned long long>(executor_id),
        static_cast<unsigned long long>(done.tl_b_ts_us),
        static_cast<unsigned long long>(done.tl_c_ts_us),
        static_cast<unsigned long long>(r_us),
        static_cast<unsigned long long>(a2_us),
        static_cast<unsigned long long>(done.tl_b_cpu_us),
        static_cast<unsigned long long>(done.tl_b_rq_us),
        static_cast<unsigned long long>(done.tl_c_cpu_us),
        static_cast<unsigned long long>(done.tl_c_rq_us),
        static_cast<unsigned long long>(done.fork_wall_us),
        static_cast<unsigned long long>(done.fork_cpu_us),
        static_cast<unsigned long long>(done.reap_ts_us),
        static_cast<unsigned long long>(done.child_cpu_us),
        static_cast<unsigned long long>(done.child_nivcsw),
        static_cast<unsigned long long>(done.child_minflt),
        static_cast<unsigned long long>(parent.pre.cpu_us),
        static_cast<unsigned long long>(parent.pre.rq_us),
        static_cast<unsigned long long>(parent.engine.cpu_us),
        static_cast<unsigned long long>(parent.engine.rq_us),
        static_cast<unsigned long long>(parent.post.cpu_us),
        static_cast<unsigned long long>(parent.post.rq_us),
        static_cast<unsigned long long>(parent.idle.cpu_us),
        static_cast<unsigned long long>(parent.idle.rq_us),
        static_cast<unsigned long long>(transcribe_cpu_us),
        static_cast<unsigned long long>(done.output_len));
    if (n > 0) {
        ::refuzz::worker::log::WriteWorkerLogBytes(buf, static_cast<size_t>(n));
    }
}

void InitProgramResultPage(ProgramResultPageV3* page,
                           uint64_t executor_id,
                           uint32_t dispatch_gen,
                           uint32_t proc_id)
{
    if (page == nullptr) {
        return;
    }
    page->executor_id = executor_id;
    page->dispatch_gen = dispatch_gen;
    page->proc_id = proc_id;
    page->result_kind = static_cast<uint32_t>(RuntimeResultKind::kNoResult);
    page->status = 0;
    page->flags = 0;
    page->output_len = 0;
    page->crash_len = 0;
    page->crash_signal = 0;
    page->fatal_reason =
        static_cast<uint32_t>(HarnessFatalReason::kNone);
    page->perf_valid = 0;
    page->tl_b_ts_us = 0;
    page->tl_c_ts_us = 0;
    page->tl_b_cpu_us = 0;
    page->tl_b_rq_us = 0;
    page->tl_c_cpu_us = 0;
    page->tl_c_rq_us = 0;
    // Unknown until the program child activates a backend that supports live
    // loop-mask publication. Supported backends replace this with 0 before
    // Execute and atomically OR bits as loop devices are attached.
    __atomic_store_n(&page->loop_devices_used_mask,
                     UINT32_MAX,
                     __ATOMIC_RELEASE);
    __atomic_store_n(&page->progress_completed_calls, 0u, __ATOMIC_RELEASE);
    __atomic_store_n(&page->progress_output_len, 0u, __ATOMIC_RELEASE);
    program_result_store_commit_seq_v3(page, 0);
    program_result_store_state_v3(page, PROGRAM_RESULT_RUNNING);
}

bool ResolveProgramBuffers(const ReadyMsg& message,
                           const ProgramBufferMapping& mapping,
                           ProgramRuntimeInput* input)
{
    if (input == nullptr || message.buffers.source != mapping.source ||
        message.buffers.worker_id != mapping.worker_id) {
        return false;
    }
    uint8_t* input_ptr = nullptr;
    uint8_t* output_ptr = nullptr;
    if (!ResolveProgramBufferRange(mapping,
                                   message.buffers.input_offset,
                                   message.input_len,
                                   mapping.input_offset,
                                   mapping.input_size,
                                   &input_ptr) ||
        !ResolveProgramBufferRange(mapping,
                                   message.buffers.output_offset,
                                   message.output_cap,
                                   mapping.output_offset,
                                   mapping.output_size,
                                   &output_ptr)) {
        return false;
    }
    input->input = input_ptr;
    input->output = output_ptr;
    input->output_cap = message.output_cap;
    if (mapping.result_page_size != 0) {
        if (message.buffers.result_page_offset != mapping.result_page_offset ||
            mapping.result_page_size < sizeof(ProgramResultPageV3)) {
            return false;
        }
        uint8_t* result_ptr = nullptr;
        if (!ResolveProgramBufferRange(mapping,
                                       message.buffers.result_page_offset,
                                       sizeof(ProgramResultPageV3),
                                       mapping.result_page_offset,
                                       mapping.result_page_size,
                                       &result_ptr)) {
            return false;
        }
        input->result_page = reinterpret_cast<ProgramResultPageV3*>(result_ptr);
    } else if (message.buffers.result_page_offset != 0) {
        return false;
    }
    return true;
}

[[noreturn]] void LoopRuntimeRun(
    int ready_pipe_r,
    int done_pipe_w,
    uint32_t worker_id,
    uint32_t proc_id,
    ::refuzz::worker::IExecBackend& backend,
    ::refuzz::worker::IObservationBus& bus,
    ::refuzz::worker::SandboxMode sandbox_mode,
    bool allow_no_private_mount_namespace_for_tests,
    size_t transport_mapped_bytes,
    void* transport_shm_base,
    size_t transport_shm_size,
    ProgramBufferMapping program_mapping,
    int startup_ack_fd,
    IProgramExecutor& executor,
    void* fork_window_base,
    size_t fork_window_size)
{
    // backend 当前不被 LoopRuntime 直接使用(InlineProgramExecutor / future
    // ForkingProgramExecutor 自己持有 backend 引用)。保留参数以便 P4 DoubleFork
    // 装配时,LoopRuntime 自己也可能需要 backend(eg. health check)。
    (void)backend;
    // child 进程的 stderr 默认继承 worker daemon (通常是 ssh 会话上游或
    // /dev/null)。glibc 在 abort/__fortify_fail/__libc_message 等路径会先把
    // 错误描述写到 stderr 再 raise(SIGABRT)。把 stderr dup 到 WorkerLogFd
    // (=ttyS0),host ConsoleSensor 能完整拿到。仅 child 做 dup,不影响 daemon。
    {
        const int log_fd = ::refuzz::worker::log::WorkerLogFd();
        if (log_fd >= 0 && log_fd != STDERR_FILENO) {
            (void)::dup2(log_fd, STDERR_FILENO);
        }
    }

    // 装 5 个真 crash 信号 handler(SIGSEGV/SIGABRT/SIGBUS/SIGILL/SIGFPE),
    // 注入 bus 给 crash snapshot。fork 后 program child 自动继承(POSIX)。
    ProgramRuntimeInstallCrashHandlers(&bus);

    // bus 初始化:KcovSink 打开 /dev/kcov, IvshmemStepEventSink 设置 ring。
    if (!bus.InitAll()) {
        LOG("child[%d]: observation_bus.InitAll: 至少一个 sink Init 返回 false (sink 已自降级)",
            getpid());
        if (startup_ack_fd >= 0) {
            ReportLoopStartup(&startup_ack_fd, false, proc_id,
                              LoopStartupStage::kKcovInit, errno);
            _exit(9);
        }
    } else {
        LOG("child[%d]: observation_bus.InitAll OK sinks=%zu",
            getpid(),
            bus.SinkCount());
    }
    // syzkaller exec-wire ABI 假设 fuzz-visible fd allocation 从 3 起。
    // 把 reFuzz internals(IPC/log/KCOV)搬到 high reserved band,然后关闭
    // 所有 inherited 低 fd,保证 program 看到的 fd 3-199 是空的。
    if (!PrepareChildFdTableAbi(&ready_pipe_r, &done_pipe_w,
                                &startup_ack_fd, bus)) {
        LOG("child[%d]: fd-table ABI setup failed (errno=%d); exiting",
            getpid(), errno);
        ReportLoopStartup(&startup_ack_fd, false, proc_id,
                          LoopStartupStage::kFdAbi, errno);
        _exit(4);
    }

    // syz_exec scratch mmap 必须在 ApplySandbox 之前 — sandbox 会把 RLIMIT_AS
    // 收紧到 ceil_pow2(base) 量级。当前 scratch 需要覆盖 linux/amd64 target
    // 的完整 exec data window(16 MiB),如果把这块私有 mmap 留给首条 task
    // 才触发,大概率超额 → 每条 task 都 exec_error。这里在 root 下主动触发。
    if (!PreallocateSyzExecScratch()) {
        LOG("child[%d]: PreallocateSyzExecScratch failed (errno=%d); exiting",
            getpid(), errno);
        ReportLoopStartup(&startup_ack_fd, false, proc_id,
                          LoopStartupStage::kScratch, errno);
        _exit(3);
    }

    // V3 mmap policy: program child 只继承本 worker 的 data window；其余
    // (header / 所有 worker 的 control / 其他 worker 的 data / step ring / 末尾)
    // 全部 MADV_DONTFORK。完成 madvise 之后立即跑一次 startup probe，
    // fail-hard verify DONTFORK 不是 silent no-op。production 不接受降级。
    // stdio profile 不走 ivshmem，传 nullptr/0 时直接跳过整段。
    //
    // 这条路径只服务旧 kDoubleFork(进程内 fork,非 exec)拓扑 —— transport_shm_base
    // 是完整多 worker BAR(带 ShmHeader),需要按 V3 layout 切片。生产用的
    // kExecDoubleFork 走下面独立的 fork_window_base 分支(见其注释),两者互斥、
    // 各自可为空,不共享判定变量。
    const bool direct_data_window_active =
        (transport_shm_base != nullptr) && (transport_shm_size != 0);
    if (direct_data_window_active) {
        if (!ApplyV3ForkMappingPolicy(transport_shm_base,
                                      transport_shm_size,
                                      worker_id)) {
            _exit(5);
        }
        if (!ProbeV3ForkMappingDontFork(transport_shm_base)) {
            _exit(6);
        }
    }

    // [fix: production staging activation] kExecDoubleFork(RunExecLoop →
    // exec_loop_entry.cpp)已经把本 worker 自己的 data window 映射好并传进来 ——
    // window.mapping/window.mapping_size 覆盖 [aligned_offset, +mapping_size),
    // 是这个 worker 专属的一段原始 range,**不含 ShmHeader**,不能也不需要走
    // ApplyV3ForkMappingPolicy 的多 worker 切片逻辑;直接对整段 MADV_DONTFORK +
    // 复用同一个 probe 即可(probe 只做"探针子进程读 base+0 应该 SIGSEGV",跟
    // ShmHeader 无关,天然通用)。stdio / 旧 kDoubleFork 传 nullptr/0 时跳过。
    const bool raw_fork_window_active =
        (fork_window_base != nullptr) && (fork_window_size != 0);
    if (raw_fork_window_active) {
        if (::madvise(fork_window_base, fork_window_size, MADV_DONTFORK) != 0) {
            LOG("child[%d]: madvise MADV_DONTFORK failed for fork window "
                "base=%p len=%zu errno=%d",
                getpid(), fork_window_base, fork_window_size, errno);
            _exit(5);
        }
        if (!ProbeV3ForkMappingDontFork(fork_window_base)) {
            _exit(6);
        }
        LOG("child[%d]: fork window DONTFORK ready wid=%u base=%p len=%zu",
            getpid(), worker_id, fork_window_base, fork_window_size);
    }

    // [full staging] anon-shared(shmem)镜像 window,替代 BAR 作为 program-child 的
    // input/output/result page 落点。MAP_SHARED|MAP_ANONYMOUS 无 anon_vma、非
    // PFNMAP → fork 跳过页表复制,child 只 fault 真正碰到的页,exit 只回收那几页,
    // 从而消掉 BAR 窗口每程序 ~6ms 的 fork+exit 页表税。loop-child 长寿,跨程序复用
    // (页常驻后 memcpy 无 fault)。**必须在 ApplySandbox 收紧 RLIMIT_AS 之前 mmap 并
    // 计入 sizing.ivshmem_bytes**,否则 18MB 要么撑爆 AS、要么吃掉留给 fuzz 程序的
    // headroom。两条 DONTFORK 路径(旧 kDoubleFork 的 direct_data_window_active、
    // 生产 kExecDoubleFork 的 raw_fork_window_active)都需要它;stdio fallback
    // 两者都不触发,不涉 BAR、无 fork 税,不 stage(staging_window=null)。
    WorkerDataWindowV3* staging_window = nullptr;
    if (direct_data_window_active || raw_fork_window_active) {
        void* p = ::mmap(nullptr, sizeof(WorkerDataWindowV3),
                         PROT_READ | PROT_WRITE,
                         MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) {
            const int saved_errno = errno;
            LOG("child[%d]: full-staging window mmap failed (errno=%d); exiting",
                getpid(), saved_errno);
            ReportLoopStartup(&startup_ack_fd, false, proc_id,
                              LoopStartupStage::kResultPage, saved_errno);
            _exit(7);
        }
        staging_window = reinterpret_cast<WorkerDataWindowV3*>(p);
        LOG("child[%d]: full-staging window ready ptr=%p size=%zu",
            getpid(), static_cast<void*>(staging_window),
            sizeof(WorkerDataWindowV3));
    }

    // Sandbox apply。顺序约束:KcovSink::Init 已完成、step event ring 已 mmap、
    // ttyS0 fd 已 lazy 打开并持有。此后 main loop 只走已打开 fd,不再 open 新资源。
    ::refuzz::worker::SandboxSizing sizing{};
    sizing.ivshmem_bytes  = transport_mapped_bytes +
        (staging_window != nullptr ? sizeof(WorkerDataWindowV3) : 0);
    sizing.scratch_bytes  = ::refuzz::worker::kSyzExecScratchBytes;
    sizing.coverage_bytes = bus.TotalBufferBytes();
    sizing.proc_id = proc_id;
    sizing.allow_no_private_mount_namespace_for_tests =
        allow_no_private_mount_namespace_for_tests;
    if (int sb_rc = ::refuzz::worker::ApplySandbox(sandbox_mode, sizing); sb_rc != 0) {
        const int startup_errno = sb_rc < 0 ? -sb_rc : sb_rc;
        LOG("child[%d]: ApplySandbox(%s) failed rc=%d; exiting",
            getpid(), ::refuzz::worker::SandboxModeName(sandbox_mode), sb_rc);
        ReportLoopStartup(&startup_ack_fd, false, proc_id,
                          LoopStartupStage::kSandbox, startup_errno);
        _exit(2);
    }
    // Production ApplySandbox success guarantees this loop domain owns a
    // recursive MS_PRIVATE mount namespace. Program children inherit it, and
    // per-program cleanup can therefore stay scoped to remove_dir(workdir).
    if (sandbox_mode != ::refuzz::worker::SandboxMode::kNone) {
        LOG("child[%d]: sandbox=%s uid=%u gid=%u",
            getpid(), ::refuzz::worker::SandboxModeName(sandbox_mode),
            static_cast<unsigned>(getuid()),
            static_cast<unsigned>(getgid()));
    }

    // [当前版本 setup-cgroups-loop-test] 对齐 syzkaller `setup_loop` 入口的
    // `setup_cgroups_loop` (common_linux.h:4847,3821)。ApplySandbox 完成后
    // (chroot + cgroup bind 已 ready) 把 loop_child 写入 /syzcgroup/unified/
    // syz<worker_id>,设 pids.max=32,后续 fork 出来的 program-child 全继承
    // 同 cgroup。累积 task 数超 32 时新 fork 返 EAGAIN,跟上游 fork-bomb 防护
    // 对齐 —— 这是 syz_clone EAGAIN deterministic 资源压力形状的根因 fix。
    ::refuzz::worker::sandbox::device_init::SetupCgroupsLoop(
        static_cast<std::uint64_t>(proc_id));
    ::refuzz::worker::topology::EmitTopologyProbeSelf(
        "loop-after-cgroup", worker_id, 0, 0);
    ::refuzz::worker::topology::EmitTopologyProbeCgroup(
        "loop-after-cgroup", worker_id, proc_id, 0, 0, 16);

    // syzkaller checkpoints netfilter state after setup and before publishing
    // READY. setuid cannot perform the later SET_REPLACE/SET_ENTRIES calls after
    // credentials are dropped, so both checkpoint and reset are disabled there.
    const bool net_namespace_reset_enabled =
        sandbox_mode != ::refuzz::worker::SandboxMode::kSetuid;
    if (net_namespace_reset_enabled &&
        !::refuzz::worker::sandbox::device_init::CheckpointNetNamespace()) {
        const int startup_errno = errno != 0 ? errno : EIO;
        LOG("child[%d]: network namespace checkpoint failed errno=%d; exiting",
            getpid(), startup_errno);
        ReportLoopStartup(&startup_ack_fd, false, proc_id,
                          LoopStartupStage::kSandbox, startup_errno);
        _exit(2);
    }

    // Production DoubleFork makes loop_child PID 1 in the new PID namespace,
    // so descendant reparenting already targets this process. Host tests can
    // fall back after unshare(CLONE_NEWPID) fails; only that non-PID1 path needs
    // subreaper semantics to exercise the same fork-server reaper.
    if (::getpid() != 1 &&
        ::prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0) {
        LOG("child[%d]: prctl(PR_SET_CHILD_SUBREAPER) errno=%d — "
            "host-fallback descendant cleanup disabled",
            getpid(), errno);
    }

    // [debug] dump steady-state mapping landscape 一次,定位 fork_avg 成本来源。
    // 默认 off;set REFUZZ_DEBUG_SMAPS=1 启用。LoopRuntime 进 main loop 前
    // 调一次,sandbox + V3 fork mapping policy + KCOV + scratch 全部 ready 状态。
    if (worker_id == 0 && ShouldDumpStartupSmaps()) {
        DumpStartupSmaps();
    }

    // [G4 stdio result page wiring — 当前版本]
    // stdio profile 没有 backing-store result page,
    // 之前走 fallback "no result page wired" → ForkingProgramExecutor 拿不到 child
    // commit 的 status/output_len → 全部返 driver rc=-1。
    //
    // 这里给 LoopRuntime 自己 mmap 一页 MAP_SHARED|MAP_ANONYMOUS(sizeof
    // ProgramResultPageV3 = PAGE_SIZE,自带 page-aligned)。MAP_SHARED 语义下 fork
    // 后 program child 跟 loop parent 映射同一物理页 — child 跑 CommitResultPage
    // 写 status/output_len/result_kind,parent _exit 后用同一 page 走 ResultPageMatches
    // + commit_seq protocol 读,跟 ivshmem 路径走完全一样的代码。loop child 长寿,
    // 各 iteration 复用同一页(InitProgramResultPage 每条 prog 入口做 reset,clear
    // commit_seq 让上一条 prog 的 stale state 不污染)。
    ProgramResultPageV3* stdio_fallback_result_page = nullptr;
    if (program_mapping.result_page_size == 0) {
        void* p = ::mmap(nullptr, sizeof(ProgramResultPageV3),
                         PROT_READ | PROT_WRITE,
                         MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) {
            const int saved_errno = errno;
            LOG("child[%d]: stdio fallback result_page mmap failed (errno=%d); exiting",
                getpid(), saved_errno);
            ReportLoopStartup(&startup_ack_fd, false, proc_id,
                              LoopStartupStage::kResultPage, saved_errno);
            _exit(7);
        }
        stdio_fallback_result_page = reinterpret_cast<ProgramResultPageV3*>(p);
        LOG("child[%d]: stdio fallback result_page ready ptr=%p size=%zu",
            getpid(),
            static_cast<void*>(stdio_fallback_result_page),
            sizeof(ProgramResultPageV3));
    }

    // [per-program workdir isolation — 镜像 syzkaller common.h:609-751 loop()]
    // sandbox apply 后(chroot 已生效)取一次 baseline cwd 的 O_PATH fd。
    // 主循环每条 prog 入口 fchdir 回它兜底 — 即使下层 ProgramRuntimeRunInline
    // 的 fchdir-back 漏了或 mount_dispatcher saved_cwd 还没 restore,这一步把
    // cwd 拉回 chroot 根,mkdir("./<iter>") 的相对解析永远稳定。
    //
    // 取不到 fd(罕见,fd 表满 / chroot 异常)→ workdir 整套退化为 no-op,
    // 跑跟旧行为 byte-equal 的 main loop,不影响 backward compat。
    int loop_baseline_cwd_fd = ::open(".", O_PATH | O_CLOEXEC);
    if (loop_baseline_cwd_fd < 0) {
        LOG("child[%d]: open(.,O_PATH) baseline cwd failed errno=%d "
            "— per-program workdir isolation disabled this session",
            getpid(), errno);
    } else {
        LOG("child[%d]: per-program workdir isolation armed, baseline cwd fd=%d",
            getpid(), loop_baseline_cwd_fd);
    }
    uint64_t program_iter = 0;

    // [remote-kcov S1] Locate the extra remote KCOV control (KcovSink when
    // threaded + coverage on). KCOV_REMOTE_ENABLE already happened in
    // bus.InitAll() above — i.e. in THIS loop_child task, BEFORE the program
    // loop forks any program-child / pool thread — so the kcov_handle=H it set
    // is inherited by the whole forked tree (kcov_task_init). We only drive
    // per-program reset/collect here. nullptr (serial / coverage-off / no
    // remote-KCOV kernel support) → the reset/count calls are skipped.
    ::refuzz::worker::IExtraKcovControl* extra_kcov = bus.FindExtraKcovControl();
    if (extra_kcov != nullptr) {
        LOG("child[%d]: remote-kcov control active (per-program extra coverage "
            "logging enabled)", getpid());
    }

    ReportLoopStartup(&startup_ack_fd, true, proc_id,
                      LoopStartupStage::kReady, 0);

    // Match syzkaller common.h loop(): create workdir → reset fixed loop →
    // receive request → execute/reap → reply → synchronous cleanup.
    constexpr uint32_t kCleanupBaselineInitFailed = 1u << 0;
    constexpr uint32_t kCleanupStaleWorkdirFailed = 1u << 2;
    constexpr uint32_t kCleanupCwdRestoreFailed = 1u << 3;
    constexpr uint32_t kCleanupWorkdirRemoveFailed = 1u << 4;
    ReadyMsg msg{};
    uint64_t loop_perf_sequence = 0;
    uint32_t cleanup_failure_flags = 0;
    const bool collect_exec_timeline =
        ::refuzz::worker::perf::Enabled();
    // [ExecTL] previous request's record, emitted one iteration later once its
    // R (ready point) and A2 (next-request arrival) are known. The DoneMsg
    // copy carries the child stamps plus the round-2 fork/reap/rusage fields.
    bool tl_pending_valid = false;
    uint64_t tl_pending_id = 0;
    DoneMsg tl_pending_done{};
    ParentTimelineCosts tl_pending_parent{};
    ParentTimelinePoint tl_pending_parent_engine_end{};
    // [ExecTL delivery] publish-side thread CPU of the request whose TL line is
    // still pending; captured after the publish resolves so the fallback path
    // (which publishes after the stash below) is not recorded as zero.
    uint64_t tl_pending_transcribe_cpu_us = 0;
    ExecCpuAccumulator exec_cpu_accumulator{};
    if (collect_exec_timeline) {
        MaybeEmitExecCpuLine(worker_id, &exec_cpu_accumulator, true);
    }
    if (loop_baseline_cwd_fd < 0) {
        cleanup_failure_flags |= kCleanupBaselineInitFailed;
    }
    while (true) {
        const bool collect_loop_perf =
            ::refuzz::worker::perf::ShouldSample(++loop_perf_sequence);
        ::refuzz::worker::perf::ProgramPerfSample program_perf{};
        auto& loop_perf = program_perf.loop;
        uint64_t phase_start = collect_loop_perf
            ? ::refuzz::worker::perf::NowUs() : 0;

        // [per-program workdir isolation] syzkaller creates the iteration
        // directory before reset_loop() and receive_execute(). Keep the same
        // ordering so workdir preparation is complete before a request is read.
        //
        // Host fallback may not have a writable sandbox root, so plain workdir
        // setup failures retain the historical no-workdir behavior. EEXIST is
        // different: failure to remove a stale prior workdir is a cleanup fatal.
        //
        // workdir_buf must stay in the while-body scope because input.workdir is
        // a raw pointer used through executor.ExecuteProgram().
        char workdir_buf[32];
        bool workdir_armed = false;
        if (cleanup_failure_flags == 0 && loop_baseline_cwd_fd >= 0) {
            // Recover the baseline cwd before resolving the relative workdir.
            if (::fchdir(loop_baseline_cwd_fd) != 0) {
                LOG("child[%d]: fchdir(baseline cwd) failed errno=%d "
                    "(iter=%llu)",
                    getpid(), errno,
                    static_cast<unsigned long long>(program_iter));
            } else {
                ::snprintf(workdir_buf, sizeof(workdir_buf), "./%llu",
                           static_cast<unsigned long long>(program_iter));
                if (::mkdir(workdir_buf, 0777) == 0) {
                    workdir_armed = true;
                } else if (errno == EEXIST) {
                    // worker respawn after iter reset or a stale prior workdir
                    LOG("child[%d]: mkdir(%s) EEXIST → cleanup + retry",
                        getpid(), workdir_buf);
                    const bool stale_removed = RemoveDirRecursive(workdir_buf);
                    if (!stale_removed) {
                        cleanup_failure_flags |= kCleanupStaleWorkdirFailed;
                    } else if (::mkdir(workdir_buf, 0777) == 0) {
                        workdir_armed = true;
                    } else {
                        LOG("child[%d]: mkdir(%s) retry failed errno=%d",
                            getpid(), workdir_buf, errno);
                    }
                } else {
                    LOG("child[%d]: mkdir(%s) failed errno=%d",
                        getpid(), workdir_buf, errno);
                }
            }
        }

        ClearLoopDevice(proc_id);
        // syzkaller reset_loop() restores netfilter state before the next
        // request is received. Keep this before the readiness timestamp/read so
        // a daemon can never dispatch into a contaminated network namespace.
        if (net_namespace_reset_enabled &&
            !::refuzz::worker::sandbox::device_init::ResetNetNamespace()) {
            const int reset_errno = errno != 0 ? errno : EIO;
            LOG("child[%d]: network namespace reset failed errno=%d; exiting",
                getpid(), reset_errno);
            _exit(10);
        }
        AddLoopElapsed(
            collect_loop_perf ? &loop_perf : nullptr,
            ::refuzz::worker::perf::LoopStage::kPrepare,
            phase_start);
        // [ExecTL] R: cleanup + next-workdir prep done — the worker is ready
        // for the next request; the read below is idle wait.
        const uint64_t tl_r_us = collect_exec_timeline ? now_us() : 0;
        const ParentTimelinePoint tl_parent_ready = collect_exec_timeline
            ? SampleParentTimelinePoint() : ParentTimelinePoint{};
        if (collect_exec_timeline && tl_pending_valid) {
            tl_pending_parent.post = ParentTimelineDiff(
                tl_pending_parent_engine_end, tl_parent_ready);
        }
        ssize_t n = read(ready_pipe_r, &msg, sizeof(msg));
        const uint64_t tl_read_end_us = collect_exec_timeline ? now_us() : 0;
        const ParentTimelinePoint tl_parent_after_read = collect_exec_timeline
            ? SampleParentTimelinePoint() : ParentTimelinePoint{};
        if (collect_exec_timeline && tl_pending_valid) {
            tl_pending_parent.idle = ParentTimelineDiff(
                tl_parent_ready, tl_parent_after_read);
            AccumulateExecCpuRequest(&exec_cpu_accumulator,
                                     tl_pending_done,
                                     tl_pending_parent);
        }
        if (n != static_cast<ssize_t>(sizeof(msg))) {
            // The new ordering can prepare the next empty workdir before a
            // graceful teardown closes the request pipe. Remove that unused
            // directory before exiting the loop child.
            if (workdir_armed && !RemoveDirRecursive(workdir_buf)) {
                LOG("child[%d]: failed to remove unused workdir %s on pipe close",
                    getpid(), workdir_buf);
            }
            if (collect_exec_timeline) {
                MaybeEmitExecCpuLine(worker_id, &exec_cpu_accumulator, true);
            }
            _exit(0); // pipe closed → daemon 要求退出
        }
        const uint64_t tl_a2_us = tl_read_end_us;
        const ParentTimelinePoint tl_parent_claim = tl_parent_after_read;
        if (collect_exec_timeline && tl_pending_valid) {
            MaybeEmitExecCpuLine(worker_id, &exec_cpu_accumulator, false);
        }
        // [ExecTL] A2: next request arrived — the previous request's reuse
        // path is closed, so emit its record now; the serial write happens
        // outside any KCOV window and off the daemon-side dispatch path.
        if (tl_pending_valid) {
            if (ExecTimelineSampled(tl_pending_id)) {
                EmitExecTimelineLoopLine(worker_id, tl_pending_id,
                                         tl_pending_done, tl_r_us, tl_a2_us,
                                         tl_pending_parent,
                                         tl_pending_transcribe_cpu_us);
            }
            tl_pending_valid = false;
        }
        auto reject_for_cleanup_failure = [&]() {
            DoneMsg failed{};
            failed.status = -1;
            failed.flags = cleanup_failure_flags;
            failed.result_kind = RuntimeResultKind::kHarnessFatal;
            failed.fatal_reason =
                HarnessFatalReason::kExecutionDomainCleanupFailed;
            LOG("child[%d]: reject executor_id=%llu dispatch_gen=%u after "
                "execution-domain cleanup failure flags=0x%x",
                getpid(),
                static_cast<unsigned long long>(msg.executor_id),
                msg.dispatch_gen,
                cleanup_failure_flags);
            return ::write(done_pipe_w, &failed, sizeof(failed)) ==
                   static_cast<ssize_t>(sizeof(failed));
        };
        if (cleanup_failure_flags != 0) {
            if (workdir_armed && !RemoveDirRecursive(workdir_buf)) {
                cleanup_failure_flags |= kCleanupWorkdirRemoveFailed;
            }
            if (!reject_for_cleanup_failure()) {
                _exit(1);
            }
            continue;
        }

        ProgramRuntimeInput input{};
        input.input_len     = msg.input_len;
        input.flags         = msg.flags;
        input.executor_id   = msg.executor_id;
        input.dispatch_gen  = msg.dispatch_gen;
        input.buffers       = msg.buffers;
        input.perf_trace = collect_loop_perf ? &program_perf : nullptr;
        input.perf_sample = collect_loop_perf ? &program_perf.child : nullptr;

        if (!ResolveProgramBuffers(msg, program_mapping, &input)) {
            LOG("child[%d]: invalid program buffer descriptor source=%u worker=%u",
                getpid(), static_cast<unsigned>(msg.buffers.source),
                msg.buffers.worker_id);
            _exit(8);
        }

        // [full staging] redirect the program-child to anon-shared staging so
        // fork/exit skip the BAR window's page tables. ResolveProgramBuffers just
        // set input.{input,output,result_page} to the BAR; remember the BAR
        // output + result page as transcribe targets (the host reads output from
        // the BAR and the adapter reads crash_len from the BAR result page), copy
        // the program bytes BAR input → staging input (the child reads staging),
        // then point the child at staging. ivshmem only (staging_window != null);
        // stdio keeps its buffers direct — nothing to transcribe.
        uint8_t* deliver_output = nullptr;
        ProgramResultPageV3* deliver_result_page = nullptr;
        if (staging_window != nullptr) {
            deliver_output = input.output;
            deliver_result_page = input.result_page;
            if (input.input != nullptr && msg.input_len > 0) {
                std::memcpy(staging_window->input_pool, input.input,
                            std::min<size_t>(msg.input_len, MAX_INPUT_SIZE));
            }
            input.input = staging_window->input_pool;
            input.output = staging_window->output_pool;
            input.result_page = &staging_window->result_page;
        }

        // [G4 stdio result page wiring] stdio profile has no shared result page,用
        // LoopRuntime 入口 mmap 的 anon shared page 代替 — 走跟 ivshmem 路径
        // 完全相同的 commit/read protocol。partial fallback 也跟着启用。
        if (input.result_page == nullptr) {
            input.result_page = stdio_fallback_result_page;
        }
        if (input.result_page != nullptr) {
            InitProgramResultPage(input.result_page, msg.executor_id,
                                  msg.dispatch_gen, proc_id);
            input.crash_len_ptr = &input.result_page->crash_len;
            input.progress_completed_calls =
                &input.result_page->progress_completed_calls;
            input.progress_output_len =
                &input.result_page->progress_output_len;
        }
        loop_perf.input_bytes = msg.input_len;

        if (workdir_armed) {
            input.workdir = workdir_buf;
        }
        ++program_iter;

        ::refuzz::worker::topology::EmitTopologyProbeSelf(
            "loop-before-program", worker_id, msg.executor_id,
            msg.dispatch_gen);
        ::refuzz::worker::topology::EmitTopologyProbeCgroup(
            "loop-before-program", worker_id, proc_id, msg.executor_id,
            msg.dispatch_gen, 16);

        // [remote-kcov S2] Clear the extra remote KCOV cursor (area[0]=0) in
        // THIS loop_child task, immediately before ExecuteProgram forks the
        // program-child. The reset writes the shared kernel kcov->area for the
        // COMMON handle, so the program-child (which inherits the fd + handle)
        // accumulates async/softirq/kthread coverage from a clean 0. The
        // collect+emit is done program-side by KcovSink::PackFeedback, which
        // appends the accumulated PCs as a program-level kCoverageKcov packet
        // (see kcov_sink.cpp / docs/plans/refuzz-remote-kcov.md S2). Host decode
        // merges that packet into the program PC union (S3).
        if (extra_kcov != nullptr) {
            extra_kcov->ResetExtraProgram();
        }

        // [early-publish + full staging] hand the executor a hook that
        // transcribes the child's staged output into the BAR and writes the
        // DoneMsg to the daemon the instant the program child commits — before it
        // dies and is reaped. The forking executor always publishes through the
        // hook (fast path at commit; every other path leaves it unpublished and
        // the fallback below delivers `done`). The inline executor ignores the
        // hook, so the fallback is its normal delivery path.
        DoneMsg done{};
        EarlyPublishState publish_state{done_pipe_w};
        publish_state.staging_output =
            staging_window != nullptr ? staging_window->output_pool : nullptr;
        publish_state.deliver_output = deliver_output;
        publish_state.output_cap = input.output_cap;
        publish_state.staging_result_page =
            staging_window != nullptr ? &staging_window->result_page : nullptr;
        publish_state.deliver_result_page = deliver_result_page;
        input.publish_result = &PublishDoneToDaemon;
        input.publish_result_ctx = &publish_state;
        const ParentTimelinePoint tl_parent_engine_start = collect_exec_timeline
            ? SampleParentTimelinePoint() : ParentTimelinePoint{};
        const ParentTimelineDelta tl_parent_pre = collect_exec_timeline
            ? ParentTimelineDiff(tl_parent_claim, tl_parent_engine_start)
            : ParentTimelineDelta{};
        publish_state.collect = collect_exec_timeline;
        phase_start = collect_loop_perf ? ::refuzz::worker::perf::NowUs() : 0;
        executor.ExecuteProgram(input, &done);
        // [ExecTL delivery] on the fast path the publish ran INSIDE
        // ExecuteProgram, so subtract it here; kDelivery is charged once,
        // below, from publish_state.delivery_us. Keeps the four stages
        // mutually exclusive on both paths. This subtraction applies to the
        // worker-perf stage ONLY -- tl_parent_engine (pec/peq) below is
        // sampled around the same call and deliberately still includes the
        // publish; see EmitExecTimelineLoopLine.
        if (collect_loop_perf && phase_start != 0) {
            uint64_t executor_us = ::refuzz::worker::perf::NowUs() - phase_start;
            executor_us -= (publish_state.delivery_us < executor_us)
                               ? publish_state.delivery_us
                               : executor_us;
            ::refuzz::worker::perf::AddStage(
                &loop_perf,
                ::refuzz::worker::perf::LoopStage::kExecutor,
                executor_us);
        }
        const ParentTimelinePoint tl_parent_engine_end = collect_exec_timeline
            ? SampleParentTimelinePoint() : ParentTimelinePoint{};
        const ParentTimelineDelta tl_parent_engine = collect_exec_timeline
            ? ParentTimelineDiff(tl_parent_engine_start, tl_parent_engine_end)
            : ParentTimelineDelta{};

        loop_perf.output_bytes = done.output_len;
        // [ExecTL] stash this request's record; emitted next iteration
        // together with R/A2.
        if (collect_exec_timeline) {
            tl_pending_valid = true;
            tl_pending_id = msg.executor_id;
            tl_pending_done = done;
            tl_pending_parent = {};
            tl_pending_parent.pre = tl_parent_pre;
            tl_pending_parent.engine = tl_parent_engine;
            tl_pending_parent_engine_end = tl_parent_engine_end;
        }

        if (!publish_state.published) {
            // Inline executor, or a forking path that returned without
            // committing (harness fatal / outer-fork failure): transcribe (if
            // staging) + publish now through the same hook the fast path uses.
            // Self-timed inside PublishDoneToDaemon, same as the fast path.
            const bool ok = PublishDoneToDaemon(&publish_state, done);
            if (!ok) {
                _exit(1); // pipe broken
            }
        } else if (!publish_state.ok) {
            _exit(1); // early publish hit a broken done pipe
        }
        // [ExecTL delivery] charged once, whichever path published.
        if (collect_loop_perf && publish_state.delivery_us != 0) {
            ::refuzz::worker::perf::AddStage(
                &loop_perf,
                ::refuzz::worker::perf::LoopStage::kDelivery,
                publish_state.delivery_us);
        }
        if (collect_exec_timeline) {
            tl_pending_transcribe_cpu_us = publish_state.transcribe_cpu_us;
        }

        // syzkaller replies first, then performs synchronous remove_dir. The
        // loop domain owns a private MS_PRIVATE mount namespace, so no global
        // mountinfo sweep or lazy-detach fallback is needed here.
        phase_start = collect_loop_perf
            ? ::refuzz::worker::perf::NowUs() : 0;
        bool cleanup_ok = true;
        if (loop_baseline_cwd_fd >= 0 &&
            ::fchdir(loop_baseline_cwd_fd) != 0) {
            LOG("child[%d]: post-reply fchdir(baseline) failed errno=%d",
                getpid(), errno);
            cleanup_ok = false;
            cleanup_failure_flags |= kCleanupCwdRestoreFailed;
        }
        if (workdir_armed && !RemoveDirRecursive(workdir_buf)) {
            cleanup_ok = false;
            cleanup_failure_flags |= kCleanupWorkdirRemoveFailed;
        }
        AddLoopElapsed(
            collect_loop_perf ? &loop_perf : nullptr,
            ::refuzz::worker::perf::LoopStage::kCleanup,
            phase_start);
        if (collect_loop_perf) {
            ::refuzz::worker::perf::RecordProgramSample(worker_id, program_perf);
        }
        if (!cleanup_ok) {
            LOG("child[%d]: post-reply cleanup failed executor_id=%llu "
                "dispatch_gen=%u; next request will force domain rebuild",
                getpid(),
                static_cast<unsigned long long>(msg.executor_id),
                msg.dispatch_gen);
        }
    }
}

} // namespace refuzz::worker::engine

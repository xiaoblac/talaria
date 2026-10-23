// Copyright 2026 reFuzz project author -------youngkk.
//
// KernelWireDriver implementation — Layer-2 of §3.3.
//
// Streams the exec wire straight from the input buffer via WireStreamReader
// (no materialized WireProgram), writes the upstream syzkaller executor's data
// segment into a private mmap region as it goes, and dispatches each syscall
// through the injected `IDispatcher`.
//
// Design notes:
//   - Scratch is per-Execute (zeroed each call). Layer-2 minimal version;
//     reuse / persistent backing is a future optimization once we measure
//     the per-task memset cost.
//   - call_id → syscall nr translation goes through a generated lite table
//     so worker hot paths do not construct the full Target schema.
//     Do not include the full schema header or call the full Target
//     singleton here: doing so reintroduces the ~27 MiB schema heap into
//     the DoubleFork template.
//   - copyout table size matches upstream's kMaxCommands (1000).
//   - Inet csum computation is a verbatim port of syzkaller executor's
//     csum_inet_update (host-endian 16-bit ones-complement sum). Symmetric
//     under endianness, so straight memcpy-add is correct.

#include "worker/driver/kernel_wire_driver.hpp"

#include "refuzz/program/syz/pseudo/limits.hpp"  // kSyzMaxArgs
#include "refuzz/program/syz/exec_wire_decode.hpp"
#include "refuzz/program/syz/generated/target_linux_amd64_call_table.gen.hpp"
#include "refuzz/proto_wire/feedback_wire.hpp"  // [v2 batch 3 PR-X review] WorkerFeedbackHeader for kKcovPacketReserve
#include "refuzz/proto_wire/ivshmem_protocol.h" // SYZKALLER_MAX_OUTPUT_* budget constants
#include "worker/backend/pseudo/pseudo_runtime.hpp"
#include "worker/backend/syz_exec_runner.hpp"   // SyzExecResult, kSyzExecScratchBytes
#include "worker/coverage/kcov_collector.hpp"   // [v2 batch 3 PR-X review] kKcovEntries
#include "worker/driver/kernel_thread_pool.hpp" // [v2 Epic 7 PR-4]
#include "worker/exec_mode.hpp"
#include "worker/log/log_macros.hpp"            // [v2 Epic 7 PR-8] tagged -1 diagnostics
#include "worker/perf/worker_perf.hpp"
#include "worker/topology/topology_probe.hpp"

#include <algorithm>
#include <bit>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <span>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <thread>
#include <unistd.h>
#include <utility>
#include <variant>
#include <vector>

namespace refuzz::worker {

namespace {

constexpr int kExecuteKcovStateInvalid = -2;

} // namespace

// Defined in src/backend/syz_exec_runner.cpp. Lazy thread-local mmap;
// `PreallocateSyzExecScratch` is declared in the public header.
uint8_t* AcquireScratch();

namespace {

namespace syz = ::refuzz::program::syz;

constexpr std::size_t kMaxCommands = 1000;
constexpr std::size_t kMaxArgs     = ::refuzz::fuzzer::syz::kSyzMaxArgs;
constexpr uint64_t    kExecNoCopyout = ~uint64_t{0};


// Whole-program per-call coverage tail budget must be derived from the output
// buffer, not from the per-syscall KCOV collector area size.
//
// Keep one worst-case sink packet worth of headroom so task-end CMP feedback
// and small metric packets can still append after the driver writes
//   [SyzExecResult × n_calls][uint64 × per-call tail].
constexpr std::size_t kFeedbackReserveBytes =
    sizeof(refuzz::proto::WorkerFeedbackHeader) +
    (kKcovEntries - 1) * sizeof(std::uint64_t);
// PC mode no longer emits a task-end KCOV packet. Only lightweight sink data
// (for example pseudo-dispatch metrics) needs headroom.
constexpr std::size_t kPcFeedbackReserveBytes = 64u << 10;

bool SkipFullScratchMemset()
{
    static const bool skip = [] {
        const char* env = std::getenv("REFUZZ_SKIP_SCRATCH_MEMSET");
        return env != nullptr && env[0] == '1' && env[1] == '\0';
    }();
    return skip;
}

bool ShouldFullClearScratch(ExecMode mode)
{
    if (SkipFullScratchMemset()) {
        return false;
    }
    return mode.scratch_reset == ScratchResetMode::kFullClear;
}

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
    while (len > 0 && (out_buf[len - 1] == '\n' ||
                       out_buf[len - 1] == '\r')) {
        --len;
    }
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
    if (value == RLIM_INFINITY) {
        std::snprintf(buf, cap, "inf");
    } else {
        std::snprintf(buf, cap, "%llu",
                      static_cast<unsigned long long>(value));
    }
    return buf;
}

void EmitCloneSnap(const char* phase,
                   uint32_t proc_slot_id,
                   uint64_t executor_id,
                   std::size_t call_index,
                   uint64_t call_id,
                   uint64_t nr,
                   const intptr_t* args,
                   std::size_t argc,
                   long ret,
                   int err)
{
    if (!::refuzz::worker::topology::TopologyProbeEnabled()) {
        return;
    }
    if (nr != 1048585uLL && nr != 1048586uLL) {
        return;
    }
    static int kRemaining = 512;
    if (kRemaining <= 0) {
        return;
    }
    --kRemaining;

    char pids_current_path[128];
    char pids_max_path[128];
    char procs_path[128];
    char threads_path[128];
    std::snprintf(pids_current_path, sizeof(pids_current_path),
                  "/syzcgroup/unified/syz%u/pids.current", proc_slot_id);
    std::snprintf(pids_max_path, sizeof(pids_max_path),
                  "/syzcgroup/unified/syz%u/pids.max", proc_slot_id);
    std::snprintf(procs_path, sizeof(procs_path),
                  "/syzcgroup/unified/syz%u/cgroup.procs", proc_slot_id);
    std::snprintf(threads_path, sizeof(threads_path),
                  "/syzcgroup/unified/syz%u/cgroup.threads", proc_slot_id);

    const long pids_current = ReadIntFile(pids_current_path);
    char pids_max[32] = {0};
    ReadLimitTextFile(pids_max_path, pids_max, sizeof(pids_max));
    const int procs_lines = CountLines(procs_path);
    const int threads_lines = CountLines(threads_path);
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

    const char* call_name = (nr == 1048585uLL) ? "syz_clone" : "syz_clone3";
    const long flags =
        (args != nullptr && argc > 0) ? static_cast<long>(args[0]) : 0;
    ::refuzz::worker::log::WorkerLog(
        "[clone-snap] phase=%s wid=%u eid=%llu call_idx=%zu call_id=%llu "
        "call=%s flags=0x%lx ret=%ld errno=%d caller_pid=%d caller_tid=%ld "
        "rlimit_nproc=%s/%s pid_max=%ld threads_max=%ld proc_count=%d "
        "thread_count=%d pids.current=%ld pids.max=%s procs_lines=%d "
        "threads_lines=%d\n",
        phase != nullptr ? phase : "unknown",
        proc_slot_id,
        static_cast<unsigned long long>(executor_id),
        call_index,
        static_cast<unsigned long long>(call_id),
        call_name,
        flags,
        ret,
        err,
        static_cast<int>(::getpid()),
        static_cast<long>(::syscall(SYS_gettid)),
        rlim_cur,
        rlim_max,
        kernel_pid_max,
        kernel_threads_max,
        proc_count,
        thread_count,
        pids_current,
        pids_max,
        procs_lines,
        threads_lines);
}

std::size_t ComputeCoverageTailBudgetEntries(uint32_t output_cap,
                                             std::size_t max_calls,
                                             KcovMode mode)
{
    const std::size_t syzkaller_cap =
        (mode == KcovMode::kCmp) ? SYZKALLER_MAX_OUTPUT_COMPARISONS
                                 : SYZKALLER_MAX_OUTPUT_COVERAGE;
    const std::size_t effective_cap =
        std::min(static_cast<std::size_t>(output_cap), syzkaller_cap);
    const std::size_t results_budget = max_calls * sizeof(SyzExecResult);
    if (effective_cap <= results_budget) {
        return 0;
    }
    const std::size_t free_bytes = effective_cap - results_budget;
    const std::size_t reserve_bytes =
        (mode == KcovMode::kCmp) ? kFeedbackReserveBytes
                                 : kPcFeedbackReserveBytes;
    if (free_bytes <= reserve_bytes) {
        return 0;
    }
    return (free_bytes - reserve_bytes) / sizeof(std::uint64_t);
}

// [v2 PR-A — special pointer wire reversal]
// 把 wire_addr (encoder 输出的 phys-data_offset 编码) 反演成 reFuzz 进程内
// 可解引用的 64-bit 值。两个调用点 (resolve_call_arg / apply_copyin) 走
// 同一逻辑,保证嵌套指针和顶层指针 arg 同语义。
//
// 上游 syzkaller executor mmap MAP_FIXED 在 data_offset (=0x2000_0000_0000,
// 即 32 TiB)。普通指针 wire_addr ∈ [0, scratch_size),va = wire_addr +
// data_offset 直接落进已映射区,可解引用。special pointer (NULL / 0xff..ff
// / 0x99..99 / kernel / vdso) 由 64-bit unsigned 加法 wrap 算回 phys 原值
// (e.g. wire 0xffffe000_00000000 + 0x2000_0000_0000 回到 0=NULL),
// 交给 kernel -EFAULT / pseudo handler null-check 兜底。
//
// reFuzz 不做 MAP_FIXED (避免 ASLR 冲突 + sanitizer 兼容),改成把 va
// 在落进 scratch 范围时翻译到真 reFuzz scratch VA;落不进的视为 special
// pointer 写 literal,留给 caller 同样兜底。
uint64_t resolve_wire_addr(uint64_t wire_addr,
                           const uint8_t* scratch,
                           std::size_t scratch_cap,
                           uint64_t data_offset) {
    const uint64_t va_upstream = wire_addr + data_offset;  // 上游加法,wrap 算回 phys
    // 第二个判定写成 (va - data_offset) < scratch_cap 而不是
    // va < data_offset + scratch_cap: 由前一条 >= data_offset 保证不下溢,
    // 且未来 scratch_cap 增大时不需要担心 64-bit 加法溢出。
    if (va_upstream >= data_offset && (va_upstream - data_offset) < scratch_cap) {
        return reinterpret_cast<uint64_t>(scratch) + (va_upstream - data_offset);
    }
    return va_upstream;
}



// [v2 Epic 6 D-3 — fail_nth honored end-to-end via inject_fault hook;
//  async / rerun remain rejected (§10 N1/N2 permanent non-goals).]
bool supported_wire_set_props(const syz::WireSetProps& props) {
    return !props.async && props.rerun == 0;
}

bool supported_threaded_wire_set_props(const syz::WireSetProps& props) {
    return props.rerun == 0;
}

// ---- Endianness helpers ----

uint64_t byteswap_to_size(uint64_t v, uint64_t size) {
    if (size == 0 || size > 8) return v;
    uint64_t r = 0;
    for (uint64_t i = 0; i < size; ++i) {
        r = (r << 8) | (v & 0xFF);
        v >>= 8;
    }
    return r;
}

bool is_native_int_size(uint64_t size) {
    return size == 1 || size == 2 || size == 4 || size == 8;
}

const char* binary_format_name(syz::BinaryFormat fmt) {
    switch (fmt) {
    case syz::BinaryFormat::kNative:
        return "native";
    case syz::BinaryFormat::kBigEndian:
        return "bigendian";
    case syz::BinaryFormat::kStrDec:
        return "strdec";
    case syz::BinaryFormat::kStrHex:
        return "strhex";
    case syz::BinaryFormat::kStrOct:
        return "stroct";
    }
    return "unknown";
}

bool scratch_range_ok(uint64_t addr, uint64_t size, std::size_t scratch_cap) {
    const uint64_t cap = static_cast<uint64_t>(scratch_cap);
    return addr <= cap && size <= cap - addr;
}

// ---- Internet checksum (port of syzkaller executor common.h
//      csum_inet_update + csum_inet_digest). 16-bit ones-complement sum;
//      symmetric under endianness, so memcpy-add is correct.
struct CsumAcc { uint32_t acc = 0; };

void csum_inet_update(CsumAcc* c, const uint8_t* data, std::size_t length) {
    if (length == 0) return;
    std::size_t i = 0;
    for (; i + 2 <= length; i += 2) {
        uint16_t w;
        std::memcpy(&w, data + i, 2);  // host-endian read; symmetric
        c->acc += w;
    }
    if (i < length) {
        // Trailing odd byte — pad with zero in the high byte (low-endian view).
        uint16_t w = static_cast<uint16_t>(data[i]);
        c->acc += w;
    }
    while (c->acc > 0xFFFF) {
        c->acc = (c->acc & 0xFFFF) + (c->acc >> 16);
    }
}

uint16_t csum_inet_digest(const CsumAcc& c) {
    return static_cast<uint16_t>(~c.acc & 0xFFFF);
}

// ---- Integer-to-scratch renderer (mirror of upstream executor copyin()).
//
// 镜像 upstream executor.cc:1654-1698 copyin() 的 fmt 分支:
//   strdec  size=20  → "%020llu"     (zero-padded decimal, no prefix)
//   strhex  size=18  → "0x%016llx"   (0x prefix + 16-hex-digit)
//   stroct  size=23  → "%023llo"     (zero-padded octal,  no prefix)
//   bigendian        → byteswap_to_size + binary memcpy
//   native           → binary memcpy
//
// size 对 strdec/strhex/stroct 是硬约束 — schema codegen + wire encoder 都按
// 这些值标 Type.size。size 不匹配就是 schema/wire bug;按 upstream
// failmsg 语义打印并让本次执行失败,不能 fallback 到 Native。
//
// 不写 NUL 终止符 — 上游 sprintf 会写,但 syzkaller schema 把后续 ','/'='
// 字节排在 strN 字段后面,Type packed layout 已经把"分隔符"安排好;NUL
// 提前终止会让 kernel options parser 把后续 key=val 全丢(本次 fuse mount
// EINVAL bug 根因)。这里 snprintf size+1 让它 NUL,然后只 memcpy size byte
// 进 scratch,丢掉那个 NUL。
//
// 给 WireConst (走 write_const_to_scratch) 和 WireResult (走 apply_copyin)
// 共用。上游 executor.cc:996-1003 的 copyin(arg_result) 路径把 fmt 从 meta
// 提取后传给 copyin() — reFuzz 之前 WireResult 路径忽略 fmt,直接 binary
// memcpy,fuse mount opts 的 fd=<ResultArg> 被写成 binary 5 字节而非 zero
// -padded decimal 20 字符,kernel 看到乱码 → -EINVAL。
bool write_int_to_scratch(uint8_t* scratch, std::size_t scratch_cap,
                          uint64_t addr, uint64_t size, uint64_t val,
                          syz::BinaryFormat fmt) {
    if (size == 0) {
        ::refuzz::worker::log::WorkerLog(
            "[Driver] reject tag=bad_copyin_int_size fmt=%s fmt_raw=%u size=%llu addr=%llu\n",
            binary_format_name(fmt),
            static_cast<unsigned>(fmt),
            static_cast<unsigned long long>(size),
            static_cast<unsigned long long>(addr));
        return false;
    }
    if (!scratch_range_ok(addr, size, scratch_cap)) {
        ::refuzz::worker::log::WorkerLog(
            "[Driver] reject tag=copyin_oob fmt=%s fmt_raw=%u addr=%llu size=%llu cap=%zu\n",
            binary_format_name(fmt),
            static_cast<unsigned>(fmt),
            static_cast<unsigned long long>(addr),
            static_cast<unsigned long long>(size),
            scratch_cap);
        return false;
    }

    switch (fmt) {
    case syz::BinaryFormat::kStrDec: {
        if (size != 20) {
            ::refuzz::worker::log::WorkerLog(
                "[Driver] reject tag=bad_strdec_size size=%llu addr=%llu\n",
                static_cast<unsigned long long>(size),
                static_cast<unsigned long long>(addr));
            return false;
        }
        char tmp[32];
        std::snprintf(tmp, sizeof(tmp), "%020llu",
                      static_cast<unsigned long long>(val));
        std::memcpy(scratch + addr, tmp, 20);
        return true;
    }
    case syz::BinaryFormat::kStrHex: {
        if (size != 18) {
            ::refuzz::worker::log::WorkerLog(
                "[Driver] reject tag=bad_strhex_size size=%llu addr=%llu\n",
                static_cast<unsigned long long>(size),
                static_cast<unsigned long long>(addr));
            return false;
        }
        char tmp[32];
        std::snprintf(tmp, sizeof(tmp), "0x%016llx",
                      static_cast<unsigned long long>(val));
        std::memcpy(scratch + addr, tmp, 18);
        return true;
    }
    case syz::BinaryFormat::kStrOct: {
        if (size != 23) {
            ::refuzz::worker::log::WorkerLog(
                "[Driver] reject tag=bad_stroct_size size=%llu addr=%llu\n",
                static_cast<unsigned long long>(size),
                static_cast<unsigned long long>(addr));
            return false;
        }
        char tmp[32];
        std::snprintf(tmp, sizeof(tmp), "%023llo",
                      static_cast<unsigned long long>(val));
        std::memcpy(scratch + addr, tmp, 23);
        return true;
    }
    case syz::BinaryFormat::kBigEndian:
        if (!is_native_int_size(size)) {
            ::refuzz::worker::log::WorkerLog(
                "[Driver] reject tag=bad_copyin_int_size fmt=bigendian size=%llu addr=%llu\n",
                static_cast<unsigned long long>(size),
                static_cast<unsigned long long>(addr));
            return false;
        }
        val = byteswap_to_size(val, size);
        break;
    case syz::BinaryFormat::kNative:
        if (!is_native_int_size(size)) {
            ::refuzz::worker::log::WorkerLog(
                "[Driver] reject tag=bad_copyin_int_size fmt=native size=%llu addr=%llu\n",
                static_cast<unsigned long long>(size),
                static_cast<unsigned long long>(addr));
            return false;
        }
        break;
    default:
        ::refuzz::worker::log::WorkerLog(
            "[Driver] reject tag=unknown_binary_format fmt_raw=%u size=%llu addr=%llu\n",
            static_cast<unsigned>(fmt),
            static_cast<unsigned long long>(size),
            static_cast<unsigned long long>(addr));
        return false;
    }
    std::memcpy(scratch + addr, &val, size);
    return true;
}

// ---- Const-arg memory write (mirror of upstream executor write_arg).
bool write_const_to_scratch(uint8_t* scratch, std::size_t scratch_cap,
                            uint64_t addr, const syz::WireConst& w,
                            uint32_t proc_slot_id) {
    if (w.size == 0) {
        ::refuzz::worker::log::WorkerLog(
            "[Driver] reject tag=bad_copyin_const_size size=0 addr=%llu\n",
            static_cast<unsigned long long>(addr));
        return false;
    }
    if (!scratch_range_ok(addr, w.size, scratch_cap)) {
        ::refuzz::worker::log::WorkerLog(
            "[Driver] reject tag=copyin_oob kind=const addr=%llu size=%llu cap=%zu\n",
            static_cast<unsigned long long>(addr),
            static_cast<unsigned long long>(w.size),
            scratch_cap);
        return false;
    }

    uint64_t val = w.val;
    if (w.pid_stride != 0) {
        val += static_cast<uint64_t>(proc_slot_id) * w.pid_stride;
    }

    if (w.bf_len == 0) {
        return write_int_to_scratch(scratch, scratch_cap, addr, w.size, val, w.fmt);
    }
    // Bitfield: read-modify-write within the integer unit. String formats on
    // bitfields match upstream's "bitmask for string format" failmsg path.
    if (w.fmt != syz::BinaryFormat::kNative &&
        w.fmt != syz::BinaryFormat::kBigEndian) {
        ::refuzz::worker::log::WorkerLog(
            "[Driver] reject tag=bitfield_string_format fmt=%s fmt_raw=%u addr=%llu size=%llu\n",
            binary_format_name(w.fmt),
            static_cast<unsigned>(w.fmt),
            static_cast<unsigned long long>(addr),
            static_cast<unsigned long long>(w.size));
        return false;
    }
    if (!is_native_int_size(w.size)) {
        ::refuzz::worker::log::WorkerLog(
            "[Driver] reject tag=bad_copyin_bitfield_size size=%llu addr=%llu\n",
            static_cast<unsigned long long>(w.size),
            static_cast<unsigned long long>(addr));
        return false;
    }
    uint64_t cur = 0;
    std::memcpy(&cur, scratch + addr, w.size);
    if (w.fmt == syz::BinaryFormat::kBigEndian) {
        cur = byteswap_to_size(cur, w.size);
    }
    const uint64_t mask  = (w.bf_len < 64) ? ((uint64_t{1} << w.bf_len) - 1)
                                           : ~uint64_t{0};
    const uint64_t shift = w.bf_off;
    cur &= ~(mask << shift);
    cur |=  (val & mask) << shift;
    uint64_t out = cur;
    if (w.fmt == syz::BinaryFormat::kBigEndian) {
        out = byteswap_to_size(out, w.size);
    }
    std::memcpy(scratch + addr, &out, w.size);
    return true;
}

// ---- Csum-arg memory write.
bool write_csum_to_scratch(uint8_t* scratch, std::size_t scratch_cap,
                           uint64_t addr, const syz::WireCsum& w) {
    if (w.csum_kind != 0) {
        ::refuzz::worker::log::WorkerLog(
            "[Driver] reject tag=unsupported_csum kind=%llu addr=%llu\n",
            static_cast<unsigned long long>(w.csum_kind),
            static_cast<unsigned long long>(addr));
        return false;
    }
    if (!scratch_range_ok(addr, 2, scratch_cap)) {
        ::refuzz::worker::log::WorkerLog(
            "[Driver] reject tag=copyin_oob kind=csum addr=%llu size=2 cap=%zu\n",
            static_cast<unsigned long long>(addr),
            scratch_cap);
        return false;
    }
    CsumAcc acc{};
    for (const auto& ch : w.chunks) {
        if (ch.kind == syz::WireCsumChunkKind::kArgData) {
            const uint64_t a = ch.addr_or_value;
            const uint64_t s = ch.size;
            if (!scratch_range_ok(a, s, scratch_cap)) {
                ::refuzz::worker::log::WorkerLog(
                    "[Driver] reject tag=copyin_oob kind=csum_chunk addr=%llu size=%llu cap=%zu\n",
                    static_cast<unsigned long long>(a),
                    static_cast<unsigned long long>(s),
                    scratch_cap);
                return false;
            }
            csum_inet_update(&acc, scratch + a, static_cast<std::size_t>(s));
        } else {
            // Const chunk: encoder packed the value into a uint64 with the
            // network-order bytes in the low N positions (after swap16/32).
            if (ch.size > 8) {
                ::refuzz::worker::log::WorkerLog(
                    "[Driver] reject tag=bad_csum_const_size size=%llu addr=%llu\n",
                    static_cast<unsigned long long>(ch.size),
                    static_cast<unsigned long long>(addr));
                return false;
            }
            uint64_t v = ch.addr_or_value;
            uint8_t  buf[8];
            std::memcpy(buf, &v, sizeof(buf));
            csum_inet_update(&acc, buf, static_cast<std::size_t>(ch.size));
        }
    }
    const uint16_t sum = csum_inet_digest(acc);
    std::memcpy(scratch + addr, &sum, 2);
    return true;
}

// ---- Arg resolution for a syscall call ----
//
// Translates a WireArg appearing as a top-level call argument into the
// intptr_t value the kernel will see. Unknown/unsupported variants
// resolve to 0 (which mirrors upstream's null-fallback for malformed
// args and keeps the call from corrupting unrelated state).
//
// [v2 PR-A — 添加 data_offset + scratch_cap 给 resolve_wire_addr 用]
intptr_t resolve_call_arg(const uint8_t* scratch,
                          const syz::WireArg& arg,
                          const int64_t copyout[],
                          const bool    copyout_set[],
                          uint32_t proc_slot_id,
                          uint64_t data_offset,
                          std::size_t scratch_cap) {
    if (auto* w = std::get_if<syz::WireConst>(&arg)) {
        uint64_t val = w->val;
        if (w->pid_stride != 0) val += static_cast<uint64_t>(proc_slot_id) * w->pid_stride;
        if (w->fmt == syz::BinaryFormat::kBigEndian) {
            val = byteswap_to_size(val, w->size);
        }
        return static_cast<intptr_t>(val);
    }

    // [v2 PR-A — WireAddr 走 resolve_wire_addr helper,special pointer 翻译为 literal]
    if (auto* w = std::get_if<syz::WireAddr>(&arg)) {
        return static_cast<intptr_t>(
            resolve_wire_addr(w->addr, scratch, scratch_cap, data_offset));
    }
    if (auto* w = std::get_if<syz::WireResult>(&arg)) {
        int64_t v;
        if (w->idx < kMaxCommands && copyout_set[w->idx]) {
            v = copyout[w->idx];
        } else {
            v = static_cast<int64_t>(w->default_val);
        }
        if (w->op_div != 0) v = static_cast<int64_t>(static_cast<uint64_t>(v) / w->op_div);
        v += static_cast<int64_t>(w->op_add);
        return static_cast<intptr_t>(v);
    }
    if (auto* w = std::get_if<syz::WireData>(&arg)) {
        // Data args at the call top-level are unusual (data normally lives
        // behind a pointer arg, written by an earlier copyin). When they
        // do appear, upstream passes a pointer to the inline blob; we'd
        // need an in-driver staging buffer to honor that. For Layer-2 we
        // log the call would corrupt; defer the rare case until corpus
        // surfaces it.
        (void)w;
        return 0;
    }
    if (std::get_if<syz::WireCsum>(&arg)) {
        // Csum doesn't appear as a call arg in upstream; would be a wire
        // oddity. Fall through to 0.
        return 0;
    }
    return 0;
}

// ---- Copyin dispatch ----
// [v2 PR-A — 添加 data_offset 给 resolve_wire_addr 用]
bool apply_copyin(uint8_t* scratch, std::size_t scratch_cap,
                  const syz::WireCopyin& ci,
                  const int64_t copyout[],
                  const bool    copyout_set[],
                  uint32_t proc_slot_id,
                  uint64_t data_offset) {
    if (auto* w = std::get_if<syz::WireConst>(&ci.arg)) {
        return write_const_to_scratch(scratch, scratch_cap, ci.addr, *w, proc_slot_id);
    }
    // [v2 PR-A — WireAddr 走 resolve_wire_addr helper]
    // 旧实现把 raw wire_addr 写到 scratch 同时引发两类问题:
    //   (a) NULL/special pointer (wire_addr=0xffffe...0 等) 翻成野指针 →
    //       pseudo handler null-check 失效 → user-space SIGSEGV (本次 incident
    //       根因路径,见 docs/plans/worker-special-pointer-fix/00_charter.md §3)。
    //   (b) 普通嵌套指针 (wire_addr=0x40 等小偏移) 写出 0x40 自身,kernel
    //       解引用走到低地址未映射区 → -EFAULT,嵌套结构永远走不通。
    // 新实现走 resolve_wire_addr,scratch 范围内写真 reFuzz scratch VA,
    // 范围外写 literal va_upstream (NULL/-1/poison 都得到 wrap 后预期值)。
    if (auto* w = std::get_if<syz::WireAddr>(&ci.arg)) {
        if (!is_native_int_size(w->ptr_size)) {
            ::refuzz::worker::log::WorkerLog(
                "[Driver] reject tag=bad_copyin_ptr_size size=%u addr=%llu\n",
                static_cast<unsigned>(w->ptr_size),
                static_cast<unsigned long long>(ci.addr));
            return false;
        }
        if (!scratch_range_ok(ci.addr, w->ptr_size, scratch_cap)) {
            ::refuzz::worker::log::WorkerLog(
                "[Driver] reject tag=copyin_oob kind=addr addr=%llu size=%u cap=%zu\n",
                static_cast<unsigned long long>(ci.addr),
                static_cast<unsigned>(w->ptr_size),
                scratch_cap);
            return false;
        }
        const uint64_t val = resolve_wire_addr(w->addr, scratch, scratch_cap, data_offset);
        std::memcpy(scratch + ci.addr, &val, w->ptr_size);
        return true;
    }
    if (auto* w = std::get_if<syz::WireResult>(&ci.arg)) {
        int64_t v;
        if (w->idx < kMaxCommands && copyout_set[w->idx]) {
            v = copyout[w->idx];
        } else {
            v = static_cast<int64_t>(w->default_val);
        }
        if (w->op_div != 0) v = static_cast<int64_t>(static_cast<uint64_t>(v) / w->op_div);
        v += static_cast<int64_t>(w->op_add);
        // 镜像上游 executor.cc:996-1003 copyin(arg_result) — fmt 从 meta 提取
        // 后必须传给 copyin()。reFuzz 之前忽略 w->fmt,直接 binary memcpy,
        // 导致 fuse mount opts `fd=<ResultArg>` 写成 5 字节 binary 而非 20
        // 字符 zero-padded decimal → kernel mount opts parser 看到乱码 →
        // -EINVAL (fuse handler 阻塞,后续 read/write FUSE 全 EPERM 级联)。
        return write_int_to_scratch(scratch, scratch_cap, ci.addr, w->size,
                                    static_cast<uint64_t>(v), w->fmt);
    }
    if (auto* w = std::get_if<syz::WireData>(&ci.arg)) {
        if (!scratch_range_ok(ci.addr, w->data.size(), scratch_cap)) {
            ::refuzz::worker::log::WorkerLog(
                "[Driver] reject tag=copyin_oob kind=data addr=%llu size=%zu cap=%zu\n",
                static_cast<unsigned long long>(ci.addr),
                w->data.size(),
                scratch_cap);
            return false;
        }
        std::memcpy(scratch + ci.addr, w->data.data(), w->data.size());
        return true;
    }
    if (auto* w = std::get_if<syz::WireCsum>(&ci.arg)) {
        return write_csum_to_scratch(scratch, scratch_cap, ci.addr, *w);
    }
    ::refuzz::worker::log::WorkerLog(
        "[Driver] reject tag=unknown_copyin_arg addr=%llu\n",
        static_cast<unsigned long long>(ci.addr));
    return false;
}

// ---- Copyout snapshot ----
void apply_copyout(const uint8_t* scratch, std::size_t scratch_cap,
                   const syz::WireCopyout& co,
                   int64_t copyout[], bool copyout_set[]) {
    if (co.idx >= kMaxCommands) return;
    if (co.size == 0 || co.size > 8) return;
    if (co.addr + co.size > scratch_cap) return;
    int64_t v = 0;
    std::memcpy(&v, scratch + co.addr, co.size);
    copyout[co.idx]     = v;
    copyout_set[co.idx] = true;
}

} // namespace

// ----------------------------------------------------------------
// KernelWireDriver
// ----------------------------------------------------------------

KernelWireDriver::KernelWireDriver(std::unique_ptr<IDispatcher> dispatcher,
                                   uint32_t proc_slot_id,
                                   InjectFaultFn inject_fault_fn,
                                   FaultInjectedFn fault_injected_fn,
                                   uint32_t thread_count)
    : dispatcher_(std::move(dispatcher))
    , proc_slot_id_(proc_slot_id)
    // [v2 Epic 6 D-14 — fault-inject test seam]
    // 默认绑到 fault_inject.hpp 实现;test 通过传 mock 验证 graceful 失败
    // 路径(open<0 / read 异常)。
    , inject_fault_fn_(inject_fault_fn != nullptr ? inject_fault_fn
                                                  : &refuzz::worker::inject_fault)
    , fault_injected_fn_(fault_injected_fn != nullptr ? fault_injected_fn
                                                      : &refuzz::worker::fault_injected)
    , thread_count_(thread_count < 1 ? 1 : thread_count)
{
    // [v2 Epic 7 PR-4] pool_ 是 lazy 的:在第一次 threaded Execute 时构造。
    // 不在 ctor 构造的原因 — profile (kernel_syz_profile.cpp) 先 construct
    // driver,再 SetKcovProvider/SetKcovDrainSink;在 ctor 当下 kcov_provider_
    // 仍是 nullptr,pool 拿不到 collector source。lazy 构造能保证 wiring 完
    // 整后才生效。lazy 也避开了 thread_count > 1 但实际从未跑 threaded
    // task 时无谓的 pool 对象内存(虽然 N 个 stub WorkerThread struct 不
    // 大,语义上更干净)。
    //
    // thread_count_ == 1 时 pool_ 永远不构造(serial 路径不走 pool)。

}

KernelWireDriver::~KernelWireDriver() = default;

// [v2 Epic 7 PR-4] Forward decl —— threaded path body 在 Execute 下方,
// 与 serial path 共用 codec/scratch/wire walk 逻辑但 dispatch 由 thread pool
// 承担。详 ExecuteThreaded 实现。
static int ExecuteThreaded(
    const uint8_t* input, uint32_t input_len,
    uint8_t* output, uint32_t output_cap, uint32_t* output_len,
    ExecMode mode,
    KcovMode kcov_mode,
    KernelThreadPool& pool,
    IKcovDrainSink& drain_sink,
    uint32_t proc_slot_id,
    InjectFaultFn inject_fault_fn,
    FaultInjectedFn fault_injected_fn,
    IKcovCollectorProvider* kcov_provider,
    uint64_t diagnostic_executor_id,
    uint32_t* progress_completed,
    uint32_t* progress_output_len,
    // [当前版本 per-call-timeout-config] driver 成员 per_call_timeout_ms_
    // 透传,free function 不能直接访问。0 在 caller 已规整成默认 5000。
    uint32_t per_call_timeout_ms,
    // [threaded end-drain parity] program timeout (exec_timeout_ms),末尾 drain
    // 用它算 program_timeout/6 尾窗。
    uint32_t program_timeout_ms);

class ThreadedTaskDrainGuard {
public:
    ThreadedTaskDrainGuard(KernelThreadPool& pool,
                           IKcovDrainSink& drain_sink,
                           int pool_size,
                           ::refuzz::worker::perf::WorkerPerfSample* perf_sample)
        : pool_(pool)
        , drain_sink_(drain_sink)
        , pool_size_(pool_size)
        , perf_sample_(perf_sample)
    {}

    ~ThreadedTaskDrainGuard()
    {
        Finish();
    }

    ThreadedTaskDrainGuard(const ThreadedTaskDrainGuard&) = delete;
    ThreadedTaskDrainGuard& operator=(const ThreadedTaskDrainGuard&) = delete;

    void Finish()
    {
        if (!active_) {
            return;
        }
        active_ = false;
        ::refuzz::worker::perf::ScopedTimer timer(
            perf_sample_,
            ::refuzz::worker::perf::WorkerStage::kTaskCleanup);
        pool_.EndTaskAllUsed();
        for (int tid = 0; tid < pool_size_; ++tid) {
            if (!pool_.ThreadUsedInLastTask(tid)) {
                continue;
            }
            auto drained = pool_.TakeThreadDrained(tid);
            if (!drained.empty()) {
                drain_sink_.AppendThreadDrained(std::move(drained));
            }
        }
    }

    // [当前版本 threaded-cleanup-skip] 仅在 caller 100% 保证调用者进程即将
    // _exit (DoubleFork program child 路径) 且没有 in-process state 需要清理
    // 时调用。Disarm 之后 dtor 不再 Finish,worker thread 内的 collector.End /
    // ctx.Cleanup 全部跳过,由 kernel 在 child _exit 时回收 KCOV fd/mmap、
    // worker thread 状态、PseudoRuntimeContext owned_fds。CMP 模式 (需要
    // EndAsCmp drain records 给 PackFeedback) / Reusable child topology
    // (跨 program 复用 KCOV/ctx) / available_caps != 0 (cap-gated pseudo 可能
    // 持有 mount/shm/pkey 等 kernel-global 副作用) 三种情况下严禁 Disarm,
    // caller 必须显式判断后调用。
    void Disarm() noexcept
    {
        active_ = false;
    }

private:
    KernelThreadPool& pool_;
    IKcovDrainSink&   drain_sink_;
    int               pool_size_;
    ::refuzz::worker::perf::WorkerPerfSample* perf_sample_ = nullptr;
    bool              active_ = true;
};

int KernelWireDriver::Execute(const uint8_t* input, uint32_t input_len,
                              uint8_t* output, uint32_t output_cap,
                              uint32_t* output_len,
                              ExecMode mode)
{
    runtime_failure_ = RuntimeFailure::kNone;
    auto* perf_sample = ::refuzz::worker::perf::CurrentSample();
    ::refuzz::worker::perf::ScopedTimer driver_timer(
        perf_sample,
        ::refuzz::worker::perf::WorkerStage::kDriverTotal);

    if (output_len == nullptr) return -1;
    *output_len = 0;
    if (dispatcher_ == nullptr) return -1;

    // [v2 Epic 7 PR-4 — 当前版本 + PR-7 放宽 pseudo allowlist]
    // threaded path 解除 ban,前置条件 + dispatch 路径见下方 ExecuteThreaded。
    // hard reject 三条:
    //   - thread_count_ == 1: 不构造 pool,threaded 任务无 worker thread 可用
    //   - kcov_provider_ / kcov_drain_sink_ nullptr: KCOV 完整 lifecycle 必须
    //     依赖这两个接口才能让 collector 在 worker thread 上下文 Begin/End
    // 任意一条 fail 返 -1(exec_error,策略 B,不降级)。
    //
    // [v2 Epic 7 PR-7 — 当前版本] 对齐 upstream syzkaller — **不做 pre-flight
    // pseudo reject**。理由:
    //   1. upstream syzkaller 没有 ConcurrentSafe metadata (`prog.SyscallAttrs`
    //      字段集没有 concurrency 标);threaded 模式直接跑所有 pseudo,bug 即
    //      fuzz 的目标。
    //   2. reFuzz 的 KernelThreadPool 给每个 WorkerThread 一个**独立**的
    //      PseudoRuntimeContext (kernel_thread_pool.cpp:96),所以 ctx 字段
    //      (cleanup_callbacks/owned_fds/named_regions/tun_fd cache 等) 都是
    //      **per-thread**,**不再共享** — 这是原始 pre-flight 设计当时的核心
    //      担忧,但后来 ctx 改成 per-thread 后 race 已经消除,reject 变成
    //      冗余的保险带。
    //   3. 仍然存在的"共享"只剩 kernel 端状态 (eg. 两个 thread 同时 mount
    //      同 /dev/loopN),这正是 syzkaller threaded 模式要找的 race bug,
    //      不该用 host 端 reject 屏蔽。
    // 验证证据:Step 8 corpus regression 已确认无 worker_crash / kernel_crash,
    // 唯一升高的是 exec_error 数,且 root cause 正是这条 pre-flight 拦截。
    // 详 docs/syzkaller-integration/040_phase_d_pseudo_runtime_expansion.md §212。
    if (mode.intra == IntraTaskMode::kThreaded) {
        const int kcov_slots =
            (kcov_provider_ != nullptr) ? kcov_provider_->ThreadCount() : 0;
        if (thread_count_ <= 1 ||
            kcov_provider_ == nullptr ||
            kcov_drain_sink_ == nullptr ||
            kcov_slots <= 0) {
            ::refuzz::worker::log::WorkerLog(
                "[Driver/threaded] reject tag=bad_cfg tc=%u prov=%d drain=%d "
                "kcov_slots=%d need_slots=1\n",
                thread_count_,
                kcov_provider_ != nullptr ? 1 : 0,
                kcov_drain_sink_ != nullptr ? 1 : 0,
                kcov_slots);
            return -1;
        }
        // [streaming] Peek num_calls up front to preserve the empty-program
        // fast path and the decode-fail diagnostic; ExecuteThreaded re-opens a
        // WireStreamReader over the same bytes and streams the rest — no
        // WireProgram materialization on the threaded path either.
        uint64_t threaded_num_calls = 0;
        {
            syz::WireStreamReader head(
                std::span<const uint8_t>(input, input_len));
            ::refuzz::worker::perf::ScopedTimer timer(
                perf_sample,
                ::refuzz::worker::perf::WorkerStage::kDriverDecode);
            if (!head.ReadNumCalls(&threaded_num_calls)) {
                const auto& e = head.error();
                char hex[40] = {0};
                const uint32_t nh = std::min<uint32_t>(16u, input_len);
                for (uint32_t i = 0; i < nh; ++i) {
                    std::snprintf(hex + i * 2, sizeof(hex) - i * 2, "%02x",
                                  input[i]);
                }
                ::refuzz::worker::log::WorkerLog(
                    "[Driver/threaded] reject tag=decode_fail input_len=%u "
                    "err='%s' off=%zu head=%s\n",
                    input_len, e.message.c_str(), e.offset, hex);
                return -1;
            }
        }
        if (threaded_num_calls == 0) {
            *output_len = 0;
            return 0;
        }
        // lazy 构造 pool(profile 已经在 ctor 之后 SetKcovProvider 完成)。
        //
        // [当前版本 threaded-kcov-parity] pool 大小直接用 logical
        // thread_count。KCOV slot 数可以更小;KernelThreadPool::ScheduleCall
        // 会把无 opened kcov fd 的 tid 视为 unschedulable。syzkaller
        // upstream 的 kCoverOptimizedCount=8 是"已打开 KCOV fd 上限";当需要
        // coverage 且调度到没有 cov.fd 的线程时 executor.cc::thread_create()
        // exitf("out of opened kcov threads"),并不会静默无 coverage 执行。
        if (pool_ == nullptr) {
            // [removed] 之前借 fault_inject_us 字段量 pool lazy create 是一次性
            // 诊断,数据已 confirmed = 1353µs/program (fault_inject_avg 在
            // run-20260521T024904Z-89012 sample)。现在 worker thread 端正经写
            // fault_inject_us (真 fault_inject_fn 调用时间),复用同字段会污染语
            // 义。继续诊断 pool create 用 WorkerLog 一行就够(数据已稳定)。
            const int pool_size = static_cast<int>(thread_count_);
            pool_ = std::make_unique<KernelThreadPool>(
                pool_size,
                kcov_provider_,
                dispatcher_.get(),
                &refuzz::fuzzer::syz::kDefaultSyzTarget,
                proc_slot_id_,
                inject_fault_fn_,
                fault_injected_fn_);
        }
        pool_->SetLoopDevicesUsedMaskCursorAllThreads(
            loop_devices_used_mask_cursor_);
        const KcovMode tm = kcov_drain_sink_->CurrentMode();
        const int rc = ExecuteThreaded(input, input_len, output, output_cap, output_len,
                               mode,
                               tm, *pool_, *kcov_drain_sink_,
                               proc_slot_id_,
                               inject_fault_fn_, fault_injected_fn_,
                               kcov_provider_,
                               diagnostic_executor_id_,
                               progress_completed_, progress_output_len_,
                               per_call_timeout_ms_,
                               program_timeout_ms_);
        if (rc == kExecuteKcovStateInvalid) {
            runtime_failure_ = RuntimeFailure::kKcovStateInvalid;
            loop_devices_used_mask_last_exec_ = pool_->TakeAggregatedLoopMask();
            return -1;
        }
        // Aggregate diagnostic candidates from worker contexts. A non-idle
        // worker makes the diagnostic set unknown; fixed-slot cleanup remains
        // independent of this value.
        loop_devices_used_mask_last_exec_ = pool_->TakeAggregatedLoopMask();
        return rc;
    }
    // serial path 继续往下。

    // [v2 Epic 7 PR-1] Resolve per-task KcovCollector once at Execute entry。
    // Step 1: serial only,池里只有 tid=0,GetCollector(0) 等价 v1 拿 collector
    // 成员的语义。命名 `kcov` (无下划线后缀) 避免误读为成员变量;以前 v1 的
    // member 已在 hpp 里替换为 kcov_provider_。
    // Step 4 (threaded): 这一行被删除,改成每个 worker thread 在自己上下文
    // 里 GetCollector(自己的 tid),主线程 Execute 不再持任何 collector。
    KcovCollector* kcov = (kcov_provider_ != nullptr)
                              ? kcov_provider_->GetCollector(0)
                              : nullptr;

    // [S2 streaming decode] The serial path pulls instructions straight from
    // the wire with WireStreamReader — no WireProgram materialization, no blob
    // copy, no second traversal. Decoding happens inline in the exec loop below
    // (a direct port of syzkaller executor.cc execute_one / read_input); the
    // threaded path (ExecuteThreaded) streams the same way.
    syz::WireStreamReader reader(std::span<const uint8_t>(input, input_len));
    uint64_t num_calls = 0;
    {
        ::refuzz::worker::perf::ScopedTimer timer(
            perf_sample,
            ::refuzz::worker::perf::WorkerStage::kDriverDecode);
        if (!reader.ReadNumCalls(&num_calls)) {
            const auto& e = reader.error();
            char hex[40] = {0};
            const uint32_t nh = std::min<uint32_t>(16u, input_len);
            for (uint32_t i = 0; i < nh; ++i) {
                std::snprintf(hex + i * 2, sizeof(hex) - i * 2, "%02x", input[i]);
            }
            ::refuzz::worker::log::WorkerLog(
                "[Driver] reject tag=decode_fail input_len=%u err='%s' off=%zu head=%s\n",
                input_len, e.message.c_str(), e.offset, hex);
            return -1;
        }
    }

    const std::size_t n = num_calls;
    if (n == 0) {
        *output_len = 0;
        return 0;
    }
    auto* results = reinterpret_cast<SyzExecResult*>(output);
    if (output_cap / sizeof(SyzExecResult) < n) {
        ::refuzz::worker::log::WorkerLog(
            "[Driver] reject tag=output_too_small n=%zu cap=%u\n",
            n, output_cap);
        return -1;
    }

    // [v1 per-call shmem write — 2026-05-13]
    // 旧:coverage_tail 累积在 local std::vector,end-of-Execute memcpy 一次。
    //     child 早退 → local 数据丢失 → host 看到 head 但 cover_offset 指向
    //     未初始化区,kAbnormalExit。
    // 新:固定 head = n_calls * sizeof(SyzExecResult)。head 全清零(未执行的
    //     call 留全零 == upstream empty_call 语义);tail 从 head 之后直接写
    //     shmem,无 local 缓冲。每完成一个 call 后按 RELEASE 顺序 atomic 更新
    //     progress_completed_ / progress_output_len_,让 fork parent 在 child
    //     早退时拿到部分结果。
    //
    // layout(固定):
    //   output = [SyzExecResult × n_calls (zero-init)] [uint64 × tail_entries (growing)]
    //   head_bytes = n * sizeof(SyzExecResult)
    //   tail_ptr   = output + head_bytes
    std::memset(output, 0, n * sizeof(SyzExecResult));
    const std::size_t head_bytes = n * sizeof(SyzExecResult);
    auto* tail_ptr = reinterpret_cast<std::uint64_t*>(output + head_bytes);
    std::size_t tail_entries = 0;
    const KcovMode serial_kcov_mode =
        (kcov != nullptr) ? kcov->CurrentMode() : KcovMode::kPc;
    const std::size_t coverage_tail_budget_entries =
        ComputeCoverageTailBudgetEntries(output_cap, n, serial_kcov_mode);
    if (kcov != nullptr) {
        kcov->BeginCallSession();
    }
    // 起点 cursor:head 全零已视为有效结果(empty_call 语义)。partial fallback
    // 进入时需要 head_bytes 起底,保证 decoder 能读 n 个 SyzExecResult。
    if (progress_output_len_ != nullptr) {
        __atomic_store_n(progress_output_len_,
                         static_cast<uint32_t>(head_bytes),
                         __ATOMIC_RELEASE);
    }
    if (progress_completed_ != nullptr) {
        __atomic_store_n(progress_completed_, 0u, __ATOMIC_RELEASE);
    }

    // ---- Acquire scratch ----
    // Reuse the existing per-thread mmap that syz_exec_runner uses; this
    // keeps the sandbox-sizing accounting (kSyzExecScratchBytes feeds
    // ComputeAddressSpaceLimit) consistent across drivers.
    uint8_t* scratch = nullptr;
    {
        ::refuzz::worker::perf::ScopedTimer timer(
            perf_sample,
            ::refuzz::worker::perf::WorkerStage::kScratchPrepare);
        if (!PreallocateSyzExecScratch()) {
            ::refuzz::worker::log::WorkerLog(
                "[Driver] reject tag=prealloc_scratch_fail\n");
            return -1;
        }
        scratch = AcquireScratch();
        if (scratch == nullptr) {
            ::refuzz::worker::log::WorkerLog(
                "[Driver] reject tag=acquire_scratch_null\n");
            return -1;
        }
    }
    // Reusable/inline children must clear the long-lived scratch window
    // between programs. DoubleFork program children inherit the loop child's
    // clean mapping and die after one program, so clearing 16 MiB here only
    // creates COW/page-fault work.
    if (ShouldFullClearScratch(mode)) {
        ::refuzz::worker::perf::ScopedTimer timer(
            perf_sample,
            ::refuzz::worker::perf::WorkerStage::kScratchClear);
        std::memset(scratch, 0, kSyzExecScratchBytes);
    }

    // ---- Per-program state ----
    int64_t copyout[kMaxCommands]    = {};
    bool    copyout_set[kMaxCommands]= {};

    // [syscall-support-detection] no cap gate; environment/capability filtering
    // happens host-side (control/support). kDefaultSyzTarget is the default table.
    PseudoRuntimeContext pseudo_ctx(
        &refuzz::fuzzer::syz::kDefaultSyzTarget, proc_slot_id_);
    pseudo_ctx.set_diagnostic_executor_id(diagnostic_executor_id_);
    pseudo_ctx.set_kcov_collector(kcov);
    pseudo_ctx.set_loop_devices_used_mask_cursor(
        loop_devices_used_mask_cursor_);
    syz::WireSetProps current_props{};
    bool              have_props = false;
    std::size_t       call_index = 0;
    // [close(9,0) fix 2026-05-24] Gate memory copyouts on the owning call's
    // success. A WireCopyout (output-memory resource, e.g. the `out_access_fd`
    // field of ioctl$IOMMU_TEST_OP_CREATE_ACCESS) appears in the instr stream
    // immediately after its WireCall; if that call failed the kernel never
    // wrote the output field, so snapshotting scratch fabricates a resource
    // (reads stale 0 → a valid fd, e.g. stdin). syzkaller leaves such a result
    // un-`executed` (executor.cc:1362) so a later ResultArg falls back to its
    // default special value (fd → -1 → EBADF). Track the most-recent call's ret
    // and skip its memory copyouts on failure so the ResultArg uses default_val.
    // The return-value copyout (ch->copyout_idx path below) stays unconditional:
    // syz always records it (val=ret, -1 on failure), already correct for fds.
    int64_t           last_call_ret = 0;

    const uint64_t data_offset = syz::generated::kLinuxAmd64DataOffset;

    {
    ::refuzz::worker::perf::ScopedTimer walk_timer(
        perf_sample,
        ::refuzz::worker::perf::WorkerStage::kWireWalk);
    syz::WireInstrView instr;
    for (;;) {
        const auto st = reader.Next(&instr);
        if (st == syz::WireStreamReader::Status::kEof) {
            break;
        }
        if (st == syz::WireStreamReader::Status::kError) {
            // Malformed wire mid-stream. Real wire from serialize_for_exec is
            // never malformed at the decode level, so this is a corruption
            // guard; unlike the old batch decode it can fire after earlier
            // calls already ran (same partial-execution contract as a crash).
            const auto& e = reader.error();
            ::refuzz::worker::log::WorkerLog(
                "[Driver] reject tag=decode_fail input_len=%u err='%s' off=%zu\n",
                input_len, e.message.c_str(), e.offset);
            pseudo_ctx.Cleanup();
            return -1;
        }
        if (auto* ci = std::get_if<syz::WireCopyin>(&instr)) {
            // [v2 PR-A — 透传 data_offset]
            {
                ::refuzz::worker::perf::ScopedTimer timer(
                    perf_sample,
                    ::refuzz::worker::perf::WorkerStage::kCopyIn);
                if (!apply_copyin(scratch, kSyzExecScratchBytes, *ci,
                                  copyout, copyout_set, proc_slot_id_,
                                  data_offset)) {
                    pseudo_ctx.Cleanup();
                    return -1;
                }
            }
            if (perf_sample != nullptr) {
                ::refuzz::worker::perf::AddSaturating(&perf_sample->copyins, 1);
            }
            continue;
        }
        if (auto* co = std::get_if<syz::WireCopyout>(&instr)) {
            // [close(9,0) fix] Owning call failed → output field was never
            // written; skip so the resource stays unproduced (ResultArg →
            // default_val), matching syzkaller's un-executed result.
            if (last_call_ret >= 0) {
                ::refuzz::worker::perf::ScopedTimer timer(
                    perf_sample,
                    ::refuzz::worker::perf::WorkerStage::kCopyOut);
                apply_copyout(scratch, kSyzExecScratchBytes, *co,
                              copyout, copyout_set);
            }
            if (perf_sample != nullptr) {
                ::refuzz::worker::perf::AddSaturating(&perf_sample->copyouts, 1);
            }
            continue;
        }
        if (auto* sp = std::get_if<syz::WireSetProps>(&instr)) {
            current_props = *sp;
            have_props    = true;
            continue;
        }
        if (auto* ch = std::get_if<syz::WireCallHeader>(&instr)) {
            if (have_props && !supported_wire_set_props(current_props)) {
                // [v2 Epic 7 PR-8 diag] async/rerun props 是 Epic 6 §10 N1/N2
                // 永久 non-goal; 这里 reject 是设计意图。tag 出来便于统计
                // exec_error 中"非 bug、design-as-intended"占比。
                ::refuzz::worker::log::WorkerLog(
                    "[Driver] reject tag=unsupported_props async=%d rerun=%lld\n",
                    current_props.async ? 1 : 0,
                    static_cast<long long>(current_props.rerun));
                pseudo_ctx.Cleanup();
                return -1;
            }
            if (call_index >= n) {
                ::refuzz::worker::log::WorkerLog(
                    "[Driver] reject tag=call_index_overflow ci=%zu n=%zu\n",
                    call_index, n);
                pseudo_ctx.Cleanup();
                return -1;
            }
            if (perf_sample != nullptr) {
                ::refuzz::worker::perf::AddSaturating(&perf_sample->calls, 1);
            }
            // Resolve args. [S2 streaming] argc + each arg come straight off the
            // wire cursor via NextArg — no materialized args vector — and each
            // arg is resolved on the spot exactly as the batch path did.
            intptr_t args[kMaxArgs] = {};
            const std::size_t argc  = static_cast<std::size_t>(ch->num_args);
            if (argc > kMaxArgs) {
                ::refuzz::worker::log::WorkerLog(
                    "[Driver] reject tag=argc_overflow argc=%zu max=%zu call_id=%llu\n",
                    argc, kMaxArgs,
                    static_cast<unsigned long long>(ch->call_id));
                pseudo_ctx.Cleanup();
                return -1;
            }
            {
                ::refuzz::worker::perf::ScopedTimer timer(
                    perf_sample,
                    ::refuzz::worker::perf::WorkerStage::kArgResolve);
                for (std::size_t ai = 0; ai < argc; ++ai) {
                    syz::WireArg arg;
                    if (!reader.NextArg(&arg)) {
                        const auto& e = reader.error();
                        ::refuzz::worker::log::WorkerLog(
                            "[Driver] reject tag=decode_fail input_len=%u "
                            "err='%s' off=%zu\n",
                            input_len, e.message.c_str(), e.offset);
                        pseudo_ctx.Cleanup();
                        return -1;
                    }
                    // [v2 PR-A — 透传 data_offset + scratch_cap]
                    args[ai] = resolve_call_arg(scratch, arg,
                                                copyout, copyout_set, proc_slot_id_,
                                                data_offset, kSyzExecScratchBytes);
                }
            }
            // call_id → kernel NR via generated lite table.
            if (ch->call_id >= syz::generated::kLinuxAmd64CallCount) {
                ::refuzz::worker::log::WorkerLog(
                    "[Driver] reject tag=bad_call_id id=%llu max=%zu\n",
                    static_cast<unsigned long long>(ch->call_id),
                    syz::generated::kLinuxAmd64CallCount);
                pseudo_ctx.Cleanup();
                return -1;
            }
            const uint64_t nr =
                syz::generated::kLinuxAmd64CallIdToNr[ch->call_id];

            EmitCloneSnap("pre",
                          proc_slot_id_,
                          diagnostic_executor_id_,
                          call_index,
                          ch->call_id,
                          nr,
                          args,
                          argc,
                          0,
                          0);

            // [v2 Epic 6 D-6 — fault-inject apply, mirror upstream
            //  executor.cc:1551-1579]
            // 在 dispatch 之前如果 SetProps 携带 fail_nth>0,通过
            // /proc/thread-self/fail-nth 通知 kernel 在第 nth 次 fault
            // injection 触发点失败。fail_fd<0(open/write 失败) → 跳过
            // inject 但 dispatch 照常执行,kCallFlagFaultInjected 留 0
            // (graceful per D-14)。dispatch 之后 fault_injected 读 flag
            // 决定置位与否;fault_injected 内部 close fd。
            int fail_fd = -1;
            if (have_props && current_props.fail_nth > 0) {
                ::refuzz::worker::perf::ScopedTimer timer(
                    perf_sample,
                    ::refuzz::worker::perf::WorkerStage::kFaultInject);
                fail_fd = inject_fault_fn_(static_cast<int>(current_props.fail_nth));
            }

            // Per-call KCOV boundary: clear area_[0] immediately before this
            // syscall, matching upstream syzkaller cover_reset. kcov == nullptr
            // / CMP mode / non-PC mode / non-session 时 no-op。
            if (kcov != nullptr) {
                {
                    ::refuzz::worker::perf::ScopedTimer timer(
                        perf_sample,
                        ::refuzz::worker::perf::WorkerStage::kKcovReset);
                    kcov->ResetForCall();
                }
                if (perf_sample != nullptr) {
                    ::refuzz::worker::perf::AddSaturating(
                        &perf_sample->kcov_resets, 1);
                }
            }

            // [kcov-window log suppression] 进 KCOV per-call 窗口前静默
            // WorkerLog,避免 handler 内 log → write(ttyS0) 让 kernel tty 路径
            // PC 污染本 syscall 覆盖(Exp C printk_tty noise 根因)。窗口结束后
            // (CollectForCallView 之后)恢复。
            if (kcov != nullptr) {
                ::refuzz::worker::log::SetWorkerLogSuppressed(true);
            }

            errno = 0;
            PseudoResult r{};
            {
                ::refuzz::worker::perf::ScopedTimer timer(
                    perf_sample,
                    ::refuzz::worker::perf::WorkerStage::kDispatch);
                r = dispatcher_->Dispatch(nr, args,
                                          static_cast<uint32_t>(argc),
                                          &pseudo_ctx);
            }
            // [v2 Epic 6 — flags carries kCallFlag* per D-4]
            // [2026-05-13 P1 fix-2] Dispatch 真跑过这条 syscall(无论 ret==0/-1/-errno),
            // 立即 set kCallFlagExecuted | kCallFlagFinished。这俩 bit 让下游消费者
            // (kcov_coverage_signal.cpp 的 execution_succeeded / per_call observation)
            // 区分:
            //   flags & Executed != 0  → 真跑过的 slot,ret/err 有意义
            //   flags == 0             → driver 已 zero-init 但 partial fallback
            //                             导致后半段未执行的 empty_call slot
            // 之前 v1 走 flags=0 让 "ret==0 success" 和 "未执行" 在数据上无法分辨,
            // 污染 prio/observation;v2 用 flag gate 治根。
            results[call_index].ret   = static_cast<int64_t>(r.ret);
            results[call_index].err   = r.err;
            results[call_index].flags = kCallFlagExecuted | kCallFlagFinished;
            // [close(9,0) fix] Remember this call's ret so the WireCopyout(s)
            // that follow it in the instr stream are skipped on failure.
            last_call_ret = static_cast<int64_t>(r.ret);
            results[call_index].cover_offset = 0;
            results[call_index].cover_count  = 0;
            if (fail_fd >= 0) {
                bool injected = false;
                {
                    ::refuzz::worker::perf::ScopedTimer timer(
                        perf_sample,
                        ::refuzz::worker::perf::WorkerStage::kFaultCheck);
                    injected = fault_injected_fn_(fail_fd);
                }
                if (injected) {
                    results[call_index].flags |= kCallFlagFaultInjected;
                }
            }

            // Per-program tail budget is output-buffer based. Truncate only
            // when the cumulative tail would crowd out the headroom reserved
            // for sink packets.
            // collector reads area_[1..area_[0]] after the syscall because
            // ResetForCall cleared the KCOV cursor immediately before dispatch.
            if (kcov != nullptr) {
                // [当前版本 zero-copy-pc-cov] 直接拿 kcov area_ 的 view,不分配
                // vector 也不 push_back。view 只在本 syscall 间有效:下次
                // ResetForCall 之前 area_ 不会被 kernel 改,主线程 memcpy 完
                // (在 ScopedTimer coverage_tail_us 内)就消费完成。
                KcovCollector::PerCallCovView view{};
                {
                    ::refuzz::worker::perf::ScopedTimer timer(
                        perf_sample,
                        ::refuzz::worker::perf::WorkerStage::kKcovCollect);
                    view = kcov->CollectForCallView();
                }
                if (perf_sample != nullptr) {
                    ::refuzz::worker::perf::AddSaturating(
                        &perf_sample->kcov_collects, 1);
                    ::refuzz::worker::perf::AddSaturating(
                        &perf_sample->cov_entries, view.size);
                }
                if (view.size > 0) {
                    const std::size_t budget =
                        (tail_entries < coverage_tail_budget_entries)
                            ? (coverage_tail_budget_entries - tail_entries)
                            : 0;
                    const std::size_t take =
                        std::min(static_cast<std::size_t>(view.size), budget);
                    {
                        ::refuzz::worker::perf::ScopedTimer timer(
                            perf_sample,
                            ::refuzz::worker::perf::WorkerStage::kCoveragePack);
                        if (take > 0) {
                            results[call_index].cover_offset =
                                static_cast<uint32_t>(tail_entries);
                            results[call_index].cover_count =
                                static_cast<uint32_t>(take);
                            // 直接 memcpy area_ → output tail,免去
                            // (a) worker push_back N×uint64,(b) per-element
                            // 拷贝 loop。view.data 指向 kcov mmap 内的 PC 区。
                            std::memcpy(tail_ptr + tail_entries,
                                        view.data,
                                        take * sizeof(std::uint64_t));
                            tail_entries += take;
                        }
                    }
                    if (perf_sample != nullptr) {
                        ::refuzz::worker::perf::AddSaturating(
                            &perf_sample->cov_taken, take);
                    }
                    if (take < view.size) {
                        results[call_index].flags |= kCallFlagCoverageOverflow;
                    }
                }
            }
            // [kcov-window log suppression] 出窗口,恢复 WorkerLog。
            if (kcov != nullptr) {
                ::refuzz::worker::log::SetWorkerLogSuppressed(false);
            }

            EmitCloneSnap("post",
                          proc_slot_id_,
                          diagnostic_executor_id_,
                          call_index,
                          ch->call_id,
                          nr,
                          args,
                          argc,
                          static_cast<long>(r.ret),
                          r.err);

            // If this call has a copyout slot for its return value, record
            // it so subsequent ResultArgs can reference the syscall ret.
            if (ch->copyout_idx != kExecNoCopyout && ch->copyout_idx < kMaxCommands) {
                copyout[ch->copyout_idx]     = static_cast<int64_t>(r.ret);
                copyout_set[ch->copyout_idx] = true;
            }
            ++call_index;
            // [v1 per-call shmem progress — 2026-05-13]
            // 本 call 的 results[ci]/.ret/.err/.flags/.cover_* 已直接写 shmem;
            // tail entries 也已写 shmem。现在按 RELEASE 顺序更新 cursor,让
            // ForkingProgramExecutor parent 在 child SIGKILL 时 ACQUIRE 读到的
            // 部分结果 self-consistent(head fixed,decoder 看到 call_index 个
            // 真实 results + 后续全零 empty_call;cover_offset 指向已写 tail)。
            const std::uint32_t current_output_len =
                static_cast<std::uint32_t>(
                    head_bytes + tail_entries * sizeof(std::uint64_t));
            if (progress_output_len_ != nullptr) {
                __atomic_store_n(progress_output_len_, current_output_len,
                                 __ATOMIC_RELEASE);
            }
            if (progress_completed_ != nullptr) {
                __atomic_store_n(progress_completed_,
                                 static_cast<std::uint32_t>(call_index),
                                 __ATOMIC_RELEASE);
            }
            // SetProps applies to the just-executed call; reset for next.
            (void)have_props;
            current_props = {};
            have_props    = false;
            continue;
        }
    }
    }
    if (have_props && !supported_wire_set_props(current_props)) {
        ::refuzz::worker::log::WorkerLog(
            "[Driver] reject tag=trailing_unsupported_props async=%d rerun=%lld\n",
            current_props.async ? 1 : 0,
            static_cast<long long>(current_props.rerun));
        pseudo_ctx.Cleanup();
        return -1;
    }
    pseudo_ctx.Cleanup();


    // [v1 per-call shmem write — 2026-05-13]
    // Driver 边执行边写 shmem:results[] 已 zero-init head 后直接写 cells,
    // tail 已 per-call append 进 output + head_bytes。这里只算最终 output_len:
    //   head_bytes(fixed, = n × sizeof(SyzExecResult))+ tail_entries × 8。
    // 旧的"tail 装不下"分支被上面 per-call budget check 自然吸收(take 永远
    // <= budget),不再可能命中。
    //
    // 单 collector 预算:
    //   results_budget = n_calls × sizeof(SyzExecResult)
    //   feedback reserve = PC mode small headroom / CMP mode one worst-case
    //                      sink packet (~4 MiB with syzkaller-aligned KCOV)
    //   tail budget = output_cap - results_budget - reserve
    const std::size_t tail_bytes = tail_entries * sizeof(std::uint64_t);
    *output_len = static_cast<uint32_t>(head_bytes + tail_bytes);
    // [Step A] surface this program's /dev/loop usage to caller via
    // TakeLoopDevicesUsedMask. pseudo_ctx is local to this Execute, so its
    // mask captures only what mount_dispatcher / pseudo_fs ReadPartTable
    // recorded during THIS program. 0 means no mount-image succeeded.
    loop_devices_used_mask_last_exec_ = pseudo_ctx.loop_devices_used_mask_;
    return 0;
}

// ----------------------------------------------------------------
// ExecuteThreaded
//
// Mirrors upstream syzkaller executor threaded scheduling:
//   - worker threads live inside the program/test child lifetime. Under the
//     default DoubleFork topology this matches syzkaller's fork-server child:
//     every program child starts from a clean thread array/pool and exits after
//     the program. Moving live threads to the loop child would cross fork()
//     with active pthread state and would also break KCOV's current-task
//     binding, so the pool stays in the driver/program-child context.
//   - normal calls are scheduled to the first idle worker and waited for.
//   - async calls are scheduled and left running; later schedule/wait points
//     opportunistically collect completed earlier calls.
//   - timed-out calls are not immediately reported as completed. If they finish
//     before task end they are reported as Finished|Blocked; otherwise task end
//     emits an Executed-only result, matching syzkaller write_call_output(false).
//   - WireCopyout instructions immediately following a WireCall belong to that
//     call and are applied only when the worker completes the syscall.
//
// KCOV Begin / Reset / Collect / End and fault injection still happen inside
// the worker thread because both are current-task/thread-local kernel APIs.
static int ExecuteThreaded(
    const uint8_t* input, uint32_t input_len,
    uint8_t* output, uint32_t output_cap, uint32_t* output_len,
    ExecMode mode,
    KcovMode kcov_mode,
    KernelThreadPool& pool,
    IKcovDrainSink& drain_sink,
    uint32_t proc_slot_id,
    InjectFaultFn /*inject_fault_fn*/,
    FaultInjectedFn /*fault_injected_fn*/,
    IKcovCollectorProvider* kcov_provider,
    uint64_t diagnostic_executor_id,
    uint32_t* progress_completed,
    uint32_t* progress_output_len,
    uint32_t per_call_timeout_ms,
    uint32_t program_timeout_ms)
{
    // [v1 per-call shmem progress — 2026-05-13] threaded path 跟 serial path
    // 同语义,只是 dispatch 由 thread pool 承担。member 变量在 free function
    // 内访问不到,从参数透传。详细注释见 serial path 上方块。
    auto& progress_completed_ = progress_completed;
    auto& progress_output_len_ = progress_output_len;

    // [S3 streaming] Own reader over the wire buffer; num_calls re-read here
    // (the caller already peeked it for the n==0 fast path). Deferred copyouts
    // are replayed from independent sub-readers over the same `input` span.
    syz::WireStreamReader reader(std::span<const uint8_t>(input, input_len));
    uint64_t num_calls = 0;
    if (!reader.ReadNumCalls(&num_calls)) return -1;
    const std::size_t n = num_calls;
    auto* results = reinterpret_cast<SyzExecResult*>(output);
    if (output_cap / sizeof(SyzExecResult) < n) return -1;

    // [当前版本 threaded-perf-instrumentation] threaded path 走 thread-local
    // CurrentSample(),跟 serial Execute() 同源。nullptr-safe — ScopedTimer 内部
    // 已 guard。计数器走 AddSaturating。同 serial path 一致,所有 sub-timer 受
    // worker_perf sample_rate gate(ShouldSample at LoopRuntime 层决定)。
    auto* perf_sample = ::refuzz::worker::perf::CurrentSample();
    auto add_thread_wait_elapsed =
        [&](uint64_t start_us,
            ::refuzz::worker::perf::WorkerStage detail_stage) {
            if (perf_sample == nullptr || start_us == 0) {
                return;
            }
            const uint64_t elapsed =
                ::refuzz::worker::perf::NowUs() - start_us;
            ::refuzz::worker::perf::AddStage(
                perf_sample,
                ::refuzz::worker::perf::WorkerStage::kThreadWait,
                elapsed);
            ::refuzz::worker::perf::AddStage(
                perf_sample, detail_stage, elapsed);
        };

    // sink threaded session start(锁定 mode + 清空 last_session_entries_)
    drain_sink.StartThreadedSession(kcov_mode);

    // pool 端开 task — 清各 thread used flag + drained。
    pool.StartTask(kcov_mode);

    {
        ::refuzz::worker::perf::ScopedTimer t(
            perf_sample,
            ::refuzz::worker::perf::WorkerStage::kScratchPrepare);
        if (!PreallocateSyzExecScratch()) return -1;
    }
    uint8_t* scratch = AcquireScratch();
    if (scratch == nullptr) return -1;
    // Same scratch lifetime rule as serial Execute().
    if (ShouldFullClearScratch(mode)) {
        ::refuzz::worker::perf::ScopedTimer t(
            perf_sample,
            ::refuzz::worker::perf::WorkerStage::kScratchClear);
        std::memset(scratch, 0, kSyzExecScratchBytes);
    }

    int64_t copyout[kMaxCommands]    = {};
    bool    copyout_set[kMaxCommands]= {};

    syz::WireSetProps current_props{};
    bool              have_props = false;
    std::size_t       call_index = 0;

    const uint64_t data_offset = syz::generated::kLinuxAmd64DataOffset;

    // [v1 per-call shmem write — 2026-05-13] 同 serial path 治理:固定 head,
    // 直接写 shmem,per-call RELEASE 更新 cursor。详 Execute() 内对应注释。
    std::memset(output, 0, n * sizeof(SyzExecResult));
    const std::size_t head_bytes = n * sizeof(SyzExecResult);
    auto* tail_ptr = reinterpret_cast<std::uint64_t*>(output + head_bytes);
    std::size_t tail_entries = 0;
    const std::size_t coverage_tail_budget_entries =
        ComputeCoverageTailBudgetEntries(output_cap, n, kcov_mode);
    if (progress_output_len_ != nullptr) {
        __atomic_store_n(progress_output_len_,
                         static_cast<uint32_t>(head_bytes),
                         __ATOMIC_RELEASE);
    }
    if (progress_completed_ != nullptr) {
        __atomic_store_n(progress_completed_, 0u, __ATOMIC_RELEASE);
    }
    // Per-call wait timeout. A timeout no longer immediately writes a result:
    // the call remains in-flight and can still be collected later, matching
    // syzkaller executor.cc:1163 followed by the later completion sweeps.
    // [当前版本 per-call-timeout-config] 5s 默认对齐 syzkaller upstream
    // executor 的 syscall 超时;driver 成员 per_call_timeout_ms_ 由
    // SetPerCallTimeoutMs 注入,经 ExecuteThreaded 参数透传到 free function。
    const std::chrono::milliseconds per_call_timeout{per_call_timeout_ms};

    // [threaded end-drain parity] End-drain deadline inputs (see
    // drain_in_flight_until_deadline). program_start mirrors executor.cc:956
    // `uint64 start = current_time_ms()`; program_timeout is the host program
    // timeout; prog_extra_timeout_ms accumulates max(call->attrs.prog_timeout)
    // over scheduled calls (executor.cc:1081-1082, slowdown=1).
    const auto program_start = std::chrono::steady_clock::now();
    const std::chrono::milliseconds program_timeout{program_timeout_ms};
    uint64_t prog_extra_timeout_ms = 0;

    const int pool_size = pool.Size();
    if (pool_size <= 0) return -1;
    // [heap churn 减少 2026-05-22] hard cap pool size to align syz
    // `kMaxThreads = 32` (executor.cc:69)。InFlightCall 改 fixed-size array
    // 避免 per-program std::vector heap alloc; [S3] copyouts 改存 wire cursor
    // 偏移 + count,completion 时用 sub-reader 重解,无 vector alloc、无 element copy。
    constexpr std::size_t kMaxThreadPoolSize = 32;
    if (static_cast<std::size_t>(pool_size) > kMaxThreadPoolSize) {
        ::refuzz::worker::log::WorkerLog(
            "[Driver/threaded] reject tag=pool_size_too_large pool=%d max=%zu\n",
            pool_size, kMaxThreadPoolSize);
        return -1;
    }
    ThreadedTaskDrainGuard task_guard(
        pool, drain_sink, pool_size, perf_sample);

    struct InFlightCall {
        std::size_t call_index = 0;
        uint64_t copyout_idx = kExecNoCopyout;
        // [S3 streaming] Byte offset in the wire where this call's copyouts
        // begin (right after its args), plus how many contiguous copyouts
        // follow it. On completion we replay them from a fresh sub-reader over
        // the same `input` span — the streaming analog of syzkaller
        // copyout_call_results reading from th->copyout_pos. Nothing is
        // materialized: no WireCopyout vector, no wire.instrs index range.
        std::size_t copyout_pos = 0;
        std::size_t copyouts_count = 0;
    };
    std::array<InFlightCall, kMaxThreadPoolSize> in_flight{};
    // Main-thread-owned scheduler state. Worker completion visibility remains
    // synchronized by KernelThreadPool; this mask only avoids repeatedly
    // scanning inactive logical slots.
    std::uint32_t active_mask = 0;
    const auto tid_mask = [](int tid) {
        return std::uint32_t{1} << static_cast<unsigned>(tid);
    };
    const auto is_in_flight = [&](int tid) {
        return (active_mask & tid_mask(tid)) != 0;
    };
    const auto clear_in_flight = [&](int tid) {
        active_mask &= ~tid_mask(tid);
    };
    std::size_t completed_outputs = 0;
    int last_scheduled_tid = -1;
    bool kcov_failed = false;

    auto publish_progress = [&]() {
        const std::uint32_t current_output_len =
            static_cast<std::uint32_t>(
                head_bytes + tail_entries * sizeof(std::uint64_t));
        if (progress_output_len_ != nullptr) {
            __atomic_store_n(progress_output_len_, current_output_len,
                             __ATOMIC_RELEASE);
        }
        if (progress_completed_ != nullptr) {
            __atomic_store_n(progress_completed_,
                             static_cast<std::uint32_t>(completed_outputs),
                             __ATOMIC_RELEASE);
        }
    };

    auto append_call_coverage =
        [&](std::size_t ci,
            const std::uint64_t* cov_data,
            std::uint32_t cov_size) {
            // [当前版本 zero-copy-pc-cov] cov_data 指向 worker thread 的
            // kcov area_(WorkerThreadOutput::per_call_cov_data),在 main
            // ScheduleCall(next) 之前 worker 没机会跑下个 syscall,所以
            // area_ 内对应区间是 stable。直接 memcpy 到 output tail,免去
            // worker 的 push_back vector + per-element 拷贝 loop。
            if (cov_size == 0 || cov_data == nullptr) {
                return;
            }
            ::refuzz::worker::perf::ScopedTimer t(
                perf_sample,
                ::refuzz::worker::perf::WorkerStage::kCoveragePack);
            const std::size_t budget =
                (tail_entries < coverage_tail_budget_entries)
                    ? (coverage_tail_budget_entries - tail_entries)
                    : 0;
            const std::size_t take = std::min(
                static_cast<std::size_t>(cov_size), budget);
            if (take > 0) {
                results[ci].cover_offset = static_cast<uint32_t>(tail_entries);
                results[ci].cover_count = static_cast<uint32_t>(take);
                std::memcpy(tail_ptr + tail_entries,
                            cov_data,
                            take * sizeof(std::uint64_t));
                tail_entries += take;
            }
            if (take < cov_size) {
                results[ci].flags |= kCallFlagCoverageOverflow;
            }
            if (perf_sample != nullptr) {
                ::refuzz::worker::perf::AddSaturating(
                    &perf_sample->cov_taken, take);
            }
        };

    auto complete_tid = [&](int tid, WorkerThreadOutput& out) {
        auto& st = in_flight[static_cast<std::size_t>(tid)];
        if (!is_in_flight(tid)) {
            return false;
        }
        const std::size_t ci = st.call_index;
        if (ci >= n) {
            return false;
        }

        if (out.kcov_failed) {
            kcov_failed = true;
            clear_in_flight(tid);
            st.copyouts_count = 0;
            return true;
        }

        results[ci].ret = out.ret;
        results[ci].err = out.err;
        results[ci].flags = kCallFlagExecuted | kCallFlagFinished;
        if (tid != last_scheduled_tid) {
            results[ci].flags |= kCallFlagBlocked;
            if (perf_sample != nullptr) {
                ::refuzz::worker::perf::AddSaturating(
                    &perf_sample->blocked_calls, 1);
            }
        }
        if (out.fault_injected) {
            results[ci].flags |= kCallFlagFaultInjected;
        }
        // [当前版本 worker-thread-perf-回传] 把 worker 在自己线程内量的子段
        // 时间累加到主线程 perf_sample。这是分析 thread_wait_avg 真去向的关键
        // (主线程 WaitCallDone 包含 worker 全程 + condvar wake + 调度,要拆开
        // 必须让 worker 自己量再回传)。
        // 跟 serial path 同字段共享:dispatch_us / kcov_reset_us /
        // kcov_collect_us / fault_inject_us / fault_check_us / cov_entries /
        // kcov_resets / kcov_collects — 主线程聚合视图,不区分 path 来源。
        // us 字段是 uint64,直接 += (不是 saturating uint32 计数器);counter
        // 字段是 uint32 用 AddSaturating 防溢出。
        if (perf_sample != nullptr) {
            ::refuzz::worker::perf::AddStage(
                perf_sample, ::refuzz::worker::perf::WorkerStage::kDispatch,
                out.dispatch_us);
            ::refuzz::worker::perf::AddStage(
                perf_sample, ::refuzz::worker::perf::WorkerStage::kKcovReset,
                out.kcov_reset_us);
            ::refuzz::worker::perf::AddStage(
                perf_sample, ::refuzz::worker::perf::WorkerStage::kKcovCollect,
                out.kcov_collect_us);
            ::refuzz::worker::perf::AddStage(
                perf_sample, ::refuzz::worker::perf::WorkerStage::kFaultInject,
                out.fault_inject_us);
            ::refuzz::worker::perf::AddStage(
                perf_sample, ::refuzz::worker::perf::WorkerStage::kFaultCheck,
                out.fault_check_us);
            // [fork-breakdown 2026-05-21] worker thread 内 NowUs 累加,
            // 让主线程能拆 threaded_wait_us - worker_total_us = condvar/
            // schedule wake latency. kcov_begin 只第一次 call 有值, 累加
            // 自动反映 per-program 单次 Begin 成本.
            ::refuzz::worker::perf::AddStage(
                perf_sample, ::refuzz::worker::perf::WorkerStage::kThreadWorker,
                out.worker_total_us);
            ::refuzz::worker::perf::AddStage(
                perf_sample, ::refuzz::worker::perf::WorkerStage::kKcovBegin,
                out.kcov_begin_us);
            // [sync_gap split 2026-05-22] pickup_gap 已由 worker 在 kCall
            // 入口算好 (worker_t0 - schedule_done_us), 直接累加. done_gap
            // 由 main 在 take 完 out 之后算 (NowUs - out.done_ready_us),
            // 反映 worker publish done → main 拿到结果的延迟.
            ::refuzz::worker::perf::AddStage(
                perf_sample, ::refuzz::worker::perf::WorkerStage::kThreadPickup,
                out.pickup_gap_us);
            if (out.done_ready_us != 0) {
                const uint64_t now = ::refuzz::worker::perf::NowUs();
                if (now > out.done_ready_us) {
                    ::refuzz::worker::perf::AddStage(
                        perf_sample,
                        ::refuzz::worker::perf::WorkerStage::kThreadDone,
                        now - out.done_ready_us);
                }
            }
            ::refuzz::worker::perf::AddSaturating(
                &perf_sample->cov_entries, out.cov_entries);
            if (out.has_kcov) {
                ::refuzz::worker::perf::AddSaturating(
                    &perf_sample->kcov_resets, 1);
                ::refuzz::worker::perf::AddSaturating(
                    &perf_sample->kcov_collects, 1);
            }
        }
        append_call_coverage(ci, out.per_call_cov_data, out.per_call_cov_size);

        if (st.copyout_idx != kExecNoCopyout && st.copyout_idx < kMaxCommands) {
            copyout[st.copyout_idx] = static_cast<int64_t>(out.ret);
            copyout_set[st.copyout_idx] = true;
        }
        // [S3 streaming] InFlightCall holds the copyouts' wire cursor offset +
        // count; complete_tid re-decodes them from a sub-reader (see below),
        // so no vector alloc and no element copy.
        // [close(9,0) fix 2026-05-24] Same success-gating as the serial path:
        // a failed call never wrote its output field, so skip its memory
        // copyouts and let later ResultArgs fall back to default_val (matches
        // syzkaller's un-executed result). The return-value copyout above
        // (st.copyout_idx) stays unconditional.
        if (st.copyouts_count > 0 && out.ret >= 0) {
            ::refuzz::worker::perf::ScopedTimer t(
                perf_sample,
                ::refuzz::worker::perf::WorkerStage::kCopyOut);
            // [S3 streaming] Replay this call's copyouts from a fresh sub-reader
            // seeked to where they begin in the wire. The sub-reader is fully
            // independent of the main `reader` cursor, so a completion firing
            // mid-schedule (poll_tid inside schedule_call) never perturbs the
            // main walk position. Decodes exactly st.copyouts_count copyouts.
            syz::WireStreamReader sub(
                std::span<const uint8_t>(input, input_len));
            sub.seek(st.copyout_pos);
            for (std::size_t i = 0; i < st.copyouts_count; ++i) {
                syz::WireInstrView cv;
                if (sub.Next(&cv) != syz::WireStreamReader::Status::kInstr) {
                    break;
                }
                if (auto* co = std::get_if<syz::WireCopyout>(&cv)) {
                    apply_copyout(scratch, kSyzExecScratchBytes, *co,
                                  copyout, copyout_set);
                }
            }
            if (perf_sample != nullptr) {
                ::refuzz::worker::perf::AddSaturating(
                    &perf_sample->copyouts,
                    static_cast<uint32_t>(st.copyouts_count));
            }
        }

        clear_in_flight(tid);
        st.copyouts_count = 0;
        ++completed_outputs;
        publish_progress();
        return true;
    };

    auto finish_unfinished_tid = [&](int tid) {
        auto& st = in_flight[static_cast<std::size_t>(tid)];
        if (!is_in_flight(tid)) {
            return false;
        }
        const std::size_t ci = st.call_index;
        if (ci < n) {
            results[ci].ret = -1;
            results[ci].err = ENOSYS;
            results[ci].flags = kCallFlagExecuted;
            // [threaded end-drain parity] This call never completed — neither in
            // its per-call wait nor the drain window — so its worker thread is
            // still inside Dispatch. Mirror executor.cc:1149-1150
            // `cover_collect(&th->cov); write_call_output(th,false)`: snapshot
            // whatever coverage the blocked syscall produced so far from its
            // per-tid collector, read on THIS (main) thread (the worker can't,
            // it's blocked). errno stays ENOSYS and flags stay Executed-only (no
            // Finished/Blocked), exactly like upstream write_call_output(false).
            if (kcov_provider != nullptr) {
                KcovCollector* col = kcov_provider->GetCollector(tid);
                if (col != nullptr) {
                    const auto view = col->SnapshotPerCallView();
                    append_call_coverage(ci, view.data, view.size);
                }
            }
            ++completed_outputs;
            publish_progress();
        }
        clear_in_flight(tid);
        st.copyouts_count = 0;
        return true;
    };

    auto poll_tid = [&](int tid) {
        if (!is_in_flight(tid)) {
            return false;
        }
        const uint64_t wait_start =
            perf_sample != nullptr ? ::refuzz::worker::perf::NowUs() : 0;
        if (!pool.IsCallDone(tid)) {
            add_thread_wait_elapsed(
                wait_start,
                ::refuzz::worker::perf::WorkerStage::kThreadPoll);
            return false;
        }
        // [sync_gap fast path 2026-05-22] 已知 done — 走 TryTakeDone, 不进
        // WaitCallDone(0) 的 cv.wait_for(0, predicate) 路径 (省 timed-wait
        // machinery 的 lock/unlock + cv state setup).
        WorkerThreadOutput out;
        const bool done = pool.TryTakeDone(tid, &out);
        add_thread_wait_elapsed(
            wait_start,
            ::refuzz::worker::perf::WorkerStage::kThreadPoll);
        if (!done) {
            return false;
        }
        return complete_tid(tid, out);
    };

    auto poll_all = [&]() {
        bool any = false;
        std::uint32_t pending = active_mask;
        while (pending != 0) {
            const int tid = static_cast<int>(std::countr_zero(pending));
            pending &= pending - 1;
            any = poll_tid(tid) || any;
        }
        return any;
    };

    enum class DrainDeadlineSource {
        kPerCall,
        kProgram,
        kExtra,
    };
    struct DrainOutcome {
        uint32_t initial_calls = 0;
        uint32_t completed_calls = 0;
        uint32_t timed_out_calls = 0;
        DrainDeadlineSource deadline_source = DrainDeadlineSource::kPerCall;
    };

    auto drain_in_flight_until_deadline = [&]() {
        DrainOutcome outcome{};
        outcome.initial_calls = static_cast<uint32_t>(
            std::popcount(active_mask));
        if (outcome.initial_calls == 0) {
            return outcome;
        }
        last_scheduled_tid = -1;
        // [threaded end-drain parity] Deadline mirrors executor.cc:1132-1135:
        //   wait_start = now
        //   wait_end   = wait_start + 2*syscall_timeout
        //   wait_end   = max(wait_end, program_start + program_timeout/6)
        //   wait_end   = max(wait_end, wait_start + prog_extra_timeout)
        // The base syscall timeout is per_call_timeout (the per-call attr add-on
        // belongs to each call's own wait, not this drain floor). The
        // program_timeout/6 term is what lets a blocked call that overran even
        // its per-call wait finish in the background so poll_all() collects its
        // full coverage — the old per_call*2 (=100ms at base 50) truncated them.
        const auto wait_start = std::chrono::steady_clock::now();
        auto wait_deadline = wait_start + per_call_timeout * 2;
        const auto prog6_deadline = program_start + program_timeout / 6;
        if (prog6_deadline > wait_deadline) {
            wait_deadline = prog6_deadline;
            outcome.deadline_source = DrainDeadlineSource::kProgram;
        }
        const auto extra_deadline =
            wait_start + std::chrono::milliseconds{prog_extra_timeout_ms};
        if (extra_deadline > wait_deadline) {
            wait_deadline = extra_deadline;
            outcome.deadline_source = DrainDeadlineSource::kExtra;
        }
        const std::size_t completed_before = completed_outputs;
        while (active_mask != 0 &&
               std::chrono::steady_clock::now() <= wait_deadline) {
            if (!poll_all()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        }
        outcome.completed_calls = static_cast<uint32_t>(
            completed_outputs - completed_before);
        outcome.timed_out_calls = static_cast<uint32_t>(
            std::popcount(active_mask));
        while (active_mask != 0) {
            const int tid = static_cast<int>(std::countr_zero(active_mask));
            (void)finish_unfinished_tid(tid);
        }
        return outcome;
    };

    auto schedule_call = [&](const WorkerThreadInput& in,
                             uint64_t call_copyout_idx,
                             std::size_t copyout_pos,
                             std::size_t copyouts_count) {
        ::refuzz::worker::perf::ScopedTimer t(
            perf_sample,
            ::refuzz::worker::perf::WorkerStage::kThreadSchedule);
        for (int tid = 0; tid < pool_size; ++tid) {
            if (is_in_flight(tid)) {
                (void)poll_tid(tid);
            }
            if (kcov_failed) {
                return kExecuteKcovStateInvalid;
            }
            if (is_in_flight(tid)) {
                continue;
            }
            if (!pool.ScheduleCall(tid, in)) {
                continue;
            }
            auto& st = in_flight[static_cast<std::size_t>(tid)];
            st.call_index = static_cast<std::size_t>(in.call_index);
            st.copyout_idx = call_copyout_idx;
            st.copyout_pos = copyout_pos;
            st.copyouts_count = copyouts_count;
            active_mask |= tid_mask(tid);
            last_scheduled_tid = tid;
            return tid;
        }
        return -1;
    };

    {
    ::refuzz::worker::perf::ScopedTimer walk_timer(
        perf_sample,
        ::refuzz::worker::perf::WorkerStage::kWireWalk);
    syz::WireInstrView instr;
    for (;;) {
        const auto st = reader.Next(&instr);
        if (st == syz::WireStreamReader::Status::kEof) {
            break;
        }
        if (st == syz::WireStreamReader::Status::kError) {
            const auto& e = reader.error();
            ::refuzz::worker::log::WorkerLog(
                "[Driver/threaded] reject tag=decode_fail input_len=%u "
                "err='%s' off=%zu\n",
                input_len, e.message.c_str(), e.offset);
            drain_in_flight_until_deadline();
            return -1;
        }
        if (auto* ci = std::get_if<syz::WireCopyin>(&instr)) {
            {
                ::refuzz::worker::perf::ScopedTimer t(
                    perf_sample,
                    ::refuzz::worker::perf::WorkerStage::kCopyIn);
                if (!apply_copyin(scratch, kSyzExecScratchBytes, *ci,
                                  copyout, copyout_set, proc_slot_id,
                                  data_offset)) {
                    drain_in_flight_until_deadline();
                    return -1;
                }
            }
            if (perf_sample != nullptr) {
                ::refuzz::worker::perf::AddSaturating(&perf_sample->copyins, 1);
            }
            continue;
        }
        if (auto* co = std::get_if<syz::WireCopyout>(&instr)) {
            // A well-formed exec wire places call-owned copyouts immediately
            // after WireCall; those are consumed by the WireCall branch below.
            // If a hand-built wire leaves a stray copyout here, apply it in
            // wire order rather than silently dropping it.
            {
                ::refuzz::worker::perf::ScopedTimer t(
                    perf_sample,
                    ::refuzz::worker::perf::WorkerStage::kCopyOut);
                apply_copyout(scratch, kSyzExecScratchBytes, *co,
                              copyout, copyout_set);
            }
            if (perf_sample != nullptr) {
                ::refuzz::worker::perf::AddSaturating(&perf_sample->copyouts, 1);
            }
            continue;
        }
        if (auto* sp = std::get_if<syz::WireSetProps>(&instr)) {
            current_props = *sp;
            have_props    = true;
            continue;
        }
        if (auto* ch = std::get_if<syz::WireCallHeader>(&instr)) {
            if (have_props && !supported_threaded_wire_set_props(current_props)) {
                // [v2 Epic 7 PR-8 diag] same tagging as serial path,便于
                // grep ttyS0 统计 threaded -1 rate 来源。
                ::refuzz::worker::log::WorkerLog(
                    "[Driver/threaded] reject tag=unsupported_props async=%d rerun=%lld\n",
                    current_props.async ? 1 : 0,
                    static_cast<long long>(current_props.rerun));
                return -1;
            }
            if (call_index >= n) {
                ::refuzz::worker::log::WorkerLog(
                    "[Driver/threaded] reject tag=call_index_overflow ci=%zu n=%zu\n",
                    call_index, n);
                return -1;
            }

            // resolve args on main thread. [S3 streaming] argc + each arg come
            // straight off the wire cursor via NextArg — no materialized args
            // vector; resolution is identical to the batch path.
            intptr_t args_local[kMaxArgs] = {};
            const std::size_t argc  = static_cast<std::size_t>(ch->num_args);
            if (argc > kMaxArgs) {
                ::refuzz::worker::log::WorkerLog(
                    "[Driver/threaded] reject tag=argc_overflow argc=%zu max=%zu call_id=%llu\n",
                    argc, kMaxArgs,
                    static_cast<unsigned long long>(ch->call_id));
                return -1;
            }
            {
                ::refuzz::worker::perf::ScopedTimer t(
                    perf_sample,
                    ::refuzz::worker::perf::WorkerStage::kArgResolve);
                for (std::size_t ai = 0; ai < argc; ++ai) {
                    syz::WireArg arg;
                    if (!reader.NextArg(&arg)) {
                        const auto& e = reader.error();
                        ::refuzz::worker::log::WorkerLog(
                            "[Driver/threaded] reject tag=decode_fail "
                            "input_len=%u err='%s' off=%zu\n",
                            input_len, e.message.c_str(), e.offset);
                        drain_in_flight_until_deadline();
                        return -1;
                    }
                    args_local[ai] = resolve_call_arg(
                        scratch, arg,
                        copyout, copyout_set, proc_slot_id,
                        data_offset, kSyzExecScratchBytes);
                }
            }
            // [S3 streaming] Cursor now sits right after this call's args — the
            // point where its copyouts (if any) begin. Save it so completion can
            // replay them (mirrors syzkaller copyout_pos = input_pos post-args).
            const std::size_t copyout_pos = reader.position();
            if (ch->call_id >= syz::generated::kLinuxAmd64CallCount) {
                ::refuzz::worker::log::WorkerLog(
                    "[Driver/threaded] reject tag=bad_call_id id=%llu max=%zu\n",
                    static_cast<unsigned long long>(ch->call_id),
                    syz::generated::kLinuxAmd64CallCount);
                return -1;
            }
            const uint64_t nr =
                syz::generated::kLinuxAmd64CallIdToNr[ch->call_id];

            // [threaded per-call timeout parity] per-call wait =
            // base syscall timeout + this call's timeout attribute. Mirrors
            // upstream executor.cc:1103
            //   timeout_ms = syscall_timeout_ms + call->attrs.timeout * slowdown_scale
            // syz_mount_image$* carries timeout[SYZ_MOUNT_IMAGE_TIMEOUT]=4000ms,
            // so its wait is 50+4000=4050ms and the mount finishes inside its
            // own per-call wait (→ full coverage), while a FUSE blocking call
            // (timeout attr 0) keeps the base 50ms wait and yields to its
            // handler. A flat per-call timeout cannot satisfy both at once.
            // slowdown=1 in the KVM-accelerated QEMU parity config, so the
            // table value (ms) is added directly.
            const std::chrono::milliseconds call_timeout{
                static_cast<uint64_t>(per_call_timeout_ms) +
                syz::generated::kLinuxAmd64CallTimeoutMs[ch->call_id]};
            // [threaded end-drain parity] accumulate prog_timeout attr for the
            // end-drain floor (executor.cc:1081-1082).
            const uint32_t call_prog_timeout =
                syz::generated::kLinuxAmd64CallProgTimeoutMs[ch->call_id];
            if (call_prog_timeout > prog_extra_timeout_ms) {
                prog_extra_timeout_ms = call_prog_timeout;
            }

            // pack input for worker thread
            WorkerThreadInput in{};
            in.executor_id = diagnostic_executor_id;
            in.call_index = static_cast<int>(call_index);
            in.call_nr    = nr;
            in.argc       = static_cast<uint32_t>(argc);
            for (size_t i = 0; i < argc; ++i) {
                in.args[i] = args_local[i];
            }
            in.fail_nth = have_props ? current_props.fail_nth : 0u;
            // [perf 采样 gate fix 2026-05-22] worker thread 根据这个 flag 决定
            // 跳过/启用 内部 NowUs() instrumentation. perf_sample==nullptr 时
            // 整条 worker measurement 路径 0 overhead (跟 main thread 对称).
            in.collect_perf = (perf_sample != nullptr);

            // [S3 streaming] Count and skip this call's contiguous trailing
            // copyouts on the main cursor: consume each WireCopyout via Next(),
            // and seek back the instant a non-copyout (or EOF) appears so the
            // main loop re-reads it. This advance is the streaming analog of the
            // old `instr_index = next_instr` skip; complete_tid later replays
            // exactly copyouts_count of them from copyout_pos.
            std::size_t copyouts_count = 0;
            for (;;) {
                const std::size_t peek = reader.position();
                syz::WireInstrView peeked;
                const auto pst = reader.Next(&peeked);
                if (pst != syz::WireStreamReader::Status::kInstr ||
                    std::get_if<syz::WireCopyout>(&peeked) == nullptr) {
                    reader.seek(peek);
                    break;
                }
                ++copyouts_count;
            }

            const bool call_async = have_props && current_props.async;
            const int chosen_tid =
                schedule_call(in, ch->copyout_idx,
                              copyout_pos, copyouts_count);
            if (chosen_tid == kExecuteKcovStateInvalid) {
                drain_in_flight_until_deadline();
                return kExecuteKcovStateInvalid;
            }
            if (chosen_tid < 0) {
                ::refuzz::worker::log::WorkerLog(
                    "[Driver/threaded] reject tag=out_of_threads ci=%zu pool=%d\n",
                    call_index, pool_size);
                drain_in_flight_until_deadline();
                return -1;
            }

            ++call_index;
            if (perf_sample != nullptr) {
                ::refuzz::worker::perf::AddSaturating(&perf_sample->calls, 1);
            }

            if (!call_async) {
                WorkerThreadOutput out;
                const uint64_t wait_start =
                    perf_sample != nullptr ? ::refuzz::worker::perf::NowUs() : 0;
                const bool done =
                    pool.WaitCallDone(chosen_tid, call_timeout, &out);
                add_thread_wait_elapsed(
                    wait_start,
                    ::refuzz::worker::perf::WorkerStage::kThreadBlockWait);
                if (done) {
                    (void)complete_tid(chosen_tid, out);
                }
                (void)poll_all();
                if (kcov_failed) {
                    drain_in_flight_until_deadline();
                    return kExecuteKcovStateInvalid;
                }
            }
            (void)have_props;
            current_props = {};
            have_props    = false;
            // The main cursor already sits past this call's copyouts (skipped
            // above), so just continue — the streaming analog of the old
            // `instr_index = next_instr`.
            continue;
        }
        // Unreachable: WireInstrView is exhaustively one of the four kinds
        // handled above, each of which `continue`s.
    }
    }  // end wire_walk_us scope
    if (have_props && !supported_threaded_wire_set_props(current_props)) {
        // 残留 SetProps 不合法 — guard 仍会 end task 防止 thread leak。
        return -1;
    }

    {
        ::refuzz::worker::perf::ScopedTimer timer(
            perf_sample,
            ::refuzz::worker::perf::WorkerStage::kPostWalkDrain);
        const DrainOutcome drain = drain_in_flight_until_deadline();
        if (perf_sample != nullptr && drain.initial_calls != 0) {
            ::refuzz::worker::perf::AddSaturating(
                &perf_sample->post_walk_drain_programs, 1);
            ::refuzz::worker::perf::AddSaturating(
                &perf_sample->post_walk_drain_initial_calls,
                drain.initial_calls);
            ::refuzz::worker::perf::AddSaturating(
                &perf_sample->post_walk_drain_completed_calls,
                drain.completed_calls);
            ::refuzz::worker::perf::AddSaturating(
                &perf_sample->post_walk_drain_timed_out_calls,
                drain.timed_out_calls);
            uint32_t* deadline_counter =
                &perf_sample->post_walk_drain_deadline_per_call;
            if (drain.deadline_source == DrainDeadlineSource::kProgram) {
                deadline_counter =
                    &perf_sample->post_walk_drain_deadline_program;
            } else if (drain.deadline_source == DrainDeadlineSource::kExtra) {
                deadline_counter = &perf_sample->post_walk_drain_deadline_extra;
            }
            ::refuzz::worker::perf::AddSaturating(deadline_counter, 1);
        }
    }
    if (kcov_failed) {
        return kExecuteKcovStateInvalid;
    }

    // EndTaskAllUsed:每个 used tid 在 worker thread 内 collector.End/EndAsCmp
    // + ctx.Cleanup。guard 同时覆盖上面的 early return -1 路径,避免
    // threaded task 在错误返回时留下 enabled KCOV session。
    //
    // [当前版本 threaded-cleanup-skip] DoubleFork program child + PC mode 下
    // child 紧跟 CommitResultPage → _exit(0),kernel 自动回收:
    //   - worker thread pthread state (child mm 释放,所有线程死)
    //   - KCOV fd / mmap (close-on-exec / mm release)
    //   - PseudoRuntimeContext.owned_fds (mm release)
    // 主动 EndTaskAllUsed → kEndTask → collector.End() + ctx.Cleanup() 是纯浪费
    // (~4.5ms / program 在 phase5_threaded 实测)。
    //
    // 严禁 Disarm 的 3 个边界:
    //   1) CMP mode (kcov_mode == kCmp): EndAsCmp drain CMP records 给 PackFeedback
    //      写程序级尾包,跳过 → CMP 反馈全丢
    //   2) Reusable child topology (scratch_reset != kForkClean): 跨 program 复用
    //      child 进程,KCOV enabled state / ctx fds / cleanup_callbacks 会泄漏到
    //      下一条 program
    //   3) a side-effectful pseudo (mount/umount, shm_unlink, pkey_free, ...)
    //      registered ctx.Cleanup() callbacks with kernel-global effects a
    //      child _exit won't undo.
    //
    // [syscall-support-detection] the cap gate is gone, so the worker can't tell
    // from a cap bitmap whether boundary 3 applies. Conservatively run full
    // cleanup every program — matches the prior caps-on behavior, and is cheap
    // when no cleanup callbacks were registered. (kcov_mode/scratch_reset are
    // still consulted elsewhere in this function.)
    task_guard.Finish();

    // [v1 per-call shmem write] 同 serial path:head 固定 + tail 已 per-call 写。
    const std::size_t tail_bytes = tail_entries * sizeof(std::uint64_t);
    *output_len = static_cast<uint32_t>(head_bytes + tail_bytes);
    return 0;
}

} // namespace refuzz::worker

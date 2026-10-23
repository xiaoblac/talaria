#pragma once

#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <fcntl.h>
#include <unistd.h>

namespace refuzz::worker::log {

// 全局日志开关。默认关闭。调用 EnableWorkerLog() 后 WorkerLog() 才有输出。
// crash 路径 (WorkerCrashLogSignalAsyncSafe) 不受此开关控制，始终可写。
//
// 写非阻塞 /dev/ttyS1 —— 专供 worker 诊断的第二串口，host 侧单独落盘，与
// serial.log(ttyS0, kernel console) 分开。
//
// 只走 ttyS1，不回退 ttyS0、也不回退 stderr：ttyS0 是 kernel console，worker
// 日志与 kernel printk 共用同一条 tty 线路会被 printk 插进行中截断（实测约
// 1.63% 的行受损，且触发内核日志多的程序更容易丢 —— 是与程序类型相关的有偏
// 采样）。回退会把数据静默退回这个被污染的状态：日志照常产出、看不出问题，
// 但样本已经有偏。失败即空文件，是可检测的显性信号；回退是不可检测的污染。
// stderr 同样可能绕回 console，是同一个问题的另一个入口，所以一并不回退。
// 所有行均以 "[WORKER]" 为前缀，与 kernel crash output 区分。
inline bool& WorkerLogEnabled()
{
    static bool enabled = false;
    return enabled;
}

// 返回 worker 诊断输出 fd，进程内单次 open。ttyS1 不可用时返回 -1（fail-closed，
// 见上方注释），所有写入随之变成 no-op。
inline int OpenWorkerLogFd()
{
    return ::open("/dev/ttyS1",
                  O_WRONLY | O_CLOEXEC | O_NOCTTY | O_NONBLOCK);
}

inline int& WorkerLogFdStorage()
{
    static int fd = OpenWorkerLogFd();
    return fd;
}

inline int WorkerLogFd()
{
    return WorkerLogFdStorage();
}

inline bool MoveWorkerLogFdAtOrAbove(int* next_fd)
{
    if (next_fd == nullptr) {
        return false;
    }
    int& fd = WorkerLogFdStorage();
    if (fd < 0) {
        return true;
    }
    if (fd >= *next_fd) {
        *next_fd = fd + 1;
        return true;
    }
    const int new_fd = ::fcntl(fd, F_DUPFD_CLOEXEC, *next_fd);
    if (new_fd < 0) {
        return false;
    }
    ::close(fd);
    fd = new_fd;
    *next_fd = new_fd + 1;
    return true;
}

inline int WorkerLogFdIfOpen()
{
    const int fd = WorkerLogFdStorage();
    return fd;
}

inline void EnableWorkerLog() { WorkerLogEnabled() = true; }
inline void DisableWorkerLog() { WorkerLogEnabled() = false; }

// [当前版本 kcov-window log suppression — 2026-05-23]
// KCOV per-call 窗口(driver ResetForCall → Dispatch → CollectForCallView)内
// 任何 WorkerLog → write(/dev/ttyS0) 会让 kernel tty 路径(n_tty_write /
// uart / vsnprintf)PC 进入**当前 syscall 的 KCOV 覆盖**,污染跟 syzkaller
// 的 PC 对比(upstream executor 不写串口)。Exp C 实测 printk_tty family
// 在 both_ok 4.3% / syz_dom 2.2%,是 reFuzz 自产噪声。
//
// driver 在进窗口前 SetWorkerLogSuppressed(true),出窗口后 false。窗口内
// handler(USB enum / vhci / mount-timing diag)的 WorkerLog 静默 —— 只丢
// 诊断输出,不改任何 syscall 行为。窗口外(init / reject / heartbeat)照常。
// thread_local:threaded mode 每个 worker 线程独立 KCOV 窗口,互不影响。
// crash log (WorkerCrashLogSignalAsyncSafe) 不走这个 gate,始终可写。
inline bool& WorkerLogSuppressed()
{
    static thread_local bool suppressed = false;
    return suppressed;
}
inline void SetWorkerLogSuppressed(bool v) { WorkerLogSuppressed() = v; }

// [mount-timing diag — 2026-06-02]
// The KCOV-window suppression above silences the per-mount timing events
// (setup_start / decompress_done / mount_enter / mount_exit) because the mount
// dispatch runs *inside* the suppressed window. But when REFUZZ_MOUNT_TIMING_DIAG
// is set (--debug-mount-timing) the run is a measurement run, not a coverage run —
// KCOV purity no longer matters, so suppression must yield to the diag. Read the
// env once; off by default ⇒ zero effect on normal fuzzing.
inline bool MountTimingDiagOverridesSuppression()
{
    static const bool on = [] {
        const char* v = std::getenv("REFUZZ_MOUNT_TIMING_DIAG");
        return v != nullptr && v[0] != '\0' && !(v[0] == '0' && v[1] == '\0');
    }();
    return on;
}

inline bool InitializeWorkerLogProducers(void* shm_base, size_t shm_size, uint32_t worker_id)
{
    (void)shm_base;
    (void)shm_size;
    (void)worker_id;
    return true;
}

inline void ResetWorkerLogProducers()
{
}

inline void WriteWorkerLogBytes(const char* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    const int fd = WorkerLogFd();
    if (fd < 0) {
        return;
    }
    const int saved_errno = errno;
    (void)::write(fd, data, size);
    errno = saved_errno;
}

inline void WorkerLog(const char* fmt, ...)
{
    if (!WorkerLogEnabled() ||
        (WorkerLogSuppressed() && !MountTimingDiagOverridesSuppression())) {
        return;
    }
    if (fmt == nullptr) {
        return;
    }
    // 写到非阻塞诊断 fd，host 侧 ConsoleSensor 可实时读取 console fallback。
    // 格式：[WORKER] <message>  — 前缀用于 host 侧区分 worker 日志与 kernel output。
    char buf[512];
    va_list args;
    va_start(args, fmt);
    int n = std::vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    if (n > 0) {
        const size_t size = static_cast<size_t>(n) < sizeof(buf)
            ? static_cast<size_t>(n) : sizeof(buf) - 1;
        WriteWorkerLogBytes(buf, size);
    }
}

inline void WorkerCrashLogSignal(int32_t signal_number)
{
    (void)signal_number;
}

// crash 路径日志不受 WorkerLogEnabled() 控制，始终可写。
// async-signal-safe：只使用 write()，不调用 malloc/printf。
inline void WorkerCrashLogSignalAsyncSafe(int32_t signal_number)
{
    // 固定格式字符串，避免 async-signal-unsafe 的格式化函数。
    const int fd = WorkerLogFd();
    if (fd < 0) {
        return;
    }
    const char prefix[] = "[WORKER] crash signal=";
    (void)::write(fd, prefix, sizeof(prefix) - 1);
    // 手动把信号号转成 ASCII 数字
    char num[8];
    int i = 0;
    int32_t sig = signal_number;
    if (sig <= 0) {
        num[i++] = '0';
    } else {
        int32_t tmp = sig;
        int len = 0;
        while (tmp > 0) { tmp /= 10; ++len; }
        for (int j = len - 1; j >= 0; --j) {
            num[j] = static_cast<char>('0' + (sig % 10));
            sig /= 10;
        }
        i = len;
    }
    num[i++] = '\n';
    (void)::write(fd, num, static_cast<size_t>(i));
}

} // namespace refuzz::worker::log

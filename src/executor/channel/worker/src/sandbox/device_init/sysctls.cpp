// SetupVmSysctls: host/VM initialization aligned with syzkaller `setup_sysctl`
// (executor/common_linux.h:5537-5602).
//
// This is worker-0 host setup, not the IPC sysctl block inside a sandbox
// namespace. The post-register hook calls it once after CLAIMED/heartbeat and
// before any domain sandbox is created. Every write keeps upstream write_file's
// best-effort behavior.

#include "worker/sandbox/device_init/device_init.hpp"

#include "worker/log/log_macros.hpp"

#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define DILOG(fmt, ...) \
    ::refuzz::worker::log::WorkerLog("[device_init] " fmt "\n", ##__VA_ARGS__)

namespace refuzz::worker::sandbox::device_init {
namespace {

struct SysctlSetting {
    const char* path;
    const char* value;
};

bool WriteSysctl(const SysctlSetting& setting)
{
    const int fd = ::open(setting.path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        const int error_number = errno;
        DILOG("setup_sysctl: open(%s) errno=%d (%s) -- skipped",
              setting.path, error_number, ::strerror(error_number));
        return false;
    }

    const std::size_t length = std::strlen(setting.value);
    const ssize_t written = ::write(fd, setting.value, length);
    const int error_number = written < 0 ? errno : EIO;
    ::close(fd);
    if (written != static_cast<ssize_t>(length)) {
        DILOG("setup_sysctl: write(%s) rc=%zd want=%zu errno=%d (%s) -- skipped",
              setting.path, written, length, error_number,
              ::strerror(error_number));
        return false;
    }
    return true;
}

void ReapCadPid(pid_t cad_pid)
{
    if (::kill(cad_pid, SIGKILL) != 0 && errno != ESRCH) {
        const int error_number = errno;
        DILOG("setup_sysctl: kill(cad_pid=%d) errno=%d (%s)",
              static_cast<int>(cad_pid), error_number,
              ::strerror(error_number));
    }

    for (;;) {
        const pid_t waited = ::waitpid(cad_pid, nullptr, 0);
        if (waited == cad_pid) {
            return;
        }
        if (waited < 0 && errno == EINTR) {
            continue;
        }
        const int error_number = errno;
        DILOG("setup_sysctl: waitpid(cad_pid=%d) failed errno=%d (%s)",
              static_cast<int>(cad_pid), error_number,
              ::strerror(error_number));
        return;
    }
}

} // namespace

void SetupVmSysctls()
{
    // setup_sysctl needs a live PID for kernel/cad_pid. Keep this child alive
    // only while the settings are written, then kill and reap it like upstream.
    const pid_t cad_pid = ::fork();
    if (cad_pid == 0) {
        for (;;) {
            ::sleep(100);
        }
    }

    if (cad_pid < 0) {
        const int error_number = errno;
        DILOG("setup_sysctl: fork failed errno=%d (%s); static settings continue; "
              "ctrl-alt-del/cad_pid skipped",
              error_number, ::strerror(error_number));
    }

    static const SysctlSetting kSettings[] = {
#if defined(__x86_64__) || defined(__amd64__) || defined(__i386__)
        // Suppress noisy/corrupted NMI duration reports on slow debug kernels.
        {"/sys/kernel/debug/x86/nmi_longest_ns", "10000000000"},
#endif
        // Keep the hung threshold unchanged; 20 seconds is khungtaskd's scan
        // cadence and makes hang/stall reporting timing more deterministic.
        {"/proc/sys/kernel/hung_task_check_interval_secs", "20"},
        // Required to unwind through BPF functions in crash reports.
        {"/proc/sys/net/core/bpf_jit_kallsyms", "1"},
        {"/proc/sys/net/core/bpf_jit_harden", "0"},
        {"/proc/sys/kernel/kptr_restrict", "0"},
        {"/proc/sys/kernel/softlockup_all_cpu_backtrace", "1"},
        {"/proc/sys/fs/mount-max", "100"},
        {"/proc/sys/vm/oom_dump_tasks", "0"},
        {"/proc/sys/debug/exception-trace", "0"},
        {"/proc/sys/kernel/printk", "7 4 1 3"},
        {"/proc/sys/kernel/keys/gc_delay", "1"},
        {"/proc/sys/vm/oom_kill_allocating_task", "1"},
    };

    std::size_t failed_writes = 0;
    for (const SysctlSetting& setting : kSettings) {
        if (!WriteSysctl(setting)) {
            ++failed_writes;
        }
    }

    char cad_pid_text[32] = {};
    bool cad_pid_text_valid = false;
    if (cad_pid > 0) {
        const int written = std::snprintf(
            cad_pid_text, sizeof(cad_pid_text), "%d", static_cast<int>(cad_pid));
        cad_pid_text_valid = written > 0 &&
                             static_cast<std::size_t>(written) < sizeof(cad_pid_text);
    }

    if (cad_pid_text_valid) {
        const SysctlSetting ctrl_alt_del{
            "/proc/sys/kernel/ctrl-alt-del", "0"};
        const SysctlSetting cad_pid_setting{
            "/proc/sys/kernel/cad_pid", cad_pid_text};
        if (!WriteSysctl(ctrl_alt_del)) {
            ++failed_writes;
        }
        if (!WriteSysctl(cad_pid_setting)) {
            ++failed_writes;
        }
    }

    if (cad_pid > 0) {
        ReapCadPid(cad_pid);
    }
    DILOG("setup_sysctl: completed (failed writes=%zu)", failed_writes);
}

} // namespace refuzz::worker::sandbox::device_init

// SetupFusectl — mount fusectl 到 /sys/fs/fuse/connections,跟 syzkaller
// `setup_fusectl` (common_linux.h:4027) 同语义:
//   mount(NULL, "/sys/fs/fuse/connections", "fusectl", 0, NULL)
//
// /sys/fs/fuse/connections 通常是 sysfs 下已存在的目录(CONFIG_FUSE_FS=y 时
// kernel 暴露);mount fusectl 类型可让 FUSE pseudo 看到 connection 控制接口。
// 缺 CONFIG_FUSE_FS 时 mount fail silent。

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "worker/sandbox/device_init/device_init.hpp"

#include "worker/log/log_macros.hpp"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <cstdlib>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <time.h>
#include <unistd.h>

namespace refuzz::worker::sandbox::device_init {

namespace {

std::uint64_t MonotonicNowUs()
{
    timespec ts{};
    if (::clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return static_cast<std::uint64_t>(ts.tv_sec) * 1'000'000ULL +
           static_cast<std::uint64_t>(ts.tv_nsec) / 1'000ULL;
}

bool DeadlineExpired(std::uint64_t absolute_deadline_us)
{
    return absolute_deadline_us != 0 &&
           MonotonicNowUs() >= absolute_deadline_us;
}

// Host tests may have user-session FUSE mounts (gvfs/vmhgfs). Keep the
// production abort behavior, but provide one process-wide test gate for every
// caller, including the program watchdog path.
bool FuseAbortDisabled()
{
    const char* value = ::getenv("REFUZZ_DISABLE_STOP_FUSE_ABORT");
    return value != nullptr && value[0] != '\0' &&
           !(value[0] == '0' && value[1] == '\0');
}

} // namespace

void SetupFusectl()
{
    if (::mount(nullptr, "/sys/fs/fuse/connections", "fusectl", 0, nullptr) != 0) {
        ::refuzz::worker::log::WorkerLog(
            "[device_init] fusectl: mount failed errno=%d (%s) — CONFIG_FUSE_FS"
            " 可能 disabled / 路径不存在,跳过\n",
            errno, strerror(errno));
        return;
    }
    ::refuzz::worker::log::WorkerLog(
        "[device_init] fusectl: mounted at /sys/fs/fuse/connections\n");
}

std::uint32_t AbortFuseConnections(std::uint64_t absolute_deadline_us)
{
    constexpr const char* kConnections = "/sys/fs/fuse/connections";
    if (FuseAbortDisabled()) {
        ::refuzz::worker::log::WorkerLog(
            "[device_init] fusectl: abort disabled by test environment\n");
        return 0;
    }
    if (DeadlineExpired(absolute_deadline_us)) {
        ::refuzz::worker::log::WorkerLog(
            "[device_init] fusectl: abort deadline already expired\n");
        return 0;
    }
    DIR* dir = ::opendir(kConnections);
    if (dir == nullptr) {
        ::refuzz::worker::log::WorkerLog(
            "[device_init] fusectl: abort scan failed errno=%d (%s)\n",
            errno, strerror(errno));
        return 0;
    }

    std::uint32_t aborted = 0;
    for (;;) {
        errno = 0;
        dirent* entry = ::readdir(dir);
        if (entry == nullptr) {
            break;
        }
        if (DeadlineExpired(absolute_deadline_us)) {
            break;
        }
        if (::strcmp(entry->d_name, ".") == 0 ||
            ::strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char path[300]{};
        const int path_len = ::snprintf(
            path, sizeof(path), "%s/%s/abort", kConnections, entry->d_name);
        if (path_len <= 0 || static_cast<std::size_t>(path_len) >= sizeof(path)) {
            continue;
        }

        const int fd = ::open(path, O_WRONLY | O_NONBLOCK | O_CLOEXEC);
        if (fd < 0) {
            ::refuzz::worker::log::WorkerLog(
                "[device_init] fusectl: open abort failed path=%s errno=%d\n",
                path, errno);
            continue;
        }
        const char trigger = '1';
        const ssize_t written = ::write(fd, &trigger, sizeof(trigger));
        const int write_error = written < 0 ? errno : 0;
        ::close(fd);
        if (written == static_cast<ssize_t>(sizeof(trigger))) {
            ++aborted;
        } else {
            ::refuzz::worker::log::WorkerLog(
                "[device_init] fusectl: abort write failed path=%s errno=%d\n",
                path, write_error);
        }
    }
    ::closedir(dir);
    ::refuzz::worker::log::WorkerLog(
        "[device_init] fusectl: timeout escalation aborted=%u\n", aborted);
    return aborted;
}

} // namespace refuzz::worker::sandbox::device_init

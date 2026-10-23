// NetdevsimAdd — 端口 syzkaller `netdevsim_add` (common_linux.h:1203)。
//
// 写 /sys/bus/netdevsim/del_device (清除上一轮),再 /sys/bus/netdevsim/new_device
// 加新 netdevsim device。`port_count` 与 sys/linux/socket_netlink_generic_devlink.txt
// 的 syscall description 同步(upstream 4)。
//
// Upstream initializes the devlink ports immediately after new_device. That
// brings each port up and gives it the stable netdevsim0, netdevsim1, ... names
// expected by the generated programs.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "worker/sandbox/device_init/device_init.hpp"

#include "worker/log/log_macros.hpp"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define NDLOG(fmt, ...) \
    ::refuzz::worker::log::WorkerLog("[device_init] netdevsim: " fmt "\n", ##__VA_ARGS__)

namespace refuzz::worker::sandbox::device_init {

namespace {

bool WriteSysfsLine(const char* path, const char* fmt, ...)
{
    char line[64];
    va_list ap;
    va_start(ap, fmt);
    const int n = ::vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    if (n < 0 || n >= static_cast<int>(sizeof(line))) {
        NDLOG("vsnprintf overflow path=%s", path);
        return false;
    }
    const int fd = ::open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        // /sys/bus/netdevsim 缺路径(CONFIG_NETDEVSIM=n)— 不致命,silent quiet
        return false;
    }
    const ssize_t w = ::write(fd, line, static_cast<size_t>(n));
    ::close(fd);
    if (w != n) {
        NDLOG("write(%s) rc=%zd want=%d errno=%d", path, w, n, errno);
        return false;
    }
    return true;
}

} // namespace

void NetdevsimAdd(unsigned addr, unsigned port_count)
{
    // 先清(sticky device,netns destruction 不会自动删,留存可能 conflict)。
    // 删失败常见(没旧设备),忽略。
    (void)WriteSysfsLine("/sys/bus/netdevsim/del_device", "%u", addr);
    if (WriteSysfsLine("/sys/bus/netdevsim/new_device", "%u %u",
                       addr, port_count)) {
        char dev_name[32];
        ::snprintf(dev_name, sizeof(dev_name), "netdevsim%u", addr);
        InitializeDevlinkPorts("netdevsim", dev_name, "netdevsim");
        NDLOG("new_device addr=%u port_count=%u ok; devlink ports initialized",
              addr, port_count);
    } else {
        NDLOG("new_device addr=%u skipped (CONFIG_NETDEVSIM=n / sysfs missing)",
              addr);
    }
}

} // namespace refuzz::worker::sandbox::device_init

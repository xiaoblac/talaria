// SetupGadgetfs — 对齐 syzkaller `setup_gadgetfs`
// (executor/common_linux.h:4010-4017)。
//
//   mkdir /dev/gadgetfs (EEXIST OK)
//   mount("gadgetfs", "/dev/gadgetfs", "gadgetfs", 0, NULL)
//
// must be called after chroot —— /dev 已 bind 至 newroot 视图。
// 缺 CONFIG_USB_GADGETFS 时 mount fail silent;syzkaller `debug()` 同行为。

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "worker/sandbox/device_init/device_init.hpp"

#include "worker/log/log_macros.hpp"

#include <errno.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>

namespace refuzz::worker::sandbox::device_init {

void SetupGadgetfs()
{
    if (::mkdir("/dev/gadgetfs", 0777) != 0 && errno != EEXIST) {
        ::refuzz::worker::log::WorkerLog(
            "[device_init] gadgetfs: mkdir(/dev/gadgetfs) errno=%d (%s)\n",
            errno, ::strerror(errno));
        // 继续 — 老 image 可能已存在但非 EEXIST(eg. ENOTDIR)
    }
    if (::mount("gadgetfs", "/dev/gadgetfs", "gadgetfs", 0, nullptr) != 0) {
        ::refuzz::worker::log::WorkerLog(
            "[device_init] gadgetfs: mount errno=%d (%s) — "
            "kernel CONFIG_USB_GADGETFS 可能 disabled,跳过\n",
            errno, ::strerror(errno));
        return;
    }
    ::refuzz::worker::log::WorkerLog(
        "[device_init] gadgetfs: mounted at /dev/gadgetfs\n");
}

} // namespace refuzz::worker::sandbox::device_init

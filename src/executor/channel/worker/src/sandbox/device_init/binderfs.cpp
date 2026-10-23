// SetupBinderfs — mount 一个 binderfs 实例到 /dev/binderfs,跟 syzkaller
// `setup_binderfs` (common_linux.h:4034) 同语义:
//   - mkdir /dev/binderfs(EEXIST OK)
//   - mount("binder", "/dev/binderfs", "binder", 0, NULL)
//
// 在 NEWNS 内 mount 生效仅本 mount namespace 可见,不影响 host。kernel
// 缺 CONFIG_ANDROID_BINDERFS 时 mount fail silent;syzkaller `debug()` 也是
// 这个行为。

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

void SetupBinderfs()
{
    if (::mkdir("/dev/binderfs", 0777) != 0 && errno != EEXIST) {
        ::refuzz::worker::log::WorkerLog(
            "[device_init] binderfs: mkdir(/dev/binderfs) failed errno=%d (%s)\n",
            errno, strerror(errno));
        // 继续 — mount 可能因 EEXIST + 已挂 OK
    }
    if (::mount("binder", "/dev/binderfs", "binder", 0, nullptr) != 0) {
        ::refuzz::worker::log::WorkerLog(
            "[device_init] binderfs: mount(binder@/dev/binderfs) failed errno=%d (%s)"
            " — kernel CONFIG_ANDROID_BINDERFS 可能 disabled,跳过\n",
            errno, strerror(errno));
        return;
    }
    ::refuzz::worker::log::WorkerLog(
        "[device_init] binderfs: mounted at /dev/binderfs\n");
}

} // namespace refuzz::worker::sandbox::device_init

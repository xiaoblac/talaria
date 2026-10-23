// SetupBinfmtMisc — 注册 syz0/syz1 magic-based binfmt handler,跟 syzkaller
// `setup_binfmt_misc` (common_linux.h:5075-5093) byte-equal:
//   1. mount(binfmt_misc, /proc/sys/fs/binfmt_misc) — EBUSY OK
//   2. write_file(/proc/sys/fs/binfmt_misc/register, ":syz0:M:0:\x01::./file0:")
//   3. write_file(/proc/sys/fs/binfmt_misc/register, ":syz1:M:1:\x02::./file0:POC")
//
// 没这一步,execveat$binfmt 在 magic-prefixed 文件上找不到 syz0/syz1 handler,
// 一律 fall-through 到 script/ELF/aout 检查 → ENOEXEC。10 个 actionable
// execveat$binfmt mismatch (syz=ENOENT/EACCES, ref=ENOEXEC) 的根因。
//
// worker 0 在 Register() 后的 VM setup hook 调一次;影响整个 host
// binfmt_misc 注册表,所有后续 loop/program 共用。

#include "worker/sandbox/device_init/device_init.hpp"

#include "worker/log/log_macros.hpp"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/mount.h>
#include <unistd.h>

namespace refuzz::worker::sandbox::device_init {

namespace {

bool WriteFileAtomic(const char* path, const char* data, std::size_t len)
{
    const int fd = ::open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        return false;
    }
    const ssize_t n = ::write(fd, data, len);
    ::close(fd);
    return n == static_cast<ssize_t>(len);
}

} // namespace

void SetupBinfmtMisc()
{
    // upstream:`if (mount(0, "/proc/sys/fs/binfmt_misc", "binfmt_misc", 0, 0)
    // && errno != EBUSY)` — host 通常已挂(VM init),EBUSY 跳过即可。
    if (::mount(nullptr, "/proc/sys/fs/binfmt_misc", "binfmt_misc", 0, nullptr) != 0
        && errno != EBUSY) {
        ::refuzz::worker::log::WorkerLog(
            "[device_init] binfmt_misc: mount failed errno=%d (%s) — "
            "kernel CONFIG_BINFMT_MISC disabled,跳过注册\n",
            errno, ::strerror(errno));
        return;
    }

    // upstream 写 2 条 register 字符串。M = magic-based(扫文件头字节),
    // 0/1 = magic offset,\x01/\x02 = magic byte,空 mask,./file0 = interpreter,
    // POC = preserve-argv0 + open-binary + credential flags(syz1 用)。
    constexpr char kSyz0[] = ":syz0:M:0:\x01::./file0:";
    constexpr char kSyz1[] = ":syz1:M:1:\x02::./file0:POC";
    if (!WriteFileAtomic("/proc/sys/fs/binfmt_misc/register",
                         kSyz0, sizeof(kSyz0) - 1)) {
        ::refuzz::worker::log::WorkerLog(
            "[device_init] binfmt_misc: register syz0 failed errno=%d (%s)\n",
            errno, ::strerror(errno));
        return;
    }
    if (!WriteFileAtomic("/proc/sys/fs/binfmt_misc/register",
                         kSyz1, sizeof(kSyz1) - 1)) {
        ::refuzz::worker::log::WorkerLog(
            "[device_init] binfmt_misc: register syz1 failed errno=%d (%s)\n",
            errno, ::strerror(errno));
        return;
    }
    ::refuzz::worker::log::WorkerLog(
        "[device_init] binfmt_misc: registered syz0 + syz1 handlers\n");
}

} // namespace refuzz::worker::sandbox::device_init

// Behavior tests for the TUN node repair and netdevsim/devlink setup paths.
// Filesystem syscalls are intercepted, so no host /dev or /sys state is touched.

#include "worker/sandbox/device_init/device_init.hpp"
#include "worker/sandbox/device_init/netlink_builders.hpp"

#include <cerrno>
#include <climits>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>

namespace device_init = ::refuzz::worker::sandbox::device_init;

namespace {

#define CHECK(expr)                                                       \
    do {                                                                  \
        if (!(expr)) {                                                    \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,  \
                         #expr);                                          \
            std::abort();                                                 \
        }                                                                 \
    } while (0)

#define RUN_TEST(fn)                                                      \
    do {                                                                  \
        std::fprintf(stderr, "RUN  %s\n", #fn);                           \
        fn();                                                             \
        std::fprintf(stderr, "OK   %s\n", #fn);                           \
    } while (0)

enum class TunNodeState {
    kCorrect,
    kWrong,
    kMissing,
};

struct TunCalls {
    unsigned int stat = 0;
    unsigned int unlink = 0;
    unsigned int mkdir = 0;
    unsigned int mknod = 0;
    unsigned int chmod = 0;
};

struct DevlinkCall {
    unsigned int count = 0;
    std::string bus;
    std::string device;
    std::string prefix;
};

constexpr int kDeleteFd = 9201;
constexpr int kNewFd = 9202;

TunNodeState g_tun_node_state = TunNodeState::kCorrect;
TunCalls g_tun_calls{};
int g_unlink_error = 0;
int g_mkdir_error = 0;
int g_mknod_error = 0;
int g_chmod_error = 0;
int g_tun_open_error = 0;
unsigned int g_tun_open_count = 0;
unsigned int g_event_sequence = 0;
unsigned int g_tun_stat_order = 0;
unsigned int g_tun_open_order = 0;

int g_delete_open_error = 0;
int g_new_open_error = 0;
bool g_short_new_write = false;
unsigned int g_delete_open_count = 0;
unsigned int g_new_open_count = 0;
unsigned int g_delete_close_count = 0;
unsigned int g_new_close_count = 0;
std::string g_delete_write;
std::string g_new_write;
DevlinkCall g_devlink_call{};

void ResetTunFakes(TunNodeState state)
{
    g_tun_node_state = state;
    g_tun_calls = {};
    g_unlink_error = 0;
    g_mkdir_error = 0;
    g_mknod_error = 0;
    g_chmod_error = 0;
    g_tun_open_error = 0;
    g_tun_open_count = 0;
    g_event_sequence = 0;
    g_tun_stat_order = 0;
    g_tun_open_order = 0;
}

void ResetNetdevsimFakes()
{
    g_delete_open_error = 0;
    g_new_open_error = 0;
    g_short_new_write = false;
    g_delete_open_count = 0;
    g_new_open_count = 0;
    g_delete_close_count = 0;
    g_new_close_count = 0;
    g_delete_write.clear();
    g_new_write.clear();
    g_devlink_call = {};
}

void TestCorrectTunNodeIsKept()
{
    ResetTunFakes(TunNodeState::kCorrect);
    device_init::CorrectDevNetTun();
    CHECK(g_tun_calls.stat == 1);
    CHECK(g_tun_calls.unlink == 0);
    CHECK(g_tun_calls.mkdir == 0);
    CHECK(g_tun_calls.mknod == 0);
    CHECK(g_tun_calls.chmod == 0);
}

void TestWrongTunNodeIsRecreated()
{
    ResetTunFakes(TunNodeState::kWrong);
    device_init::CorrectDevNetTun();
    CHECK(g_tun_calls.stat == 1);
    CHECK(g_tun_calls.unlink == 1);
    CHECK(g_tun_calls.mkdir == 1);
    CHECK(g_tun_calls.mknod == 1);
    CHECK(g_tun_calls.chmod == 1);
}

void TestMissingTunNodeIsCreated()
{
    ResetTunFakes(TunNodeState::kMissing);
    g_mkdir_error = EEXIST;
    device_init::CorrectDevNetTun();
    CHECK(g_tun_calls.stat == 1);
    CHECK(g_tun_calls.unlink == 0);
    CHECK(g_tun_calls.mkdir == 1);
    CHECK(g_tun_calls.mknod == 1);
    CHECK(g_tun_calls.chmod == 1);
}

void TestTunRepairAttemptsAllOperationsAfterFailures()
{
    ResetTunFakes(TunNodeState::kWrong);
    g_unlink_error = EACCES;
    g_mkdir_error = EACCES;
    g_mknod_error = EPERM;
    g_chmod_error = EPERM;
    device_init::CorrectDevNetTun();
    CHECK(g_tun_calls.unlink == 1);
    CHECK(g_tun_calls.mkdir == 1);
    CHECK(g_tun_calls.mknod == 1);
    CHECK(g_tun_calls.chmod == 1);
}

void TestInitializeTunRepairsBeforeOpen()
{
    ResetTunFakes(TunNodeState::kCorrect);
    g_tun_open_error = ENODEV;
    CHECK(device_init::InitializeTun() == -ENODEV);
    CHECK(g_tun_calls.stat == 1);
    CHECK(g_tun_open_count == 1);
    CHECK(g_tun_stat_order != 0);
    CHECK(g_tun_stat_order < g_tun_open_order);
}

void TestNetdevsimSuccessInitializesPorts()
{
    ResetNetdevsimFakes();
    g_delete_open_error = ENOENT;
    device_init::NetdevsimAdd(17, 4);

    CHECK(g_delete_open_count == 1);
    CHECK(g_delete_write.empty());
    CHECK(g_new_open_count == 1);
    CHECK(g_new_write == "17 4");
    CHECK(g_new_close_count == 1);
    CHECK(g_devlink_call.count == 1);
    CHECK(g_devlink_call.bus == "netdevsim");
    CHECK(g_devlink_call.device == "netdevsim17");
    CHECK(g_devlink_call.prefix == "netdevsim");
}

void TestNetdevsimFormatsMaximumAddress()
{
    ResetNetdevsimFakes();
    device_init::NetdevsimAdd(UINT_MAX, UINT_MAX);

    CHECK(g_delete_write == std::to_string(UINT_MAX));
    CHECK(g_new_write == std::to_string(UINT_MAX) + " " +
                             std::to_string(UINT_MAX));
    CHECK(g_devlink_call.count == 1);
    CHECK(g_devlink_call.device ==
          std::string("netdevsim") + std::to_string(UINT_MAX));
}

void TestNetdevsimCreationFailureSkipsPorts()
{
    ResetNetdevsimFakes();
    g_new_open_error = ENOENT;
    device_init::NetdevsimAdd(9, 4);

    CHECK(g_delete_write == "9");
    CHECK(g_new_open_count == 1);
    CHECK(g_new_write.empty());
    CHECK(g_devlink_call.count == 0);
}

void TestNetdevsimShortWriteSkipsPorts()
{
    ResetNetdevsimFakes();
    g_short_new_write = true;
    device_init::NetdevsimAdd(11, 4);

    CHECK(g_new_write == "11 4");
    CHECK(g_new_close_count == 1);
    CHECK(g_devlink_call.count == 0);
}

} // namespace

namespace refuzz::worker::sandbox::device_init {

void InitializeDevlinkPorts(const char* bus_name,
                            const char* dev_name,
                            const char* netdev_prefix)
{
    ++g_devlink_call.count;
    g_devlink_call.bus = bus_name;
    g_devlink_call.device = dev_name;
    g_devlink_call.prefix = netdev_prefix;
}

void NetlinkAddAddr4(Nlmsg*, int, const char*, const char*) {}
void NetlinkAddAddr6(Nlmsg*, int, const char*, const char*) {}
void NetlinkAddNeigh(Nlmsg*, int, const char*, const void*, int,
                     const void*, int) {}
void NetlinkDeviceChange(Nlmsg*, int, const char*, bool, const char*,
                         const void*, int, const char*) {}

} // namespace refuzz::worker::sandbox::device_init

extern "C" int __real_stat(const char* path, struct stat* status);
extern "C" int __real_unlink(const char* path);
extern "C" int __real_mkdir(const char* path, mode_t mode);
extern "C" int __real_mknod(const char* path, mode_t mode, dev_t device);
extern "C" int __real_chmod(const char* path, mode_t mode);
extern "C" int __real_open(const char* path, int flags, ...);
extern "C" ssize_t __real_write(int fd, const void* data, size_t size);
extern "C" int __real_close(int fd);

extern "C" int __wrap_stat(const char* path, struct stat* status)
{
    if (::strcmp(path, "/dev/net/tun") != 0) {
        return __real_stat(path, status);
    }
    CHECK(status != nullptr);
    ++g_tun_calls.stat;
    g_tun_stat_order = ++g_event_sequence;
    ::memset(status, 0, sizeof(*status));
    switch (g_tun_node_state) {
    case TunNodeState::kCorrect:
        status->st_mode = S_IFCHR | 0600;
        status->st_rdev = ::makedev(10, 200);
        return 0;
    case TunNodeState::kWrong:
        status->st_mode = S_IFREG | 0644;
        return 0;
    case TunNodeState::kMissing:
        errno = ENOENT;
        return -1;
    }
    std::abort();
}

extern "C" int __wrap_unlink(const char* path)
{
    if (::strcmp(path, "/dev/net/tun") != 0) {
        return __real_unlink(path);
    }
    ++g_tun_calls.unlink;
    if (g_unlink_error != 0) {
        errno = g_unlink_error;
        return -1;
    }
    return 0;
}

extern "C" int __wrap_mkdir(const char* path, mode_t mode)
{
    if (::strcmp(path, "/dev/net") != 0) {
        return __real_mkdir(path, mode);
    }
    CHECK(mode == 0755);
    ++g_tun_calls.mkdir;
    if (g_mkdir_error != 0) {
        errno = g_mkdir_error;
        return -1;
    }
    return 0;
}

extern "C" int __wrap_mknod(const char* path, mode_t mode, dev_t device)
{
    if (::strcmp(path, "/dev/net/tun") != 0) {
        return __real_mknod(path, mode, device);
    }
    CHECK((mode & S_IFMT) == S_IFCHR);
    CHECK((mode & 0777) == 0666);
    CHECK(::major(device) == 10);
    CHECK(::minor(device) == 200);
    ++g_tun_calls.mknod;
    if (g_mknod_error != 0) {
        errno = g_mknod_error;
        return -1;
    }
    return 0;
}

extern "C" int __wrap_chmod(const char* path, mode_t mode)
{
    if (::strcmp(path, "/dev/net/tun") != 0) {
        return __real_chmod(path, mode);
    }
    CHECK(mode == 0666);
    ++g_tun_calls.chmod;
    if (g_chmod_error != 0) {
        errno = g_chmod_error;
        return -1;
    }
    return 0;
}

extern "C" int __wrap_open(const char* path, int flags, ...)
{
    if (::strcmp(path, "/dev/net/tun") == 0) {
        CHECK(flags == (O_RDWR | O_NONBLOCK));
        ++g_tun_open_count;
        g_tun_open_order = ++g_event_sequence;
        if (g_tun_open_error != 0) {
            errno = g_tun_open_error;
            return -1;
        }
        std::abort();
    }
    if (::strcmp(path, "/sys/bus/netdevsim/del_device") == 0) {
        CHECK(flags == (O_WRONLY | O_CLOEXEC));
        ++g_delete_open_count;
        if (g_delete_open_error != 0) {
            errno = g_delete_open_error;
            return -1;
        }
        return kDeleteFd;
    }
    if (::strcmp(path, "/sys/bus/netdevsim/new_device") == 0) {
        CHECK(flags == (O_WRONLY | O_CLOEXEC));
        ++g_new_open_count;
        if (g_new_open_error != 0) {
            errno = g_new_open_error;
            return -1;
        }
        return kNewFd;
    }
    if ((flags & O_CREAT) != 0) {
        va_list args;
        va_start(args, flags);
        const mode_t mode = static_cast<mode_t>(va_arg(args, int));
        va_end(args);
        return __real_open(path, flags, mode);
    }
    return __real_open(path, flags);
}

extern "C" ssize_t __wrap_write(int fd, const void* data, size_t size)
{
    CHECK(data != nullptr);
    const std::string value(static_cast<const char*>(data), size);
    if (fd == kDeleteFd) {
        g_delete_write = value;
        return static_cast<ssize_t>(size);
    }
    if (fd == kNewFd) {
        g_new_write = value;
        if (g_short_new_write) {
            errno = EIO;
            return size == 0 ? 0 : static_cast<ssize_t>(size - 1);
        }
        return static_cast<ssize_t>(size);
    }
    return __real_write(fd, data, size);
}

extern "C" int __wrap_close(int fd)
{
    if (fd == kDeleteFd) {
        ++g_delete_close_count;
        return 0;
    }
    if (fd == kNewFd) {
        ++g_new_close_count;
        return 0;
    }
    return __real_close(fd);
}

int main()
{
    RUN_TEST(TestCorrectTunNodeIsKept);
    RUN_TEST(TestWrongTunNodeIsRecreated);
    RUN_TEST(TestMissingTunNodeIsCreated);
    RUN_TEST(TestTunRepairAttemptsAllOperationsAfterFailures);
    RUN_TEST(TestInitializeTunRepairsBeforeOpen);
    RUN_TEST(TestNetdevsimSuccessInitializesPorts);
    RUN_TEST(TestNetdevsimFormatsMaximumAddress);
    RUN_TEST(TestNetdevsimCreationFailureSkipsPorts);
    RUN_TEST(TestNetdevsimShortWriteSkipsPorts);
    return 0;
}

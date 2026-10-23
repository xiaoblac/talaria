// Copyright 2026 reFuzz project author -------youngkk.
//
// fault_inject.cpp — implementation of worker-side fault-injection helpers.
// See fault_inject.hpp for the contract.

#include "worker/driver/fault_inject.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

namespace refuzz::worker {

namespace {

constexpr const char* kFailNthPath = "/proc/thread-self/fail-nth";

}  // namespace

int inject_fault(int nth)
{
    const int fd = ::open(kFailNthPath, O_RDWR);
    if (fd < 0) {
        return -1;
    }
    char buf[16];
    const int n = std::snprintf(buf, sizeof(buf), "%d", nth);
    if (n <= 0 || static_cast<std::size_t>(n) >= sizeof(buf)) {
        ::close(fd);
        return -1;
    }
    const ssize_t written = ::write(fd, buf, static_cast<std::size_t>(n));
    if (written != static_cast<ssize_t>(n)) {
        ::close(fd);
        return -1;
    }
    return fd;
}

bool fault_injected(int fd)
{
    if (fd < 0) {
        return false;
    }
    char buf[16];
    const ssize_t n = ::read(fd, buf, sizeof(buf) - 1);
    bool injected = false;
    if (n == 2 && buf[0] == '0' && buf[1] == '\n') {
        injected = true;
    }
    // Reset to "0" for the next iteration's fail-nth probe (mirror
    // upstream common_linux.h:4775).
    buf[0] = '0';
    (void)::write(fd, buf, 1);
    ::close(fd);
    return injected;
}

}  // namespace refuzz::worker

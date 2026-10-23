#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "worker/ivshmem_attach.hpp"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

namespace refuzz::worker {
namespace {

void SetError(std::string* error_message, const std::string& message)
{
    if (error_message != nullptr) {
        *error_message = message;
    }
}

int ParseBarSize(const char* dev_dir, int bar_index, size_t* out_size)
{
    std::string path = std::string(dev_dir) + "/resource";
    FILE* file = fopen(path.c_str(), "r");
    if (file == nullptr) {
        return -1;
    }
    char line[256];
    for (int index = 0; index <= bar_index; ++index) {
        if (fgets(line, sizeof(line), file) == nullptr) {
            fclose(file);
            return -1;
        }
    }
    fclose(file);

    unsigned long long start = 0;
    unsigned long long end = 0;
    unsigned long long flags = 0;
    if (sscanf(line, "%llx %llx %llx", &start, &end, &flags) != 3 || end < start) {
        return -1;
    }
    *out_size = static_cast<size_t>(end - start + 1);
    return 0;
}

int FindIvshmemDevice(char* out_dev, size_t out_len, size_t* bar0_size, size_t* bar2_size)
{
    DIR* dir = opendir("/sys/bus/pci/devices");
    if (dir == nullptr) {
        return -1;
    }

    char best_dev[4096] = {0};
    size_t best_bar0 = 0;
    size_t best_bar2 = 0;
    dirent* entry = nullptr;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_name[0] == '.') {
            continue;
        }

        const std::string dev_path = std::string("/sys/bus/pci/devices/") + entry->d_name;
        if (dev_path.size() + 1 > sizeof(best_dev)) {
            continue;
        }

        char dev_dir[4096];
        memcpy(dev_dir, dev_path.c_str(), dev_path.size() + 1);
        const std::string vendor_path = std::string(dev_dir) + "/vendor";
        const std::string device_path = std::string(dev_dir) + "/device";

        FILE* file = fopen(vendor_path.c_str(), "r");
        if (file == nullptr) {
            continue;
        }
        unsigned int vendor = 0;
        int matched = fscanf(file, "%x", &vendor);
        fclose(file);
        if (matched != 1 || vendor != 0x1af4) {
            continue;
        }

        file = fopen(device_path.c_str(), "r");
        if (file == nullptr) {
            continue;
        }
        unsigned int device = 0;
        matched = fscanf(file, "%x", &device);
        fclose(file);
        if (matched != 1 || device != 0x1110) {
            continue;
        }

        size_t current_bar0 = 0;
        size_t current_bar2 = 0;
        if (ParseBarSize(dev_dir, 0, &current_bar0) != 0 ||
            ParseBarSize(dev_dir, 2, &current_bar2) != 0) {
            continue;
        }

        if (current_bar2 >= best_bar2) {
            best_bar2 = current_bar2;
            best_bar0 = current_bar0;
            if (snprintf(best_dev, sizeof(best_dev), "%s", dev_dir) >=
                static_cast<int>(sizeof(best_dev))) {
                continue;
            }
        }
    }

    closedir(dir);
    if (best_dev[0] == '\0' || strlen(best_dev) + 1 > out_len) {
        return -1;
    }
    if (snprintf(out_dev, out_len, "%s", best_dev) >= static_cast<int>(out_len)) {
        return -1;
    }
    *bar0_size = best_bar0;
    *bar2_size = best_bar2;
    return 0;
}

int ResolveResources(char* out_res0,
                     size_t out_res0_len,
                     char* out_res2,
                     size_t out_res2_len,
                     size_t* bar0_size,
                     size_t* bar2_size)
{
    char dev_dir[4096];
    if (FindIvshmemDevice(dev_dir, sizeof(dev_dir), bar0_size, bar2_size) != 0) {
        return -1;
    }

    const std::string res0 = std::string(dev_dir) + "/resource0";
    const std::string res2 = std::string(dev_dir) + "/resource2";
    if (res0.size() + 1 > out_res0_len || res2.size() + 1 > out_res2_len) {
        return -1;
    }

    memcpy(out_res0, res0.c_str(), res0.size() + 1);
    memcpy(out_res2, res2.c_str(), res2.size() + 1);
    return 0;
}

} // namespace

bool AttachIvshmemMapping(IvshmemMapping* mapping, std::string* error_message)
{
    if (mapping == nullptr) {
        SetError(error_message, "mapping is null");
        return false;
    }

    char res0[4096] = {0};
    char res2[4096] = {0};
    size_t bar0_size = 0;
    size_t bar2_size = 0;
    if (ResolveResources(res0, sizeof(res0), res2, sizeof(res2), &bar0_size, &bar2_size) != 0) {
        SetError(error_message, "failed to resolve ivshmem resources");
        return false;
    }

    mapping->driver_fd = open("/dev/ivshmem0", O_RDWR | O_CLOEXEC);

    const int fd = open(res2, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        SetError(error_message, std::string("open ") + res2 + " failed: " + strerror(errno));
        DetachIvshmemMapping(mapping);
        return false;
    }
    mapping->shm = mmap(nullptr, bar2_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mapping->shm == MAP_FAILED) {
        mapping->shm = nullptr;
        const int saved_errno = errno;
        close(fd);
        SetError(error_message, std::string("mmap BAR2 failed: ") + strerror(saved_errno));
        DetachIvshmemMapping(mapping);
        return false;
    }
    mapping->resource2_fd = fd;
    mapping->shm_size = bar2_size;

    const int fd0 = open(res0, O_RDWR);
    if (fd0 >= 0) {
        mapping->bar0 = mmap(nullptr, bar0_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd0, 0);
        close(fd0);
        if (mapping->bar0 == MAP_FAILED) {
            mapping->bar0 = nullptr;
        } else {
            mapping->bar0_size = bar0_size;
        }
    }

    return true;
}

void DetachIvshmemMapping(IvshmemMapping* mapping)
{
    if (mapping == nullptr) {
        return;
    }
    if (mapping->bar0 != nullptr) {
        munmap(mapping->bar0, mapping->bar0_size);
        mapping->bar0 = nullptr;
        mapping->bar0_size = 0;
    }
    if (mapping->shm != nullptr) {
        munmap(mapping->shm, mapping->shm_size);
        mapping->shm = nullptr;
        mapping->shm_size = 0;
    }
    if (mapping->driver_fd >= 0) {
        close(mapping->driver_fd);
        mapping->driver_fd = -1;
    }
    if (mapping->resource2_fd >= 0) {
        close(mapping->resource2_fd);
        mapping->resource2_fd = -1;
    }
}

} // namespace refuzz::worker

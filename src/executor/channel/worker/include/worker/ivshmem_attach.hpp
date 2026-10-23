#pragma once

#include <cstddef>
#include <string>

namespace refuzz::worker {

struct IvshmemMapping {
    void* shm = nullptr;
    size_t shm_size = 0;
    void* bar0 = nullptr;
    size_t bar0_size = 0;
    int driver_fd = -1;
    int resource2_fd = -1;
};

bool AttachIvshmemMapping(IvshmemMapping* mapping,
                          std::string* error_message = nullptr);
void DetachIvshmemMapping(IvshmemMapping* mapping);

} // namespace refuzz::worker

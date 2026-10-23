#pragma once

#include <cstdint>

namespace refuzz::worker {

struct PseudoResult {
    intptr_t ret = -1;
    int err = 0;
    const char* blocked_reason = nullptr;
};

} // namespace refuzz::worker

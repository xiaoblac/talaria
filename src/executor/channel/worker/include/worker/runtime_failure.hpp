#pragma once

#include <cstdint>

namespace refuzz::worker {

enum class RuntimeFailure : uint32_t {
    kNone = 0,
    kKcovStateInvalid = 1,
};

} // namespace refuzz::worker

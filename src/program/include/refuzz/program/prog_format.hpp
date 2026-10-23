#pragma once

#include <cstdint>

namespace refuzz::fuzzer {

enum class ProgFormat : uint8_t {
    kFlatProg = 0,
    kSyzProg = 1,
    kAflRaw = 2,
    kCustom = 3,
};

class IProgram {
public:
    virtual ~IProgram() = default;
    virtual ProgFormat Format() const = 0;
};

} // namespace refuzz::fuzzer

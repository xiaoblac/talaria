#pragma once

#include "refuzz/program/prog_format.hpp"

#include <memory>
#include <vector>

namespace refuzz::fuzzer {

class IProgCodec {
public:
    virtual ~IProgCodec() = default;

    virtual std::unique_ptr<IProgram> Decode(const std::vector<uint8_t>& payload) const = 0;
    virtual std::vector<uint8_t> Encode(const IProgram& prog) const = 0;
    virtual bool CanDecode(const std::vector<uint8_t>& payload) const = 0;
    virtual ProgFormat Format() const = 0;
};

} // namespace refuzz::fuzzer

#pragma once

#include "refuzz/program/prog_codec.hpp"

#include <memory>
#include <vector>

namespace refuzz::fuzzer {

class CodecRegistry {
public:
    void Register(std::unique_ptr<IProgCodec> codec);
    const IProgCodec* Detect(const std::vector<uint8_t>& payload) const;
    const IProgCodec* Get(ProgFormat fmt) const;

private:
    std::vector<std::unique_ptr<IProgCodec>> codecs_;
};

} // namespace refuzz::fuzzer

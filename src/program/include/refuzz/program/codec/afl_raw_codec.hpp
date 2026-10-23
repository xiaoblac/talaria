#pragma once

#include "refuzz/program/prog_codec.hpp"

namespace refuzz::fuzzer {

class AflRawCodec final : public IProgCodec {
public:
    ProgFormat Format() const override;
    bool CanDecode(const std::vector<uint8_t>& payload) const override;
    std::unique_ptr<IProgram> Decode(const std::vector<uint8_t>& payload) const override;
    std::vector<uint8_t> Encode(const IProgram& prog) const override;
};

} // namespace refuzz::fuzzer

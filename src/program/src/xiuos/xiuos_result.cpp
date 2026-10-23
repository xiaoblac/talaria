// Copyright 2026 reFuzz project author -------youngkk.

#include "refuzz/program/xiuos/xiuos_result.hpp"

#include <stdexcept>

namespace refuzz::program::xiuos {

XiuosDecodedResult XiuosDecodeResult(std::span<const std::uint8_t> payload) {
    if (payload.size() < XIUOS_RESULT_HEADER_SIZE) {
        throw std::invalid_argument("XiUOS RESULT payload too short");
    }
    if (payload[0] != XIUOS_RESULT_VERSION) {
        throw std::invalid_argument("XiUOS RESULT version mismatch");
    }

    XiuosDecodedResult r;
    r.status         = static_cast<XiuosResultStatus>(payload[1]);
    r.flags          = XiuosReadU16Be(payload.data() + 2);
    r.calls_executed = XiuosReadU16Be(payload.data() + 4);
    const std::uint16_t coverage_size = XiuosReadU16Be(payload.data() + 6);
    r.trap_or_pc     = XiuosReadU32Be(payload.data() + 8);
    const std::uint32_t aux_raw = XiuosReadU32Be(payload.data() + 12);
    r.aux = static_cast<std::int32_t>(aux_raw);

    const std::size_t expected_size = XIUOS_RESULT_HEADER_SIZE + coverage_size;
    if (payload.size() < expected_size) {
        throw std::invalid_argument("XiUOS RESULT coverage truncated");
    }
    r.coverage.assign(payload.begin() + XIUOS_RESULT_HEADER_SIZE,
                      payload.begin() + static_cast<std::ptrdiff_t>(expected_size));
    return r;
}

}  // namespace refuzz::program::xiuos

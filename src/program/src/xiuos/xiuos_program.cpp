// Copyright 2026 reFuzz project author -------youngkk.

#include "refuzz/program/xiuos/xiuos_program.hpp"

#include <stdexcept>

namespace refuzz::program::xiuos {

std::array<std::uint8_t, XIUOS_CALL_RECORD_SIZE>
XiuosEncodeCall(const XiuosProgramCall& call) {
    if (call.argc > 4) {
        throw std::invalid_argument("XiUOS call argc > 4");
    }
    std::array<std::uint8_t, XIUOS_CALL_RECORD_SIZE> out{};
    out[0] = static_cast<std::uint8_t>(call.api_id);
    out[1] = call.argc;
    XiuosPutU16Be(out.data() + 2, call.flags);
    for (std::size_t i = 0; i < 4; ++i) {
        XiuosPutU32Be(out.data() + 4 + i * 4, call.args[i]);
    }
    return out;
}

std::vector<std::uint8_t>
XiuosEncodeProgram(std::span<const XiuosProgramCall> calls,
                   XiuosSuiteId suite_id,
                   std::uint8_t flags) {
    if (calls.size() > 0xFFu) {
        throw std::invalid_argument("XiUOS program has too many calls");
    }
    if (calls.size() > kXiuosMaxCallsPerProgram) {
        throw std::invalid_argument("XiUOS program payload exceeds wire maximum");
    }
    std::vector<std::uint8_t> out;
    out.reserve(kXiuosProgramHeaderSize + calls.size() * XIUOS_CALL_RECORD_SIZE);
    out.push_back(XIUOS_PROGRAM_VERSION);
    out.push_back(static_cast<std::uint8_t>(suite_id));
    out.push_back(static_cast<std::uint8_t>(calls.size()));
    out.push_back(flags);
    for (const auto& call : calls) {
        const auto encoded = XiuosEncodeCall(call);
        out.insert(out.end(), encoded.begin(), encoded.end());
    }
    return out;
}

XiuosDecodedProgram
XiuosDecodeProgram(std::span<const std::uint8_t> payload) {
    if (payload.size() < 4) {
        throw std::invalid_argument("XiUOS program payload truncated header");
    }
    if (payload.size() > XIUOS_MAX_PAYLOAD) {
        throw std::invalid_argument("XiUOS program payload exceeds wire maximum");
    }
    if (payload[0] != XIUOS_PROGRAM_VERSION) {
        throw std::invalid_argument("XiUOS program version mismatch");
    }
    XiuosDecodedProgram out;
    out.suite_id = static_cast<XiuosSuiteId>(payload[1]);
    const std::uint8_t call_count = payload[2];
    out.flags = payload[3];

    const std::size_t expected =
        4u + static_cast<std::size_t>(call_count) * XIUOS_CALL_RECORD_SIZE;
    if (payload.size() != expected) {
        throw std::invalid_argument("XiUOS program payload size mismatch");
    }

    out.calls.reserve(call_count);
    for (std::size_t i = 0; i < call_count; ++i) {
        const std::uint8_t* base =
            payload.data() + 4 + i * XIUOS_CALL_RECORD_SIZE;
        XiuosProgramCall c;
        c.api_id = static_cast<XiuosApiId>(base[0]);
        c.argc = base[1];
        if (c.argc > 4) {
            throw std::invalid_argument("XiUOS call argc > 4");
        }
        c.flags = XiuosReadU16Be(base + 2);
        for (std::size_t k = 0; k < 4; ++k) {
            c.args[k] = XiuosReadU32Be(base + 4 + k * 4);
        }
        out.calls.push_back(c);
    }
    return out;
}

}  // namespace refuzz::program::xiuos

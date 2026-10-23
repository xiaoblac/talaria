// Copyright 2026 reFuzz project author -------youngkk.
//
// XiUOS program execution RESULT — types + decoder.
//
// This is the mirror of XiuosEncodeProgram in xiuos_program.hpp: that header
// turns an in-memory program into PROGRAM payload bytes; this header turns
// RESULT payload bytes back into a typed XiuosDecodedResult. Both are
// "program execution protocol" concepts and live in refuzz_program, not in
// executor/channel/. The wire frame (magic / type / seq / CRC) that carries
// these payloads is handled by the shared pure-C UART codec.
//
// Status enum and the payload byte layout are pinned by
// docs/xiuos-refuzz/030_worker_abi.md §"RESULT Payload" and §"Status".
// `proto/wire/include/refuzz/proto_wire/xiuos_uart_protocol.h` holds the
// C-compatible constants (XIUOS_RESULT_VERSION / XIUOS_RESULT_HEADER_SIZE /
// XIUOS_STATUS_*).

#pragma once

#include "refuzz/proto_wire/xiuos_uart_protocol.h"

#include <cstdint>
#include <span>
#include <vector>

namespace refuzz::program::xiuos {

enum class XiuosResultStatus : std::uint8_t {
    Ok              = XIUOS_STATUS_OK,
    ProgramRejected = XIUOS_STATUS_PROGRAM_REJECTED,
    UnsupportedApi  = XIUOS_STATUS_UNSUPPORTED_API,
    WorkerError     = XIUOS_STATUS_WORKER_ERROR,
    StateViolation  = XIUOS_STATUS_STATE_VIOLATION,
    ContractViolation = XIUOS_STATUS_CONTRACT_VIOLATION,
    PriorityInversion = XIUOS_STATUS_PRIORITY_INVERSION,
    StackOverflow   = XIUOS_STATUS_STACK_OVERFLOW,
    Trap            = XIUOS_STATUS_TRAP,
};

struct XiuosDecodedResult {
    XiuosResultStatus            status{XiuosResultStatus::Ok};
    std::uint16_t                flags{0};
    std::uint16_t                calls_executed{0};
    std::uint32_t                trap_or_pc{0};
    std::int32_t                 aux{0};
    std::vector<std::uint8_t>    coverage;  // size == coverage_size on the wire
};

// Parse a RESULT payload. Throws std::invalid_argument on bad version /
// truncated coverage.
XiuosDecodedResult XiuosDecodeResult(std::span<const std::uint8_t> payload);

}  // namespace refuzz::program::xiuos

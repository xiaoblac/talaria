// Copyright 2026 reFuzz project author -------youngkk.

#include "refuzz/feedback/signal/xiuos_call_transition_signal.hpp"

#include "refuzz/proto_wire/xiuos_uart_protocol.h"  // XIUOS_CALL_RECORD_SIZE

#include <cstddef>
#include <cstdint>
#include <vector>

namespace refuzz::fuzzer {

namespace cc = refuzz::core::channel_contract;

namespace {

// PROGRAM wire layout: [ver, suite, ncalls, flags] (4B header) + ncalls records
// of XIUOS_CALL_RECORD_SIZE bytes; api_id is record byte 0.
constexpr std::size_t kProgramHeaderSize = 4;
constexpr std::uint32_t kStart = 0x100u;  // START sentinel (api_id is a byte, 0..255)

const std::vector<std::uint8_t>* ProgramOf(const cc::ChannelEvent& ev) {
    if (const auto* c = ev.AsCompletion(); c != nullptr) return &c->ctx.program_payload;
    if (const auto* a = ev.AsAbnormal();   a != nullptr) return &a->ctx.program_payload;
    return nullptr;
}

}  // namespace

SignalContribution XiuosCallTransitionSignal::Sample(const cc::ChannelEvent& event) {
    SignalContribution out;
    out.id   = "xiuos_call_transition";
    out.kind = SignalKind::kCoverage;
    // Default fired=false: stay silent unless a NEW edge appears (so we never
    // contribute to is_coverage_empty — that's PC coverage's job).

    const std::vector<std::uint8_t>* prog = ProgramOf(event);
    if (prog == nullptr || prog->size() < kProgramHeaderSize) {
        return out;
    }
    const auto& p = *prog;
    const std::size_t ncalls = p[2];

    std::uint64_t magnitude = 0;
    std::uint32_t prev = kStart;
    for (std::size_t i = 0; i < ncalls; ++i) {
        const std::size_t off = kProgramHeaderSize + i * XIUOS_CALL_RECORD_SIZE;
        if (off >= p.size()) break;  // truncated / malformed — stop counting edges
        const std::uint32_t api  = p[off];
        const std::uint32_t edge = (prev << 8) | api;
        if (seen_.insert(edge).second) {
            ++magnitude;
        }
        prev = api;
    }

    if (magnitude > 0) {
        // New call-graph edge(s) → interesting (kCoverage) → admit + promote.
        out.fired       = true;
        out.interesting = true;
        out.magnitude   = magnitude;
    }
    return out;
}

void XiuosCallTransitionSignal::OnGenerationReset() {
    seen_.clear();
}

}  // namespace refuzz::fuzzer

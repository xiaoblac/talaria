// Copyright 2026 reFuzz project author -------youngkk.
//
// XiuosCoverageSignal — Phase 2 §C #16, coverage signal for the XiUOS UART
// backend.
//
// The XiUOS worker (kernel/refuzz/refuzz_worker.c) already aggregates path
// hits into a 256-byte bitmap with saturating `cov[id]++` counts, so the
// host doesn't need PC decoding / saturation gating / kcov hashing the way
// KcovCoverageSignal does. This signal performs the AFL-style log2
// bucketize + global bitmap OR that 050_corpus_generation_method.md
// §"Stage 6" pins as the v1 coverage-interesting algorithm:
//
//     bucketize(c) = 0 if c == 0 else 1 << (bit_length(c) - 1)   // {1,2,4,8,16,32,64,128}
//     new_bits     = bucketize(c) & ~global_bitmap[i]
//     interesting  = any new_bits != 0
//     magnitude    = # bytes contributing at least one new bit
//
// Stateful: holds a private 256-byte accumulated bitmap. Sample() is the
// only mutator and must be called from a single thread (the feedback
// engine's loop). Generation reset via OnGenerationReset() clears the
// bitmap; OnSeedAdmitted is a no-op.
//
// Wire contract: depends on Completion.output being exactly 256 bytes
// (XIUOS_COVERAGE_SIZE) — matches docs/xiuos-refuzz/030_worker_abi.md
// §"Coverage 语义". Smaller/larger output → SignalContribution.malformed = true.

#pragma once

#include "refuzz/feedback/signal/signal.hpp"
#include "refuzz/proto_wire/xiuos_uart_protocol.h"

#include <array>
#include <cstdint>
#include <string>

namespace refuzz::fuzzer {

class XiuosCoverageSignal final : public ISignal {
public:
    XiuosCoverageSignal() = default;

    std::string Id() const override   { return "xiuos_coverage"; }
    SignalKind  Kind() const override { return SignalKind::kCoverage; }

    SignalContribution Sample(
        const refuzz::core::channel_contract::ChannelEvent& event) override;

    void OnGenerationReset() override;

    // Test / introspection: read the accumulated bitmap.
    const std::array<std::uint8_t, XIUOS_COV_MAP_SIZE>&
        accumulated() const noexcept { return seen_; }

    // Bucketization helper (header-public so tests can re-check golden
    // vectors without duplicating the formula).
    static std::uint8_t Bucketize(std::uint8_t count) noexcept;

private:
    std::array<std::uint8_t, XIUOS_COV_MAP_SIZE> seen_{};
};

}  // namespace refuzz::fuzzer

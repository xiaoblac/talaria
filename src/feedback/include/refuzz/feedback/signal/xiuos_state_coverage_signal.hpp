// Copyright 2026 reFuzz project author -------youngkk.
//
// XiuosStateCoverageSignal — a SECOND coverage dimension for the XiUOS UART
// backend: interaction/state coverage, to escape the PC-coverage-saturation
// local optimum (9h run: `interesting` froze at 69, corpus stopped growing —
// PC coverage had no gradient left). See
// docs/plans/xiuos-state-coverage-exploration.md.
//
// The worker (refuzz_worker.c, RESULT v2) appends a per-program PEAK state
// region (XIUOS_STATE_SIZE bytes) after the 256-byte coverage bitmap. Bytes
// 0..13 are DETERMINISTIC simultaneously-live object counts per family
// (sem/mutex/.../avl); 14..15 are timing-sensitive blocked/delay residue
// (emitted but excluded from the hash to avoid noise-driven false novelty).
//
// This signal JOINT-HASHES the deterministic features into one state id and
// keeps a set of seen ids. A program reaching a NEW joint configuration →
// magnitude=1 + interesting (kCoverage), so it flows through the existing
// coverage→admit→promote path with ZERO aggregator change: a program is
// interesting on (new PC) OR (new state). When the state is already seen the
// signal stays fired=false so it never contributes to is_coverage_empty.
//
// Single-threaded (feedback engine loop). OnGenerationReset clears the set.

#pragma once

#include "refuzz/feedback/signal/signal.hpp"
#include "refuzz/proto_wire/xiuos_uart_protocol.h"

#include <cstdint>
#include <string>
#include <unordered_set>

namespace refuzz::fuzzer {

class XiuosStateCoverageSignal final : public ISignal {
public:
    XiuosStateCoverageSignal() = default;

    std::string Id() const override   { return "xiuos_state_coverage"; }
    SignalKind  Kind() const override { return SignalKind::kCoverage; }

    SignalContribution Sample(
        const refuzz::core::channel_contract::ChannelEvent& event) override;

    void OnGenerationReset() override;

    // Number of deterministic state features that feed the joint hash (idx 0..13,
    // the per-family live-object counts). 14..15 (blocked/delay) are intentionally
    // excluded — timing-sensitive → would create noise-driven false-new states.
    static constexpr std::size_t kHashFeatures = 14;

    // Test / introspection: how many distinct joint states have been seen.
    std::size_t distinct_states() const noexcept { return seen_.size(); }

private:
    std::unordered_set<std::uint64_t> seen_;
};

}  // namespace refuzz::fuzzer

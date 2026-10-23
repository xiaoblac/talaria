// Copyright 2026 reFuzz project author -------youngkk.

#include "refuzz/feedback/signal/xiuos_state_coverage_signal.hpp"

#include <cstddef>

namespace refuzz::fuzzer {

namespace cc = refuzz::core::channel_contract;

SignalContribution XiuosStateCoverageSignal::Sample(const cc::ChannelEvent& event) {
    SignalContribution out;
    out.id   = "xiuos_state_coverage";
    out.kind = SignalKind::kCoverage;
    // Default fired=false: when the state is already seen we stay silent so we
    // never contribute to is_coverage_empty (that's PC coverage's job). We only
    // speak up to mark a NEW joint state interesting.

    if (!event.IsCompletion()) {
        return out;
    }
    const cc::Completion* completion = event.AsCompletion();
    if (completion == nullptr) {
        return out;
    }

    // [real-kcov v3] The RESULT feedback region is sparse coverage
    // (u16 n_hit + n_hit*(u16 idx, u8 cnt)) followed by the state region
    // (XIUOS_STATE_SIZE). The state offset is therefore dynamic — computed from
    // n_hit. Need the full region present; an old worker / short frame simply
    // yields no state signal (not malformed — PC coverage validates the prefix).
    const auto& output = completion->output;
    if (output.size() < 2) {
        return out;
    }
    const std::size_t n_hit =
        (static_cast<std::size_t>(output[0]) << 8) | static_cast<std::size_t>(output[1]);
    const std::size_t state_off = 2 + n_hit * 3;
    if (output.size() < state_off + XIUOS_STATE_SIZE) {
        return out;
    }

    // Joint-hash the deterministic live-object-count features (idx 0..13). FNV-1a.
    // Raw counts (not bucketized) for maximum resolution; the joint space is bounded
    // by the slot tables, so this can't run away into a count-maximization optimum —
    // each distinct configuration is one set element.
    std::uint64_t h = 1469598103934665603ULL;
    for (std::size_t i = 0; i < kHashFeatures; ++i) {
        h ^= static_cast<std::uint64_t>(output[state_off + i]);
        h *= 1099511628211ULL;
    }

    if (seen_.insert(h).second) {
        // New joint configuration → interesting (kCoverage), drives admit + promote.
        out.fired       = true;
        out.interesting = true;
        out.magnitude   = 1;
    }
    return out;
}

void XiuosStateCoverageSignal::OnGenerationReset() {
    seen_.clear();
}

}  // namespace refuzz::fuzzer

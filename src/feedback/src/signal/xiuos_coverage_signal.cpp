// Copyright 2026 reFuzz project author -------youngkk.

#include "refuzz/feedback/signal/xiuos_coverage_signal.hpp"

#include <bit>

namespace refuzz::fuzzer {

namespace cc = refuzz::core::channel_contract;

std::uint8_t XiuosCoverageSignal::Bucketize(std::uint8_t count) noexcept {
    if (count == 0) return 0;
    // bit_width(c) is the position of the highest set bit + 1, so shifting
    // 1 by (bit_width - 1) yields the "log2 bucket" single-bit value:
    //   1     → 1<<0  = 0x01
    //   2..3  → 1<<1  = 0x02
    //   4..7  → 1<<2  = 0x04
    //   ...
    //   128..255 → 1<<7 = 0x80
    return static_cast<std::uint8_t>(1u << (std::bit_width(count) - 1));
}

SignalContribution XiuosCoverageSignal::Sample(const cc::ChannelEvent& event) {
    SignalContribution out;
    out.id = "xiuos_coverage";
    out.kind = SignalKind::kCoverage;

    // Only Completion events carry coverage — abnormal/fault events leave
    // SignalContribution.fired = false so the aggregator can route on
    // exec_result / fault signals instead.
    if (!event.IsCompletion()) {
        return out;
    }
    const cc::Completion* completion = event.AsCompletion();
    if (completion == nullptr) {
        return out;
    }

    // [real-kcov v3] coverage region = u16 n_hit + n_hit*(u16 idx, u8 cnt), then
    // the state region (XiuosStateCoverageSignal reads that). AFL log2-bucketize +
    // global OR over seen_, applied per sparse hit entry.
    const auto& output = completion->output;
    if (output.size() < 2) {  // need at least n_hit
        out.fired = true;
        out.malformed = true;
        return out;
    }
    const std::size_t n_hit =
        (static_cast<std::size_t>(output[0]) << 8) | static_cast<std::size_t>(output[1]);
    if (output.size() < 2 + n_hit * 3) {  // entries truncated
        out.fired = true;
        out.malformed = true;
        return out;
    }

    std::uint64_t magnitude = 0;
    for (std::size_t k = 0; k < n_hit; ++k) {
        const std::size_t p   = 2 + k * 3;
        const std::size_t idx =
            (static_cast<std::size_t>(output[p]) << 8) | static_cast<std::size_t>(output[p + 1]);
        const std::uint8_t cnt = output[p + 2];
        if (idx >= XIUOS_COV_MAP_SIZE) {
            continue;  // defensive: worker map size must match
        }
        const std::uint8_t bucket   = Bucketize(cnt);
        const std::uint8_t new_bits = static_cast<std::uint8_t>(bucket & ~seen_[idx]);
        if (new_bits != 0) {
            ++magnitude;
            seen_[idx] = static_cast<std::uint8_t>(seen_[idx] | bucket);
        }
    }

    out.fired = true;
    out.interesting = magnitude > 0;
    out.magnitude = magnitude;
    return out;
}

void XiuosCoverageSignal::OnGenerationReset() {
    seen_.fill(0);
}

}  // namespace refuzz::fuzzer

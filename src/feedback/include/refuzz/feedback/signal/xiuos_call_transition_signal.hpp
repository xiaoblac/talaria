// Copyright 2026 reFuzz project author -------youngkk.
//
// XiuosCallTransitionSignal — a THIRD coverage dimension: call-graph EDGE
// coverage over the executed program's API sequence. A program that exhibits a
// new (prev_api -> cur_api) bigram (including the synthetic START -> first call)
// is interesting.
//
// Rationale (docs/plans/xiuos-state-coverage-exploration.md §8.1): the MVP state
// coverage (per-family live-object COUNTS) un-froze `interesting` 69->80 but
// re-saturated — counts over 4-slot tables are too coarse and carry no ORDERING.
// XiUOS programs ARE API sequences; the bigram space is ~|API|^2 (thousands),
// a far longer exploration gradient, and it directly rewards trying the novel
// orderings where stateful bugs (leak/contract/deadlock setups) live.
//
// Host-side: decodes the API sequence straight from the completion's
// program_payload (wire = [ver,suite,ncalls,flags] 4B + ncalls * 20B records,
// api_id at record byte 0) — NO worker change. Like the other XiUOS coverage
// signals it stays fired=false unless a NEW edge appears, so it never feeds
// is_coverage_empty. Single-threaded; OnGenerationReset clears the set.

#pragma once

#include "refuzz/feedback/signal/signal.hpp"

#include <cstdint>
#include <string>
#include <unordered_set>

namespace refuzz::fuzzer {

class XiuosCallTransitionSignal final : public ISignal {
public:
    XiuosCallTransitionSignal() = default;

    std::string Id() const override   { return "xiuos_call_transition"; }
    SignalKind  Kind() const override { return SignalKind::kCoverage; }

    SignalContribution Sample(
        const refuzz::core::channel_contract::ChannelEvent& event) override;

    void OnGenerationReset() override;

    // Test / introspection: number of distinct call-graph edges seen.
    std::size_t distinct_transitions() const noexcept { return seen_.size(); }

private:
    // edge id = (prev << 8) | cur ; prev == 0x100 is the synthetic START.
    std::unordered_set<std::uint32_t> seen_;
};

}  // namespace refuzz::fuzzer

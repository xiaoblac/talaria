// Copyright 2026 reFuzz project author -------youngkk.
//
// XiuosOracleSignal — per-program invariant oracle as a feedback signal.
//
// The XiUOS worker runs per-call heap/state invariant checks
// (kernel/refuzz/refuzz_worker.c CheckDynamicMemoryIntegrity) and an LSan-style
// per-program leak probe, and reports the verdict on a normal RESULT via the
// shared channel contract: Completion.vendor_status == STATE_VIOLATION (a
// silent heap/state corruption caught before it faulted) and Completion.
// vendor_flags > 0 (the net per-program leak delta).
//
// This signal turns those verdicts into the framework's normal finding path —
// a SignalContribution.crash_payload that the aggregator forwards to
// EngineOutput.crash_dispatch → crash pipeline — instead of being hand-handled
// in a bespoke campaign loop. The interface is target-agnostic (it is the same
// "completion → finding" shape as FaultSignal); only the vendor-field meanings
// are XiUOS-specific, which is why it lives next to XiuosCoverageSignal. A
// Linux/syzkaller KASAN/LSan signal is a sibling reusing the same skeleton.
//
// Severity split (Stage 1): STATE_VIOLATION is a hard memory-safety finding
// (ResultCode::kCrashed); a leak is a soft LEAD (ResultCode::kExecError,
// magnitude = leak bytes). The lead/severity-tier evidence model is Stage 2.

#pragma once

#include "refuzz/feedback/signal/signal.hpp"

namespace refuzz::fuzzer {

class XiuosOracleSignal final : public ISignal {
public:
    std::string Id() const override   { return "xiuos_oracle"; }
    SignalKind  Kind() const override { return SignalKind::kSanitizer; }

    SignalContribution Sample(
        const refuzz::core::channel_contract::ChannelEvent& event) override;
};

}  // namespace refuzz::fuzzer

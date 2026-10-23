// Copyright 2026 reFuzz project author -------youngkk.

#include "refuzz/feedback/aggregator/blackbox_aggregator.hpp"

#include "refuzz/proto_domain/types.hpp"

namespace refuzz::fuzzer {

CompositeScore BlackboxAggregator::Aggregate(
    const refuzz::core::channel_contract::ChannelEvent& /*event*/,
    std::span<const SignalContribution> contribs)
{
    CompositeScore score;

    for (const auto& c : contribs) {
        // 只关心执行结果 + 故障信号；覆盖 / cmp 信号完全忽略。
        if (c.kind == SignalKind::kExecResult) {
            switch (c.exec_code) {
            case proto::ResultCode::kCrashed:
                score.is_crash = true;
                break;
            case proto::ResultCode::kTimeout:
                score.is_timeout = true;
                break;
            case proto::ResultCode::kExecError:
                score.is_exec_error = true;
                break;
            default:
                break;
            }
        }
        if (c.kind == SignalKind::kFault || c.kind == SignalKind::kSanitizer) {
            if (c.exec_code == proto::ResultCode::kCrashed || c.crash_payload.has_value()) {
                score.is_crash = true;
            }
            if (c.crash_payload.has_value()) {
                score.crash_payload = c.crash_payload;
            }
        }
        // [XiUOS leak 一等公民化 Phase 1] resource-leak terminal — a non-crash
        // finding that still dispatches its crash_payload to the resource_leak/
        // bucket. Mirror the coverage aggregator so blackbox runs don't drop it.
        if (c.kind == SignalKind::kResource &&
            c.exec_code == proto::ResultCode::kResourceLeak) {
            score.is_resource_leak = true;
            if (c.crash_payload.has_value()) {
                score.crash_payload = c.crash_payload;
            }
        }
    }

    // Blackbox：所有 disposition 保持 neutral；interesting 永不置位。
    score.disposition = SeedDisposition::kNeutral;
    return score;
}

} // namespace refuzz::fuzzer

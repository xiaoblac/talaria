// Copyright 2026 reFuzz project author -------youngkk.

#include "refuzz/feedback/aggregator/weighted_or_aggregator.hpp"

#include "refuzz/proto_domain/types.hpp"

#include <utility>

namespace refuzz::fuzzer {

WeightedOrAggregator::WeightedOrAggregator(std::unordered_map<std::string, double> weights,
                                           double interesting_threshold)
    : weights_(std::move(weights))
    , threshold_(interesting_threshold)
{}

CompositeScore WeightedOrAggregator::Aggregate(
    const refuzz::core::channel_contract::ChannelEvent& /*event*/,
    std::span<const SignalContribution> contribs)
{
    CompositeScore score;
    double weighted_sum = 0.0;

    for (const auto& c : contribs) {
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
            // is_crash 与 crash_payload 解耦(对齐 CoverageGuidedAggregator 的 PR-C):
            // is_crash **仅**看 exec_code==kCrashed —— 否则 program-child 自身 crash
            // (方案 A 的 child-abort completion,exec_code=kExecError + crash_payload)
            // 会被误判为 crash → abnormal → interesting=false,把它有效的新覆盖丢出
            // corpus(正是方案 A 要防的)。crash_payload 无条件透传,让下游 crash
            // pipeline 照常按 bucket 落盘。
            if (c.exec_code == proto::ResultCode::kCrashed) {
                score.is_crash = true;
            }
            if (c.crash_payload.has_value()) {
                score.crash_payload = c.crash_payload;
            }
        }
        if (c.malformed && (c.kind == SignalKind::kCoverage ||
                            c.kind == SignalKind::kComparison)) {
            score.is_malformed = true;
        }
        // [v2 Epic 5 PR-5-B — split kCoverage vs kComparison gain channels]
        if (c.kind == SignalKind::kComparison) {
            score.cmp_gain += c.magnitude;
        } else {
            score.cov_gain += c.magnitude;
        }

        auto it = weights_.find(c.id);
        if (it != weights_.end()) {
            weighted_sum += it->second * static_cast<double>(c.magnitude);
        }
    }

    const bool abnormal = score.is_crash || score.is_timeout || score.is_exec_error;
    score.interesting = !abnormal && (weighted_sum > threshold_);

    if (score.interesting) {
        score.disposition = SeedDisposition::kPromote;
    } else if (score.is_timeout || score.is_exec_error) {
        score.disposition = SeedDisposition::kDemote;
    } else {
        score.disposition = SeedDisposition::kNeutral;
    }
    return score;
}

} // namespace refuzz::fuzzer

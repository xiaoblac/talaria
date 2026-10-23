// Copyright 2026 reFuzz project author -------youngkk.

#include "refuzz/feedback/aggregator/coverage_guided_aggregator.hpp"

#include "refuzz/proto_domain/types.hpp"

namespace refuzz::fuzzer {

CompositeScore CoverageGuidedAggregator::Aggregate(
    const refuzz::core::channel_contract::ChannelEvent& /*event*/,
    std::span<const SignalContribution> contribs)
{
    CompositeScore score;

    for (const auto& c : contribs) {
        // 执行结果类信号：决定 exec 派系标志位
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
            // [XiUOS leak 一等公民化 Phase 1] resource-leak terminal.
            case proto::ResultCode::kResourceLeak:
                score.is_resource_leak = true;
                break;
            default:
                break;
            }
        }

        // [XiUOS leak 一等公民化 Phase 1] the leak lead arrives as a kResource
        // signal carrying exec_code == kResourceLeak (XiuosOracleSignal). Mark
        // the non-crash leak terminal so it dispatches its crash_payload to the
        // resource_leak/ bucket but stays non-interesting-for-coverage.
        if (c.kind == SignalKind::kResource &&
            c.exec_code == proto::ResultCode::kResourceLeak) {
            score.is_resource_leak = true;
        }

        // [Contract oracle §3.1] contract violation arrives as a kSanitizer signal
        // carrying exec_code == kContractViolation (XiuosOracleSignal). Mark the
        // non-crash terminal so its crash_payload dispatches to contract_violation/
        // but it stays non-interesting-for-coverage.
        if (c.exec_code == proto::ResultCode::kContractViolation) {
            score.is_contract_violation = true;
        }

        // [Priority-inversion detector] non-crash terminal; dispatches crash_payload
        // to priority_inversion/ but stays non-interesting-for-coverage.
        if (c.exec_code == proto::ResultCode::kPriorityInversion) {
            score.is_priority_inversion = true;
        }

        // [Stack-overflow detector] non-crash terminal → stack_overflow/ bucket.
        if (c.exec_code == proto::ResultCode::kStackOverflow) {
            score.is_stack_overflow = true;
        }

        // [v2 PR-C 把 is_crash 跟 crash_payload 解耦 — 当前版本]
        // PR-C 让 fault path 的 vm_dead/worker_dead 也构造 crash_payload(让它们能进
        // crash pipeline 落盘到对应 diagnostics bucket)。但 vm_dead/worker_dead 是
        // infra-fault,program 本身并没有"撞出 crash",aggregator 不应把它视作 crash
        // 来污染 corpus admit 决策。所以这里:
        //   - is_crash 仅看 exec_code == kCrashed (kKernelCrash fault / kCrashed abnormal)
        //   - crash_payload 不论 kind 都透传(让下游 crash pipeline 走 bucket 分流)
        if (c.kind == SignalKind::kFault || c.kind == SignalKind::kSanitizer) {
            if (c.exec_code == proto::ResultCode::kCrashed) {
                score.is_crash = true;
            }
        }
        if (c.crash_payload.has_value()) {
            score.crash_payload = c.crash_payload;
        }

        // [v2 Epic 5 PR-5-B — split cov_gain (kCoverage) vs cmp_gain (kComparison)]
        // 两者由独立的 HashFeedbackStore 实例去重 (Q3 决议),分别驱动
        // fuzzer.cov.{new_total,unique} 与 fuzzer.cov.cmp.{new_total,unique}。
        if (c.kind == SignalKind::kCoverage || c.kind == SignalKind::kComparison) {
            if (c.malformed) {
                score.is_malformed = true;
            }
            if (c.fired && c.hashes.empty() && c.magnitude == 0 && !c.malformed) {
                score.is_coverage_empty = true;
            }
            if (c.kind == SignalKind::kCoverage) {
                score.cov_gain += c.magnitude;
            } else { // kComparison
                score.cmp_gain += c.magnitude;
            }
            if (c.magnitude > 0) {
                score.interesting = true;
            }
        }
    }

    // 仅在非异常执行的情况下，coverage 才能把 seed 标 interesting。
    // [XiUOS leak 一等公民化 Phase 1] a resource leak is an abnormal terminal too.
    if (score.is_crash || score.is_timeout || score.is_exec_error ||
        score.is_resource_leak || score.is_contract_violation ||
        score.is_priority_inversion || score.is_stack_overflow) {
        score.interesting = false;
    }

    // Disposition 建议
    if (score.interesting) {
        score.disposition = SeedDisposition::kPromote;
    } else if (score.is_timeout || score.is_exec_error || score.is_resource_leak ||
               score.is_contract_violation || score.is_priority_inversion ||
               score.is_stack_overflow) {
        score.disposition = SeedDisposition::kDemote;
    } else {
        score.disposition = SeedDisposition::kNeutral;
    }

    return score;
}

} // namespace refuzz::fuzzer

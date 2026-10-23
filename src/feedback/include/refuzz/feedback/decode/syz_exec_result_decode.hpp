// Copyright 2026 reFuzz project author -------youngkk.
//
// Host-side decoder for the SyzExecResult[n_calls] block at the head
// of a worker output buffer — Epic 6 §3.14 PR-6-A D-8.
//
// Reads `SyzExecResult.flags` (per-call kCallFlag* bits, mirror upstream
// pkg/flatrpc/flatrpc.fbs:212-218 CallFlag) without going through the
// FeedbackDelta codec. PR-6-C `FaultInjectionConsumerStage` is the
// only consumer in Epic 6; it observes
// `decoded[call_index].flags & kCallFlagFaultInjected` to decide
// whether to push the next FailNth iteration or break the chain
// (plan §3 D-1, D-10).
//
// The helper is a `memcpy + size check`; no codec layering, no schema
// bump (FeedbackDelta stays at schema_version=2 from Epic 5 PR-5-A).

#pragma once

#include "worker/backend/syz_exec_runner.hpp"  // SyzExecResult, kCallFlag*

#include <cstddef>
#include <cstdint>
#include <optional>  // [v2 batch 3 PR-X — review revise] strict-mode parameter
#include <span>
#include <vector>

namespace refuzz::feedback::decode {

// Decode the leading SyzExecResult[n_calls] block from a worker
// output buffer.
//
// Returns an empty vector when:
//   - output.size() < n_calls * sizeof(SyzExecResult) — output too short
//   - n_calls == 0                                    — no calls
//   - output.empty()                                  — abnormal/early
//
// Caller (FaultInjectionConsumerStage) treats an empty result as
// "no observation" — falls through to D-1's missing-info rule
// (continue iteration; do NOT break the chain).
std::vector<refuzz::worker::SyzExecResult>
DecodeSyzExecResults(std::span<const std::uint8_t> output, std::size_t n_calls);

// [v2 batch 3 PR-X — review revise: Finding 5 fix] Decode SyzExecResult head +
// per-call coverage tail。
//
// Wire layout (Q1=A,driver `KernelWireDriver::Execute` 写入):
//   output = [SyzExecResult × n] [uint64 × total_cov] [...其它 packets...]
//
// 返回 results + coverage_tail(uint64 array)。每 call 的 cover slice 为
//   coverage_tail[results[i].cover_offset .. cover_offset + cover_count]
//
// 调用契约 — **两种模式**:
//
//   1. **Strict mode**(`expected_tail_uint64s` 提供;新代码应用此模式):
//      caller 必须先 peel 所有 trailing feedback packets(eg. 用
//      `CoverageFeedbackCodec::Extract` 剥 KCOV packet),传入 raw
//      `[results × n][uint64 × expected_tail_uint64s]` view,且
//      `output.size()` 严格 == `n_calls * sizeof(SyzExecResult) +
//       expected_tail_uint64s * 8`。
//      tail_bytes 不匹配 → 视为 corrupted,所有 `results[i].cover_count` 清零。
//      Step 8 host-side `KcovCoverageSignal::Sample` 注入路径走 strict mode。
//
//   2. **Lenient mode**(`expected_tail_uint64s == std::nullopt`,兼容 PR-X
//      partial 的 single test caller):`output.size() - head_bytes` 视为 tail
//      上限,helper 仅读 `max(cover_offset + cover_count)` 之内 uint64;**不会**
//      读取 packet 字节当 cov,但若 `cover_offset/count` 是脏数据且
//      `max_end < cov_uint64s_avail`,可能把 packet 字节读成 cov entry
//      (silent corruption risk)。**新代码不应用 lenient mode**。
//
// 失败回退(返空 results / 空 tail / 各 cover_count=0):
//   - `n_calls == 0` / `output` 空
//   - `output.size() < n_calls * sizeof(SyzExecResult)`
//   - 任一 `results[i].cover_offset + cover_count` 越界(lenient:
//     `tail_bytes / 8`;strict:`expected_tail_uint64s`)
//   - strict mode 且 `tail_bytes != expected_tail_uint64s * 8`
struct DecodedExecResultsWithCoverage {
    std::vector<refuzz::worker::SyzExecResult> results;
    std::vector<std::uint64_t>                  coverage_tail;
};

DecodedExecResultsWithCoverage
DecodeSyzExecResultsWithCoverage(
    std::span<const std::uint8_t> output,
    std::size_t                   n_calls,
    std::optional<std::size_t>    expected_tail_uint64s = std::nullopt);

}  // namespace refuzz::feedback::decode

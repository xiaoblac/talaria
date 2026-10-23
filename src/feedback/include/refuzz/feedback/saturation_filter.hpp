// Copyright 2026 reFuzz project author -------youngkk.
//
// ISaturationFilter —— G5 framework primitive: signal-time per-syscall coverage
// saturation gating。在 `HashFeedbackStore::MergeCoverage` 之前决定哪些
// program-level coverage hashes 应进 store。
//
// 跟 IPriorityCalculator(PR-Y)同层 — 都是 signal-time interest decision,
// 但 saturation 是**stateful**(per-syscall counter),priority calc 是 stateless;
// 两者并存让 family 可独立替换 / override。
//
// 设计原则(继承父 plan §2 P3):interface 暴露 facts(observation + program_hashes),
// impl 内部决策 keep/drop。
//   - kernel:`KernelCoverageSaturationFilter` — per-syscall normalized hash count
//             + threshold;syzkaller `corpus.go saturatedCalls` 等价
//   - kernel-no-triage:`NoopSaturationFilter` — 永远 nullopt(透传)
//   - PyTorch / 协议 family(future):各自决定 saturation 策略
//
// Framework primitive injection pattern 沿用 SubT-A/B + PR-Y 的 7 步 canon:
//   1. interface 在 feedback/include/refuzz/feedback/<name>.hpp(本头)
//   2. kernel impl 在 feedback/include/refuzz/feedback/saturation/<impl>.hpp + .cpp
//   3. AssembledBundle 持 std::unique_ptr<ISaturationFilter>
//   4. JobDeps 持 ISaturationFilter*(暂无 job caller,canon 一致性)
//   5. KcovCoverageSignal 通过 SignalTraits::BuildContext 注入(catalog 路径)
//   6. ProfileDefaults::make_saturation_filter factory + Assembler P7 fail-loud
//   7. tests/{kernel_coverage_,noop_,kcov_signal_pipeline_}saturation_filter_test
//
// **返值语义**(Arch A' 关键 — 详 G5 plan §3.G5):
//   - `nullopt`                      — 无 drop 发生;caller 应原样用 program_hashes
//                                      (byte-equal invariant 严格保)
//   - decision.hashes non-empty      — 部分 drop;caller 用 filtered = sort+unique
//                                      accepted per-call slices union
//   - decision.hashes empty          — 全 drop;caller 应 c.fired=false
//   - decision.keep_calls non-empty  — 与 KernelExecutionObservation::per_call
//                                      对齐,明确哪些 call 参与 admission。不能从
//                                      decision.hashes 反推 per-call 归因。
//
// **input contract**:
//   - `obs`:整个 event 的 observation,实现侧 cast 回 family-specific 类型
//            (kernel 是 `obs.Get<KernelExecutionObservation>()`)。kernel runtime 的
//            missing/empty per-call observation 已由 KcovCoverageSignal fail-loud;
//            filter 层的 nullopt 只表示非 kernel/测试调用或 no-drop。
//   - `program_hashes`:codec 输出的 normalized program-level hashes
//                       (sorted unique;saturation filter 的 union 输出也必须
//                        sort+unique 保持同形态)
//
// 详 docs/admit-pipeline-alignment/300_batch3_kernel_profile_stages.md §3.G5。

#pragma once

#include "refuzz/feedback/observation/execution_observation.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace refuzz::fuzzer {

struct SaturationDecision {
    std::vector<std::uint64_t> hashes;
    std::vector<bool> keep_calls;
};

class ISaturationFilter {
public:
    virtual ~ISaturationFilter() = default;

    virtual std::optional<SaturationDecision> Filter(
        const ExecutionObservation& obs,
        std::span<const std::uint64_t> program_hashes) = 0;
};

}  // namespace refuzz::fuzzer

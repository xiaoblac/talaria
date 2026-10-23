// Copyright 2026 reFuzz project author -------youngkk.
//
// IPriorityCalculator —— PR-Y framework primitive: 把 SignalAttributes 翻译成
// priority 标量(8-bit weight),是 family-specific 加权 / bit-packing 的纯函数策略层。
//
// 设计原则(继承父 plan §2 P3):interface 暴露 facts,impl 内部 weighting/bit-packing。
//   - kernel:`SyzkallerPriorityCalculator` 模拟 syzkaller hash.go 的 prio bit-packing
//             (bit1=execution_succeeded,bit0=!involves_special_input)
//   - PyTorch (future):numerical magnitude → 渐变 weight
//   - 协议 (future):响应有效字节 → byte-count weight
//
// Framework primitive injection pattern 沿用 SubT-A/B 7 步 canon:
//   1. interface 在 feedback/include/refuzz/feedback/<name>.hpp(本头)
//   2. kernel impl 在 feedback/include/refuzz/feedback/priority/<impl>.hpp + .cpp
//   3. AssembledBundle 持 std::unique_ptr<IPriorityCalculator>
//   4. StageDeps 持 IPriorityCalculator*(暂无 stage caller,保一致)
//   5. KcovCoverageSignal 通过 SignalTraits::BuildContext 注入(catalog 路径)
//   6. ProfileDefaults::make_priority_calculator factory + Assembler P7 fail-loud
//   7. tests/syzkaller_priority_calculator_test.cpp 4-case truth table
//
// Thread safety: stateless / pure;Calculate() 应不依赖 mutable state。
//
// 详 docs/admit-pipeline-alignment/300_batch3_kernel_profile_stages.md §3.PR-Y。

#pragma once

#include "refuzz/feedback/signal_attributes.hpp"

#include <cstdint>

namespace refuzz::fuzzer {

class IPriorityCalculator {
public:
    virtual ~IPriorityCalculator() = default;
    virtual std::uint8_t Calculate(const SignalAttributes& attrs) const = 0;
};

}  // namespace refuzz::fuzzer

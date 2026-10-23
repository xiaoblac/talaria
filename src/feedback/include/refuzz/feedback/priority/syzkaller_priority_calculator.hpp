// Copyright 2026 reFuzz project author -------youngkk.
//
// SyzkallerPriorityCalculator —— PR-Y kernel impl of IPriorityCalculator。
//
// 数值布局 (mirror syzkaller `pkg/fuzzer/queue/queue.go` priority bit-packing):
//
//   bit1 (0b10): execution_succeeded
//      "任一 call err==0" 的 program 比"全 fail"的更值得入 corpus
//      (cov 信号反映真实 syscall 路径而非 fail-fast 早返路径)
//
//   bit0 (0b01): !involves_special_input
//      "全 call 不含 any-ptr"的 program 比"含 any-ptr"的更值得 priority
//      (any-ptr cov 主要由 mutator squash 路径产生,优先"自然"输入)
//
// 4-case truth table:
//   (succeeded=true,  no_any=true)  → 0b11 = 3  最高
//   (succeeded=true,  any=true)     → 0b10 = 2
//   (succeeded=false, no_any=true)  → 0b01 = 1
//   (succeeded=false, any=true)     → 0b00 = 0  最低
//
// 详 docs/admit-pipeline-alignment/300_batch3_kernel_profile_stages.md §3.PR-Y。

#pragma once

#include "refuzz/feedback/priority_calculator.hpp"

#include <cstdint>

namespace refuzz::fuzzer {

class SyzkallerPriorityCalculator final : public IPriorityCalculator {
public:
    std::uint8_t Calculate(const SignalAttributes& attrs) const override;
};

}  // namespace refuzz::fuzzer

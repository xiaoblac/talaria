// Copyright 2026 reFuzz project author -------youngkk.
//
// SignalAttributes —— PR-Y framework primitive: priority 计算的 facts。
//
// IPriorityCalculator 输入字段集,family-agnostic 名词,facts 计算由 family-specific
// signal impl 负责(eg. KcovCoverageSignal::Sample 反查 ctx.artifact 后填入)。
//
// 字段语义(kernel family):
//   - execution_succeeded:被评价的执行单元是否成功。KCOV 覆盖信号按 syscall
//                          填(call.executed && errno==0),Info.Extra 直接用 prio 0。
//   - involves_special_input:被评价的执行单元 args 是否含 any-ptr。KCOV 覆盖信号
//                          按 syscall 填(call_contains_any),让自然输入优先。
//
// future family 加字段时:小心保持向后兼容(默认值不破坏现有降级语义)。
//
// 详 docs/admit-pipeline-alignment/300_batch3_kernel_profile_stages.md §3.PR-Y。

#pragma once

namespace refuzz::fuzzer {

struct SignalAttributes {
    bool execution_succeeded    = true;
    bool involves_special_input = false;
};

}  // namespace refuzz::fuzzer

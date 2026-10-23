// Copyright 2026 reFuzz project author -------youngkk.
//
// fault_inject_variant — Epic 6 PR-6-B algorithm helper.
//
// MakeFaultInjectVariant 是 Epic 6 fault-injection 唯一的算法 helper:它把一个
// 已认证的 base seed (FailNth=0) 克隆出来,并在指定 call 上把 CallProps.fail_nth
// 改成 nth。Producer 用它生成第一个 nth=1 的迭代任务;Consumer 拿 ExecResult
// 的 kCallFlagFaultInjected 决定是否再生成 nth+1 任务。
//
// 严格 mirror upstream `pkg/fuzzer/job.go:506-509`(see plan §3 D-9):
//
//     newProg := job.p.Clone()
//     newProg.Calls[job.call].Props.FailNth = nth
//
// 不做候选集扩展(per memory `feedback_porting_keep_candidate_set_minimal`);
// 不引入 IR 层(per memory `feedback_adapt_three_tiers` — 单 free function 跨切
// 用 cross-cutting orchestrator);不污染 hints/ 的 mutator 边界。

#pragma once

#include "refuzz/program/syz/prog.hpp"

#include <memory>

namespace refuzz::mutator::linux::syz_v2::fault_inject {

// Clone `prog` (deep,via syz::DeepClone) 并在 calls[call_index] 上设置
// CallProps.fail_nth = nth。`async` / `rerun` 不动(它们是 Epic 6 §10 N1/N2
// 永久非目标;driver 端 supported_wire_set_props 维持 reject)。
//
// 调用约定:
//   - call_index 必须 in [0, prog.calls().size()),否则返 nullptr。
//   - nth 通常 >= 1(upstream 1-based);nth=0 等价于"取消 fault inject"也合法。
//   - validation 由 caller 负责(prog/syz/validation.cpp:127 已在 codec 路径
//     拒绝 fail_nth>0 && rerun>0 的组合;Consumer 不会触发该组合)。
std::unique_ptr<refuzz::program::syz::Prog>
MakeFaultInjectVariant(const refuzz::program::syz::Prog& prog,
                       int call_index, int nth);

}  // namespace refuzz::mutator::linux::syz_v2::fault_inject

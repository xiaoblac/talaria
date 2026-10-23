// Copyright 2026 reFuzz project author -------youngkk.
//
// AssignRandomAsync —— collide 变换层唯一的算法 helper。
//
// 严格 mirror upstream prog/collide.go:24-60 `AssignRandomAsync`:把一个已产出的
// 新程序（gen/mut 输出）克隆一份，从后往前给部分 call 打上 CallProps.async，让它们
// 在 threaded 执行下并发跑（executor 主线程遇 async 不等其完成即派发下一个 call），
// 从而制造 syscall 并发、触发内核 data race。
//
// 只做 async 赋值（refuzz 已支持的 race 原语），**不**碰 rerun / DoubleExecCollide /
// DupCallCollide：
//   - rerun：worker driver supported_threaded_wire_set_props 硬性 rerun==0（§10 N1/N2
//     permanent non-goal），发了被 reject；
//   - DoubleExec/DupCall：需复制 call + syzkaller cloneCall(nil) 的“共享外部 producer
//     引用”语义，与 refuzz DeepClone + ResultArg::uses_ 不变式冲突。
//
// 资源依赖保护（mirror 上游）：async producer 与其 consumer 之间至少隔一个非 async
// call，避免 consumer 拿到未就绪的 resource；最后一个 call 永不 async；每 prog ≤24 个
// async（executor ≤32 线程的保守上限）。
//
// 纯变换：只读 orig，返回一份新 Prog（DeepClone）。随机性来自 RandGen。

#pragma once

#include "refuzz/mutator/linux/syz_v2/random.hpp"  // RandGen
#include "refuzz/program/syz/prog.hpp"

#include <memory>

namespace refuzz::mutator::syz_v2::collide {

// executor ≤32 线程（async + 超时 call 共用），保守用 ≤24 async（mirror
// prog/collide.go maxAsyncPerProg）。
inline constexpr int kMaxAsyncPerProg = 24;

// DeepClone `orig` 并按上游 AssignRandomAsync 逻辑给部分 call 设 async。
// 返回克隆（可能一个 async 都没打，取决于 RNG / 资源依赖）；DeepClone 失败返 nullptr。
std::unique_ptr<::refuzz::program::syz::Prog>
AssignRandomAsync(const ::refuzz::program::syz::Prog& orig, RandGen& r);

}  // namespace refuzz::mutator::syz_v2::collide

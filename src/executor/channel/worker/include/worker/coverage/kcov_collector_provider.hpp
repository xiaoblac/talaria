// Copyright 2026 reFuzz project author -------youngkk.
//
// IKcovCollectorProvider: coverage 层小接口,抽象"谁持有 kcov collector 池"
// 与"谁借 collector 做 per-call 切片"两侧。
//
// 背景 (Epic 7 per-thread KCOV 对齐 syzkaller):
//   - KcovSink (observation/) 持 collector 的 fd/mmap 生命周期。
//   - KernelWireDriver (driver/) 借 collector 做 BeginCallSession /
//     ResetForCall / CollectForCall / EndCallSession 调度。
//   - Threaded mode (Epic 7 Step 4+) 会 spawn N 个 worker thread,每个自己
//     拥有所属 collector 的 KCOV lifecycle (Begin/Reset/Collect/End)——
//     KCOV 是 per-task (TID) 的 kernel 资源,必须在使用线程上 KCOV_ENABLE。
//
// 设计选择:
//   - driver 仅依赖本接口 (coverage/),不依赖 observation/ 具体类,模块边界
//     守住 (per memory: "适配架构三层 — 模块边界不可破")。
//   - Step 1 池大小=1,tid 永远=0,行为与 v1 完全等价;后续 step 扩到
//     kMaxThreads,driver/profile callsite 无需再改。
//
// KCOV 同线程约束:
//   返回的 collector 上,Begin / ResetForCall / CollectForCall / End /
//   EndAsCmp 必须由 KCOV_ENABLE 它的同一个线程调用 (Linux kernel 把 KCOV
//   绑在 current task)。Step 1 (serial) 这是 main thread;Step 4+ 改成
//   worker thread 自身。Init / 析构 是 process-scope (open + mmap +
//   KCOV_INIT_TRACE,无 per-task 绑定),可以在 main thread 做。

#pragma once

#include "worker/coverage/kcov_collector.hpp"

namespace refuzz::worker {

class IKcovCollectorProvider {
public:
    virtual ~IKcovCollectorProvider() = default;

    // 取 tid 对应 collector;tid ∈ [0, ThreadCount()) 之外或槽位未初始化
    // 时返回 nullptr。返回指针在 provider 生命周期内稳定,调用方不得 delete。
    virtual KcovCollector* GetCollector(int tid) = 0;

    virtual int ThreadCount() const = 0;
};

} // namespace refuzz::worker

// Copyright 2026 reFuzz project author -------youngkk.
//
// Null Object impls of the coverage-layer seams (IKcovCollectorProvider /
// IKcovDrainSink) for coverage-off threaded execution (target.coverage_mode=
// none + intra_task_mode=threaded).
//
// 设计动机(speed-compare arm B / "纯 executor 速度"对照):
//   threaded 执行算法本身不依赖 KCOV —— KernelThreadPool 的 per-call
//   Begin/Reset/Collect/End 全部以 `collector != nullptr && task_active` 守卫,
//   ScheduleCall 的 "opened kcov fd" 调度门以 `kcov_provider_ != nullptr` 守卫。
//   "关闭 coverage" 不是一个新执行模式,而是在同一组接口背后换一个**中性实现**
//   (Null Object),让 driver / pool 代码保持 mode-agnostic、热路径零改动。
//
//   - NullKcovProvider:ThreadCount() 报满 logical thread_count,使
//     ScheduleCall 对每个 tid ∈ [0, thread_count) 都放行(coverage-off 下没有
//     "必须持 kcov fd" 的约束);GetCollector() 返回 nullptr —— 这是
//     IKcovCollectorProvider 契约钦定的合法 sentinel("槽位未初始化时返回
//     nullptr"),热路径的 `collector != nullptr` 守卫据此把所有 KCOV 操作
//     no-op 掉。
//   - NullKcovDrainSink:threaded path 仍会调 StartThreadedSession /
//     AppendThreadDrained / CurrentMode,全部 no-op。CurrentMode 返回 kPc
//     (enum 无 kNone;kPc 是最轻默认,且根本不会采集)。
//
// 为什么用非空 Null Object 而非裸 nullptr provider/drain:
//   ① driver 保留 provider/drain 非空的 fail-closed reject —— Null Object 满足
//      它,而裸 null 会触发 reject;② 把"故意 coverage-off"与"没接线 bug"显式
//      区分开,ScheduleCall 的调度门照常运行(报满 thread_count),语义清晰。
//
// 模块边界:与真实 KcovSink 一样,只实现 coverage/ 的接口,不被 driver/ 直接
// #include 具体类(profile/factory 层装配时按 coverage_mode 选择实现)。

#pragma once

#include "worker/coverage/kcov_collector_provider.hpp"
#include "worker/coverage/kcov_drain_sink.hpp"

#include <cstdint>
#include <vector>

namespace refuzz::worker {

class NullKcovProvider final : public IKcovCollectorProvider {
public:
    explicit NullKcovProvider(int thread_count) : thread_count_(thread_count) {}

    // 不发 collector —— 契约允许返回 nullptr;热路径 collector==nullptr 守卫
    // 让 Begin/Reset/Collect/End 全跳过。
    KcovCollector* GetCollector(int /*tid*/) override { return nullptr; }

    // 报满 logical thread_count,使每个 tid 都通过 ScheduleCall 的 kcov-slot 门。
    int ThreadCount() const override { return thread_count_; }

private:
    int thread_count_;
};

class NullKcovDrainSink final : public IKcovDrainSink {
public:
    // enum 无 kNone;kPc 是最轻默认且不触发采集行为。
    KcovMode CurrentMode() const override { return KcovMode::kPc; }
    void StartThreadedSession(KcovMode /*mode*/) override {}
    void AppendThreadDrained(std::vector<uint64_t> /*entries*/) override {}
};

}  // namespace refuzz::worker

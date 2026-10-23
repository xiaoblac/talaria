#pragma once

#include "refuzz/core/metrics/metric_registry.hpp"
#include "refuzz/telemetry/observation/run_summary.hpp"

#include <chrono>
#include <vector>

namespace refuzz::telemetry {

// 纯函数:按 RunSummarySchema() 投影 samples,产出完整 RunSummary。
//
// 无副作用:
//   - 不读 Registry(samples 已由 projector CollectPrefix 给出)
//   - 不写任何全局/存储
//   - is_final=false  → invariants.status = kPending (跳过校验)
//   - is_final=true + enable_invariants=true  → 跑该模式适用的那套:kOk / kViolated
//   - is_final=true + enable_invariants=false → kDisabled
//   - samples 为空 → kSkipped (无论 is_final)
//
// [fixed request stream] run_mode 决定评估哪一组 invariant。不是"算完再按模式过滤
// 结果",而是不适用的 invariant 根本不评估 —— 一条读着结构性为 0 的计数器的检查,
// 在那个模式下不是"碰巧不通过",是压根不成立。详见 SummaryRunMode 与 InvariantList()。
RunSummary ComputeRunSummary(
    const std::vector<core::metrics::MetricRegistry::Sample>& samples,
    std::chrono::steady_clock::time_point session_start,
    std::chrono::steady_clock::time_point now,
    std::chrono::system_clock::time_point session_start_wall,
    std::chrono::system_clock::time_point now_wall,
    bool is_final,
    bool enable_invariants,
    SummaryRunMode run_mode = SummaryRunMode::kFuzzing);

} // namespace refuzz::telemetry

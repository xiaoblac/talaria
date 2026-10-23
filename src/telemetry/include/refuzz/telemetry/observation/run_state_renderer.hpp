#pragma once

#include "refuzz/core/runtime_state.hpp"
#include "refuzz/telemetry/observation/run_state_store.hpp"

#include <cstddef>
#include <map>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace refuzz::telemetry {

// fuzzer + executor 行从 metric_samples 读而非 snapshot.{fuzzer,executor} 字段
std::string RenderRuntimePanel(const refuzz::core::RuntimeSnapshot& snapshot,
                               const RunStateStore::SampleMap& metric_samples,
                               const std::vector<refuzz::core::RuntimeEvent>& recent_events,
                               std::string_view tag = "RuntimePanel");

// Store-based overload:从 store 取 snapshot + samples + events,传给底层重载
std::string RenderRuntimePanel(const RunStateStore& store,
                               std::string_view tag = "RuntimePanel",
                               size_t max_events = 5);

// [v2 run_summary redesign] 从 store 读已算好的 RunSummary 渲染 TUI 块。
// summary 缺失(projector 尚未首个 tick) → 返回单行提示,不报错。
// Dashboard 在 RuntimePanel 之上插这一块。
std::string RenderRunSummary(const RunStateStore& store,
                             std::string_view tag = "RunSummary");

// [v2 PR-K-B] Descriptor-driven coverage render. Iterates
// store.RegisteredSeries() and emits one line per series:
//   "\n  <display_name> total=N Δ=N <sparkline>"
// or, if the buffer is empty:
//   "\n  <display_name> (no coverage data)"
//
// Sparkline width = min(buffer.size(), spark_width). Ramp is the 8-level
// ASCII set `._:-=+*#`; level mapping per plan §6.1 D-3 (level =
// min(7, value_delta * 7 / max_delta_in_window); all-zero-delta window
// → all level 0).
//
// Per Rule B (§1.2), this helper is the SINGLE entry point any renderer
// uses to display coverage; metric-name reads are forbidden in the
// renderer (enforced by check_coverage_render_no_metric_name.sh which
// lands in this PR).
std::string RenderCoverageBlock(const RunStateStore& store, size_t spark_width = 60);

} // namespace refuzz::telemetry

#pragma once

#include "refuzz/core/metrics/metric_registry.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <string>
#include <utility>
#include <vector>

namespace refuzz::telemetry {

// RunSummary schema & shared value types — 详细设计见
// docs/telemetry-redesign/040_run_summary_redesign.md §5.1/§6。
// 字段 schema/派生公式硬编码在 run_summary.cpp,新增字段必须同步 020 naming catalog。

enum class SummaryValueKind : uint8_t {
    kInt,
    kDouble,
};

struct SummaryValue {
    SummaryValueKind kind = SummaryValueKind::kInt;
    int64_t i = 0;
    double  d = 0.0;

    static SummaryValue Int(int64_t v)   { return SummaryValue{SummaryValueKind::kInt,    v, 0.0}; }
    static SummaryValue Double(double v) { return SummaryValue{SummaryValueKind::kDouble, 0,   v}; }
};

struct SummaryField {
    std::string out_name;
    // extract 读原始 samples + 同一 tick 内已算好的先行字段(computed_so_far)
    // + session_start/now,返回本字段值。派生字段依赖先行字段通过 LookupComputed 取。
    std::function<SummaryValue(
        const std::vector<core::metrics::MetricRegistry::Sample>& samples,
        const std::vector<std::pair<std::string, SummaryValue>>& computed_so_far,
        std::chrono::steady_clock::time_point session_start,
        std::chrono::steady_clock::time_point now)> extract;
};

// 项目唯一 schema。schema 顺序 = 计算顺序,派生字段放后面以保证先行字段就位。
const std::vector<SummaryField>& RunSummarySchema();

// [fixed request stream] docs/plans/fixed-request-stream-performance-replay.md
// §6. Which workload source produced this run. This is NOT decoration on the
// output: the summary is not assembled the same way in the two modes, because
// the pipeline itself is not the same shape.
//
//   kFuzzing: ExploreJob supplies gen/mut programs, completion-derived
//     cascades (triage/smash/retry) feed corpus evolution. "Work entered the
//     pipeline" is expressed by `generated`.
//   kReplay: the orchestrator sets suppress_default_producer=true and
//     catch_all_triage_enabled=false, so ExploreJob never runs and no
//     completion-derived task is ever created. `generated` is therefore
//     STRUCTURALLY zero — not measured-zero — and the fixed-input producer's
//     work lands in `reexec` instead.
//
// A telemetry-local enum on purpose: telemetry is below control/, must not
// include orchestrator headers, and does not need orchestrator's full RunMode
// (which also drives stream loading, producer selection, etc.). Orchestrator
// maps its RunMode onto this one when it configures the projector.
enum class SummaryRunMode : uint8_t {
    kFuzzing = 0,
    kReplay,
};

const char* SummaryRunModeName(SummaryRunMode mode);

struct RunSummaryInvariants {
    enum class Status : uint8_t {
        kPending,   // 过程 tick:尚未跑校验
        kOk,        // final tick,全部通过
        kViolated,  // final tick,至少一条失败
        kDisabled,  // 配置关闭
        kSkipped,   // registry=nullptr / samples 为空等降级情形
    };
    Status status = Status::kPending;
    std::vector<std::string> failures;  // id 列表,status==kViolated 时非空
};

const char* InvariantStatusName(RunSummaryInvariants::Status s);

struct RunSummary {
    // fields 按 RunSummarySchema() 顺序一一对应,序列化 key 顺序稳定
    std::vector<std::pair<std::string, SummaryValue>> fields;
    RunSummaryInvariants invariants;
    // [fixed request stream] 本次 run 的 workload 来源。序列化出去,让读 json 的人
    // 能区分"某字段测出来是 0"和"该字段在这个模式下结构性不存在"(见 SummaryRunMode)。
    SummaryRunMode run_mode = SummaryRunMode::kFuzzing;
    std::chrono::steady_clock::time_point snapshot_ts{};
    // 以 session_start 为 0 点的墙钟表示,单独存一份给 json 输出用
    std::chrono::system_clock::time_point session_start_wall{};
    std::chrono::system_clock::time_point snapshot_wall{};
    bool is_final = false;
};

// samples 内查单个 series 值(给 extract lambda 用);未命中返回 0。
int64_t CounterInSamples(
    const std::vector<core::metrics::MetricRegistry::Sample>& samples,
    std::string_view name,
    const core::metrics::Labels& labels = {});

int64_t LookupComputedInt(
    const std::vector<std::pair<std::string, SummaryValue>>& prior,
    std::string_view key);

double LookupComputedDouble(
    const std::vector<std::pair<std::string, SummaryValue>>& prior,
    std::string_view key);

} // namespace refuzz::telemetry

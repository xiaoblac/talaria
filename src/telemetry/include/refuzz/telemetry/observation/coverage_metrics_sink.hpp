#pragma once

#include "refuzz/core/metrics/metric_registry.hpp"
#include "refuzz/telemetry/observation/periodic_sample_gate.hpp"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string_view>
#include <vector>

namespace refuzz::telemetry {

// 覆盖指标的周期性磁盘落盘。四个测量口径 all_pc/corpus_pc/all_edge/corpus_edge
// 写进**同一个** append-only log,每 10s 一行、key=value 自描述:
//
//   # coverage series — key=value per 10s window: t=<HH:MM:SS>,all_pc,corpus_pc,all_edge,corpus_edge
//   t=13:23:30,all_pc=101,corpus_pc=41,all_edge=203,corpus_edge=73
//   t=13:23:40,all_pc=111,corpus_pc=43,all_edge=211,corpus_edge=79
//
// 设计要点:
//   - 间隔判定走 steady_clock 的 PeriodicSampleGate(单调,不受系统时间回拨影响);
//   - 行内 t 字段是**墙钟本地时间 HH:MM:SS**(方便人直接对着日志读),由调用方把
//     采样时刻的 system_clock::time_point 传进来,sink 只负责格式化;
//   - projector 的 tick 只做去重键(单调计数,永不撞行),不写进文件。
class CoverageMetricsSink {
public:
    static constexpr const char* kFilename = "coverage_series.log";
    static constexpr const char* kHeader =
        "# coverage series — key=value per 10s window: "
        "t=<HH:MM:SS>,all_pc,corpus_pc,all_edge,corpus_edge\n";

    CoverageMetricsSink(
        std::filesystem::path logs_dir,
        std::chrono::steady_clock::time_point start,
        std::chrono::seconds interval = std::chrono::seconds{10});

    void MaybeFlush(
        std::chrono::steady_clock::time_point now_steady,
        std::chrono::system_clock::time_point now_wall,
        std::uint64_t tick,
        const std::vector<refuzz::core::metrics::MetricRegistry::Sample>& samples);
    void FlushFinal(
        std::chrono::system_clock::time_point now_wall,
        std::uint64_t tick,
        const std::vector<refuzz::core::metrics::MetricRegistry::Sample>& samples);

    bool Degraded() const noexcept { return degraded_; }

private:
    static std::uint64_t GaugeValue(
        const std::vector<refuzz::core::metrics::MetricRegistry::Sample>& samples,
        std::string_view name);
    // tick 只做去重键;写入行的时间字段来自 now_wall(墙钟本地 HH:MM:SS)。
    void Write(
        std::chrono::system_clock::time_point now_wall,
        std::uint64_t tick,
        const std::vector<refuzz::core::metrics::MetricRegistry::Sample>& samples);
    bool HeaderNeeded() const;

    std::filesystem::path path_;
    PeriodicSampleGate gate_;
    std::optional<std::uint64_t> last_tick_;
    bool header_checked_ = false;
    bool header_written_ = false;
    bool degraded_ = false;
};

} // namespace refuzz::telemetry

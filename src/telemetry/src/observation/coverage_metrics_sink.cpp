#include "refuzz/telemetry/observation/coverage_metrics_sink.hpp"

#include "refuzz/core/metrics/metric_kind.hpp"
#include "refuzz/logging/host_logger.hpp"
#include "refuzz/telemetry/observation/wall_clock_hms.hpp"

#include <fstream>
#include <system_error>
#include <utility>

namespace refuzz::telemetry {

CoverageMetricsSink::CoverageMetricsSink(
    std::filesystem::path logs_dir,
    std::chrono::steady_clock::time_point start,
    std::chrono::seconds interval)
    : path_(std::move(logs_dir) / kFilename)
    , gate_(interval, start)
{}

std::uint64_t CoverageMetricsSink::GaugeValue(
    const std::vector<refuzz::core::metrics::MetricRegistry::Sample>& samples,
    std::string_view name)
{
    for (const auto& sample : samples) {
        if (sample.kind == refuzz::core::metrics::MetricKind::kGauge &&
            sample.name == name && sample.labels.empty()) {
            return static_cast<std::uint64_t>(sample.value);
        }
    }
    return 0;
}

void CoverageMetricsSink::MaybeFlush(
    std::chrono::steady_clock::time_point now_steady,
    std::chrono::system_clock::time_point now_wall,
    std::uint64_t tick,
    const std::vector<refuzz::core::metrics::MetricRegistry::Sample>& samples)
{
    if (!gate_.Poll(now_steady).has_value()) {
        return;
    }
    Write(now_wall, tick, samples);
}

void CoverageMetricsSink::FlushFinal(
    std::chrono::system_clock::time_point now_wall,
    std::uint64_t tick,
    const std::vector<refuzz::core::metrics::MetricRegistry::Sample>& samples)
{
    Write(now_wall, tick, samples);
}

void CoverageMetricsSink::Write(
    std::chrono::system_clock::time_point now_wall,
    std::uint64_t tick,
    const std::vector<refuzz::core::metrics::MetricRegistry::Sample>& samples)
{
    // 同一 tick 不重复写(周期 flush 与 final flush 可能落在同一 projector tick)。
    if (last_tick_.has_value() && *last_tick_ == tick) {
        return;
    }
    std::error_code ec;
    std::filesystem::create_directories(path_.parent_path(), ec);
    if (ec) {
        degraded_ = true;
        refuzz::logging::HostLineBuilder("CoverageMetricsSink", "logs_dir_create_failed")
            << path_.parent_path().string() << "\n";
        return;
    }
    if (!header_checked_) {
        header_written_ = !HeaderNeeded();
        header_checked_ = true;
    }
    std::ofstream file(path_, std::ios::out | std::ios::app | std::ios::binary);
    if (!file) {
        degraded_ = true;
        refuzz::logging::HostLineBuilder("CoverageMetricsSink", "open_failed")
            << path_.string() << "\n";
        return;
    }
    if (!header_written_) {
        file << kHeader;
    }
    file << "t=" << FormatWallClockHms(now_wall)
         << ",all_pc=" << GaugeValue(samples, "fuzzer.cov.all_pc")
         << ",corpus_pc=" << GaugeValue(samples, "fuzzer.cov.corpus_pc")
         << ",all_edge=" << GaugeValue(samples, "fuzzer.cov.all_edge")
         << ",corpus_edge=" << GaugeValue(samples, "fuzzer.cov.corpus_edge")
         << '\n';
    file.flush();
    if (!file) {
        degraded_ = true;
        refuzz::logging::HostLineBuilder("CoverageMetricsSink", "write_failed")
            << path_.string() << "\n";
        return;
    }
    header_written_ = true;
    last_tick_ = tick;
}

bool CoverageMetricsSink::HeaderNeeded() const
{
    std::error_code ec;
    if (!std::filesystem::exists(path_, ec) || ec) {
        return true;
    }
    return std::filesystem::file_size(path_, ec) == 0 || ec;
}

} // namespace refuzz::telemetry

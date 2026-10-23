#include "refuzz/telemetry/observation/fuzzer_stats_sink.hpp"

#include "refuzz/core/metrics/metric_kind.hpp"
#include "refuzz/logging/host_logger.hpp"
#include "refuzz/telemetry/observation/wall_clock_hms.hpp"

#include <fstream>
#include <string>
#include <system_error>
#include <utility>

namespace refuzz::telemetry {

namespace {

constexpr std::uint64_t kIntervalSeconds = 60;

bool HasKindLabel(const refuzz::core::metrics::Labels& labels, const char* kind)
{
    for (const auto& [key, value] : labels) {
        if (key == "kind" && value == kind) {
            return true;
        }
    }
    return false;
}

std::uint64_t CounterValue(
    const std::vector<refuzz::core::metrics::MetricRegistry::Sample>& samples,
    const char* name,
    const char* kind)
{
    for (const auto& s : samples) {
        if (s.kind == refuzz::core::metrics::MetricKind::kCounter &&
            s.name == name && HasKindLabel(s.labels, kind)) {
            return static_cast<std::uint64_t>(s.value);
        }
    }
    return 0;
}

// [collide 变换层] 按名匹配一个**无 kind label**的 counter(如 fuzzer.exec_collide)。
// 上面的 CounterValue 走 {kind=...} 分桶计数;collide 是命中即记的单值计数、无 label,
// 故单独按名取。
std::uint64_t CounterValueByName(
    const std::vector<refuzz::core::metrics::MetricRegistry::Sample>& samples,
    const char* name)
{
    for (const auto& s : samples) {
        if (s.kind == refuzz::core::metrics::MetricKind::kCounter &&
            s.name == name) {
            return static_cast<std::uint64_t>(s.value);
        }
    }
    return 0;
}

// [Step 4] point-in-time gauge value by name (inflight_seeds / *_job). Gauges
// carry no kind label; match by bare name + kGauge kind.
std::int64_t GaugeValue(
    const std::vector<refuzz::core::metrics::MetricRegistry::Sample>& samples,
    const char* name)
{
    for (const auto& s : samples) {
        if (s.kind == refuzz::core::metrics::MetricKind::kGauge &&
            s.name == name) {
            return static_cast<std::int64_t>(s.value);
        }
    }
    return 0;
}

} // namespace

FuzzerStatsSink::FuzzerStatsSink(
    std::filesystem::path logs_dir,
    std::chrono::steady_clock::time_point start_steady)
    : output_path_(std::move(logs_dir) / kFilename)
    , sample_gate_(std::chrono::seconds{kIntervalSeconds}, start_steady)
{}

FuzzerStatsSink::Snapshot
FuzzerStatsSink::Collect(
    const std::vector<refuzz::core::metrics::MetricRegistry::Sample>& samples)
{
    Snapshot s;
    // [per-task completed] +1 per completed executor task of each job.
    s.triage = CounterValue(samples, "fuzzer.triage", "task_completed");
    s.minimize = CounterValue(samples, "fuzzer.minimize", "task_completed");
    s.hints = CounterValue(samples, "fuzzer.hints", "task_completed");
    s.fault_inject = CounterValue(samples, "fuzzer.fault_inject", "task_completed");
    s.smash = CounterValue(samples, "fuzzer.smash", "task_completed");
    // [collide 变换层] per-hit 计数。
    s.collide = CounterValueByName(samples, "fuzzer.exec_collide");
    // Job outcome counters.
    s.triage_completed   = CounterValue(samples, "fuzzer.triage", "completed");
    s.triage_admit       = CounterValue(samples, "fuzzer.triage", "admit_stable");
    s.triage_drop        = CounterValue(samples, "fuzzer.triage", "drop_flaky");
    s.minimize_completed = CounterValue(samples, "fuzzer.minimize", "completed");
    s.smash_completed    = CounterValue(samples, "fuzzer.smash", "completed");
    s.hints_completed    = CounterValue(samples, "fuzzer.hints", "completed");
    // Point-in-time job concurrency gauges。
    s.triage_job   = GaugeValue(samples, "fuzzer.triage_job");
    s.minimize_job = GaugeValue(samples, "fuzzer.minimize_job");
    s.smash_job    = GaugeValue(samples, "fuzzer.smash_job");
    s.hints_job    = GaugeValue(samples, "fuzzer.hints_job");
    s.fault_job    = GaugeValue(samples, "fuzzer.fault_job");
    return s;
}

void FuzzerStatsSink::MaybeFlush(
    std::chrono::steady_clock::time_point now,
    std::chrono::system_clock::time_point now_wall,
    const std::vector<refuzz::core::metrics::MetricRegistry::Sample>& samples)
{
    // 间隔判定仍走 steady_clock 门(60s);门放行后行内时间用墙钟本地时间。
    if (!sample_gate_.Poll(now).has_value()) {
        return;
    }
    WriteRow(now_wall, /*final=*/false, Collect(samples));
}

void FuzzerStatsSink::FlushFinal(
    std::chrono::steady_clock::time_point now,
    std::chrono::system_clock::time_point now_wall,
    const std::vector<refuzz::core::metrics::MetricRegistry::Sample>& samples)
{
    (void)now;
    WriteRow(now_wall, /*final=*/true, Collect(samples));
}

bool FuzzerStatsSink::HeaderNeeded() const
{
    std::error_code ec;
    if (!std::filesystem::exists(output_path_, ec)) {
        return true;
    }
    if (ec) {
        return true;
    }
    const auto size = std::filesystem::file_size(output_path_, ec);
    if (ec) {
        return true;
    }
    return size == 0;
}

bool FuzzerStatsSink::WriteRow(std::chrono::system_clock::time_point now_wall,
                              bool final, const Snapshot& s)
{
    std::error_code ec;
    std::filesystem::create_directories(output_path_.parent_path(), ec);
    if (ec) {
        degraded_ = true;
        refuzz::logging::HostLineBuilder("FuzzerStatsSink", "stats_logs_dir_create_failed")
            << output_path_.parent_path().string() << "\n";
        return false;
    }

    if (!header_checked_) {
        header_written_ = !HeaderNeeded();
        header_checked_ = true;
    }

    std::ofstream f(output_path_, std::ios::out | std::ios::app | std::ios::binary);
    if (!f) {
        degraded_ = true;
        refuzz::logging::HostLineBuilder("FuzzerStatsSink", "stats_open_failed")
            << output_path_.string() << "\n";
        return false;
    }

    if (!header_written_) {
        f << kHeader;
    }
    f << "t=" << FormatWallClockHms(now_wall)
      << " final=" << (final ? 1 : 0)
      << " triage_task=" << s.triage
      << " minimize_task=" << s.minimize
      << " hints_task=" << s.hints
      << " fault_task=" << s.fault_inject
      << " smash_task=" << s.smash
      << " collide=" << s.collide
      << " triage_completed=" << s.triage_completed
      << " triage_admit=" << s.triage_admit
      << " triage_drop=" << s.triage_drop
      << " minimize_completed=" << s.minimize_completed
      << " smash_completed=" << s.smash_completed
      << " hints_completed=" << s.hints_completed
      << " triage_job=" << s.triage_job
      << " minimize_job=" << s.minimize_job
      << " smash_job=" << s.smash_job
      << " hints_job=" << s.hints_job
      << " fault_job=" << s.fault_job
      << '\n';
    f.flush();
    if (!f) {
        degraded_ = true;
        refuzz::logging::HostLineBuilder("FuzzerStatsSink", "stats_write_failed")
            << output_path_.string() << "\n";
        return false;
    }
    header_written_ = true;
    return true;
}

} // namespace refuzz::telemetry

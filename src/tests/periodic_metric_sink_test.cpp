#include "refuzz/core/metrics/metric_registry.hpp"
#include "refuzz/fuzzer/metrics/fuzzer_metrics.hpp"
#include "refuzz/telemetry/observation/coverage_metrics_sink.hpp"
#include "refuzz/telemetry/observation/fuzzer_stats_sink.hpp"
#include "refuzz/telemetry/observation/periodic_sample_gate.hpp"

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <unistd.h>

namespace {

#define CHECK(cond)                                                             \
    do {                                                                        \
        if (!(cond)) {                                                          \
            std::fprintf(stderr, "CHECK failed: %s (line %d)\n", #cond, __LINE__); \
            return 1;                                                           \
        }                                                                       \
    } while (0)

std::filesystem::path MakeTempDir(const char* suffix)
{
    const auto path = std::filesystem::temp_directory_path() /
        (std::string("refuzz_periodic_metric_") + suffix + "_" +
         std::to_string(::getpid()));
    std::filesystem::remove_all(path);
    std::filesystem::create_directories(path);
    return path;
}

std::vector<std::string> ReadLines(const std::filesystem::path& path)
{
    std::ifstream file(path);
    std::vector<std::string> lines;
    for (std::string line; std::getline(file, line);) {
        lines.push_back(std::move(line));
    }
    return lines;
}

int TestPeriodicGateSkipsHistory()
{
    using namespace std::chrono;
    const steady_clock::time_point start{seconds{1000}};
    refuzz::telemetry::PeriodicSampleGate gate(seconds{60}, start);
    CHECK(!gate.Poll(start + seconds{59}).has_value());
    CHECK(gate.Poll(start + seconds{60}) == 60);
    CHECK(gate.Poll(start + seconds{185}) == 185);
    CHECK(!gate.Poll(start + seconds{239}).has_value());
    CHECK(gate.Poll(start + seconds{240}) == 240);
    return 0;
}

int TestFourCoverageGaugesBind()
{
    refuzz::core::metrics::MetricRegistry registry;
    refuzz::fuzzer::metrics::FuzzerMetrics metrics;
    metrics.Bind(registry);
    CHECK(metrics.cov_all_pc != nullptr);
    CHECK(metrics.cov_corpus_pc != nullptr);
    CHECK(metrics.cov_all_edge != nullptr);
    CHECK(metrics.cov_corpus_edge != nullptr);
    CHECK(registry.CollectPrefix("fuzzer.cov.").size() >= 4);
    return 0;
}

int TestCoverageFilesShareSnapshot()
{
    using namespace std::chrono;
    const auto dir = MakeTempDir("coverage");
    const steady_clock::time_point start{seconds{2000}};
    // 墙钟只用于行内 t=HH:MM:SS 显示;间隔判定走 steady_clock。取固定墙钟点让行结构确定,
    // 但不断言具体 HH:MM:SS(依赖本地时区,不可移植)。
    const system_clock::time_point wall{hours{47} + minutes{23} + seconds{30}};
    refuzz::core::metrics::MetricRegistry registry;
    auto& all_pc = registry.GaugeOf("fuzzer.cov.all_pc");
    auto& corpus_pc = registry.GaugeOf("fuzzer.cov.corpus_pc");
    auto& all_edge = registry.GaugeOf("fuzzer.cov.all_edge");
    auto& corpus_edge = registry.GaugeOf("fuzzer.cov.corpus_edge");
    all_pc.Set(101);
    corpus_pc.Set(41);
    all_edge.Set(203);
    corpus_edge.Set(73);

    refuzz::telemetry::CoverageMetricsSink sink(dir, start, seconds{10});
    auto samples = registry.CollectPrefix("fuzzer.");
    sink.MaybeFlush(start + seconds{9}, wall, 9, samples);
    CHECK(!std::filesystem::exists(
        dir / refuzz::telemetry::CoverageMetricsSink::kFilename));
    sink.MaybeFlush(start + seconds{10}, wall, 10, samples);

    all_pc.Set(111);
    corpus_pc.Set(43);
    all_edge.Set(211);
    corpus_edge.Set(79);
    samples = registry.CollectPrefix("fuzzer.");
    sink.MaybeFlush(start + seconds{35}, wall, 35, samples);

    const auto lines = ReadLines(
        dir / refuzz::telemetry::CoverageMetricsSink::kFilename);
    // header + 两行数据(9s 被门挡下,不落行)。
    CHECK(lines.size() == 3);
    CHECK(lines[0].rfind("# coverage series", 0) == 0);
    // 全四口径在同一行、key=value 自描述;时间字段带 t= 前缀与 HH:MM:SS 冒号。
    CHECK(lines[1].find(
        "all_pc=101,corpus_pc=41,all_edge=203,corpus_edge=73") != std::string::npos);
    CHECK(lines[2].find(
        "all_pc=111,corpus_pc=43,all_edge=211,corpus_edge=79") != std::string::npos);
    for (std::size_t i = 1; i < lines.size(); ++i) {
        CHECK(lines[i].rfind("t=", 0) == 0);
        CHECK(lines[i].find(':') != std::string::npos);
        CHECK(lines[i].find('\t') == std::string::npos);
    }
    std::filesystem::remove_all(dir);
    return 0;
}

int TestStatsDoesNotBackfill()
{
    using namespace std::chrono;
    const auto dir = MakeTempDir("stats");
    const steady_clock::time_point start{seconds{3000}};
    // 墙钟只用于行内 t=HH:MM:SS 显示;间隔判定走 steady_clock。不断言具体时钟字符串
    // (依赖本地时区),只断言单行、t= 前缀、HH:MM:SS 结构与计数字段。
    const system_clock::time_point wall{hours{47} + minutes{5} + seconds{9}};
    refuzz::core::metrics::MetricRegistry registry;
    registry.CounterOf("fuzzer.triage", {{"kind", "task_completed"}}).Inc(7);
    const auto samples = registry.CollectPrefix("fuzzer.");
    refuzz::telemetry::FuzzerStatsSink sink(dir, start);
    // 一次晚 poll(跨过多个 60s 窗口)只写当前一行,不回填历史窗口。
    sink.MaybeFlush(start + seconds{185}, wall, samples);

    const auto lines = ReadLines(dir / refuzz::telemetry::FuzzerStatsSink::kFilename);
    std::size_t rows = 0;
    for (const auto& line : lines) {
        if (line.rfind("t=", 0) == 0) {
            ++rows;
            CHECK(line.find(':') != std::string::npos);
            CHECK(line.find("window_s=") == std::string::npos);
            CHECK(line.find("triage_task=7") != std::string::npos);
        }
    }
    CHECK(rows == 1);
    std::filesystem::remove_all(dir);
    return 0;
}

} // namespace

int main()
{
    if (TestPeriodicGateSkipsHistory() != 0) return 1;
    if (TestFourCoverageGaugesBind() != 0) return 1;
    if (TestCoverageFilesShareSnapshot() != 0) return 1;
    if (TestStatsDoesNotBackfill() != 0) return 1;
    return 0;
}

#include "refuzz/telemetry/observation/run_summary_json_sink.hpp"

#include "refuzz/telemetry/observation/run_state_store.hpp"
#include "refuzz/telemetry/observation/run_summary.hpp"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <ios>
#include <sstream>
#include <string>
#include <system_error>

namespace refuzz::telemetry {

namespace {

// ISO-8601 UTC 字符串(精度到秒)。system_clock::time_point 的 duration 可能是
// nanoseconds,先截到 seconds 再 gmtime_r。zero time_point → "1970-01-01T00:00:00Z"。
std::string IsoUtc(std::chrono::system_clock::time_point tp)
{
    const auto secs = std::chrono::time_point_cast<std::chrono::seconds>(tp);
    const std::time_t t = std::chrono::system_clock::to_time_t(secs);
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return std::string(buf);
}

void AppendEscapedKey(std::string& out, const std::string& key)
{
    out += '"';
    // schema key 受 ValidateName 限制(ASCII 小写+数字+下划线+点),无需 escape。
    out += key;
    out += '"';
}

void AppendSummaryValue(std::string& out, const SummaryValue& v)
{
    if (v.kind == SummaryValueKind::kInt) {
        out += std::to_string(v.i);
    } else {
        // 固定 6 位小数,足够展示 rate/秒级精度,又不至于引入 double 抖动尾数。
        char buf[64];
        std::snprintf(buf, sizeof(buf), "%.6f", v.d);
        out += buf;
    }
}

} // namespace

const char* JsonWriteStatusName(JsonWriteStatus s)
{
    switch (s) {
    case JsonWriteStatus::kOk:              return "ok";
    case JsonWriteStatus::kInvariantFailed: return "invariant_failed";
    case JsonWriteStatus::kIoError:         return "io_error";
    case JsonWriteStatus::kSkipped:         return "skipped";
    }
    return "unknown";
}

RunSummaryJsonSink::RunSummaryJsonSink(RunSummaryJsonSinkConfig cfg,
                                       const RunStateStore& store)
    : cfg_(std::move(cfg))
    , store_(store)
{}

std::string RunSummaryJsonSink::RenderJson() const
{
    const auto summary_opt = store_.LatestRunSummary();
    if (!summary_opt) {
        return std::string{};
    }
    const RunSummary& s = *summary_opt;

    std::string out;
    out.reserve(2048);
    out += "{\n";
    out += "  \"session_start_ts\": \""; out += IsoUtc(s.session_start_wall); out += "\",\n";
    out += "  \"snapshot_ts\": \"";      out += IsoUtc(s.snapshot_wall);      out += "\",\n";
    out += "  \"is_final\": ";           out += s.is_final ? "true" : "false"; out += ",\n";
    // [fixed request stream] 让读 json 的人能区分"测出来是 0"和"这个模式下该字段
    // 结构性不存在"(replay 下 generated / corpus 演化族恒 0),以及知道 invariants
    // 是按哪一组评估的。追加字段,不动既有 key。
    out += "  \"run_mode\": \"";         out += SummaryRunModeName(s.run_mode);  out += "\",\n";
    out += "  \"fields\": {\n";
    for (size_t i = 0; i < s.fields.size(); ++i) {
        out += "    ";
        AppendEscapedKey(out, s.fields[i].first);
        out += ": ";
        AppendSummaryValue(out, s.fields[i].second);
        if (i + 1 < s.fields.size()) out += ',';
        out += '\n';
    }
    out += "  },\n";
    out += "  \"invariants\": {\n";
    out += "    \"status\": \""; out += InvariantStatusName(s.invariants.status); out += "\",\n";
    out += "    \"failures\": [";
    for (size_t i = 0; i < s.invariants.failures.size(); ++i) {
        if (i > 0) out += ", ";
        out += '"';
        out += s.invariants.failures[i];
        out += '"';
    }
    out += "]\n";
    out += "  }\n";
    out += "}\n";
    return out;
}

JsonWriteStatus RunSummaryJsonSink::WriteFinal()
{
    const auto summary_opt = store_.LatestRunSummary();
    if (!summary_opt) {
        return JsonWriteStatus::kSkipped;
    }
    if (summary_opt->invariants.status == RunSummaryInvariants::Status::kSkipped) {
        return JsonWriteStatus::kSkipped;
    }

    std::error_code ec;
    std::filesystem::create_directories(cfg_.logs_dir, ec);  // 若已存在不报错
    if (ec) {
        return JsonWriteStatus::kIoError;
    }

    const auto final_path = cfg_.logs_dir / cfg_.filename;
    const auto tmp_path   = cfg_.logs_dir / (cfg_.filename + ".tmp");

    {
        std::ofstream f(tmp_path, std::ios::out | std::ios::trunc | std::ios::binary);
        if (!f) return JsonWriteStatus::kIoError;
        f << RenderJson();
        f.flush();
        if (!f) return JsonWriteStatus::kIoError;
    }

    std::filesystem::rename(tmp_path, final_path, ec);
    if (ec) return JsonWriteStatus::kIoError;

    return summary_opt->invariants.status == RunSummaryInvariants::Status::kViolated
        ? JsonWriteStatus::kInvariantFailed
        : JsonWriteStatus::kOk;
}

} // namespace refuzz::telemetry

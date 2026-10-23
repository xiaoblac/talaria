// Characterize a fixed request stream using the same typed-program path as
// production replay.  All reported properties are known before execution.

#include "refuzz/control/request_stream_reader.hpp"
#include "refuzz/program/syz/encoding.hpp"
#include "refuzz/program/syz/exec_wire.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"
#include "util/json.hpp"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;
namespace stream = ::refuzz::request_stream;
namespace syz = ::refuzz::program::syz;
using Json = nlohmann::ordered_json;

namespace {

constexpr std::uint64_t kFlatRpcThreaded = 1ULL << 4;

struct Counts {
    std::uint64_t programs = 0;
    std::uint64_t calls = 0;
    std::uint64_t native_calls = 0;
    std::uint64_t pseudo_calls = 0;
    std::uint64_t programs_with_pseudo = 0;

    std::uint64_t timeout_calls = 0;
    std::uint64_t programs_with_timeout = 0;
    std::uint64_t prog_timeout_calls = 0;
    std::uint64_t programs_with_prog_timeout = 0;

    std::uint64_t async_calls = 0;
    std::uint64_t programs_with_async = 0;
    std::uint64_t threaded_programs = 0;
    std::uint64_t threaded_async_programs = 0;
    std::uint64_t effective_async_calls = 0;

    std::uint64_t remote_cover_calls = 0;
    std::uint64_t programs_with_remote_cover = 0;
};

struct Distributions {
    std::vector<std::uint64_t> exec_wire_bytes;
    std::vector<std::uint64_t> calls_per_program;
    std::vector<std::uint64_t> native_calls_per_program;
    std::vector<std::uint64_t> pseudo_calls_per_pseudo_program;

    // Timeout is a per-call extension.  Preserve both the call-level values and
    // the per-program sum/max without treating either as measured runtime.
    std::vector<std::uint64_t> timeout_attr_ms;
    std::vector<std::uint64_t> timeout_calls_per_timeout_program;
    std::vector<std::uint64_t> timeout_sum_ms_per_timeout_program;
    std::vector<std::uint64_t> timeout_max_ms_per_timeout_program;

    // Syzkaller applies the maximum ProgTimeout attribute in a program.
    std::vector<std::uint64_t> prog_timeout_attr_ms;
    std::vector<std::uint64_t> prog_timeout_calls_per_program;
    std::vector<std::uint64_t> prog_timeout_max_ms_per_program;

    std::vector<std::uint64_t> async_calls_per_async_program;
    std::vector<std::uint64_t> effective_async_calls_per_program;
    std::vector<std::uint64_t> remote_cover_calls_per_program;
};

bool ValidId(std::string_view id)
{
    if (id.empty()) return false;
    for (const unsigned char c : id) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_') {
            continue;
        }
        return false;
    }
    return true;
}

double Percent(std::uint64_t numerator, std::uint64_t denominator)
{
    if (denominator == 0) return 0.0;
    return 100.0 * static_cast<double>(numerator) /
           static_cast<double>(denominator);
}

std::uint64_t NearestRank(const std::vector<std::uint64_t>& sorted, double q)
{
    if (sorted.empty()) return 0;
    const auto rank = static_cast<std::size_t>(
        std::ceil(q * static_cast<double>(sorted.size())));
    return sorted[std::max<std::size_t>(1, rank) - 1];
}

Json Describe(const std::vector<std::uint64_t>& values)
{
    Json out;
    out["n"] = values.size();
    if (values.empty()) {
        out["min"] = nullptr;
        out["p50"] = nullptr;
        out["p95"] = nullptr;
        out["p99"] = nullptr;
        out["max"] = nullptr;
        out["mean"] = nullptr;
        return out;
    }

    std::vector<std::uint64_t> sorted = values;
    std::sort(sorted.begin(), sorted.end());
    long double sum = 0.0L;
    for (const auto value : sorted) sum += static_cast<long double>(value);

    out["min"] = sorted.front();
    out["p50"] = NearestRank(sorted, 0.50);
    out["p95"] = NearestRank(sorted, 0.95);
    out["p99"] = NearestRank(sorted, 0.99);
    out["max"] = sorted.back();
    out["mean"] = static_cast<double>(sum / sorted.size());
    return out;
}

Json CountSummary(const Counts& c)
{
    Json out;
    out["programs"] = c.programs;
    out["calls"] = c.calls;
    out["native_calls"] = c.native_calls;
    out["pseudo_calls"] = c.pseudo_calls;
    out["pseudo_call_share_pct"] = Percent(c.pseudo_calls, c.calls);
    out["programs_with_pseudo"] = c.programs_with_pseudo;
    out["programs_with_pseudo_pct"] = Percent(c.programs_with_pseudo, c.programs);

    out["timeout_calls"] = c.timeout_calls;
    out["programs_with_timeout"] = c.programs_with_timeout;
    out["programs_with_timeout_pct"] = Percent(c.programs_with_timeout, c.programs);
    out["prog_timeout_calls"] = c.prog_timeout_calls;
    out["programs_with_prog_timeout"] = c.programs_with_prog_timeout;
    out["programs_with_prog_timeout_pct"] =
        Percent(c.programs_with_prog_timeout, c.programs);

    out["async_calls"] = c.async_calls;
    out["programs_with_async"] = c.programs_with_async;
    out["programs_with_async_pct"] = Percent(c.programs_with_async, c.programs);
    out["threaded_programs"] = c.threaded_programs;
    out["threaded_programs_pct"] = Percent(c.threaded_programs, c.programs);
    out["threaded_async_programs"] = c.threaded_async_programs;
    out["threaded_async_programs_pct"] =
        Percent(c.threaded_async_programs, c.programs);
    out["effective_async_calls"] = c.effective_async_calls;

    out["remote_cover_calls"] = c.remote_cover_calls;
    out["programs_with_remote_cover"] = c.programs_with_remote_cover;
    out["programs_with_remote_cover_pct"] =
        Percent(c.programs_with_remote_cover, c.programs);
    return out;
}

Json DistributionSummary(const Distributions& d)
{
    Json out;
    out["request_footprint"]["exec_wire_bytes_per_program"] =
        Describe(d.exec_wire_bytes);

    out["program_structure"]["calls_per_program"] =
        Describe(d.calls_per_program);
    out["program_structure"]["native_calls_per_program"] =
        Describe(d.native_calls_per_program);
    out["program_structure"]["pseudo_calls_per_pseudo_program"] =
        Describe(d.pseudo_calls_per_pseudo_program);

    out["declared_wait_budget"]["timeout_attr_ms_per_marked_call"] =
        Describe(d.timeout_attr_ms);
    out["declared_wait_budget"]["timeout_calls_per_marked_program"] =
        Describe(d.timeout_calls_per_timeout_program);
    out["declared_wait_budget"]["timeout_sum_ms_per_marked_program"] =
        Describe(d.timeout_sum_ms_per_timeout_program);
    out["declared_wait_budget"]["timeout_max_ms_per_marked_program"] =
        Describe(d.timeout_max_ms_per_timeout_program);
    out["declared_wait_budget"]["prog_timeout_attr_ms_per_marked_call"] =
        Describe(d.prog_timeout_attr_ms);
    out["declared_wait_budget"]["prog_timeout_calls_per_marked_program"] =
        Describe(d.prog_timeout_calls_per_program);
    out["declared_wait_budget"]["prog_timeout_max_ms_per_marked_program"] =
        Describe(d.prog_timeout_max_ms_per_program);

    out["intra_program_concurrency"]["async_calls_per_async_program"] =
        Describe(d.async_calls_per_async_program);
    out["intra_program_concurrency"]["effective_async_calls_per_program"] =
        Describe(d.effective_async_calls_per_program);

    out["remote_coverage"]["remote_cover_calls_per_marked_program"] =
        Describe(d.remote_cover_calls_per_program);
    return out;
}

void PublishFile(const fs::path& partial, const fs::path& final)
{
    std::error_code ec;
    fs::rename(partial, final, ec);
    if (ec) {
        throw std::runtime_error("cannot publish " + final.string() + ": " + ec.message());
    }
}

void Usage(const char* argv0)
{
    std::fprintf(stderr,
                 "usage: %s <stream.bin> <workload-id> <output-dir>\n",
                 argv0);
}

} // namespace

int main(int argc, char** argv)
{
    if (argc != 4) {
        Usage(argv[0]);
        return 2;
    }

    const fs::path stream_path = argv[1];
    const std::string workload_id = argv[2];
    const fs::path output_dir = argv[3];
    if (!ValidId(workload_id)) {
        std::fprintf(stderr, "invalid workload id: %s\n", workload_id.c_str());
        return 2;
    }

    const fs::path records_path = output_dir / (workload_id + ".records.jsonl");
    const fs::path summary_path = output_dir / (workload_id + ".summary.json");
    const fs::path records_partial = records_path.string() + ".partial";
    const fs::path summary_partial = summary_path.string() + ".partial";

    try {
        fs::create_directories(output_dir);
        if (fs::exists(records_path) || fs::exists(summary_path)) {
            throw std::runtime_error("refusing to overwrite existing characterization output");
        }
        fs::remove(records_partial);
        fs::remove(summary_partial);

        const auto parsed = stream::ReadFile(stream_path.string());
        if (!parsed.has_value()) {
            throw std::runtime_error("request-stream validation failed: " + parsed.error());
        }

        std::ofstream records_out(records_partial, std::ios::binary);
        if (!records_out) {
            throw std::runtime_error("cannot open records sidecar");
        }

        const auto& target = syz::Target::linux_amd64();
        syz::TextDecoder decoder(target);
        Counts counts;
        Distributions dist;
        dist.exec_wire_bytes.reserve(parsed->records.size());
        dist.calls_per_program.reserve(parsed->records.size());
        dist.native_calls_per_program.reserve(parsed->records.size());

        for (const auto& record : parsed->records) {
            const auto decoded = decoder.decode(std::string_view(
                reinterpret_cast<const char*>(record.prog_text.data()),
                record.prog_text.size()));
            if (!decoded.has_value() || *decoded == nullptr) {
                throw std::runtime_error("typed decode failed at sequence " +
                                         std::to_string(record.sequence));
            }
            const syz::Prog& prog = **decoded;
            const auto wire = syz::serialize_for_exec(prog);
            if (!wire.has_value()) {
                throw std::runtime_error("exec-wire lowering failed at sequence " +
                                         std::to_string(record.sequence));
            }

            std::uint64_t native_calls = 0;
            std::uint64_t pseudo_calls = 0;
            std::uint64_t timeout_calls = 0;
            std::uint64_t timeout_sum_ms = 0;
            std::uint64_t timeout_max_ms = 0;
            std::uint64_t prog_timeout_calls = 0;
            std::uint64_t prog_timeout_max_ms = 0;
            std::uint64_t async_calls = 0;
            std::uint64_t remote_cover_calls = 0;

            for (const auto& call : prog.calls()) {
                if (call == nullptr || call->meta() == nullptr) {
                    throw std::runtime_error("missing syscall metadata at sequence " +
                                             std::to_string(record.sequence));
                }
                const auto* meta = call->meta();
                const auto& attrs = meta->attrs();
                if (meta->is_pseudo()) {
                    ++pseudo_calls;
                } else {
                    ++native_calls;
                }
                if (attrs.timeout != 0) {
                    ++timeout_calls;
                    timeout_sum_ms += attrs.timeout;
                    timeout_max_ms = std::max(timeout_max_ms, attrs.timeout);
                    dist.timeout_attr_ms.push_back(attrs.timeout);
                }
                if (attrs.prog_timeout != 0) {
                    ++prog_timeout_calls;
                    prog_timeout_max_ms =
                        std::max(prog_timeout_max_ms, attrs.prog_timeout);
                    dist.prog_timeout_attr_ms.push_back(attrs.prog_timeout);
                }
                if (call->props().async) ++async_calls;
                if (attrs.remote_cover) ++remote_cover_calls;
            }

            const bool threaded = (record.exec_flags & kFlatRpcThreaded) != 0;
            const bool threaded_async = threaded && async_calls != 0;
            const auto call_count = static_cast<std::uint64_t>(prog.calls().size());

            ++counts.programs;
            counts.calls += call_count;
            counts.native_calls += native_calls;
            counts.pseudo_calls += pseudo_calls;
            counts.timeout_calls += timeout_calls;
            counts.prog_timeout_calls += prog_timeout_calls;
            counts.async_calls += async_calls;
            counts.remote_cover_calls += remote_cover_calls;
            if (pseudo_calls != 0) ++counts.programs_with_pseudo;
            if (timeout_calls != 0) ++counts.programs_with_timeout;
            if (prog_timeout_calls != 0) ++counts.programs_with_prog_timeout;
            if (async_calls != 0) ++counts.programs_with_async;
            if (threaded) ++counts.threaded_programs;
            if (threaded_async) {
                ++counts.threaded_async_programs;
                counts.effective_async_calls += async_calls;
            }
            if (remote_cover_calls != 0) ++counts.programs_with_remote_cover;

            dist.exec_wire_bytes.push_back(wire->size());
            dist.calls_per_program.push_back(call_count);
            dist.native_calls_per_program.push_back(native_calls);
            if (pseudo_calls != 0) {
                dist.pseudo_calls_per_pseudo_program.push_back(pseudo_calls);
            }
            if (timeout_calls != 0) {
                dist.timeout_calls_per_timeout_program.push_back(timeout_calls);
                dist.timeout_sum_ms_per_timeout_program.push_back(timeout_sum_ms);
                dist.timeout_max_ms_per_timeout_program.push_back(timeout_max_ms);
            }
            if (prog_timeout_calls != 0) {
                dist.prog_timeout_calls_per_program.push_back(prog_timeout_calls);
                dist.prog_timeout_max_ms_per_program.push_back(prog_timeout_max_ms);
            }
            if (async_calls != 0) {
                dist.async_calls_per_async_program.push_back(async_calls);
            }
            if (threaded_async) {
                dist.effective_async_calls_per_program.push_back(async_calls);
            }
            if (remote_cover_calls != 0) {
                dist.remote_cover_calls_per_program.push_back(remote_cover_calls);
            }

            Json row;
            row["sequence"] = record.sequence;
            row["program_text_bytes"] = record.prog_text.size();
            row["exec_wire_bytes"] = wire->size();
            row["calls"] = call_count;
            row["native_calls"] = native_calls;
            row["pseudo_calls"] = pseudo_calls;
            row["timeout_calls"] = timeout_calls;
            row["timeout_sum_ms"] = timeout_sum_ms;
            row["timeout_max_ms"] = timeout_max_ms;
            row["prog_timeout_calls"] = prog_timeout_calls;
            row["prog_timeout_max_ms"] = prog_timeout_max_ms;
            row["async_calls"] = async_calls;
            row["threaded"] = threaded;
            row["threaded_async"] = threaded_async;
            row["remote_cover_calls"] = remote_cover_calls;
            records_out << row.dump() << '\n';
            if (!records_out) {
                throw std::runtime_error("failed writing records sidecar");
            }

            if (counts.programs % 10000 == 0) {
                std::fprintf(stderr, "%s: processed %llu/%zu records\n",
                             workload_id.c_str(),
                             static_cast<unsigned long long>(counts.programs),
                             parsed->records.size());
            }
        }

        records_out.close();
        if (!records_out) throw std::runtime_error("failed closing records sidecar");

        Json summary;
        summary["schema"] = "refuzz-workload-shape-v1";
        summary["workload"] = workload_id;
        summary["input"]["path"] = stream_path.string();
        summary["input"]["stream_bytes"] = fs::file_size(stream_path);
        summary["input"]["validated_records"] = parsed->records.size();
        summary["method"]["boundary"] =
            "typed request immediately before submission";
        summary["method"]["decoder"] =
            "request-stream v2 reader + syz::TextDecoder";
        summary["method"]["request_bytes"] =
            "syz::serialize_for_exec output bytes";
        summary["method"]["quantiles"] =
            "nearest-rank over the stated population";
        summary["method"]["timeout"] =
            "per-call schema attribute; values and per-program sum/max reported separately";
        summary["method"]["prog_timeout"] =
            "per-program maximum of nonzero call attributes";
        summary["method"]["effective_async"] =
            "async call in a request carrying flatrpc threaded mode";
        summary["method"]["remote_cover"] =
            "program contains at least one call whose syscall metadata has remote_cover";
        summary["counts"] = CountSummary(counts);
        summary["distributions"] = DistributionSummary(dist);

        std::ofstream summary_out(summary_partial, std::ios::binary);
        if (!summary_out) throw std::runtime_error("cannot open summary output");
        summary_out << summary.dump(2) << '\n';
        summary_out.close();
        if (!summary_out) throw std::runtime_error("failed closing summary output");

        PublishFile(records_partial, records_path);
        PublishFile(summary_partial, summary_path);
        std::printf("workload=%s records=%llu calls=%llu summary=%s records_sidecar=%s\n",
                    workload_id.c_str(),
                    static_cast<unsigned long long>(counts.programs),
                    static_cast<unsigned long long>(counts.calls),
                    summary_path.c_str(), records_path.c_str());
        return 0;
    } catch (const std::exception& error) {
        std::error_code ignored;
        fs::remove(records_partial, ignored);
        fs::remove(summary_partial, ignored);
        std::fprintf(stderr, "characterization failed: %s\n", error.what());
        return 1;
    }
}

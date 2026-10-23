// [v1 — DELETED in PR-K-0, see docs/plans/kcov-coverage-curve.md §4.1]
//
// Implementation removed in PR-K-0; see header for rationale (Rule A,
// matrix row #5). Source list line is commented in
// telemetry/CMakeLists.txt with the same v1 marker.
//
// ROLLBACK: change `#if 0` to `#if 1` and restore the CMake line.
#if 0

#include "refuzz/telemetry/coverage/coverage_tracker.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

namespace refuzz::telemetry {
namespace {

std::string JsonEscape(const std::string& value)
{
    std::string out;
    out.reserve(value.size() + 8);
    out.push_back('"');
    for (char c : value) {
        switch (c) {
        case '"':
            out += "\\\"";
            break;
        case '\\':
            out += "\\\\";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        default:
            out.push_back(c);
            break;
        }
    }
    out.push_back('"');
    return out;
}

} // namespace

CoverageTracker::CoverageTracker(CoverageTrackerConfig config)
    : config_(std::move(config))
{}

void CoverageTracker::OnCoverageHashes(const std::vector<uint64_t>& cov_hashes)
{
    if (cov_hashes.empty()) {
        return;
    }

    std::lock_guard<std::mutex> lock(mu_);
    if (inbox_.size() >= config_.max_inbox_batches) {
        ++dropped_batches_;
        return;
    }
    inbox_.push_back(cov_hashes);
}

void CoverageTracker::Drain()
{
    std::deque<std::vector<uint64_t>> pending;
    {
        std::lock_guard<std::mutex> lock(mu_);
        pending.swap(inbox_);
    }
    if (pending.empty()) {
        return;
    }

    std::lock_guard<std::mutex> lock(mu_);
    while (!pending.empty()) {
        for (uint64_t value : pending.front()) {
            coverage_hashes_.insert(value);
        }
        pending.pop_front();
    }
}

void CoverageTracker::Persist(const std::string& output_dir)
{
    Drain();

    std::filesystem::create_directories(output_dir);
    const std::filesystem::path base = output_dir;
    const std::filesystem::path bin_path = base / "coverage_hashes.bin";
    const std::filesystem::path txt_path = base / "coverage_hashes.txt";
    const std::filesystem::path json_path = base / "coverage_hashes.json";

    std::vector<uint64_t> snapshot;
    size_t dropped_batches = 0;
    {
        std::lock_guard<std::mutex> lock(mu_);
        snapshot.assign(coverage_hashes_.begin(), coverage_hashes_.end());
        dropped_batches = dropped_batches_;
    }

    std::ofstream bin_out(bin_path, std::ios::binary | std::ios::trunc);
    std::ofstream txt_out(txt_path, std::ios::trunc);
    if (!bin_out || !txt_out) {
        return;
    }

    for (uint64_t value : snapshot) {
        bin_out.write(reinterpret_cast<const char*>(&value), sizeof(value));
        std::ostringstream line;
        line << "0x" << std::hex << value;
        txt_out << line.str() << "\n";
    }

    const auto now = std::chrono::system_clock::now().time_since_epoch();
    const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();

    std::ofstream json_out(json_path, std::ios::trunc);
    if (!json_out) {
        return;
    }

    json_out << "{\n";
    json_out << "  \"total_hash_count\": " << snapshot.size() << ",\n";
    json_out << "  \"dropped_batches\": " << dropped_batches << ",\n";
    json_out << "  \"flush_unix_ms\": " << now_ms << ",\n";
    json_out << "  \"coverage_hashes_bin\": " << JsonEscape(bin_path.string()) << ",\n";
    json_out << "  \"coverage_hashes_txt\": " << JsonEscape(txt_path.string()) << "\n";
    json_out << "}\n";
}

size_t CoverageTracker::TotalHashCount() const
{
    std::lock_guard<std::mutex> lock(mu_);
    return coverage_hashes_.size();
}

size_t CoverageTracker::DroppedBatches() const
{
    std::lock_guard<std::mutex> lock(mu_);
    return dropped_batches_;
}

} // namespace refuzz::telemetry

#endif // [v1 — DELETED in PR-K-0]

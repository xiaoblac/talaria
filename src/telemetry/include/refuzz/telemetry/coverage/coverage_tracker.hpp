#pragma once

// [v1 — DELETED in PR-K-0, see docs/plans/kcov-coverage-curve.md §4.1]
//
// CoverageTracker was a duplicate aggregate truth-store sitting in the
// telemetry layer (matrix row #5). It mirrored feedback's
// HashFeedbackStore::seen_ via ICoverageSink::OnCoverageHashes and
// produced a parallel coverage_hashes.{bin,txt,json} persistence path
// that was format-incompatible with HashFeedbackStore::SaveToFile.
//
// Per Rule A (data ownership) the truth-store + persistence belong
// only to feedback/. PR-K-0 removes the duplicate. The orchestrator
// now writes both coverage_output_dir/coverage_hashes.bin and
// coverage_persist_path via HashFeedbackStore::SaveToFile at Stop.
//
// ROLLBACK: change `#if 0` to `#if 1`, restore the CMakeLists.txt
// source-list line, and re-thread coverage_sink/coverage_tracker per
// pre-PR-K-0 git history.
#if 0

#include "refuzz/core/coverage.hpp"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

namespace refuzz::telemetry {

struct CoverageTrackerConfig {
    size_t max_inbox_batches = 4096;
};

class CoverageTracker final : public core::ICoverageSink {
public:
    explicit CoverageTracker(CoverageTrackerConfig config = {});

    void OnCoverageHashes(const std::vector<uint64_t>& cov_hashes) override;
    void Drain();
    void Persist(const std::string& output_dir);
    void Flush(const std::string& output_dir) { Persist(output_dir); }

    size_t TotalHashCount() const;
    size_t DroppedBatches() const;

private:
    CoverageTrackerConfig config_;
    mutable std::mutex mu_;
    std::deque<std::vector<uint64_t>> inbox_;
    std::unordered_set<uint64_t> coverage_hashes_;
    size_t dropped_batches_ = 0;
};

} // namespace refuzz::telemetry

#endif // [v1 — DELETED in PR-K-0]

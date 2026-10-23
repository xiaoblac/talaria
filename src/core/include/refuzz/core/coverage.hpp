#pragma once

// [v1 — DELETED in PR-K-0, see docs/plans/kcov-coverage-curve.md §4.1]
//
// ICoverageSink was the polymorphic sink that KcovCoverageSignal used to
// fan coverage hashes into telemetry::CoverageTracker (a duplicate of
// feedback::HashFeedbackStore::seen_). Per Rule A, telemetry never owns
// coverage hash sets — HashFeedbackStore is the sole authority. With
// CoverageTracker gone (§4.1), this interface has no implementer and
// no caller; the sink/coverage_tracker plumbing on the feedback +
// assembler + orchestrator side is stripped per §4.2.
//
// ROLLBACK: change `#if 0` to `#if 1` and re-add the strip points listed
// under PR-K-0 §4.2.
#if 0

#include <cstdint>
#include <vector>

namespace refuzz::core {

class ICoverageSink {
public:
    virtual ~ICoverageSink() = default;
    virtual void OnCoverageHashes(const std::vector<uint64_t>& cov_hashes) = 0;
};

} // namespace refuzz::core

#endif // [v1 — DELETED in PR-K-0]

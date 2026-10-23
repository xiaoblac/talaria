// Copyright 2026 reFuzz project author -------youngkk.
//
// Coverage series substrate (PR-K-A) — see header for design.

#include "refuzz/telemetry/observation/coverage_series.hpp"

#include <algorithm>

namespace refuzz::telemetry {

CoverageSeriesBuffer::CoverageSeriesBuffer(size_t capacity)
    : capacity_(capacity == 0 ? kDefaultCapacity : capacity)
{}

void CoverageSeriesBuffer::Push(CoverageSamplePoint point)
{
    if (points_.size() >= capacity_) {
        points_.pop_front();
        ++dropped_total_;
    }
    points_.push_back(point);
}

const CoverageSamplePoint* CoverageSeriesBuffer::Latest() const
{
    if (points_.empty()) {
        return nullptr;
    }
    return &points_.back();
}

std::vector<CoverageSamplePoint>
CoverageSeriesBuffer::Snapshot(size_t max_n) const
{
    if (points_.empty() || max_n == 0) {
        return {};
    }
    const size_t take  = std::min(max_n, points_.size());
    const size_t begin = points_.size() - take;
    std::vector<CoverageSamplePoint> out;
    out.reserve(take);
    for (size_t i = begin; i < points_.size(); ++i) {
        out.push_back(points_[i]);
    }
    return out;
}

} // namespace refuzz::telemetry

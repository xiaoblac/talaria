// Copyright 2026 reFuzz project author -------youngkk.

#pragma once

#include <cstdint>
#include <span>
#include <vector>

namespace refuzz::fuzzer {

struct CoverageNormalizationConfig;

bool CoverageEntriesPassSignalFilter(
    std::span<const uint64_t> entries,
    const CoverageNormalizationConfig& config);

std::vector<uint64_t> NormalizeCoverageEntries(std::vector<uint64_t> entries,
                                               const CoverageNormalizationConfig& config);

// [P2 edge-signal admission] Derive per-call EDGE signal from a PC slice in
// EXECUTION ORDER (before any sort — order carries the transition info).
// sig = pc ^ (hash(prev_pc & 0xfff) & 0xfff), prev reset to 0 at the start of the call.
// Mirrors syzkaller executor.cc write_signal (use_cover_edges). Feeds the
// admission feedback_store only; raw PCs are kept separately for triage/corpus_pc.
// Caller passes ONE call's ordered slice at a time.
std::vector<uint64_t> ComputeEdgeSignal(const std::vector<uint64_t>& ordered_pcs);

} // namespace refuzz::fuzzer

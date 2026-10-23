// Structural transformations for the syz_v2 IR.
//
// These helpers own IR-level invariants such as ResultArg back/forward
// edge cleanup. Policy decisions about when to remove calls still live
// in mutator or crash/repro code.

#pragma once

#include "refuzz/program/syz/prog.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace refuzz::program::syz {

// Remove a contiguous range of calls. Returns false when the range is
// empty, out of bounds, or would remove every call from the program.
//
// Any surviving ResultArg whose res() pointed into the removed call
// subtree is reset to the resource type's default value before the
// removed calls are destroyed.
bool RemoveCallRange(Prog& prog, std::size_t start, std::size_t count);

// Remove a single call, preserving the same invariants as
// RemoveCallRange.
bool RemoveCall(Prog& prog, std::size_t index);

// Return the transitive closure of calls related to anchor_index by
// typed ResultArg edges. The walk follows both producer back-edges
// (consumer.res()) and forward consumer edges (producer.uses()).
std::vector<bool> RelatedCalls(Prog& prog, std::size_t anchor_index);

struct RelatedCallAnalysis {
    std::vector<bool> keep;
    std::uint64_t owner_entries = 0;
    std::uint64_t result_args = 0;
    std::uint64_t filename_atoms = 0;
    std::uint64_t producer_edge_checks = 0;
    std::uint64_t producer_edge_adds = 0;
    std::uint64_t consumer_edge_checks = 0;
    std::uint64_t consumer_edge_adds = 0;
    std::uint64_t filename_edge_checks = 0;
    std::uint64_t filename_edge_adds = 0;
};

// Same closure as RelatedCalls, plus edge counters for diagnostics.
// The keep vector is authoritative; callers must not recompute a parallel
// closure for logging because that can drift from minimize behavior.
RelatedCallAnalysis AnalyzeRelatedCalls(Prog& prog, std::size_t anchor_index);

} // namespace refuzz::program::syz

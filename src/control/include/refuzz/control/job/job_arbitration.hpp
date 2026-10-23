#pragma once
// Tier-aware job arbitration at the FuzzerLoop pull point.
//
// This mirrors syzkaller's:
//   Order(triageCandidate, candidate, triage, Alternate(smash, 3), genFuzz)
//
// The task queue has the same ordering after requests are submitted, but routed
// job requests never enter that queue.  FuzzerLoop must therefore apply the same
// ordering while choosing which suspended job to pull from.

#include "refuzz/queue/task_tier.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace refuzz::control::job {

struct PendingJobView {
    // nullopt means the job is not currently suspended on a pending request.
    std::optional<::refuzz::queue::TaskTier> pending_tier;
};

struct JobArbitrationState {
    std::array<std::size_t, ::refuzz::queue::kTaskTierCount> tier_round_robin_cursor{};
    std::uint64_t smash_explore_alternate_seq = 0;
};

inline std::optional<std::size_t> FindReadyJobInTier(
    std::span<const PendingJobView> jobs,
    JobArbitrationState& state,
    ::refuzz::queue::TaskTier tier)
{
    if (jobs.empty()) {
        return std::nullopt;
    }
    std::size_t& cursor =
        state.tier_round_robin_cursor[static_cast<std::size_t>(tier)];
    const std::size_t n = jobs.size();
    for (std::size_t k = 0; k < n; ++k) {
        const std::size_t idx = (cursor + k) % n;
        if (jobs[idx].pending_tier == tier) {
            cursor = (idx + 1) % n;
            return idx;
        }
    }
    return std::nullopt;
}

inline std::optional<std::size_t> SelectNextReadyJobIndex(
    std::span<const PendingJobView> jobs,
    JobArbitrationState& state)
{
    using ::refuzz::queue::TaskTier;
    for (TaskTier t : {TaskTier::CandidateTriage, TaskTier::Candidate, TaskTier::Triage}) {
        if (auto idx = FindReadyJobInTier(jobs, state, t); idx.has_value()) {
            return idx;
        }
    }

    // Alternate(smash, 3): two pulls prefer Smash, every third pull lets Explore
    // run first. If Explore is not ready on the skip round, fall back to Smash;
    // unlike syzkaller's genFuzz callback, reFuzz's Explore source is a real job
    // and may temporarily have no pending request.
    const bool alternate_skip_smash = (++state.smash_explore_alternate_seq % 3 == 0);
    if (!alternate_skip_smash) {
        if (auto idx = FindReadyJobInTier(jobs, state, TaskTier::Smash); idx.has_value()) {
            return idx;
        }
        return FindReadyJobInTier(jobs, state, TaskTier::Explore);
    }
    if (auto idx = FindReadyJobInTier(jobs, state, TaskTier::Explore); idx.has_value()) {
        return idx;
    }
    return FindReadyJobInTier(jobs, state, TaskTier::Smash);
}

} // namespace refuzz::control::job

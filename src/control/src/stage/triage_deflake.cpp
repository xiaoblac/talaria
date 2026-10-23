// triage_deflake.cpp — pure deflake analysis, extracted verbatim from
// triage_stage.cpp (job-loop redesign Step 3, Slice A). Behavior-preserving:
// the logic is byte-for-byte the pre-extraction triage functions; only the
// enclosing namespace and the observation type names changed (nested
// TriageJobState::RunObservation → deflake::RunObservation). See the header for
// why this now lives in its own translation unit.

#include "refuzz/control/stage/triage_deflake.hpp"

#include "refuzz/control/stage/stable_cover.hpp"  // shared ComputeFullStableCover / ComputeUnstableRatio

#include <algorithm>
#include <cstdint>
#include <iterator>
#include <optional>
#include <unordered_map>
#include <utility>
#include <vector>

namespace refuzz::control::deflake {

namespace {

void SortUnique(std::vector<std::uint64_t>& values)
{
    std::sort(values.begin(), values.end());
    values.erase(std::unique(values.begin(), values.end()), values.end());
}

std::vector<std::uint64_t> IntersectSorted(std::vector<std::uint64_t> lhs,
                                           std::vector<std::uint64_t> rhs)
{
    SortUnique(lhs);
    SortUnique(rhs);
    std::vector<std::uint64_t> out;
    std::set_intersection(lhs.begin(), lhs.end(),
                          rhs.begin(), rhs.end(),
                          std::back_inserter(out));
    return out;
}

bool HasAnyEdgeSignal(const std::vector<RunObservation>& runs)
{
    for (const auto& run : runs) {
        if (run.extra_signal_hashes_are_edges &&
            !run.extra_signal_hashes.empty()) {
            return true;
        }
        for (const auto& call : run.per_call) {
            if (!call.edge_hashes.empty()) {
                return true;
            }
        }
    }
    return false;
}

const std::vector<std::uint64_t>& CallSignalHashes(
    const CallObservation& call,
    bool use_edge_hashes)
{
    return use_edge_hashes ? call.edge_hashes : call.coverage_hashes;
}

using PrioritySignal = std::unordered_map<std::uint64_t, std::uint8_t>;

struct StableSignal {
    std::vector<std::uint64_t> hashes;
    std::vector<std::uint8_t> prios;
};

void MergePrioritySignal(PrioritySignal& dst, const PrioritySignal& src)
{
    for (const auto& [hash, priority] : src) {
        auto it = dst.find(hash);
        if (it == dst.end() || priority > it->second) {
            dst[hash] = priority;
        }
    }
}

PrioritySignal IntersectPrioritySignal(const PrioritySignal& lhs,
                                       const PrioritySignal& rhs)
{
    PrioritySignal out;
    for (const auto& [hash, priority] : lhs) {
        const auto it = rhs.find(hash);
        if (it != rhs.end() && it->second >= priority) {
            out.emplace(hash, priority);
        }
    }
    return out;
}

PrioritySignal MakePrioritySignal(const std::vector<std::uint64_t>& hashes,
                                  std::uint8_t priority)
{
    PrioritySignal out;
    out.reserve(hashes.size());
    for (const std::uint64_t hash : hashes) {
        out[hash] = priority;
    }
    return out;
}

PrioritySignal MakePrioritySignal(const std::vector<std::uint64_t>& hashes,
                                  const std::vector<std::uint8_t>& prios)
{
    PrioritySignal out;
    out.reserve(hashes.size());
    for (std::size_t i = 0; i < hashes.size(); ++i) {
        const std::uint8_t priority = i < prios.size() ? prios[i] : 0;
        auto it = out.find(hashes[i]);
        if (it == out.end() || priority > it->second) {
            out[hashes[i]] = priority;
        }
    }
    return out;
}

PrioritySignal MakeChasedSignal(const ChasedCall& chased)
{
    PrioritySignal out;
    out.reserve(chased.new_signal_hashes.size());
    for (std::size_t i = 0; i < chased.new_signal_hashes.size(); ++i) {
        const std::uint8_t priority =
            i < chased.new_signal_prios.size() ? chased.new_signal_prios[i] : 0;
        auto it = out.find(chased.new_signal_hashes[i]);
        if (it == out.end() || priority > it->second) {
            out[chased.new_signal_hashes[i]] = priority;
        }
    }
    return out;
}

StableSignal SerializePrioritySignal(const PrioritySignal& signal)
{
    StableSignal out;
    out.hashes.reserve(signal.size());
    for (const auto& [hash, priority] : signal) {
        (void)priority;
        out.hashes.push_back(hash);
    }
    std::sort(out.hashes.begin(), out.hashes.end());
    out.prios.reserve(out.hashes.size());
    for (const std::uint64_t hash : out.hashes) {
        out.prios.push_back(signal.at(hash));
    }
    return out;
}

std::vector<PrioritySignal> ComputeSignalLevelsForCall(
    const std::vector<RunObservation>& runs,
    std::size_t call_index,
    std::size_t first_run_index,
    std::size_t level_count,
    bool use_edge_hashes)
{
    std::vector<PrioritySignal> levels(level_count);
    if (level_count == 0) {
        return levels;
    }
    for (std::size_t run_index = first_run_index;
         run_index < runs.size(); ++run_index) {
        const auto& run = runs[run_index];
        if (call_index >= run.per_call.size()) {
            continue;
        }
        const auto& call = run.per_call[call_index];
        const PrioritySignal sample = MakePrioritySignal(
            CallSignalHashes(call, use_edge_hashes), call.signal_priority);
        for (std::size_t level = level_count - 1; level > 0; --level) {
            const PrioritySignal intersection =
                IntersectPrioritySignal(levels[level - 1], sample);
            MergePrioritySignal(levels[level], intersection);
        }
        MergePrioritySignal(levels[0], sample);
    }
    return levels;
}

StableSignal ComputeStableSignalForCall(
    const std::vector<RunObservation>& runs,
    std::size_t call_index,
    std::size_t first_run_index,
    std::size_t vote_k,
    bool use_edge_hashes)
{
    const auto levels = ComputeSignalLevelsForCall(
        runs, call_index, first_run_index, vote_k, use_edge_hashes);
    if (levels.empty()) {
        return {};
    }
    return SerializePrioritySignal(levels.back());
}

std::vector<std::uint64_t> ComputeCallCoverUnion(
    const std::vector<RunObservation>& runs,
    std::size_t call_index,
    std::size_t first_run_index = 0)
{
    std::vector<std::uint64_t> cover;
    for (std::size_t run_index = first_run_index;
         run_index < runs.size(); ++run_index) {
        const auto& run = runs[run_index];
        if (!run.contributes_cover || call_index >= run.per_call.size()) {
            continue;
        }
        cover.insert(cover.end(),
                     run.per_call[call_index].coverage_hashes.begin(),
                     run.per_call[call_index].coverage_hashes.end());
    }
    SortUnique(cover);
    return cover;
}

// [Extra/-1 — syz Info.Extra as job.calls[-1]] program-level remote/async
// coverage (khubd/softirq/kthread PCs), not attributable to any syscall.
// Mirrors ComputeStableSignalForCall but votes over RunObservation.extra_*
// directly instead of indexing per_call[call_index].
std::vector<PrioritySignal> ComputeSignalLevelsForExtra(
    const std::vector<RunObservation>& runs,
    std::size_t first_run_index,
    std::size_t level_count)
{
    std::vector<PrioritySignal> levels(level_count);
    if (level_count == 0) {
        return levels;
    }
    for (std::size_t run_index = first_run_index;
         run_index < runs.size(); ++run_index) {
        const PrioritySignal sample =
            MakePrioritySignal(runs[run_index].extra_signal_hashes, 0);
        for (std::size_t level = level_count - 1; level > 0; --level) {
            const PrioritySignal intersection =
                IntersectPrioritySignal(levels[level - 1], sample);
            MergePrioritySignal(levels[level], intersection);
        }
        MergePrioritySignal(levels[0], sample);
    }
    return levels;
}

StableSignal ComputeStableSignalForExtra(
    const std::vector<RunObservation>& runs,
    std::size_t first_run_index,
    std::size_t vote_k)
{
    const auto levels = ComputeSignalLevelsForExtra(
        runs, first_run_index, vote_k);
    if (levels.empty()) {
        return {};
    }
    return SerializePrioritySignal(levels.back());
}

std::vector<std::uint64_t> ComputeExtraCoverUnion(
    const std::vector<RunObservation>& runs,
    std::size_t first_run_index = 0)
{
    std::vector<std::uint64_t> cover;
    for (std::size_t run_index = first_run_index;
         run_index < runs.size(); ++run_index) {
        const auto& run = runs[run_index];
        if (!run.contributes_cover) {
            continue;
        }
        cover.insert(cover.end(), run.extra_cover.begin(), run.extra_cover.end());
    }
    SortUnique(cover);
    return cover;
}

// Adapt per_run_observations → runs[r][c] = call c's raw coverage hashes — the
// shape both the shared ComputeFullStableCover and ComputeUnstableRatio consume
// (also used by corpus_verify so boot + fuzz seeds share one cover basis).
std::vector<std::vector<std::vector<std::uint64_t>>> ToRunCallCover(
    const std::vector<RunObservation>& runs)
{
    std::vector<std::vector<std::vector<std::uint64_t>>> rc;
    rc.reserve(runs.size());
    for (const auto& run : runs) {
        if (!run.contributes_cover) {
            continue;
        }
        std::vector<std::vector<std::uint64_t>> calls;
        calls.reserve(run.per_call.size());
        for (const auto& c : run.per_call) {
            calls.push_back(c.coverage_hashes);
        }
        rc.push_back(std::move(calls));
    }
    return rc;
}

void UnionSortedInto(std::vector<std::uint64_t>& dst,
                     const std::vector<std::uint64_t>& src)
{
    if (src.empty()) {
        return;
    }
    dst.insert(dst.end(), src.begin(), src.end());
    SortUnique(dst);
}

}  // namespace

std::optional<SelectedStableCall> SelectStableCall(
    const std::vector<RunObservation>& runs,
    const std::vector<std::uint64_t>& program_stable)
{
    if (runs.empty() || program_stable.empty()) {
        return std::nullopt;
    }

    std::size_t min_calls = runs.front().per_call.size();
    for (const auto& run : runs) {
        min_calls = std::min(min_calls, run.per_call.size());
    }
    if (min_calls == 0) {
        return std::nullopt;
    }

    // k-of-n voting (syz deflake semantics), NOT strict cross-run intersection —
    // see ComputeFullStableCover. k = min(MinStableVotes, N).
    const std::size_t vote_k = std::min(
        refuzz::control::kStableCoverMinVotes, runs.size());

    const bool use_edge_hashes = HasAnyEdgeSignal(runs);
    std::optional<SelectedStableCall> best;
    for (std::size_t call_index = 0; call_index < min_calls; ++call_index) {
        const std::uint32_t syscall_id = runs.front().per_call[call_index].syscall_id;

        bool shape_consistent = true;
        for (std::size_t run_index = 1; run_index < runs.size(); ++run_index) {
            if (runs[run_index].per_call[call_index].syscall_id != syscall_id) {
                shape_consistent = false;
                break;
            }
        }
        if (!shape_consistent) {
            continue;
        }

        // Signal units covered by this call in >= vote_k of the deflake runs,
        // preserving syzkaller's per-element priority intersection.
        auto stable_signal = ComputeStableSignalForCall(
            runs, call_index, /*first_run_index=*/0, vote_k, use_edge_hashes);
        if (stable_signal.hashes.empty()) {
            continue;
        }

        auto stable = IntersectSorted(stable_signal.hashes, program_stable);
        if (stable.empty()) {
            continue;
        }

        if (!best.has_value() || stable.size() > best->hashes.size()) {
            best = SelectedStableCall{
                .call_index  = static_cast<int>(call_index),
                .hashes      = std::move(stable),
                .errno_value = runs.front().per_call[call_index].errno_value,
                .syscall_id  = syscall_id,
                .hashes_are_edges = use_edge_hashes,
            };
        }
    }
    return best;
}

std::vector<refuzz::fuzzer::TriagePerCallCandidateMetadata::Candidate>
ComputeNewStableCallCandidates(
    const std::vector<RunObservation>& runs,
    const std::vector<std::uint64_t>& program_stable,
    const std::vector<ChasedCall>&    chased_calls,
    int min_votes)
{
    using Candidate = refuzz::fuzzer::TriagePerCallCandidateMetadata::Candidate;
    std::vector<Candidate> out;
    if (runs.empty() || program_stable.empty() || chased_calls.empty()) {
        return out;
    }

    const bool use_edge_hashes = HasAnyEdgeSignal(runs);
    const std::size_t vote_k = min_votes > 0
        ? static_cast<std::size_t>(min_votes) : runs.size();

    for (const auto& chased : chased_calls) {
        // syz handleCall runs once per job.calls entry, INCLUDING call=-1
        //   (Info.Extra: fuzzer.go seeds job.calls[-1] from res.Info.Extra, and
        //   prog.Minimize(p, -1, ...) is a legal path — prog.CallName(-1) =
        //   ExtraCallName). Empty accumulated newSignal ⇒ this call/Extra
        //   first-owned nothing → skip (= syz `if info.newStableSignal.Empty()
        //   { return }`, pre-intersection).
        if (chased.new_signal_hashes.empty()) {
            continue;
        }
        if (chased.call_index < 0) {
            // [Extra/-1] mirrors the per-call branch below but sourced from
            //   RunObservation.extra_*; no syscall_id/errno_value (not a call).
            if (chased.signal_hashes_are_edges != use_edge_hashes) {
                continue;
            }
            auto stable_signal = ComputeStableSignalForExtra(
                runs, chased.first_run_index, vote_k);
            if (stable_signal.hashes.empty()) {
                continue;
            }
            const auto chased_signal = MakeChasedSignal(chased);
            const auto new_stable_signal = IntersectPrioritySignal(
                chased_signal,
                MakePrioritySignal(stable_signal.hashes, stable_signal.prios));
            if (new_stable_signal.empty()) {
                continue;
            }
            const auto new_stable = SerializePrioritySignal(new_stable_signal);
            Candidate c;
            c.call_index = -1;
            c.stable_signal_hashes = std::move(stable_signal.hashes);
            c.new_stable_signal_hashes = std::move(new_stable.hashes);
            c.new_stable_signal_prios = std::move(new_stable.prios);
            c.cover_hashes = ComputeExtraCoverUnion(runs, chased.first_run_index);
            c.signal_cover_prios = std::move(stable_signal.prios);
            c.errno_value = std::nullopt;
            c.syscall_id = std::nullopt;
            c.signal_hashes_are_edges = use_edge_hashes;
            out.push_back(std::move(c));
            continue;
        }
        const std::size_t call_index = static_cast<std::size_t>(chased.call_index);
        if (chased.first_run_index >= runs.size()) {
            continue;
        }
        std::uint32_t syscall_id = 0;
        bool shape_consistent = true;
        for (std::size_t run_index = chased.first_run_index;
             run_index < runs.size(); ++run_index) {
            if (call_index >= runs[run_index].per_call.size()) {
                shape_consistent = false;
                break;
            }
            if (run_index == chased.first_run_index) {
                syscall_id = runs[run_index].per_call[call_index].syscall_id;
            } else if (runs[run_index].per_call[call_index].syscall_id != syscall_id) {
                shape_consistent = false;
                break;
            }
        }
        if (!shape_consistent ||
            (chased.syscall_id.has_value() && *chased.syscall_id != syscall_id)) {
            continue;
        }

        auto stable_signal = ComputeStableSignalForCall(
            runs, call_index, chased.first_run_index, vote_k, use_edge_hashes);
        if (chased.signal_hashes_are_edges != use_edge_hashes) {
            continue;
        }
        // [domain-fix] no program_stable cross-check here — program_stable is
        //   always raw-PC (NormalizeCoverageEntries never edge-transforms it),
        //   while `stable` is edge-domain whenever use_edge_hashes is true.
        //   Intersecting the two silently zeroed every candidate in cover_edges
        //   mode regardless of how stable the per-call signal actually was. syz
        //   has no program-level cross-check at all (job.go: info.newStableSignal
        //   = info.newSignal.Intersection(info.stableSignal), purely per-call) —
        //   match that exactly.
        if (stable_signal.hashes.empty()) {
            continue;
        }

        // syz newStableSignal = newSignal ∩ stableSignal — PER CALL, against THIS
        //   call's accumulated newSignal (chased), NOT a program-level novel union.
        const auto chased_signal = MakeChasedSignal(chased);
        const auto new_stable_signal = IntersectPrioritySignal(
            chased_signal,
            MakePrioritySignal(stable_signal.hashes, stable_signal.prios));
        if (new_stable_signal.empty()) {
            continue;
        }
        const auto new_stable = SerializePrioritySignal(new_stable_signal);

        Candidate c;
        c.call_index = static_cast<int>(call_index);
        c.stable_signal_hashes = std::move(stable_signal.hashes);
        c.new_stable_signal_hashes = std::move(new_stable.hashes);
        c.new_stable_signal_prios = std::move(new_stable.prios);
        c.cover_hashes = ComputeCallCoverUnion(
            runs, call_index, chased.first_run_index);
        c.signal_cover_prios = std::move(stable_signal.prios);
        c.errno_value = runs[chased.first_run_index].per_call[call_index].errno_value;
        c.syscall_id = syscall_id;
        c.signal_hashes_are_edges = use_edge_hashes;
        out.push_back(std::move(c));
    }
    return out;
}

bool ShouldStopFuzzDeflake(
    const std::vector<RunObservation>& runs,
    const std::vector<ChasedCall>&     chased_calls,
    int                                min_votes,
    int                                max_runs)
{
    if (runs.empty()) {
        return false;
    }
    if (max_runs > 0 && static_cast<int>(runs.size()) >= max_runs) {
        return true;
    }
    if (chased_calls.empty()) {
        return true;
    }

    const bool use_edge_hashes = HasAnyEdgeSignal(runs);
    const std::size_t vote_k = min_votes > 0
        ? static_cast<std::size_t>(min_votes) : runs.size();
    if (vote_k == 0) {
        return false;
    }

    const int configured_max = max_runs > 0 ? max_runs : static_cast<int>(runs.size());
    const int left = std::max(0, configured_max - static_cast<int>(runs.size()));
    bool have_signal = true;
    bool no_chance = true;
    bool saw_valid_chased_call = false;

    for (const auto& chased : chased_calls) {
        if (chased.new_signal_hashes.empty()) {
            continue;
        }
        if (chased.call_index < 0) {
            // [Extra/-1] same k-of-n chase-vs-stable check as a per-call entry,
            //   but sourced from RunObservation.extra_signal_hashes.
            saw_valid_chased_call = true;
            if (chased.signal_hashes_are_edges != use_edge_hashes) {
                have_signal = false;
                continue;
            }
            auto stable = ComputeStableSignalForExtra(
                runs, chased.first_run_index, vote_k);
            const auto new_stable = IntersectPrioritySignal(
                MakeChasedSignal(chased),
                MakePrioritySignal(stable.hashes, stable.prios));
            if (new_stable.empty()) {
                have_signal = false;
                if (left >= static_cast<int>(vote_k)) {
                    no_chance = false;
                } else {
                    const std::size_t chance_votes =
                        vote_k > static_cast<std::size_t>(left)
                            ? vote_k - static_cast<std::size_t>(left)
                            : 1;
                    auto chance_stable = ComputeStableSignalForExtra(
                        runs, chased.first_run_index, chance_votes);
                    auto possible = IntersectPrioritySignal(
                        MakeChasedSignal(chased),
                        MakePrioritySignal(chance_stable.hashes,
                                            chance_stable.prios));
                    if (!possible.empty()) {
                        no_chance = false;
                    }
                }
            }
            continue;
        }
        saw_valid_chased_call = true;
        const std::size_t call_index = static_cast<std::size_t>(chased.call_index);
        if (chased.first_run_index >= runs.size()) {
            have_signal = false;
            continue;
        }
        const std::size_t first_run_index = chased.first_run_index;
        std::uint32_t syscall_id = 0;
        bool shape_consistent = true;
        for (std::size_t run_index = first_run_index;
             run_index < runs.size(); ++run_index) {
            if (call_index >= runs[run_index].per_call.size()) {
                shape_consistent = false;
                break;
            }
            if (run_index == first_run_index) {
                syscall_id = runs[run_index].per_call[call_index].syscall_id;
            } else if (runs[run_index].per_call[call_index].syscall_id != syscall_id) {
                shape_consistent = false;
                break;
            }
        }
        if (!shape_consistent ||
            (chased.syscall_id.has_value() && *chased.syscall_id != syscall_id) ||
            chased.signal_hashes_are_edges != use_edge_hashes) {
            have_signal = false;
            continue;
        }

        auto stable = ComputeStableSignalForCall(
            runs, call_index, first_run_index, vote_k, use_edge_hashes);
        const auto new_stable = IntersectPrioritySignal(
            MakeChasedSignal(chased),
            MakePrioritySignal(stable.hashes, stable.prios));
        if (new_stable.empty()) {
            have_signal = false;
            if (left >= static_cast<int>(vote_k)) {
                no_chance = false;
            } else {
                const std::size_t chance_votes =
                    vote_k > static_cast<std::size_t>(left)
                        ? vote_k - static_cast<std::size_t>(left)
                        : 1;
                auto chance_stable = ComputeStableSignalForCall(
                    runs, call_index, first_run_index, chance_votes,
                    use_edge_hashes);
                auto possible = IntersectPrioritySignal(
                    MakeChasedSignal(chased),
                    MakePrioritySignal(chance_stable.hashes,
                                        chance_stable.prios));
                if (!possible.empty()) {
                    no_chance = false;
                }
            }
        }
    }

    if (!saw_valid_chased_call) {
        return true;
    }
    return have_signal || no_chance;
}

bool ShouldStopCorpusDeflake(
    const std::vector<RunObservation>& runs,
    const std::vector<ChasedCall>&     chased_calls,
    int                                min_votes,
    int                                min_runs,
    int                                max_runs,
    int                                total_runs,
    bool                               no_new_signal)
{
    if (runs.empty()) {
        return false;
    }
    if (total_runs > 0 && static_cast<int>(runs.size()) >= total_runs) {
        return true;
    }
    if (!no_new_signal || static_cast<int>(runs.size()) < min_runs) {
        return false;
    }
    if (max_runs > 0 && static_cast<int>(runs.size()) >= max_runs) {
        return true;
    }

    const bool have_signal = [&]() {
        if (chased_calls.empty()) {
            return true;
        }
        const bool use_edge_hashes = HasAnyEdgeSignal(runs);
        for (const auto& chased : chased_calls) {
            if (chased.new_signal_hashes.empty() ||
                chased.signal_hashes_are_edges != use_edge_hashes) {
                return false;
            }
            if (chased.call_index < 0) {
                const auto stable = ComputeStableSignalForExtra(
                    runs, chased.first_run_index,
                    min_votes > 0 ? static_cast<std::size_t>(min_votes)
                                  : runs.size());
                if (IntersectPrioritySignal(
                        MakeChasedSignal(chased),
                        MakePrioritySignal(stable.hashes, stable.prios)).empty()) {
                    return false;
                }
                continue;
            }
            const std::size_t call_index =
                static_cast<std::size_t>(chased.call_index);
            if (chased.first_run_index >= runs.size() ||
                call_index >= runs[chased.first_run_index].per_call.size()) {
                return false;
            }
            const std::uint32_t syscall_id =
                runs[chased.first_run_index].per_call[call_index].syscall_id;
            if (chased.syscall_id.has_value() &&
                *chased.syscall_id != syscall_id) {
                return false;
            }
            for (std::size_t run_index = chased.first_run_index;
                 run_index < runs.size(); ++run_index) {
                if (call_index >= runs[run_index].per_call.size() ||
                    runs[run_index].per_call[call_index].syscall_id != syscall_id) {
                    return false;
                }
            }
            const auto stable = ComputeStableSignalForCall(
                runs, call_index, chased.first_run_index,
                min_votes > 0 ? static_cast<std::size_t>(min_votes)
                              : runs.size(),
                use_edge_hashes);
            if (IntersectPrioritySignal(
                    MakeChasedSignal(chased),
                    MakePrioritySignal(stable.hashes, stable.prios)).empty()) {
                return false;
            }
        }
        return true;
    }();

    return static_cast<int>(runs.size()) >= min_runs && have_signal;
}

// [Task A] Full corpus coverage of the triaged program: the union of raw
// per-call PCs across contributing deflake replays. Built from RAW per-call
// coverage_hashes (pre-saturation), so it
// is the reFuzz analog of syzkaller's inp.Cover — NOT the saturation-filtered
// / guilty-narrowed signal in TriageStableSignalMetadata.hashes. Used as the
// corpus-cover carrier used when minimize has no final-exec snapshot.
std::vector<std::uint64_t> ComputeFullStableCover(
    const std::vector<RunObservation>& runs)
{
    // [3-of-5 syz parity] COVER = full union across deflake runs (k=1), matching
    // syzkaller's info.cover.Merge(res.Cover) on EVERY run (pkg/fuzzer/job.go:286):
    // a PC hit in ANY run counts. The SIGNAL (admission) is k-of-n (3-of-5), but the
    // COVER is the union — keeping timing-flaky-but-real PCs (async USB probe /
    // softirq RX / RCU). The old default k=2 still dropped 1-run PCs; syz uses k=1.
    auto cover = refuzz::control::ComputeFullStableCover(
        ToRunCallCover(runs), /*min_votes=*/1);
    for (const auto& run : runs) {
        if (!run.contributes_cover) {
            continue;
        }
        UnionSortedInto(cover, run.extra_cover);
    }
    return cover;
}

// [seed-value signal B] cross-run coverage variance (race-proximity, docs/plans/
// seed-value-signals.md §2.2) — the side ComputeFullStableCover discards.
refuzz::control::UnstableCoverStats ComputeUnstableStats(
    const std::vector<RunObservation>& runs)
{
    return refuzz::control::ComputeUnstableRatio(ToRunCallCover(runs));
}

std::optional<refuzz::proto::ResultCode> SelectStableExecStatus(
    const std::vector<RunObservation>& runs)
{
    // 只在**产出了结果**的 run 之间求 exec_status 共识。per_call 为空 = 这次没解码出
    // 任何 call 结果(kNoResult 的形状:worker 健在,但这一发零产出),对齐 syzkaller
    // deflake 的 `if result.Info == nil { continue }` —— 无 Info 的 run 不参与、也不否决
    // 共识。
    //
    // 此前它被当成一个普通(kExecError)run 拉进"全体一致"判定:一次瞬时空产出就让
    // 整批 kOk run 被判为"exec_status 不一致" → 返回 nullopt → 上层 stable=false →
    // **已经稳定的 per-call 候选被误当 flaky 丢弃**。这正是 List3 的粒度错配:停止判据
    // (ShouldStopFuzzDeflake)是 per-call 的,而这里的准入却要求整程序每一发都同状态。
    //
    // 真正**有结果的两发**若状态不同(如 kOk vs kCrashed),仍视为 flaky → nullopt。
    std::optional<refuzz::proto::ResultCode> status;
    for (const auto& run : runs) {
        if (run.per_call.empty()) {
            continue;   // no-result run(= syz Info==nil):不投票、不否决
        }
        if (!status.has_value()) {
            status = run.exec_status;
        } else if (*status != run.exec_status) {
            return std::nullopt;   // 两个有结果的 run 真不一致 → flaky
        }
    }
    return status;   // 全是 no-result run → nullopt(没有可稳定的结果)
}

StableSeedDecision DecideAndStampStableSeed(
    refuzz::fuzzer::Seed&               seed,
    const std::vector<RunObservation>& runs,
    const std::vector<std::uint64_t>&  intersection,
    refuzz::proto::ResultCode          stable_exec_status,
    int                                min_votes,
    bool                               seed_value_shadow_enabled,
    const std::vector<ChasedCall>&     chased_calls)
{
    StableSeedDecision decision;

    auto stamp_stability = [&](refuzz::fuzzer::Seed& dst) {
        // [seed-value signal B] stamp cross-run coverage variance. An admitted
        // (stable) seed can still have flaky edges (k-of-n let it in); that
        // flakiness is the race-proximity signal.
        if (seed_value_shadow_enabled) {
            const auto us = ComputeUnstableStats(runs);
            refuzz::fuzzer::SeedStabilityMetadata sb;
            sb.unstable_pc_count = us.unstable_pc_count;
            sb.union_pc_count    = us.union_pc_count;
            sb.observed_runs     = static_cast<std::uint8_t>(
                std::min<std::size_t>(runs.size(), 255));
            dst.metadata.Set(sb);
        }
    };

    // [per-call — syz job.calls] Candidates come only from chased_calls
    // (discovery + every deflake re-exec's per-call novelty). Empty chased
    // calls are not a normal alternate path: they mean the attribution chain did
    // not produce syz's job.calls equivalent. Return a typed drop so the runtime
    // caller can log it with executor/seed context.
    if (chased_calls.empty()) {
        decision.drop_reason = StableSeedDropReason::kNoChasedCalls;
        return decision;
    }

    auto candidates = ComputeNewStableCallCandidates(
        runs, intersection, chased_calls, min_votes);
    if (candidates.empty()) {
        decision.drop_reason = StableSeedDropReason::kNoPerCallCandidate;
        return decision;
    }

    refuzz::fuzzer::TriagePerCallCandidateMetadata pcm;
    pcm.candidates  = candidates;              // copy: also returned to caller
    pcm.exec_status = stable_exec_status;
    decision.admitted_units = pcm.candidates.size();
    seed.metadata.Set(std::move(pcm));
    stamp_stability(seed);
    decision.per_call_candidates = std::move(candidates);
    decision.admit = true;

    return decision;
}

}  // namespace refuzz::control::deflake

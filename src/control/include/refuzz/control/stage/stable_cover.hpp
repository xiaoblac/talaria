// Copyright 2026 reFuzz project author -------youngkk.
//
// [Task A] Shared "full stable coverage" computation, used by BOTH the
// triage stage (fuzz-discovered seeds) and the corpus_verify stage
// (boot-corpus seeds, syzkaller-style load-time re-triage). Keeping a
// single implementation guarantees both seed lineages contribute corpus
// coverage on the SAME basis (raw per-call KCOV, deflaked across runs) —
// otherwise corpus_pc would mix two different cover definitions.
//
// Header-only (no new translation unit / CMake change).
#pragma once

#include <algorithm>
#include <cstdint>
#include <iterator>
#include <unordered_map>
#include <utility>
#include <vector>

namespace refuzz::control {

// Sorted-unique set intersection of two hash vectors (inputs need not be
// pre-sorted).
inline std::vector<std::uint64_t> SortedIntersect(std::vector<std::uint64_t> a,
                                                  std::vector<std::uint64_t> b)
{
    std::sort(a.begin(), a.end());
    a.erase(std::unique(a.begin(), a.end()), a.end());
    std::sort(b.begin(), b.end());
    b.erase(std::unique(b.begin(), b.end()), b.end());
    std::vector<std::uint64_t> out;
    std::set_intersection(a.begin(), a.end(), b.begin(), b.end(),
                          std::back_inserter(out));
    return out;
}

// Minimum per-PC vote count for a PC to count as stable across deflake runs.
// syzkaller's deflake is k-of-n voting (pkg/fuzzer deflakeNeedRuns / reFuzz
// retry_policy MinStableVotes = 2), NOT strict cross-run intersection. Strict
// intersection (k = N) drops coverage that is REAL but timing-flaky — the async
// USB driver-probe (drivers/hid / sound/usb / net/usb), softirq RX, RCU/deferred
// work — which appears in some runs but not all, so reFuzz's corpus missed it
// while syz (2-of-N) kept it. k=2 restores syz parity.
inline constexpr std::size_t kStableCoverMinVotes = 2;

// Full stable cover of a program executed across several deflake runs.
// `runs[r][c]` = the KCOV PC hashes of call c in run r. For each call we keep
// the PCs that appear in at least `min_votes` runs (capped at the run count =
// k-of-n voting), then union across calls. reFuzz analog of syzkaller's
// per-corpus-entry cover (inp.Cover) feeding syz_corpus_cover.
inline std::vector<std::uint64_t> ComputeFullStableCover(
    const std::vector<std::vector<std::vector<std::uint64_t>>>& runs,
    std::size_t min_votes = kStableCoverMinVotes)
{
    if (runs.empty()) {
        return {};
    }
    std::size_t min_calls = runs.front().size();
    for (const auto& r : runs) {
        min_calls = std::min(min_calls, r.size());
    }
    // k = min(min_votes, N): with a single run everything it covers is "stable".
    const std::size_t k =
        std::min(min_votes == 0 ? std::size_t{1} : min_votes, runs.size());
    std::vector<std::uint64_t> cover;  // sorted-unique accumulator
    for (std::size_t ci = 0; ci < min_calls; ++ci) {
        // Count, per PC, how many runs covered it in this call (each run votes
        // a PC at most once).
        std::unordered_map<std::uint64_t, std::uint32_t> votes;
        for (std::size_t ri = 0; ri < runs.size(); ++ri) {
            std::vector<std::uint64_t> seen = runs[ri][ci];
            std::sort(seen.begin(), seen.end());
            seen.erase(std::unique(seen.begin(), seen.end()), seen.end());
            for (const std::uint64_t pc : seen) {
                ++votes[pc];
            }
        }
        std::vector<std::uint64_t> stable;
        stable.reserve(votes.size());
        for (const auto& [pc, cnt] : votes) {
            if (cnt >= k) {
                stable.push_back(pc);
            }
        }
        if (stable.empty()) {
            continue;
        }
        std::sort(stable.begin(), stable.end());
        std::vector<std::uint64_t> merged;
        merged.reserve(cover.size() + stable.size());
        std::set_union(cover.begin(), cover.end(), stable.begin(), stable.end(),
                       std::back_inserter(merged));
        cover = std::move(merged);
    }
    return cover;
}

// [seed-value signal B] 跨执行覆盖方差(race-proximity 信号,宪法
// docs/plans/seed-value-signals.md §2.2)。吃与 ComputeFullStableCover 同一份
// runs[r][c] 数据,但取的是它丢掉的那一面 —— 「不稳定」覆盖。ComputeFullStableCover
// 做 per-call k-of-n voting 保留稳定 PC 用于准入 / 语料;这里只问一个 program-level
// 的可复现性问题:把每个 run 跨所有 call union 成一个 PC 足迹,看哪些 PC 出现在
// 「某些但非全部」run 里(= 时序敏感)。返回 unstable 计数与 union 计数(分母)。
//   * 每个 run 对一条 PC 至多投一票(跨 call union 后)。
//   * 单 run(N<2)无方差可言,返回零。
struct UnstableCoverStats {
    std::uint32_t unstable_pc_count = 0;  // 出现在 some-but-not-all run 的 PC 数
    std::uint32_t union_pc_count    = 0;  // 至少出现一次的 distinct PC 数
};

inline UnstableCoverStats ComputeUnstableRatio(
    const std::vector<std::vector<std::vector<std::uint64_t>>>& runs)
{
    const std::size_t n = runs.size();
    if (n < 2) {
        return {};  // 单 run / 空:无跨执行方差
    }
    // PC -> 命中它的 distinct run 数(每 run 跨所有 call union 后投一票)。
    std::unordered_map<std::uint64_t, std::uint32_t> votes;
    for (const auto& run : runs) {
        std::vector<std::uint64_t> seen;
        for (const auto& call : run) {
            seen.insert(seen.end(), call.begin(), call.end());
        }
        std::sort(seen.begin(), seen.end());
        seen.erase(std::unique(seen.begin(), seen.end()), seen.end());
        for (const std::uint64_t pc : seen) {
            ++votes[pc];
        }
    }
    UnstableCoverStats stats;
    stats.union_pc_count = static_cast<std::uint32_t>(votes.size());
    for (const auto& [pc, cnt] : votes) {
        if (cnt < n) {  // 出现在某些但非全部 run → 不稳定
            ++stats.unstable_pc_count;
        }
    }
    return stats;
}

// [remote-kcov] Union the program-level EXTRA / remote cover (syzkaller
// Info.Extra: USB khubd enumeration + driver-bind, softirq RX, RCU/kthread)
// into a seed's corpus cover. Unlike the per-call synchronous cover, EXTRA is
// NOT k-of-n voted across deflake runs — syz folds it in with info.cover.Merge
// (a plain union; see pkg/fuzzer/job.go deflakeCall(-1, Extra)). It is one-time
// / cold-connect coverage (the first USB device of its kind triggers module
// probe + hid_parse; warm re-runs don't), so it shows up in some deflake runs
// only; a union keeps it, voting would drop it. Mutates `cover` in place,
// keeping it sorted-unique.
inline void MergeExtraCoverInto(
    std::vector<std::uint64_t>&                        cover,
    const std::vector<std::vector<std::uint64_t>>&     per_run_extra)
{
    std::vector<std::uint64_t> extra_union;
    for (const auto& run_extra : per_run_extra) {
        extra_union.insert(extra_union.end(), run_extra.begin(), run_extra.end());
    }
    if (extra_union.empty()) {
        return;
    }
    std::sort(extra_union.begin(), extra_union.end());
    extra_union.erase(std::unique(extra_union.begin(), extra_union.end()),
                      extra_union.end());
    std::vector<std::uint64_t> merged;
    merged.reserve(cover.size() + extra_union.size());
    std::set_union(cover.begin(), cover.end(), extra_union.begin(),
                   extra_union.end(), std::back_inserter(merged));
    cover = std::move(merged);
}

}  // namespace refuzz::control

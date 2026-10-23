// hints_limiter.hpp — Epic 5 PR-5-C
//
// Mirror of `prog/hints.go::HintsLimiter`. Tracks per-PC replacement
// attempts globally across all hints mutations and prunes records once
// a PC has been tried > N (= 10 upstream) times. Without this, hints
// jobs grow unboundedly because the same kernel comparison fires for
// every program that touches that code path.
//
// Lifetime: a single static-storage instance (one per fuzzer process).
// Thread-safe via internal mutex (hints stage may run concurrently with
// other admit/mutate paths in future revs; current rev calls Limit
// from a single thread, but the lock is cheap and matches upstream).

#pragma once

#include "refuzz/mutator/linux/syz_v2/hints/comp_map.hpp"

#include <cstdint>
#include <mutex>
#include <unordered_map>

namespace refuzz::mutator::syz_v2::hints {

class HintsLimiter {
public:
    // Per-PC attempt cap. Mirror of upstream `const N = 10`. Process-
    // global (not per-program / per-corpus) — once a PC has produced
    // N hint candidates ever, future replays drop further records
    // pointing at it. Resets only on process restart, matching upstream
    // Fuzzer lifetime semantics.
    static constexpr int kPerPcCap = 10;

    HintsLimiter() = default;

    // Mirror of (HintsLimiter).Limit(comps): increment per-PC counters
    // for every (pc, op1, op2) triple in `comps`; drop triples whose
    // PC has accumulated > kPerPcCap attempts. Empty op2 maps drop op1;
    // empty pc sets drop op2 — symmetric with CompMap::InplaceIntersect.
    void Limit(CompMap& comps);

    // Test-only — diagnostic accessor. Production code should not need it.
    int AttemptsForTest(uint64_t pc) const;
    void ResetForTest();

private:
    mutable std::mutex          mu_;
    std::unordered_map<uint64_t, int> attempts_;  // PC → cumulative attempts
};

} // namespace refuzz::mutator::syz_v2::hints

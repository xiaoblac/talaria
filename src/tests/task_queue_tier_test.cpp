// task_queue_tier_test.cpp
//
// [job-loop Step 5] Unit proof for InMemoryTaskQueue's 5-tier strict Order + Alternate
// Pop, mirroring syzkaller's source (pkg/fuzzer/fuzzer.go:106):
//   Order(triageCandidate①, candidate②, triage③, Alternate(smash④, 3), genFuzz⑤)
//
// Cases:
//   1. SingleTierFifo    — Triage-only (the default tier) is strict FIFO — the
//                          flag-off byte-identical guarantee (every un-tagged Push
//                          defaults to Triage → single tier → FIFO).
//   2. StrictOrder       — higher tier is drained fully before lower (①>②>③).
//   3. SmashExploreAlt   — with both ④ and ⑤ present, the deterministic 2-Smash /
//                          1-Explore interleave (= syz Alternate(_,3)), then FIFO drain.
//   4. StrictBeatsAlt    — any ①②③ present is served before ④/⑤ (Alternate only kicks
//                          in once the strict tiers are empty).
//   5. SmashOnly_NoIdle  — ⑤ empty ⇒ ④ served every pull (no Alternate skip → no idle).
//   6. PendingAndClose   — PendingSize=total across tiers; drain-after-close in Order;
//                          Push after Close fails.

#include "refuzz/queue/task_queue.hpp"

#include <chrono>
#include <cstdint>
#include <cstdio>

namespace {

using refuzz::queue::HostFuzzTask;
using refuzz::queue::InMemoryTaskQueue;
using refuzz::queue::TaskTier;

constexpr std::chrono::milliseconds kNoWait{0};

HostFuzzTask Task(std::uint64_t id)
{
    HostFuzzTask t;
    t.executor_id = id;   // nonzero required by Push; used as the order marker
    return t;
}

std::uint64_t PopId(InMemoryTaskQueue& q)
{
    auto t = q.Pop(kNoWait);
    return t.has_value() ? t->executor_id : 0;
}

int TestSingleTierFifo()
{
    InMemoryTaskQueue q;
    for (std::uint64_t i = 1; i <= 5; ++i) {
        if (!q.Push(Task(i))) return 1;   // default tier = Triage
    }
    for (std::uint64_t i = 1; i <= 5; ++i) {
        if (PopId(q) != i) return 1;      // strict FIFO within a single tier
    }
    if (PopId(q) != 0) return 1;
    return 0;
}

int TestStrictOrder()
{
    InMemoryTaskQueue q;
    // Push low→high tier out of order; Pop must serve highest tier fully first.
    if (!q.Push(Task(301), TaskTier::Triage))          return 1;
    if (!q.Push(Task(302), TaskTier::Triage))          return 1;
    if (!q.Push(Task(201), TaskTier::Candidate))       return 1;
    if (!q.Push(Task(1),   TaskTier::CandidateTriage)) return 1;
    const std::uint64_t expected[4] = {1, 201, 301, 302};   // ① then ② then ③(FIFO)
    for (int i = 0; i < 4; ++i) {
        if (PopId(q) != expected[i]) return 1;
    }
    return 0;
}

int TestSmashExploreAlternate()
{
    InMemoryTaskQueue q;
    for (std::uint64_t i = 101; i <= 106; ++i) if (!q.Push(Task(i), TaskTier::Explore)) return 1;
    for (std::uint64_t i = 1;   i <= 6;   ++i) if (!q.Push(Task(i), TaskTier::Smash))   return 1;
    // Alternate counter advances only when BOTH tiers present; every 3rd → Explore.
    // Once Smash empties, Explore drains FIFO. (Trace in task_queue.cpp Pop.)
    const std::uint64_t expected[12] =
        {1, 2, 101, 3, 4, 102, 5, 6, 103, 104, 105, 106};
    for (int i = 0; i < 12; ++i) {
        if (PopId(q) != expected[i]) return 1;
    }
    if (PopId(q) != 0) return 1;
    return 0;
}

int TestStrictBeatsAlternate()
{
    InMemoryTaskQueue q;
    if (!q.Push(Task(1),   TaskTier::Smash))   return 1;
    if (!q.Push(Task(101), TaskTier::Explore)) return 1;
    if (!q.Push(Task(201), TaskTier::Triage))  return 1;
    if (PopId(q) != 201) return 1;   // ③ Triage strictly first (Alternate not consulted)
    // Now ③ empty → Smash/Explore Alternate: counter=1 → Smash.
    if (PopId(q) != 1)   return 1;
    if (PopId(q) != 101) return 1;
    return 0;
}

int TestSmashOnlyNoIdle()
{
    InMemoryTaskQueue q;
    for (std::uint64_t i = 1; i <= 3; ++i) if (!q.Push(Task(i), TaskTier::Smash)) return 1;
    // Explore empty ⇒ no Alternate skip; every pull serves Smash (no idle/nullopt).
    for (std::uint64_t i = 1; i <= 3; ++i) if (PopId(q) != i) return 1;
    if (PopId(q) != 0) return 1;
    return 0;
}

int TestPendingAndClose()
{
    InMemoryTaskQueue q;
    if (!q.Push(Task(1),   TaskTier::CandidateTriage)) return 1;
    if (!q.Push(Task(2),   TaskTier::Smash))           return 1;
    if (!q.Push(Task(101), TaskTier::Explore))         return 1;
    if (q.PendingSize() != 3) return 1;                // total across tiers
    q.Close();
    if (q.Push(Task(9))) return 1;                     // closed -> Push fails
    if (PopId(q) != 1)   return 1;                     // drain in Order: ① first
    if (PopId(q) != 2)   return 1;                     // then ④ Smash
    if (PopId(q) != 101) return 1;                     // then ⑤ Explore
    if (PopId(q) != 0)   return 1;                     // empty + closed -> nullopt
    return 0;
}

} // namespace

int main()
{
    struct Case { const char* name; int (*fn)(); };
    const Case cases[] = {
        {"SingleTierFifo", TestSingleTierFifo},
        {"StrictOrder", TestStrictOrder},
        {"SmashExploreAlternate", TestSmashExploreAlternate},
        {"StrictBeatsAlternate", TestStrictBeatsAlternate},
        {"SmashOnlyNoIdle", TestSmashOnlyNoIdle},
        {"PendingAndClose", TestPendingAndClose},
    };
    for (const auto& c : cases) {
        if (c.fn() != 0) {
            std::fprintf(stderr, "FAILED: %s\n", c.name);
            return 1;
        }
        std::printf("PASS: %s\n", c.name);
    }
    return 0;
}

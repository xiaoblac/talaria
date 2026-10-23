#pragma once

// recent_program_ring.hpp — Layer-2 crash history (async-deferred trigger capture)
//
// Per-worker-slot, count-bounded ring of recently COMPLETED programs. The
// Channel's Layer-1 crash evidence is the in-flight `pending_` snapshot — perfect
// for synchronous crashes (the guilty syscall is still in-flight when KASAN fires)
// but structurally blind to async/deferred-trigger bugs (USB async firmware, RCU
// callbacks, timers, workqueue-deferred frees): by the time the deferred kernel
// work explodes, the triggering program has long completed and left `pending_`.
//
// This ring is Layer-2: it retains the last N completed programs per worker slot
// so a crash harvest can reconstruct the recent execution sequence. Mirrors
// syzkaller pkg/rpcserver `LastExecuting` (count-bounded per proc, timestamps used
// only for ordering, hanged programs kept beyond the ring). See
// docs/plans/crash-execution-history-ring.md.
//
// Threading: owned by Channel::loop_thread_ (single-threaded writer/reader, same
// discipline as `pending_`). No internal locking.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <unordered_set>
#include <utility>
#include <vector>

namespace refuzz::channel {

struct RecentProgramRecord {
    uint64_t             executor_id    = 0;
    uint64_t             seed_id        = 0;
    uint64_t             origin_seed_id = 0;
    uint64_t             submit_ts_us   = 0;  // ordering key at harvest
    std::vector<uint8_t> payload;             // exec-wire payload (== rec.payload)
};

class RecentProgramRing {
public:
    RecentProgramRing() = default;

    // depth == 0 disables the ring (Note/NoteHanged become no-ops; Collect empty),
    // giving a zero-overhead fallback that preserves Layer-1-only behavior.
    RecentProgramRing(uint32_t worker_count, std::size_t depth)
        : depth_(depth), per_worker_(worker_count) {}

    bool enabled() const { return depth_ > 0 && !per_worker_.empty(); }

    // Continuous accumulation: record a completed program on its worker slot.
    // Oldest entry is evicted once the slot ring exceeds `depth_`.
    void Note(uint32_t worker_slot, RecentProgramRecord rec) {
        if (!enabled() || worker_slot >= per_worker_.size()) return;
        auto& q = per_worker_[worker_slot];
        q.push_back(std::move(rec));
        while (q.size() > depth_) q.pop_front();
    }

    // A task-hang program (daemon-level hang: error 11/14/15, no result was
    // obtained): a likely culprit, retained beyond the ring so a later async
    // crash can still see it (mirrors syzkaller LastExecuting.Hanged).
    // Program-watchdog timeouts (ERR_TIMEOUT) are data-bearing completions and
    // must go through Note() to the evictable per-worker ring instead.
    void NoteHanged(RecentProgramRecord rec) {
        if (!enabled()) return;
        hanged_.push_back(std::move(rec));
    }

    // Harvest: every retained program, time-sorted ascending by submit_ts_us,
    // excluding executor_ids already present in `exclude` (the in-flight Layer-1
    // snapshot) so the two layers don't double-count. Only called on a confirmed
    // fault — copies are acceptable on this cold path.
    std::vector<RecentProgramRecord> Collect(
        const std::unordered_set<uint64_t>& exclude) const {
        std::vector<RecentProgramRecord> out;
        for (const auto& q : per_worker_) {
            for (const auto& r : q) {
                if (exclude.find(r.executor_id) == exclude.end()) out.push_back(r);
            }
        }
        for (const auto& r : hanged_) {
            if (exclude.find(r.executor_id) == exclude.end()) out.push_back(r);
        }
        std::stable_sort(out.begin(), out.end(),
            [](const RecentProgramRecord& a, const RecentProgramRecord& b) {
                return a.submit_ts_us < b.submit_ts_us;
            });
        return out;
    }

    // Drop all retained programs (VM reboot / session reset — old programs belong
    // to a dead kernel generation and must not be attributed to a future crash).
    void Reset() {
        for (auto& q : per_worker_) q.clear();
        hanged_.clear();
    }

private:
    std::size_t                                  depth_ = 0;
    std::vector<std::deque<RecentProgramRecord>> per_worker_;  // [slot] -> ring
    std::vector<RecentProgramRecord>             hanged_;
};

} // namespace refuzz::channel

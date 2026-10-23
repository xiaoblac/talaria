// kernel_coverage_saturation_filter_test.cpp
//
// [v2 batch 3 G5] KernelCoverageSaturationFilter 单测。
//
// Cases(G5 plan §3.G5 验收):
//   1. EmptyObservationReturnsNullopt:obs.per_call empty / 没 KCO → nullopt
//   2. SingleSyscallUnderThresholdReturnsNullopt:incoming hash count
//      累计 < threshold → nullopt(no drop)
//   3. SingleSyscallOverThresholdDrops:超 threshold 后 incoming call drop;
//      返 non-empty optional + filtered = sort+unique accepted union
//   4. DifferentSyscallsIsolated:syscall A 饱和不影响 syscall B
//   5. AllCallsDropReturnsEmptyOptional:所有 call 均饱和 → 返 empty optional
//      (caller 走 c.fired=false 路径)
//   6. UnionSortedUnique:filtered union 在多 call 含 dup 时 sort + dedup

#include "refuzz/feedback/observation/kernel_observation.hpp"
#include "refuzz/feedback/saturation/kernel_coverage_saturation_filter.hpp"

#include <algorithm>
#include <cassert>
#include <cstdio>
#include <vector>

namespace {

using refuzz::fuzzer::ExecutionObservation;
using refuzz::fuzzer::KernelCallObservation;
using refuzz::fuzzer::KernelCoverageSaturationFilter;
using refuzz::fuzzer::KernelExecutionObservation;

ExecutionObservation MakeObs(std::vector<KernelCallObservation> calls)
{
    ExecutionObservation obs;
    KernelExecutionObservation kco;
    kco.per_call = std::move(calls);
    obs.Set(std::move(kco));
    return obs;
}

}  // namespace

int main()
{
    std::fprintf(stdout, "Running kernel_coverage_saturation_filter_test...\n");

    // ── Case 1: empty observation → nullopt(safe fallback)─────────────────
    {
        KernelCoverageSaturationFilter f(/*threshold=*/100);
        ExecutionObservation obs;  // 没 KCO
        std::vector<std::uint64_t> ph = {0xAA, 0xBB};
        auto r = f.Filter(obs, ph);
        assert(!r.has_value());

        ExecutionObservation obs2 = MakeObs({});  // KCO empty per_call
        auto r2 = f.Filter(obs2, ph);
        assert(!r2.has_value());
    }

    // ── Case 2: under threshold → nullopt(no drop) ─────────────────────────
    {
        KernelCoverageSaturationFilter f(/*threshold=*/100);
        // 单 syscall=1,5 hashes < 100 → no drop
        auto obs = MakeObs({{
            /*coverage_hashes=*/{0x1, 0x2, 0x3, 0x4, 0x5},
            /*errno=*/0,
            /*syscall_id=*/1,
        }});
        std::vector<std::uint64_t> ph = {0x1, 0x2, 0x3, 0x4, 0x5};
        auto r = f.Filter(obs, ph);
        assert(!r.has_value());
        assert(f.CountForSyscall(1) == 5);
    }

    // ── Case 3: over threshold → drop + filtered union ─────────────────────
    {
        KernelCoverageSaturationFilter f(/*threshold=*/3);
        // tick 1:syscall=1,3 hashes;count=3 等于 threshold(>=)→ accept-then-count
        // 语义:**先** accept(count 检查在 increment 前),所以 tick 1 整体 accept
        // (count 0 < 3),accept 后 count=3。
        {
            auto obs = MakeObs({{
                {0xA, 0xB, 0xC},
                /*errno=*/0,
                /*syscall_id=*/1,
            }});
            std::vector<std::uint64_t> ph = {0xA, 0xB, 0xC};
            auto r = f.Filter(obs, ph);
            assert(!r.has_value());  // 0 < 3 → accept,no drop
            assert(f.CountForSyscall(1) == 3);
        }
        // tick 2:syscall=1,2 hashes;count 3 >= threshold 3 → drop;
        // 同时 tick 含一个 syscall=2 的 call(count 0 < 3 → accept)
        {
            auto obs = MakeObs({
                {{0xD, 0xE},               /*errno=*/0, /*syscall_id=*/1},  // drop
                {{0x10, 0x11},             /*errno=*/0, /*syscall_id=*/2},  // accept
            });
            std::vector<std::uint64_t> ph = {0xD, 0xE, 0x10, 0x11};
            auto r = f.Filter(obs, ph);
            assert(r.has_value());
            assert(!r->hashes.empty());
            assert((r->keep_calls == std::vector<bool>{false, true}));
            // accepted = syscall 2 的 slice {0x10, 0x11};sort + unique
            assert(r->hashes.size() == 2);
            assert(r->hashes[0] == 0x10);
            assert(r->hashes[1] == 0x11);
            // syscall 1 count 不增(drop 路径不 count)
            assert(f.CountForSyscall(1) == 3);
            assert(f.CountForSyscall(2) == 2);
        }
    }

    // ── Case 4: different syscalls isolated ────────────────────────────────
    {
        KernelCoverageSaturationFilter f(/*threshold=*/5);
        // syscall=1 灌 6 hashes 一次 → tick 内自身 count 0 < 5 → accept(然后
        // count=6 超阈值,**下一**次 incoming syscall=1 才 drop)。
        {
            auto obs = MakeObs({{
                {0x1, 0x2, 0x3, 0x4, 0x5, 0x6},
                /*errno=*/0,
                /*syscall_id=*/1,
            }});
            std::vector<std::uint64_t> ph = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6};
            auto r = f.Filter(obs, ph);
            assert(!r.has_value());
            assert(f.CountForSyscall(1) == 6);
        }
        // syscall=2 应不受影响,首次 accept(count 0 < 5)
        {
            auto obs = MakeObs({{
                {0xAA},
                /*errno=*/0,
                /*syscall_id=*/2,
            }});
            std::vector<std::uint64_t> ph = {0xAA};
            auto r = f.Filter(obs, ph);
            assert(!r.has_value());  // syscall 2 隔离不饱和
            assert(f.CountForSyscall(2) == 1);
        }
        // syscall=1 再来一次 → drop(count 6 >= 5)
        {
            auto obs = MakeObs({{
                {0x100},
                /*errno=*/0,
                /*syscall_id=*/1,
            }});
            std::vector<std::uint64_t> ph = {0x100};
            auto r = f.Filter(obs, ph);
            assert(r.has_value());
            assert((r->keep_calls == std::vector<bool>{false}));
            assert(r->hashes.empty());  // 全 drop
        }
    }

    // ── Case 5: all calls drop → empty optional ────────────────────────────
    {
        KernelCoverageSaturationFilter f(/*threshold=*/2);
        // 先饱和 syscall 1 + 2
        {
            auto obs = MakeObs({
                {{0x1, 0x2}, 0, 1},
                {{0xA, 0xB}, 0, 2},
            });
            std::vector<std::uint64_t> ph = {0x1, 0x2, 0xA, 0xB};
            auto r = f.Filter(obs, ph);
            assert(!r.has_value());
            assert(f.CountForSyscall(1) == 2);
            assert(f.CountForSyscall(2) == 2);
        }
        // 再来 → 全饱和 → empty optional
        {
            auto obs = MakeObs({
                {{0x100}, 0, 1},
                {{0x200}, 0, 2},
            });
            std::vector<std::uint64_t> ph = {0x100, 0x200};
            auto r = f.Filter(obs, ph);
            assert(r.has_value());
            assert((r->keep_calls == std::vector<bool>{false, false}));
            assert(r->hashes.empty());  // 全 drop → caller fired=false
        }
    }

    // ── Case 6: union sorted + unique on dup hashes across calls ───────────
    {
        KernelCoverageSaturationFilter f(/*threshold=*/2);
        // 先饱和 syscall 1
        {
            auto obs = MakeObs({{{0x1, 0x2}, 0, 1}});
            std::vector<std::uint64_t> ph = {0x1, 0x2};
            (void)f.Filter(obs, ph);
        }
        // tick:syscall 1 drop,syscall 2 + syscall 3 accept,且 hash 有重叠
        {
            auto obs = MakeObs({
                {{0x99}, 0, 1},                  // drop
                {{0xCC, 0xAA, 0xBB}, 0, 2},      // accept(unsorted)
                {{0xBB, 0xDD}, 0, 3},            // accept,跟 syscall 2 共享 0xBB
            });
            std::vector<std::uint64_t> ph = {0xAA, 0xBB, 0xCC, 0xDD, 0x99};
            auto r = f.Filter(obs, ph);
            assert(r.has_value());
            assert((r->keep_calls == std::vector<bool>{false, true, true}));
            // sort + unique:{0xAA, 0xBB, 0xCC, 0xDD}
            assert(r->hashes.size() == 4);
            assert(r->hashes[0] == 0xAA);
            assert(r->hashes[1] == 0xBB);
            assert(r->hashes[2] == 0xCC);
            assert(r->hashes[3] == 0xDD);
            assert(std::is_sorted(r->hashes.begin(), r->hashes.end()));
        }
    }

    return 0;
}

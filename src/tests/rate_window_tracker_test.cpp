// rate_window_tracker_test.cpp
//
// [v2 G5 follow-up] RateWindowTracker 单测 — LibAFL `afl_exec_sec` 等价。
//
// Cases:
//   1. EmptyTrackerReturnsZero:无 sample → SmoothedRate / RawWindowedRate / LastValue 全 0
//   2. SingleSampleReturnsZero:1 sample dt=0 → rate=0(防 div0)
//   3. RawWindowedRateAcrossWindow:在窗口内 push N 个 sample,raw = (last-first)/dt 严格
//   4. EwmaSmoothingApproachesSteady:稳定 N tick rate=R,smoothed 趋近 R(EWMA 收敛)
//   5. WindowPrunesOldSamples:超 5s 老 sample 被 prune,raw 只看 window 内
//   6. NonMonotonicCounterFreezesSmoothed:counter 倒退(reset 等)→ invalid → smoothed 沿用
//   7. **ValidZeroStallSmoothesToZero**(P1 fix):counter 不变(fuzz stall)→
//      raw=0 valid → EWMA 收敛到 0(不再 freeze 在最后正值)

#include "refuzz/telemetry/observation/rate_window_tracker.hpp"

#include <cassert>
#include <cmath>
#include <cstdio>

namespace {

constexpr std::uint64_t kUsPerSec = 1'000'000ull;

// 浮点比较 helper(基于绝对+相对 epsilon)
bool ApproxEqual(double a, double b, double abs_eps = 1e-6, double rel_eps = 1e-3)
{
    if (std::abs(a - b) < abs_eps) return true;
    const double scale = std::max(std::abs(a), std::abs(b));
    return std::abs(a - b) < scale * rel_eps;
}

}  // namespace

int main()
{
    using refuzz::telemetry::RateWindowTracker;

    std::fprintf(stdout, "Running rate_window_tracker_test...\n");

    // ── Case 1: empty tracker → 全 0 ──────────────────────────────────────
    {
        RateWindowTracker t;
        assert(t.SmoothedRate() == 0.0);
        assert(t.RawWindowedRate() == 0.0);
        assert(t.LastValue() == 0);
    }

    // ── Case 2: single sample → dt=0 → rate=0(防 div0)─────────────────
    {
        RateWindowTracker t;
        t.Observe(1'000'000, 100);
        assert(t.SmoothedRate() == 0.0);   // 1 sample,raw=0,smoothed_inited=false → 0
        assert(t.RawWindowedRate() == 0.0);
        assert(t.LastValue() == 100);
    }

    // ── Case 3: raw windowed rate 严格 = (last-first)/dt ───────────────────
    // 在 1s 内 push 100 → 1100,raw = 1000/1s = 1000 ev/s。
    {
        RateWindowTracker t(/*window_secs=*/5.0, /*alpha=*/0.5);
        t.Observe(0,           100);
        t.Observe(kUsPerSec,   1100);  // 1s later, +1000 events
        assert(ApproxEqual(t.RawWindowedRate(), 1000.0));
    }

    // ── Case 4: EWMA 趋近稳态 ─────────────────────────────────────────────
    // 每秒固定 +500 events,跑 20 tick,smoothed 应收敛到 500。
    // 用大 alpha=0.5 加速收敛。
    {
        RateWindowTracker t(/*window_secs=*/5.0, /*alpha=*/0.5);
        std::uint64_t value = 0;
        for (int i = 0; i < 20; ++i) {
            value += 500;
            t.Observe(static_cast<std::uint64_t>(i + 1) * kUsPerSec, value);
        }
        // EWMA bootstrap 后 20 tick,误差应 < 5%(稳态值 500)。
        assert(ApproxEqual(t.SmoothedRate(), 500.0, /*abs=*/0.0, /*rel=*/0.05));
    }

    // ── Case 5: window prunes old samples ─────────────────────────────────
    // 5s window;先 push @0s, @1s, @10s 三个 sample;
    // observe @10s 后 prune 让 @0s/@1s 都被 drop(都 < cutoff=5s)。
    // 但 prune 至少保留 1 个 sample → 留 @10s。然后 dt=0 → raw=0。
    {
        RateWindowTracker t(/*window_secs=*/5.0);
        t.Observe(0,             100);
        t.Observe(1 * kUsPerSec, 200);
        t.Observe(10 * kUsPerSec, 1100);
        // @10s observe 后,@0/@1 都 < (10 - 5)*1e6 = 5*1e6 → 被 prune
        // tracker 保留至少 1 个 → 只剩 @10s
        // raw 需要 ≥2 sample → 0
        assert(t.RawWindowedRate() == 0.0);
        assert(t.LastValue() == 1100);
    }

    // 但**在 prune 之前**的 raw rate 应当是合理的:再 push 一个 @11s。
    {
        RateWindowTracker t(/*window_secs=*/5.0);
        t.Observe(0,             100);  // 5s 之外
        t.Observe(10 * kUsPerSec, 1100);
        // 现在剩 [@10s=1100](@0 被 prune)
        t.Observe(11 * kUsPerSec, 1600);
        // 现在 [@10s=1100, @11s=1600] —— 1s 间隔,500 events → raw=500
        assert(ApproxEqual(t.RawWindowedRate(), 500.0));
    }

    // ── Case 6: non-monotonic counter → invalid → smoothed 不偏移 ─────────
    // counter reset 是 bug 防御(真实场景中 monotonic counter 不应该倒退;
    // 倒退 = invalid window,smoothed 沿用前值)。区别于 Case 7 valid stall。
    {
        RateWindowTracker t(/*window_secs=*/5.0, /*alpha=*/0.5);
        // 先建立 smoothed=500
        std::uint64_t value = 0;
        for (int i = 0; i < 20; ++i) {
            value += 500;
            t.Observe(static_cast<std::uint64_t>(i + 1) * kUsPerSec, value);
        }
        const double s_before = t.SmoothedRate();
        assert(s_before > 0);

        // 模拟 counter reset:value 倒退 → first.value > last.value → invalid window
        t.Observe(21 * kUsPerSec, 100);
        // smoothed **不**偏移(防 dashboard 闪烁;invalid 不喂 EWMA)
        const double s_after = t.SmoothedRate();
        assert(ApproxEqual(s_after, s_before));
    }

    // ── Case 7 [P1 fix]: valid zero stall → smoothed 收敛到 0 ────────────
    // fuzz stall 场景:counter 不增长但时间在走 → raw=0 valid → EWMA 应平滑到 0。
    // 不能像 Case 6 freeze(LibAFL afl_exec_sec live rate 必须反映 stall)。
    {
        RateWindowTracker t(/*window_secs=*/5.0, /*alpha=*/0.5);
        // 先建立 smoothed=500
        std::uint64_t value = 0;
        for (int i = 0; i < 20; ++i) {
            value += 500;
            t.Observe(static_cast<std::uint64_t>(i + 1) * kUsPerSec, value);
        }
        const double s_before = t.SmoothedRate();
        assert(s_before > 100);  // 应该建立到稳态附近

        // stall:value 不变,push 10 tick(每 1s)
        // 收敛分析:
        //   - 5s window:stall 起 5 tick 内 window 仍含老 high-value sample → raw
        //     渐变小但 > 0;5 tick 后 window 内 first.value == last.value → raw=0
        //   - EWMA α=0.5:从 raw=0 起每 tick smoothed *= 0.5;再 5 tick 衰到 ~3% 初值
        //   - 共 ~10 tick 收敛 ~50x(从 500 → ~3.0);LibAFL afl_exec_sec 加 5x drop
        //     reset 加速收敛(可作 follow-up,EWMA 本身慢收敛是 expected by design)
        const std::uint64_t stall_value = value;
        for (int i = 0; i < 10; ++i) {
            t.Observe(static_cast<std::uint64_t>(20 + i + 1) * kUsPerSec, stall_value);
        }
        const double s_after = t.SmoothedRate();
        // 10 tick 后从 ~500 朝 0 衰 50x+ 即可证明 valid-zero EWMA 工作 — 区别
        // 于 Case 6 (non-monotonic) 完全 freeze 的 invalid 防御行为。
        assert(s_after < s_before / 50.0);
        assert(s_after > 0.0);  // EWMA 渐近 0 但 finite tick 不会到 0
    }

    return 0;
}

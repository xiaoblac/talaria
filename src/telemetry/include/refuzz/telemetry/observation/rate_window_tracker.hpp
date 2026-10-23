// Copyright 2026 reFuzz project author -------youngkk.
//
// RateWindowTracker —— LibAFL `afl_exec_sec` 等价物:基于 sliding window 的 delta
// rate + EWMA 平滑。让"当前/末段速率"独立于"累计平均"展示。
//
// 跟现有 `execs_per_sec = terminal / exec_fuzz_s`(累计平均,LibAFL default mode)
// 并存而**不替代** — 累计平均是 historical retrospective,windowed rate 是 live
// throughput。同 LibAFL 的 default vs `afl_exec_sec` feature 双轨。
//
// 用法(典型):
//   - Orchestrator 每 status tick(eg. 5s 一次)调:
//     `state_store->ObserveExecRate(now_us, terminal_count)`
//   - Renderer / RunSummary 调:
//     `state_store->WindowedExecsPerSec()` → smoothed value
//
// 算法(LibAFL `crates/libafl/src/monitors/stats/mod.rs:255` 等价):
//   - 维护 `deque<{ts_us, value}>`,Observe 时 push;prune 5s 之外的老 sample
//   - raw rate = (last.value - first.value) / (last.ts - first.ts) seconds
//   - smoothed = α * raw + (1 - α) * smoothed_prev(EWMA;α=0.3 默认)
//
// **invalid vs valid-zero 区分**(P1 fix 2026-05-10):
//   - invalid window(samples<2 / dt=0 / counter reset)→ smoothed 沿用前值
//     (无法计算 raw,EWMA 没法用 NaN 描述;真 invalid 是 startup phase / counter
//     bug 防御)
//   - **valid zero**(dt>0 + counter 没增长 → fuzz stall)→ EWMA update with 0
//     让 smoothed 真正反映 stall(否则 stall 后 smoothed 永远卡在最后正值,
//     违反 LibAFL afl_exec_sec live rate 语义)。EWMA α=0.3 → ~3.3 tick
//     (即 ~16s)收敛 90% 到 0。
//
// Thread safety: Observe 在 orchestrator status thread 调,Query 在 dashboard
// render thread 调 → 用内部 mutex。
//
// 详 docs/telemetry-redesign/090_component_metric_recipe.md 模式;
// LibAFL ref: /workspace/syzkaller/project/LibAFL/crates/libafl/src/monitors/stats/mod.rs:255

#pragma once

#include <cstdint>
#include <deque>
#include <mutex>
#include <optional>

namespace refuzz::telemetry {

class RateWindowTracker {
public:
    // 默认 5s window + EWMA α=0.3,跟 LibAFL `afl_exec_sec` feature 对齐
    // (LibAFL window=5s 来自 `Cargo.toml:83` 注释 "5 second time windows")。
    explicit RateWindowTracker(double window_secs = 5.0,
                                double ewma_alpha = 0.3);

    // 推一个 monotonic counter sample。`ts_us` 单调递增(steady_clock micros)。
    // 重复 ts(同一 tick 多次调)等价 update last sample value。
    // **value 必须单调非降**(累计 counter 语义);非单调输入(eg. counter
    // reset)会让 raw rate < 0 — 此时返 0 防御。
    void Observe(std::uint64_t ts_us, std::uint64_t value);

    // 平滑后的 windowed rate(events / second)。
    // - 无 sample / single sample / dt=0 → 返 0(防御 startup phase)
    // - 第一次有效 raw 时 smoothed = raw(EWMA bootstrap)
    double SmoothedRate() const;

    // 不平滑的 raw windowed rate(window 内 first/last sample delta)。
    // 给单测 / debug 用;production 推荐 SmoothedRate。
    double RawWindowedRate() const;

    // 最近一次 Observe 的 value。用于诊断。
    std::uint64_t LastValue() const;

    // 清空(test fixture 用)。
    void Reset();

private:
    struct Sample {
        std::uint64_t ts_us;
        std::uint64_t value;
    };

    // Drop sample 比 (now_us - window_us) 还老的;保留至少 1 个让 last 可读。
    void PruneOldestLocked_(std::uint64_t now_us);

    // 计算 raw rate(基于 samples_ 当前内容)。持 mu_ 进入。
    // [P1 fix] 返 optional:
    //   nullopt — invalid(samples<2 / dt=0 / counter reset)
    //   有值    — valid(可以是 0.0,表示 valid stall)
    std::optional<double> RawRateLocked_() const;

    const double window_secs_;
    const double ewma_alpha_;
    const std::uint64_t window_us_;

    mutable std::mutex mu_;
    std::deque<Sample> samples_;          // sorted by ts_us ascending
    double smoothed_       = 0.0;
    bool   smoothed_inited_ = false;      // 第一次有 raw 时直接赋 raw,跳 EWMA bootstrap
};

}  // namespace refuzz::telemetry

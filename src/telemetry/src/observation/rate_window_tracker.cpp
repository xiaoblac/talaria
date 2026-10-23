// Copyright 2026 reFuzz project author -------youngkk.
//
// RateWindowTracker —— 详 .hpp doc。

#include "refuzz/telemetry/observation/rate_window_tracker.hpp"

#include <algorithm>

namespace refuzz::telemetry {

namespace {
constexpr std::uint64_t kUsPerSec = 1'000'000ull;
}

RateWindowTracker::RateWindowTracker(double window_secs, double ewma_alpha)
    : window_secs_(window_secs > 0.0 ? window_secs : 5.0),
      ewma_alpha_(std::clamp(ewma_alpha, 0.0, 1.0)),
      window_us_(static_cast<std::uint64_t>(window_secs_ * kUsPerSec))
{}

void RateWindowTracker::Observe(std::uint64_t ts_us, std::uint64_t value)
{
    std::lock_guard<std::mutex> lk(mu_);

    // 同一 ts 重复 observe → update last(避免 zero-dt 噪音放大 EWMA)。
    if (!samples_.empty() && samples_.back().ts_us == ts_us) {
        samples_.back().value = value;
    } else {
        samples_.push_back({ts_us, value});
    }
    PruneOldestLocked_(ts_us);

    // [G5 follow-up-2 P1 fix] 区分 "invalid raw" vs "valid zero raw":
    //   - invalid(samples<2 / dt=0 / counter reset)→ 不更新 smoothed
    //     (无法计算,EWMA 没法用 NaN 描述,沿用前值是正确防御)
    //   - **valid zero**(stall:dt>0 + counter 没增长)→ EWMA update with 0
    //     让 smoothed 真正反映 stall(否则 stall 后 smoothed 永远卡在最后正值,
    //     违反 LibAFL afl_exec_sec live rate 语义)
    auto raw_opt = RawRateLocked_();
    if (!raw_opt.has_value()) {
        return;  // invalid window — smoothed 沿用前值
    }
    const double raw = *raw_opt;  // 可能是 0.0(valid stall)
    if (!smoothed_inited_) {
        smoothed_         = raw;
        smoothed_inited_  = true;
    } else {
        smoothed_ = ewma_alpha_ * raw + (1.0 - ewma_alpha_) * smoothed_;
    }
}

double RateWindowTracker::SmoothedRate() const
{
    std::lock_guard<std::mutex> lk(mu_);
    return smoothed_inited_ ? smoothed_ : 0.0;
}

double RateWindowTracker::RawWindowedRate() const
{
    std::lock_guard<std::mutex> lk(mu_);
    // [G5 follow-up-2 P1 fix] 返 nullopt → 0.0 让 diagnostic 显示一致;
    // caller 想区分 invalid vs valid-zero 应看 LastValue + sample 历史。
    auto opt = RawRateLocked_();
    return opt.value_or(0.0);
}

std::uint64_t RateWindowTracker::LastValue() const
{
    std::lock_guard<std::mutex> lk(mu_);
    return samples_.empty() ? 0ull : samples_.back().value;
}

void RateWindowTracker::Reset()
{
    std::lock_guard<std::mutex> lk(mu_);
    samples_.clear();
    smoothed_         = 0.0;
    smoothed_inited_  = false;
}

void RateWindowTracker::PruneOldestLocked_(std::uint64_t now_us)
{
    if (samples_.size() < 2) return;
    const std::uint64_t cutoff = (now_us > window_us_) ? (now_us - window_us_) : 0;
    // 保留至少 1 个 sample(让 LastValue 始终有值);用 size > 1 守门。
    while (samples_.size() > 1 && samples_.front().ts_us < cutoff) {
        samples_.pop_front();
    }
}

// [G5 follow-up-2 P1 fix] 改返 optional 让 caller 区分 invalid vs valid-zero:
//   nullopt — invalid(samples<2 / dt=0 / counter reset),caller 不更新 EWMA
//   有值    — valid raw rate(可以是 0.0,表示 stall)
std::optional<double> RateWindowTracker::RawRateLocked_() const
{
    if (samples_.size() < 2) return std::nullopt;        // 单 sample / 空
    const auto& first = samples_.front();
    const auto& last  = samples_.back();
    if (last.ts_us <= first.ts_us) return std::nullopt;  // dt=0 防 div0
    if (last.value < first.value)  return std::nullopt;  // counter reset / 非单调防御
    const double dt_secs = static_cast<double>(last.ts_us - first.ts_us) / kUsPerSec;
    const double dvalue  = static_cast<double>(last.value - first.value);
    return dvalue / dt_secs;  // 可以是 0.0(valid stall:counter 没动)
}

}  // namespace refuzz::telemetry

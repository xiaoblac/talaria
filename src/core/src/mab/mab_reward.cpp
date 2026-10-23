// [mab-stage-selection — reFuzz reward] MabReward 实现,详见头注 + docs/plans/mab-stage-selection.md。

#include "refuzz/core/mab/mab_reward.hpp"

#include <cmath>

namespace refuzz::mab {

namespace {
// σ 下限:低于此视为零方差(样本不足 / 全相等),归一返回中性 0,避免 g/σ 爆炸。
constexpr double kSigmaEps = 1e-12;
} // namespace

MabReward::MabReward(MabRewardConfig cfg) : cfg_(cfg) {}

double MabReward::CapTime(double t) const
{
    if (t < 0.0) {
        return 0.0;
    }
    if (cfg_.time_cap_s > 0.0 && t > cfg_.time_cap_s) {
        return cfg_.time_cap_s;
    }
    return t;
}

double MabReward::Rate() const
{
    // 历史「覆盖/时间」率 R=C/T。无时间观测(T==0)→ 0;全 miss(C==0)→ 自然 0/T=0。
    // R=0 时首/早期任务退化为 g=c(无历史率可比 → 纯覆盖,= bootstrap,直到第一个 win 建率)。
    return total_t_ > 0.0 ? total_c_ / total_t_ : 0.0;
}

double MabReward::InvRate() const
{
    // T/C = 每单位覆盖的历史秒数(= 1/Rate,SyzVegas Eq 1 的 t_exp 系数)。无覆盖(C==0)→ 0
    // (bootstrap:首 win 前无率可比)。随饱和 C/T↓ → T/C↑ → 放大晚期稀有 win。
    return total_c_ > 0.0 ? total_t_ / total_c_ : 0.0;
}

double MabReward::Settle(double coverage, double task_time)
{
    const double t = CapTime(task_time);
    // [SyzVegas Eq 2 — time-unit] g = c·(T/C) − t = expected_time − actual_time。T/C=InvRate
    // 放大晚期稀有 win;miss(c=0)→ g=−t(纯时间,**不乘 R** → 重尾任务不被 anchored-high R
    // 放大成巨罚,reward 跟 covX/s 而非 mean-time)。⚠ 曾用 coverage-unit g=c−t·R:晚期 R 锚高
    // → t·R 淹没 c → reward 退化成 mean-time penalty → 重尾的 generation 被误罚(8h run 实锤,
    // 见 project_mab_task_t_probe_verdict)。InvRate/σ 用本次未计入的历史;C==0 → g=−t(n<2 中性)。
    const double g = coverage * InvRate() - t;

    // Eq 10:rescaled logistic = tanh(g/2σ),σ 取**先前**观测的标准差。**不减均值** → zero
    // reward 恒映射到 0、跑赢→正、miss(g=−t)→负(Ĝ 回落)。先前样本 <2 / 零方差 → 中性 0。
    double x = 0.0;
    if (n_ >= 2) {
        const double sigma = Sigma();  // over the n_ prior observations
        if (sigma > kSigmaEps) {
            x = std::tanh(g / (2.0 * sigma));
        }
    }

    // 计入累积统计(SyzVegas Eq 13:三标量,O(1))。每次任务(win + miss)都计入。
    total_c_ += coverage;
    total_t_ += t;
    sum_g_   += g;
    sum_g2_  += g * g;
    ++n_;
    return x;
}

double MabReward::Sigma() const
{
    if (n_ < 2) {
        return 0.0;
    }
    const double inv  = 1.0 / static_cast<double>(n_);
    const double mean = sum_g_ * inv;
    double       var  = sum_g2_ * inv - mean * mean;  // 总体方差(Eq 13:/n)
    if (var < 0.0) {
        var = 0.0;  // 浮点抖动夹回
    }
    return std::sqrt(var);
}

} // namespace refuzz::mab

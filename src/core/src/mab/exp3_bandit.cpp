// [当前版本 mab-stage-selection Step 0] Exp3Bandit 实现,详见头注 + docs/plans/mab-stage-selection.md §4/§5。

#include "refuzz/core/mab/exp3_bandit.hpp"

#include <algorithm>
#include <cmath>
#include <limits>

namespace refuzz::mab {

namespace {
constexpr double kE = 2.718281828459045;  // e —— 避免依赖非 ISO 的 M_E
} // namespace

Exp3Bandit::Exp3Bandit(Exp3Config cfg) : cfg_(cfg)
{
    if (cfg_.mode == Exp3Config::Mode::kEpoch) {
        StartEpoch(1);
    }
    // kFixedTheta:η/γ 在 Select 时按当前 K 现算(RefreshFixedTheta)。
}

void Exp3Bandit::AddArm(std::uint64_t arm_id, double ghat0)
{
    ghat_.emplace(arm_id, ghat0);  // 默认 0(SyzVegas baseline);已存在则 no-op
}

void Exp3Bandit::RemoveArm(std::uint64_t arm_id)
{
    ghat_.erase(arm_id);
}

bool Exp3Bandit::HasArm(std::uint64_t arm_id) const
{
    return ghat_.find(arm_id) != ghat_.end();
}

double Exp3Bandit::Ghat(std::uint64_t arm_id) const
{
    auto it = ghat_.find(arm_id);
    return it == ghat_.end() ? 0.0 : it->second;
}

void Exp3Bandit::StartEpoch(std::uint32_t r)
{
    epoch_ = r;
    gamma_ = std::pow(2.0, -static_cast<double>(r));  // γ = 2^−r
    eta_   = 2.0 * gamma_;                             // η = 2γ
    for (auto& [id, g] : ghat_) {
        (void)id;
        g = 0.0;  // [SyzVegas baseline] 新 epoch 清零 Ĝ
    }
}

double Exp3Bandit::EpochThreshold() const
{
    // SyzVegas Alg1 line6:Ĝ_threshold = K·lnK/(e−1)·4^r − 1/(5γ)。K<2 时 lnK≤0,夹到 K=2 防
    // 退化(否则 base=0 每步触发)。−1/(5γ)=2^r/5 是 Exp3.1 的越界修正(让 epoch 略早推进)。
    const double k    = static_cast<double>(std::max<std::size_t>(ghat_.size(), 2));
    const double base = (k * std::log(k) / (kE - 1.0)) * std::pow(4.0, static_cast<double>(epoch_));
    const double corr = (gamma_ > 0.0) ? 1.0 / (5.0 * gamma_) : 0.0;
    const double thr  = base - corr;
    return thr > 0.0 ? thr : base;  // 守卫:绝不取非正(否则每步 reset)
}

void Exp3Bandit::MaybeAdvanceEpoch()
{
    if (ghat_.empty()) {
        return;
    }
    // SyzVegas Algorithm 1 line 7:max_i|Ĝ_i| ≥ threshold。signed reward 下 Ĝ 可正可负
    // (miss=−t 让它回落),故取 |Ĝ| —— 正向攒够证据或负向跌够都触发 epoch 重置。
    double g_max = 0.0;
    for (const auto& [id, g] : ghat_) {
        (void)id;
        g_max = std::max(g_max, std::fabs(g));
    }
    if (g_max >= EpochThreshold()) {
        StartEpoch(epoch_ + 1);
    }
}

void Exp3Bandit::RefreshFixedTheta(std::size_t k)
{
    if (k >= 2) {
        const double kd = static_cast<double>(k);
        eta_   = cfg_.theta * std::sqrt(2.0 * std::log(kd) / kd);  // η = θ·√(2lnK/K)
        gamma_ = eta_ * 0.5;                                       // γ = η/2
    } else {
        // 0/1 个 arm:退化为均匀(η=0 → 所有权重 e^0=1);γ 取个小正数防除零。
        eta_   = 0.0;
        gamma_ = cfg_.theta;
    }
}

std::optional<Exp3Bandit::Selection>
Exp3Bandit::Select(const std::vector<std::uint64_t>& eligible, std::mt19937_64& rng)
{
    // 候选 = eligible∩已注册;eligible 空 → 全部已注册。
    std::vector<std::uint64_t> cand;
    if (eligible.empty()) {
        cand.reserve(ghat_.size());
        for (const auto& [id, g] : ghat_) {
            (void)g;
            cand.push_back(id);
        }
    } else {
        cand.reserve(eligible.size());
        for (std::uint64_t id : eligible) {
            if (HasArm(id)) {
                cand.push_back(id);
            }
        }
    }
    if (cand.empty()) {
        return std::nullopt;
    }

    if (cfg_.mode == Exp3Config::Mode::kFixedTheta) {
        RefreshFixedTheta(ghat_.size());  // K = 全 arm 数(seed-MAB 全 eligible)
    }

    // 权重 w_i = e^{η·Ĝ_i},做 max 平移防 overflow(不改概率)。
    double g_max = -std::numeric_limits<double>::infinity();
    for (std::uint64_t id : cand) {
        g_max = std::max(g_max, Ghat(id));
    }
    std::vector<double> w(cand.size());
    double sum_w = 0.0;
    for (std::size_t i = 0; i < cand.size(); ++i) {
        w[i] = std::exp(eta_ * (Ghat(cand[i]) - g_max));
        sum_w += w[i];
    }
    if (!(sum_w > 0.0)) {
        // 数值兜底:全 0 → 均匀。
        for (std::size_t i = 0; i < cand.size(); ++i) {
            w[i] = 1.0;
        }
        sum_w = static_cast<double>(cand.size());
    }

    // [SyzVegas baseline] 纯 softmax p_i = w_i/Σw(Algorithm 1/2 line 9)。探索由 Exp3-IX 的
    //   γ(update 隐式)+ Exp3.1 epoch-reset(Ĝ 清零→短暂均匀)提供,无 explore-floor 补丁。
    const std::size_t k = cand.size();
    std::vector<double> p(k);
    for (std::size_t i = 0; i < k; ++i) {
        p[i] = w[i] / sum_w;
    }

    // 按 p 抽样(r ∈ [0,1))。
    std::uniform_real_distribution<double> dist(0.0, 1.0);
    double r = dist(rng);
    std::size_t chosen = k - 1;  // 兜底末位(防浮点累加略小于 1)
    double acc = 0.0;
    for (std::size_t i = 0; i < k; ++i) {
        acc += p[i];
        if (r < acc) {
            chosen = i;
            break;
        }
    }

    Selection sel;
    sel.arm_id = cand[chosen];
    sel.pr     = p[chosen];
    sel.gamma  = gamma_;
    return sel;
}

void Exp3Bandit::Update(std::uint64_t arm_id, double pr, double gamma, double x)
{
    auto it = ghat_.find(arm_id);
    if (it == ghat_.end()) {
        return;  // arm 已退役,reward 迟到 → 丢弃
    }
    const double denom = pr + gamma;
    if (denom > 0.0) {
        it->second += x / denom;  // Exp3-IX:Ĝ_i += x/(pr+γ)
    }
    if (cfg_.mode == Exp3Config::Mode::kEpoch) {
        MaybeAdvanceEpoch();
    }
}

} // namespace refuzz::mab

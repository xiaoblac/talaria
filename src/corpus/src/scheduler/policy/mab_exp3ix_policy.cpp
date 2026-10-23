// [mab-stage-selection Step 2] MabExp3IxPolicy 实现,详见头注 + docs/plans/mab-stage-selection.md §5。

#include "refuzz/scheduler/policy/mab_exp3ix_policy.hpp"

#include "refuzz/scheduler/rarity_score.hpp"  // [signal A prior] shared Σ 1/pc_count

#include <vector>

namespace refuzz::fuzzer {

namespace {
refuzz::mab::Exp3Config MakeSeedBanditConfig()
{
    refuzz::mab::Exp3Config c;
    c.mode  = refuzz::mab::Exp3Config::Mode::kFixedTheta;  // Algorithm 2:不分 epoch
    c.theta = 0.1;                                          // 论文全程 θ=0.1
    return c;
}
// cold-arm prior 的 boost 上限:Ĝ₀ ≤ α·cap。稀有度重尾(CV~1.5),不封顶会让极值臂
// 拿到过大 head-start;封在 α·8 把先验集中在 rare tail 又不爆。
constexpr double kPriorBoostCap = 8.0;
} // namespace

MabExp3IxPolicy::MabExp3IxPolicy(double rarity_prior_alpha)
    : bandit_(MakeSeedBanditConfig())
    , reward_(refuzz::mab::MabRewardConfig{.time_cap_s = 2.0})
    , prior_alpha_(rarity_prior_alpha > 0.0 ? rarity_prior_alpha : 0.0)
{}

double MabExp3IxPolicy::ColdArmPrior(SchedulerContext& ctx, uint64_t seed_id) const
{
    if (prior_alpha_ <= 0.0 || ctx.seed_cover == nullptr || ctx.pc_count == nullptr) {
        return 0.0;  // α=0(基线)/ 无覆盖数据 → 无先验
    }
    const auto it = ctx.seed_cover->find(seed_id);
    if (it == ctx.seed_cover->end() || it->second.empty()) {
        return 0.0;
    }
    const double rar = RarityScore(it->second, *ctx.pc_count);
    double g0 = 0.0;
    if (rar_n_ > 0) {  // 用**先前**均值(免自比);第一颗种子无均值 → 0
        const double mu = rar_sum_ / static_cast<double>(rar_n_);
        if (mu > 0.0) {
            double boost = rar / mu - 1.0;  // ×平均稀有度之上的倍数
            if (boost < 0.0) boost = 0.0;   // 只 boost 高于均值的(不罚常见)
            if (boost > kPriorBoostCap) boost = kPriorBoostCap;
            g0 = prior_alpha_ * boost;
        }
    }
    rar_sum_ += rar;  // 计入运行均值(在用过先前均值之后)
    ++rar_n_;
    return g0;
}

std::optional<uint64_t> MabExp3IxPolicy::Next(SchedulerContext& ctx) const
{
    if (ctx.ready_queue.empty()) {
        return std::nullopt;
    }
    // eligible = ready_queue 去掉 cooled(demoted);顺手 lazy 注册 arm。
    std::vector<uint64_t> eligible;
    eligible.reserve(ctx.ready_queue.size());
    for (const uint64_t id : ctx.ready_queue) {
        if (ctx.cooled.erase(id) > 0) {
            continue;
        }
        if (!bandit_.HasArm(id)) {
            // 首见即注册;Ĝ₀ = cold-arm rarity prior(α=0 → 0 = SyzVegas 基线)。
            bandit_.AddArm(id, ColdArmPrior(ctx, id));
        }
        eligible.push_back(id);
    }
    if (eligible.empty()) {
        return std::nullopt;
    }
    if (ctx.rng == nullptr) {
        return eligible.back();  // 防御:无 rng → 退化取尾
    }
    auto sel = bandit_.Select(eligible, *ctx.rng);
    if (!sel.has_value()) {
        return eligible.back();
    }
    // [无状态] 把本次抽样的 (pr, γ) 写回 ctx 出参,交还调用方(engine→loop)。policy 自己不留
    // 任何 per-seed 在途快照 → 并发同 seed 不可能互相覆盖(在途簿记按 exec_id 归 control loop)。
    ctx.sel_pr    = sel->pr;
    ctx.sel_gamma = sel->gamma;
    return sel->arm_id;
}

void MabExp3IxPolicy::OnFeedback(SchedulerContext& ctx, uint64_t seed_id,
                                 SeedDisposition disposition) const
{
    // 与其它 policy 同语义:demote → cooled(下次 Next 跳过一轮)。
    if (disposition == SeedDisposition::kDemote) {
        ctx.cooled.insert(seed_id);
    }
}

void MabExp3IxPolicy::OnSeedReward(uint64_t seed_id, double pr, double gamma,
                                   double cov_gain, double task_time_s) const
{
    if (!bandit_.HasArm(seed_id)) {
        return;  // 非本 policy 注册的 arm(如 policy 切换前的旧任务回流)→ 不归属,跳过
    }
    // [SyzVegas baseline] 无状态结算该 seed 的变异任务:cov_gain = 本次变异的 found 覆盖,
    // task_time_s = 任务时间(基线 1)。g = c·(Tmut/Cmut) − t → x = tanh(g/2σ)(本实例只见
    // mutation 任务 → bar 自动 = Tmut/Cmut = SyzVegas Eq 11)→ Exp3-IX 更新该 seed 的 Ĝ。
    // miss(c=0)→ g=−t → x<0 → Ĝ 回落(无产出的 seed 降权)。(pr, γ) 是该次抽样的快照,由
    // control loop 从 exec_id 在途簿记回传 → 并发同 seed 各自带各自的快照,不互相覆盖。
    const double x = reward_.Settle(cov_gain, task_time_s);
    bandit_.Update(seed_id, pr, gamma, x);  // Ĝ += x/(pr+γ)
}

double MabExp3IxPolicy::SeedMabGhat(uint64_t seed_id) const
{
    return bandit_.HasArm(seed_id) ? bandit_.Ghat(seed_id) : 0.0;
}

} // namespace refuzz::fuzzer

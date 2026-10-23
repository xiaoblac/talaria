// [mab-stage-selection — SyzVegas baseline] MabTaskSelector 实现,详见头注 + docs/plans/mab-stage-selection.md §4。

#include "refuzz/control/mab/mab_task_selector.hpp"

#include <cmath>
#include <cstdint>
#include <vector>

namespace refuzz::control::mab {

namespace {
// task-MAB = Exp3.1 分 epoch 重置(Algorithm 1)。探索由 Exp3-IX γ + epoch-reset 提供。
Exp3Config MakeTaskBanditConfig()
{
    Exp3Config c;
    c.mode = Exp3Config::Mode::kEpoch;
    return c;
}
} // namespace

MabTaskSelector::MabTaskSelector(MabTaskConfig cfg)
    : bandit_(MakeTaskBanditConfig())
    , reward_(MabRewardConfig{.time_cap_s = cfg.time_cap_s})
{
    // 只 2 个 arm:generate / mutate。triage 是记账(覆盖≈0),退出 MAB 由 FuzzerLoop 优先 drain。
    bandit_.AddArm(MabArmId(MabArm::kGenerate));
    bandit_.AddArm(MabArmId(MabArm::kMutate));
}

std::optional<MabTaskSelector::Pick>
MabTaskSelector::Select(const ArmEligibility& elig, std::mt19937_64& rng)
{
    std::lock_guard<std::mutex> lk(mu_);
    std::vector<std::uint64_t> eligible;
    eligible.reserve(kMabArmCount);
    if (elig.generate) eligible.push_back(MabArmId(MabArm::kGenerate));
    if (elig.mutate)   eligible.push_back(MabArmId(MabArm::kMutate));
    if (elig.triage)   eligible.push_back(MabArmId(MabArm::kTriage));
    if (eligible.empty()) {
        return std::nullopt;
    }

    auto sel = bandit_.Select(eligible, rng);
    if (!sel.has_value()) {
        return std::nullopt;
    }
    Pick pick;
    pick.arm   = static_cast<MabArm>(sel->arm_id);
    pick.pr    = sel->pr;
    pick.gamma = sel->gamma;
    ++picks_[sel->arm_id];
    return pick;
}

void MabTaskSelector::RecordProduced(std::uint64_t executor_id, const Pick& pick)
{
    std::lock_guard<std::mutex> lk(mu_);
    inflight_[executor_id] = Inflight{.arm = pick.arm, .pr = pick.pr, .gamma = pick.gamma};
}

void MabTaskSelector::OnEvent(std::uint64_t executor_id, double cov_gain, double task_time_s)
{
    std::lock_guard<std::mutex> lk(mu_);
    auto it = inflight_.find(executor_id);
    if (it == inflight_.end()) {
        return;  // 非 MAB 产出 / 已消费 → no-op
    }
    const Inflight in = it->second;
    inflight_.erase(it);

    const std::uint64_t arm_idx = MabArmId(in.arm);
    // per-arm FOUND-coverage 诊断(panel 辨 found vs admitted)。
    ++events_[arm_idx];
    cov_sum_[arm_idx] += cov_gain;
    time_sum_[arm_idx] += task_time_s;  // [t-probe] raw guest exec 时间累计(秒)
    {   // [t-probe] log 桶直方图:bucket = log2(t_ms)*5,~1ms–6s,低端细分辨
        const double t_ms = task_time_s * 1000.0;
        int b = (t_ms <= 1.0) ? 0 : static_cast<int>(std::log2(t_ms) * 5.0);
        if (b < 0) b = 0;
        if (b > 63) b = 63;
        ++t_hist_[arm_idx][static_cast<std::size_t>(b)];
    }
    if (cov_gain > 0.0) {
        ++cov_hits_[arm_idx];
    }

    // [reFuzz reward] 结算该次选择:g = cov_gain − t·R → x = tanh(g/2σ) → Ĝ_arm += x/(pr+γ)。
    //   t = task_time_s(guest exec 窗,秒,triage-immune);miss(cov_gain=0)→ g=−t·R → x<0 → Ĝ 回落。
    const double x = reward_.Settle(cov_gain, task_time_s);
    bandit_.Update(arm_idx, in.pr, in.gamma, x);
}

void MabTaskSelector::RecordAdmitDiagnostic(MabArm arm, double admitted_cov)
{
    std::lock_guard<std::mutex> lk(mu_);
    const std::uint64_t id = MabArmId(arm);
    ++admit_events_[id];
    admit_cov_sum_[id] += admitted_cov;
}

double MabTaskSelector::Ghat(MabArm a) const
{
    std::lock_guard<std::mutex> lk(mu_);
    return bandit_.Ghat(MabArmId(a));
}

std::uint32_t MabTaskSelector::Epoch() const
{
    std::lock_guard<std::mutex> lk(mu_);
    return bandit_.Epoch();
}

std::size_t MabTaskSelector::InflightCount() const
{
    std::lock_guard<std::mutex> lk(mu_);
    return inflight_.size();
}

std::uint64_t MabTaskSelector::PickCount(MabArm a) const
{
    std::lock_guard<std::mutex> lk(mu_);
    return picks_[MabArmId(a)];
}

std::uint64_t MabTaskSelector::EventCount(MabArm a) const
{
    std::lock_guard<std::mutex> lk(mu_);
    return events_[MabArmId(a)];
}

double MabTaskSelector::CovSum(MabArm a) const
{
    std::lock_guard<std::mutex> lk(mu_);
    return cov_sum_[MabArmId(a)];
}

std::uint64_t MabTaskSelector::CovHits(MabArm a) const
{
    std::lock_guard<std::mutex> lk(mu_);
    return cov_hits_[MabArmId(a)];
}

double MabTaskSelector::TimeSum(MabArm a) const
{
    std::lock_guard<std::mutex> lk(mu_);
    return time_sum_[MabArmId(a)];
}

double MabTaskSelector::TimePctlMs(MabArm a, double q) const
{
    std::lock_guard<std::mutex> lk(mu_);
    // [t-probe] 从 log 桶直方图反算分位(ms);桶 i 代表 t_ms∈[2^(i/5),2^((i+1)/5)),取中点。
    const auto& h = t_hist_[MabArmId(a)];
    std::uint64_t total = 0;
    for (auto v : h) total += v;
    if (total == 0) return 0.0;
    const std::uint64_t target = static_cast<std::uint64_t>(q * static_cast<double>(total));
    std::uint64_t cum = 0;
    for (std::size_t i = 0; i < h.size(); ++i) {
        cum += h[i];
        if (cum >= target) {
            return std::exp2((static_cast<double>(i) + 0.5) / 5.0);
        }
    }
    return std::exp2(63.5 / 5.0);
}

std::uint64_t MabTaskSelector::AdmitEventCount(MabArm a) const
{
    std::lock_guard<std::mutex> lk(mu_);
    return admit_events_[MabArmId(a)];
}

double MabTaskSelector::AdmitCovSum(MabArm a) const
{
    std::lock_guard<std::mutex> lk(mu_);
    return admit_cov_sum_[MabArmId(a)];
}

} // namespace refuzz::control::mab

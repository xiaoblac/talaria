// [当前版本 mab-stage-selection Step 0] Exp3Bandit —— SyzVegas 两个 MAB 的共享核。
//
// 详见 docs/plans/mab-stage-selection.md §4(Algorithm 1)/ §5(Algorithm 2)。
// 纯算法件:权重 / 抽样 / Exp3-IX 更新 / Exp3.1 分 epoch 重置。无 IO、无 refuzz 依赖。
//
//   weight   w_i = e^{η·Ĝ_i}        prob pr_i = w_i / Σ_{j∈elig} w_j   (eligible 集内归一)
//   update   Ĝ_i ← Ĝ_i + x_i/(pr_i+γ)                                 (+γ = Exp3-IX 隐式探索)
//   kEpoch   每 epoch r: γ=2^−r, η=2γ, threshold=K·lnK/(e−1)·4^r;     (Exp3.1,task-MAB)
//            max_i|Ĝ_i| ≥ threshold → 进下个 epoch(Ĝ 清零)
//   kFixedTheta  η=2γ=θ·√(2lnK/K),K=arm 数,不重置                    (Exp3-IX,seed-MAB)
//
// 异步特性:产 task(Select)与收 reward(Update)跨 tick,故 Select 把抽样时的
// (pr, γ) 一并返回,Update 用这份 snapshot 做归属,而非"当前" pr/γ。

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <random>
#include <unordered_map>
#include <vector>

namespace refuzz::mab {

struct Exp3Config {
    enum class Mode : std::uint8_t {
        kEpoch,       // Algorithm 1(task-MAB):Exp3.1 分 epoch 重置 + Exp3-IX
        kFixedTheta,  // Algorithm 2(seed-MAB):纯 Exp3-IX,η/γ 由 θ 与 K 定
    };
    Mode   mode  = Mode::kEpoch;
    double theta = 0.1;  // kFixedTheta:η = 2γ = θ·√(2·lnK / K)
    // [SyzVegas baseline] 探索由 Exp3-IX 的隐式 γ + Exp3.1 epoch-reset(Ĝ 清零→短暂均匀)提供
    //   —— 论文 Algorithm 1/2 即此,无额外 explore-floor / 乐观初始化。这两个旋钮(Step D 补丁)
    //   已移除:基线 Select = 纯 softmax pr=w/Σw,AddArm/StartEpoch 初值 Ĝ=0。
};

class Exp3Bandit {
public:
    explicit Exp3Bandit(Exp3Config cfg = {});

    // arm 增删(seed-MAB arm 随 corpus 来去;task-MAB 构造后固定)。Ĝ 初值默认 0
    // (SyzVegas baseline);ghat0 != 0 用于 seed-MAB 的 cold-arm 结构先验(α·rarity),
    // 让冷种子带一点前瞻性 head-start,真实 reward 累积后自然淹过。
    void        AddArm(std::uint64_t arm_id, double ghat0 = 0.0);
    void        RemoveArm(std::uint64_t arm_id);
    bool        HasArm(std::uint64_t arm_id) const;
    std::size_t ArmCount() const { return ghat_.size(); }

    // Select 的产物;pr/gamma 是**抽样瞬间**的快照,供 deferred Update 归属。
    struct Selection {
        std::uint64_t arm_id = 0;
        double        pr     = 0.0;
        double        gamma  = 0.0;
    };

    // 在 eligible(⊆ 已注册;空 = 全部已注册)内按 pr 抽一个 arm。
    //   无 eligible-且-已注册 arm → nullopt(调用方本 slot 不投)。
    //   概率只在 eligible 集内归一(sleeping bandit,§4.1)。
    std::optional<Selection> Select(const std::vector<std::uint64_t>& eligible,
                                    std::mt19937_64& rng);

    // Exp3-IX deferred 更新:Ĝ_arm += x/(pr+γ),pr/γ 取自抽中它的 Selection。
    //   arm 已被 RemoveArm → 忽略(reward 迟到于退役)。
    //   kEpoch:施加后若 max|Ĝ| ≥ threshold 则进下个 epoch。
    void Update(std::uint64_t arm_id, double pr, double gamma, double x);

    // 内省(metrics / 单测)。
    double        Ghat(std::uint64_t arm_id) const;
    double        Gamma() const { return gamma_; }
    std::uint32_t Epoch() const { return epoch_; }

private:
    void   StartEpoch(std::uint32_t r);       // kEpoch:设 γ/η + 清零 Ĝ
    void   RefreshFixedTheta(std::size_t k);  // kFixedTheta:由 K 算 η/γ
    void   MaybeAdvanceEpoch();
    double EpochThreshold() const;            // K·lnK/(e−1)·4^epoch_

    Exp3Config                                 cfg_;
    std::unordered_map<std::uint64_t, double>  ghat_;
    std::uint32_t                              epoch_ = 1;
    double                                     gamma_ = 0.0;
    double                                     eta_   = 0.0;
};

} // namespace refuzz::mab

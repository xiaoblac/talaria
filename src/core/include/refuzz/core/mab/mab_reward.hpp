// [mab-stage-selection — reFuzz reward] MabReward —— reward 归一器(纯算法,无 IO、无 refuzz
// 依赖、可独立单测)。两层 MAB(task + seed)共用。
//
// **rate-relative reward(coverage 单位 + 真实时间)** —— 在 SyzVegas 相对货币思路上,针对 reFuzz
// 「triage 强制 drain 出 bandit + 异步管线」的架构做的**有意改造**(非照抄 paper):
//   R = C/T                历史「覆盖/时间」率(累积全量,= 单位时间挖到的边数)
//   g = c − t·R            实得覆盖 c 减去「按历史率、用时间 t 本应挖到的期望覆盖」
//   x = tanh( g / 2σ )     σ=g 的累积标准差;**不减均值**(zero reward→0)
//   σ = √(Σg²/n − (Σg/n)²) 累积全量,三标量 O(1)
//
// **为什么 coverage 单位(g=c−t·R)而不是 paper 的 time 单位(g=c·(T/C)−t)**:paper 的 time
//   单位下,失败(c=0)→ g=−t,**历史率被乘成 0、失败只剩纯时间惩罚**;reFuzz 又曾把 t 钉成 1
//   → 失败恒 −1、零散布 → σ 收缩 → tanh 饱和成 bang-bang。改 coverage 单位后:
//     · WIN(c>0):g = c − t·R,跑赢历史率 → 正,正比于超出量。
//     · FAIL(c=0):g = −t·R —— **同时带历史率 R(早期率高罚重 / 饱和率低罚轻)与真实时间 t
//       (费时多罚更狠)**;两个诉求一个公式拿下,且 win/fail 同单位喂同一个 σ(混单位不自洽)。
//   两者符号一致(g_cov = (C/T)·g_time)、决策序不变;coverage 单位放弃了 paper 对晚期稀有 win
//   的 ×(T/C) 放大,换来失败侧的率分级 —— reFuzz 取舍(σ 归一兜住量级)。
//
// **时间 t = guest exec 窗(worker_done−worker_start),triage-immune**:reFuzz triage 强制 drain
//   出 bandit、和 gen/mut 抢 executor slot;若用 host 墙钟(queue/submit)t 会被 triage 争用污染,
//   guest 内执行窗不受 host 侧 triage 调度影响 → 干净的 per-task 时间。**副产物**:被 minimize 缩小
//   的 seed,其 mutation 的 t 天然更小 → seed 层 g 更大 → seed-MAB 自动偏好已瘦身/高产种子(= 架构
//   性实现 paper 的 minimize `m·Δt` 价值,无需把 triage 设成 bandit 臂)。
//
// 详见 docs/plans/mab-stage-selection.md。两层共用同一 MabReward:task 层实例见全部 gen/mut 任务
//   → R=全局 C/T;seed 层实例只见 mutation 任务 → R 自动 = Cmut/Tmut(SyzVegas Eq 11,免特判)。

#pragma once

#include <cstdint>

namespace refuzz::mab {

struct MabRewardConfig {
    // 任务时间成本 t 的 outlier 截顶(秒);<=0 关闭。真实 exec 时间下生效:罕见的超长 exec
    // (timeout/hang)会抬高 σ、扭曲归一,截到 cap 稳住标尺(SyzVegas §Outlier Handling,论文 ~2s)。
    double time_cap_s = 2.0;
};

class MabReward {
public:
    explicit MabReward(MabRewardConfig cfg = {});

    // 单次结算:g = c·(T/C) − cap(t)(SyzVegas Eq 2 time-unit;T/C 用**本次未计入**的历史),
    // x = tanh(g/2σ)。**有副作用**:更新 C、T 与累积 σ 统计。返回 x ∈ (−1,1)。
    //   头两次(n<2,σ 未定义)/ 零方差 → 0(中性)。C==0 → T/C=0(bootstrap:首任务 g=−t,
    //   无历史率可比,直到第一个 win 建立率)。
    double Settle(double coverage, double task_time);

    // 内省(panel / 单测)。
    double        Rate() const;    // 当前历史率 R=C/T(无时间观测 → 0)
    double        InvRate() const; // T/C = 1/Rate(每边历史秒数;C==0 → 0)
    double        Sigma() const;   // 当前累积 σ(g)
    std::uint64_t Count() const { return n_; }

private:
    double CapTime(double t) const;

    MabRewardConfig cfg_;
    double          total_c_ = 0.0;  // C —— 累积覆盖
    double          total_t_ = 0.0;  // T —— 累积时间
    double          sum_g_   = 0.0;  // Σg
    double          sum_g2_  = 0.0;  // Σg²
    std::uint64_t   n_       = 0;    // 观测数
};

} // namespace refuzz::mab

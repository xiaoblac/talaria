// mab_bandit_reward_test.cpp
//
// [mab-stage-selection — SyzVegas baseline] MabReward + Exp3Bandit 纯算法单测。
// 详见 docs/plans/mab-stage-selection.md。裸 assert harness(repo 约定,无 gtest)。

#include "refuzz/core/mab/exp3_bandit.hpp"
#include "refuzz/core/mab/mab_reward.hpp"

#include <cassert>
#include <cmath>
#include <cstdio>
#include <random>
#include <vector>

namespace {

using refuzz::mab::Exp3Bandit;
using refuzz::mab::Exp3Config;
using refuzz::mab::MabReward;
using refuzz::mab::MabRewardConfig;

bool approx(double a, double b, double eps = 1e-6)
{
    return std::fabs(a - b) < eps;
}

// ── MabReward:reFuzz rate-relative g=c−t·R(R=C/T),x=tanh(g/2σ),累积 σ ──────────

// Rate = C/T bootstrap(T==0→0)+ 累积跟踪;count 每次(win+miss)都增。
void TestRateAndCount()
{
    MabReward r;
    assert(approx(r.Rate(), 0.0));   // 无观测 → R=0(bootstrap:首任务 g=c)
    assert(r.Count() == 0);
    r.Settle(/*c=*/10.0, /*t=*/1.0); // 首次:n<2 → 返回 0(只建标尺);C=10,T=1
    assert(r.Count() == 1);
    assert(approx(r.Rate(), 10.0));  // C/T = 10/1
    r.Settle(/*c=*/0.0, /*t=*/1.0);  // miss 也计入(C 不变,T+1)
    assert(r.Count() == 2);
    assert(approx(r.Rate(), 10.0 / 2.0));  // C/T = 10/2
    std::fprintf(stdout, "  [ok] MabReward rate(C/T) + count (miss counted)\n");
}

// 核心:signed + zero-centered。跑赢历史率→正、平→0、跑输→负、miss→更负(rate-aware penalty)。
void TestSignedZeroCentered()
{
    MabReward r;
    // warmup:交替 c=8 / c=12(t=1)→ 全局率 R=C/T=10,g∈{−2,+2}(非零方差,σ≈2)。
    for (int i = 0; i < 2000; ++i) {
        r.Settle(i % 2 == 0 ? 8.0 : 12.0, 1.0);
    }
    assert(approx(r.Rate(), 10.0, 0.2));  // C/T ≈ 20000/2000

    // [time-unit] T/C=1/R=0.1。平均率任务(c=10,t=1)→ g = 10·0.1 − 1 = 0 → x ≈ 0(zero-centered)。
    const double x_avg = r.Settle(10.0, 1.0);
    assert(std::fabs(x_avg) < 0.05);
    // 跑赢(c=20)→ g = 20·0.1 − 1 = +1 > 0 → x>0。
    const double x_win = r.Settle(20.0, 1.0);
    assert(x_win > 0.3);
    // 跑输(c=5)→ g = 5·0.1 − 1 = −0.5 < 0 → x<0。
    const double x_lo = r.Settle(5.0, 1.0);
    assert(x_lo < 0.0);
    // miss(c=0)→ g = 0·0.1 − 1 = −1 → x<0,且比单纯跑输更负(miss 按纯时间 −t 罚,无覆盖抵)。
    const double x_miss = r.Settle(0.0, 1.0);
    assert(x_miss < x_lo);
    assert(x_miss < -0.3);
    std::fprintf(stdout,
                 "  [ok] MabReward signed/zero-centered (avg=%.3f win=%.2f lo=%.2f miss=%.2f)\n",
                 x_avg, x_win, x_lo, x_miss);
}

// 跨臂期望序:gen 高频浅 win、mut 低频深 win 且平均覆盖率更高 → time-unit g=c·(T/C)−t 下
// E[x|mut] > E[x|gen](= 不被命中率误导,按覆盖率排)。共享一个 reward 实例(= 真实 task-MAB
// 的共享率 R)。
void TestExpectationOrder()
{
    MabReward r;
    std::mt19937_64 rng(2026);
    std::uniform_real_distribution<double> u(0.0, 1.0);
    // gen: h=0.5, win c=2 → 平均覆盖率 0.5·2=1.0 ; mut: h=0.1, win c=25 → 0.1·25=2.5(2.5× gen)。
    double sum_gen = 0.0, sum_mut = 0.0;
    int n_gen = 0, n_mut = 0;
    const int N = 40000;
    for (int i = 0; i < N; ++i) {
        if (i % 2 == 0) {
            const double c = (u(rng) < 0.5) ? 2.0 : 0.0;
            sum_gen += r.Settle(c, 1.0); ++n_gen;
        } else {
            const double c = (u(rng) < 0.1) ? 25.0 : 0.0;
            sum_mut += r.Settle(c, 1.0); ++n_mut;
        }
    }
    const double ex_gen = sum_gen / n_gen;
    const double ex_mut = sum_mut / n_mut;
    assert(ex_mut > ex_gen);  // mut 真货币更高 → 期望 reward 更高(命中率更低却胜出)
    std::fprintf(stdout,
                 "  [ok] expectation-order (E[x|mut]=%.4f > E[x|gen]=%.4f, currency 2.5x)\n",
                 ex_mut, ex_gen);
}

// 时间截顶:t>cap 夹到 cap(默认 2s);真实 exec 时间下防超长 exec/timeout 扭曲 σ。
void TestTimeCap()
{
    MabReward r;  // time_cap_s = 2.0(默认)
    for (int i = 0; i < 50; ++i) r.Settle(10.0, 1.0);  // 建率 R≈10
    const double x_big_t  = r.Settle(0.0, 100.0);  // g = 0 − cap(100→2)·R(非 −100·R 爆炸)
    const double x_unit_t = r.Settle(0.0, 1.0);    // g = 0 − 1·R
    // 两者都负;big-t 被 cap=2 截住,x 不爆。
    assert(x_big_t < 0.0 && x_unit_t < 0.0);
    std::fprintf(stdout, "  [ok] MabReward time_cap (big-t clamped to 2s, x=%.3f)\n", x_big_t);
}

// ── Exp3Bandit:kEpoch(task-MAB,Algorithm 1) ────────────────────────────────

void TestEpochUniformStart()
{
    Exp3Bandit b;  // kEpoch default
    b.AddArm(10);
    b.AddArm(20);
    b.AddArm(30);
    assert(b.ArmCount() == 3);
    assert(b.HasArm(20) && !b.HasArm(99));
    assert(approx(b.Ghat(10), 0.0));  // [SyzVegas baseline] fresh arm Ĝ=0(无 optimistic init)
    assert(b.Epoch() == 1);
    assert(approx(b.Gamma(), 0.5));  // 2^−1

    // 全 Ĝ=0 → 概率均匀。纯 Select(不 Update,不触发 epoch),统计应近 1/3。
    std::mt19937_64 rng(12345);
    int cnt[3] = {0, 0, 0};
    const int N = 6000;
    for (int i = 0; i < N; ++i) {
        auto sel = b.Select(/*eligible=*/{}, rng);
        assert(sel.has_value());
        if (sel->arm_id == 10) ++cnt[0];
        else if (sel->arm_id == 20) ++cnt[1];
        else ++cnt[2];
        assert(sel->pr > 0.25 && sel->pr < 0.42);  // pr ≈ 1/3(纯 softmax,无 floor)
    }
    for (int i = 0; i < 3; ++i) {
        assert(cnt[i] > N / 3 - 600 && cnt[i] < N / 3 + 600);
    }
    std::fprintf(stdout, "  [ok] Exp3.kEpoch uniform-at-start (%d/%d/%d)\n",
                 cnt[0], cnt[1], cnt[2]);
}

void TestEpochAdvanceAndReset()
{
    Exp3Bandit b;  // kEpoch
    b.AddArm(1);
    b.AddArm(2);
    b.AddArm(3);
    assert(b.Epoch() == 1);

    // 持续给 arm 1 正 reward,Ĝ_1 累积越过 threshold → 进 epoch 2(Ĝ 清零、γ 减半)。
    int guard = 0;
    while (b.Epoch() == 1 && guard < 1000) {
        b.Update(/*arm=*/1, /*pr=*/0.33, /*gamma=*/0.5, /*x=*/1.0);
        ++guard;
    }
    assert(b.Epoch() == 2);
    assert(approx(b.Gamma(), 0.25));   // 2^−2
    assert(approx(b.Ghat(1), 0.0));    // StartEpoch 清零(到 0,无 optimistic init)
    assert(approx(b.Ghat(2), 0.0));
    std::fprintf(stdout, "  [ok] Exp3.kEpoch advance+reset after %d updates\n", guard);
}

// signed reward:负 x 让 Ĝ 回落,|Ĝ| 越负向 threshold 也触发 epoch(SyzVegas Algorithm 1 line 7)。
void TestEpochAdvanceOnNegative()
{
    Exp3Bandit b;  // kEpoch
    b.AddArm(1);
    b.AddArm(2);
    int guard = 0;
    while (b.Epoch() == 1 && guard < 2000) {
        b.Update(/*arm=*/1, /*pr=*/0.33, /*gamma=*/0.5, /*x=*/-1.0);  // 持续负 reward
        ++guard;
    }
    assert(b.Epoch() == 2);          // |Ĝ_1| 跌过 threshold → 进 epoch
    assert(approx(b.Ghat(1), 0.0));  // reset
    std::fprintf(stdout, "  [ok] Exp3.kEpoch advances on negative Ĝ (|Ĝ|, %d updates)\n", guard);
}

void TestSleepingBandit()
{
    Exp3Bandit b;  // kEpoch
    b.AddArm(1);
    b.AddArm(2);
    b.AddArm(3);

    std::mt19937_64 rng(777);
    int c3 = 0;
    std::vector<std::uint64_t> elig{1, 2};
    for (int i = 0; i < 2000; ++i) {
        auto sel = b.Select(elig, rng);
        assert(sel.has_value());
        if (sel->arm_id == 3) ++c3;
        assert(sel->arm_id == 1 || sel->arm_id == 2);
    }
    assert(c3 == 0);

    auto none = b.Select(/*eligible=*/{99, 100}, rng);
    assert(!none.has_value());

    auto one = b.Select(/*eligible=*/{2}, rng);
    assert(one.has_value() && one->arm_id == 2 && approx(one->pr, 1.0));
    std::fprintf(stdout, "  [ok] Exp3 sleeping-bandit (arm3 chosen %d times)\n", c3);
}

// ── Exp3Bandit:kFixedTheta(seed-MAB,Algorithm 2) ───────────────────────────

void TestFixedThetaDominance()
{
    Exp3Config cfg;
    cfg.mode  = Exp3Config::Mode::kFixedTheta;
    cfg.theta = 0.1;
    Exp3Bandit b(cfg);
    const std::uint64_t kGood = 1;
    b.AddArm(1);
    b.AddArm(2);
    b.AddArm(3);
    b.AddArm(4);
    assert(b.ArmCount() == 4);

    // arm 1 一直 +0.8,其它 −0.5(signed reward 合法)→ Ĝ_1 升至最高、被选频率主导。
    std::mt19937_64 rng(2026);
    int last_good = 0;
    const int N = 8000;
    const int kTailStart = 7000;
    for (int i = 0; i < N; ++i) {
        auto sel = b.Select(/*eligible=*/{}, rng);
        assert(sel.has_value());
        double x = (sel->arm_id == kGood) ? 0.8 : -0.5;
        b.Update(sel->arm_id, sel->pr, sel->gamma, x);
        if (i >= kTailStart && sel->arm_id == kGood) ++last_good;
    }
    assert(last_good > 500);
    assert(b.Ghat(1) > b.Ghat(2));
    assert(b.Ghat(1) > b.Ghat(3));
    assert(b.Ghat(1) > b.Ghat(4));
    std::fprintf(stdout, "  [ok] Exp3.kFixedTheta dominance (good tail %d/1000)\n",
                 last_good);
}

void TestArmLifecycleAndLateReward()
{
    Exp3Config cfg;
    cfg.mode = Exp3Config::Mode::kFixedTheta;
    Exp3Bandit b(cfg);
    b.AddArm(5);
    std::mt19937_64 rng(42);
    auto sel = b.Select(/*eligible=*/{}, rng);
    assert(sel.has_value() && sel->arm_id == 5 && approx(sel->pr, 1.0));

    b.RemoveArm(5);
    assert(b.ArmCount() == 0);
    b.Update(5, sel->pr, sel->gamma, /*x=*/0.7);  // no-op
    assert(!b.HasArm(5));
    assert(approx(b.Ghat(5), 0.0));

    auto empty = b.Select(/*eligible=*/{}, rng);
    assert(!empty.has_value());
    std::fprintf(stdout, "  [ok] Exp3 arm lifecycle + late-reward ignored\n");
}

} // namespace

int main()
{
    std::fprintf(stdout, "Running mab_bandit_reward_test...\n");
    TestRateAndCount();
    TestSignedZeroCentered();
    TestExpectationOrder();
    TestTimeCap();
    TestEpochUniformStart();
    TestEpochAdvanceAndReset();
    TestEpochAdvanceOnNegative();
    TestSleepingBandit();
    TestFixedThetaDominance();
    TestArmLifecycleAndLateReward();
    std::fprintf(stdout, "mab_bandit_reward_test: ALL PASS\n");
    return 0;
}

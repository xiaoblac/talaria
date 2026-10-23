// mab_seed_policy_test.cpp
//
// [mab-stage-selection Step 2] MabExp3IxPolicy(seed-selection MAB,Exp3-IX)单测:
// reward 驱动 seed 选择 + engine 注册/转发 + demote。详见 docs/plans/mab-stage-selection.md §5。
// 裸 assert harness。

#include "refuzz/scheduler/engine/priority_scheduler_engine.hpp"
#include "refuzz/scheduler/policy/mab_exp3ix_policy.hpp"
#include "refuzz/scheduler/scheduling_context.hpp"

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <memory>
#include <random>
#include <unordered_set>
#include <vector>

namespace {

using refuzz::fuzzer::MabExp3IxPolicy;
using refuzz::fuzzer::PrioritySchedulerEngine;
using refuzz::fuzzer::SchedulerContext;
using refuzz::fuzzer::SeedDisposition;

// 完整周期:reward 高的 seed 被选频率主导(Exp3-IX 经 OnSeedReward 学习)。
void TestRewardDrivenDominance()
{
    MabExp3IxPolicy policy;
    std::vector<std::uint64_t> ready = {1, 2, 3, 4};
    std::deque<std::uint64_t> boosted;
    std::unordered_set<std::uint64_t> cooled;
    std::size_t cursor = 0;
    std::mt19937_64 rng(2026);

    const std::uint64_t kGood = 1;
    const double kExecT = 0.1;
    int last_good = 0, tail_total = 0;
    const int N = 6000, kTail = 4500;
    int saw[5] = {0, 0, 0, 0, 0};
    for (int i = 0; i < N; ++i) {
        SchedulerContext ctx{ready, boosted, cooled, cursor, nullptr, nullptr, &rng};
        auto s = policy.Next(ctx);
        assert(s.has_value() && *s >= 1 && *s <= 4);
        ++saw[*s];
        // seed 1 一直高覆盖,其它零 → seed 1 的 Ĝ 升高、被选主导。
        const double cov = (*s == kGood) ? 5.0 : 0.0;
        // [无状态] (pr,γ) 由 Next() 写回 ctx 出参,调用方回传(= engine/loop 的角色)。
        policy.OnSeedReward(*s, ctx.sel_pr, ctx.sel_gamma, cov, kExecT);
        if (i >= kTail) { ++tail_total; if (*s == kGood) ++last_good; }
    }
    // 开局每个都被选过(lazy 注册 + 均匀起步)
    assert(saw[1] > 0 && saw[2] > 0 && saw[3] > 0 && saw[4] > 0);
    // 尾段 good seed 占多数
    assert(last_good * 2 > tail_total);
    std::fprintf(stdout, "  [ok] seed-MAB reward-driven dominance (saw=%d/%d/%d/%d, tail good %d/%d)\n",
                 saw[1], saw[2], saw[3], saw[4], last_good, tail_total);
}

// demote → cooled(下一轮跳过)。
void TestDemoteCools()
{
    MabExp3IxPolicy policy;
    std::vector<std::uint64_t> ready = {7};
    std::deque<std::uint64_t> boosted;
    std::unordered_set<std::uint64_t> cooled;
    std::size_t cursor = 0;
    std::mt19937_64 rng(1);

    SchedulerContext ctx{ready, boosted, cooled, cursor, nullptr, nullptr, &rng};
    policy.OnFeedback(ctx, 7, SeedDisposition::kDemote);
    assert(cooled.count(7) == 1);
    // cooled 命中 → 本轮唯一候选被跳过 → nullopt(并清掉 cooled 标记)
    auto s = policy.Next(ctx);
    assert(!s.has_value());
    assert(cooled.count(7) == 0);
    // 下一轮恢复可选
    auto s2 = policy.Next(ctx);
    assert(s2.has_value() && *s2 == 7);
    std::fprintf(stdout, "  [ok] seed-MAB demote→cooled (skip one round)\n");
}

// engine 路径:mab_exp3ix 注册 + 可切 + OnSeedReward 转发不崩。
void TestEngineRegistrationAndForward()
{
    PrioritySchedulerEngine engine;
    engine.RegisterPolicy("mab_exp3ix", std::make_unique<MabExp3IxPolicy>());
    assert(engine.SwitchPolicyByName("mab_exp3ix"));
    assert(engine.ActivePolicyName() == "mab_exp3ix");

    engine.OnSeedAdded(10);
    engine.OnSeedAdded(20);
    bool seen10 = false, seen20 = false;
    for (int i = 0; i < 200; ++i) {
        auto s = engine.NextSeedId();
        assert(s.has_value() && (s->seed_id == 10 || s->seed_id == 20));
        if (s->seed_id == 10) seen10 = true; else seen20 = true;
        // engine 把 NextSeedId 的 {seed,pr,γ} 回传给无状态 OnSeedReward(= loop 的角色)。
        engine.OnSeedReward(s->seed_id, s->pr, s->gamma,
                            /*cov=*/(s->seed_id == 10 ? 3.0 : 0.0), /*t=*/0.1);
    }
    assert(seen10 && seen20);
    // 未跟踪 seed 的 reward → no-op(不崩)
    engine.OnSeedReward(99999, /*pr=*/1.0, /*gamma=*/0.0, /*cov=*/1.0, /*t=*/0.1);
    std::fprintf(stdout, "  [ok] engine mab_exp3ix register + OnSeedReward forward\n");
}

} // namespace

int main()
{
    std::fprintf(stdout, "Running mab_seed_policy_test...\n");
    TestRewardDrivenDominance();
    TestDemoteCools();
    TestEngineRegistrationAndForward();
    std::fprintf(stdout, "mab_seed_policy_test: ALL PASS\n");
    return 0;
}

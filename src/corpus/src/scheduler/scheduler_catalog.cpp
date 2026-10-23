// Copyright 2026 reFuzz project author -------youngkk.

#include "refuzz/scheduler/scheduler_catalog.hpp"

#include "refuzz/scheduler/engine/priority_scheduler_engine.hpp"
#include "refuzz/scheduler/policy/mab_exp3ix_policy.hpp"  // [mab Step 2] seed-MAB
#include "refuzz/scheduler/policy/priority_policy.hpp"
#include "refuzz/scheduler/policy/rarity_weighted_policy.hpp"
#include "refuzz/scheduler/policy/round_robin_policy.hpp"
#include "refuzz/scheduler/policy/size_weighted_policy.hpp"
#include "refuzz/scheduler/policy/uniform_policy.hpp"

#include <cstdio>   // [signal A prior] one-line stderr confirmation when α>0
#include <cstdlib>  // [signal A prior] getenv/atof for REFUZZ_SEED_RARITY_PRIOR_ALPHA
#include <memory>

namespace refuzz::fuzzer {

void RegisterBuiltinSchedulerEngines(SchedulerEngineCatalog& catalog)
{
    // "priority_scheduler" — 默认优先级调度 engine，
    // 内部一次性装入 priority + round_robin 两个 policy，priority 为默认 active。
    SchedulerEngineCatalog::Entry entry;
    entry.meta = {
        "priority_scheduler",
        "Priority Scheduler",
        "Priority-driven seed scheduling engine (policies: priority, round_robin)",
    };
    entry.build = [](const SchedulerEngineTraits::BuildContext& ctx)
        -> core::Result<std::unique_ptr<ISchedulerEngine>> {
        // corpus_store 透传给 engine:size_weighted / rarity_weighted 据它读
        // per-seed cover;为空时 engine 退化为 coverage-blind(不影响其它 policy)。
        auto engine = std::make_unique<PrioritySchedulerEngine>(ctx.corpus_store);
        // [seed-future-value] non-owning SeedHorizon (null = disabled, no overhead).
        engine->SetSeedHorizon(ctx.seed_horizon);
        // [future_band2] non-owning band-② shadow candidate (null = disabled).
        engine->SetSeedBand2(ctx.seed_band2);
        // [belief-graph] non-owning static belief-graph prior (null = disabled).
        engine->SetBeliefGraph(ctx.belief_graph);
        // 第一个注册的(priority)= 默认 active(保持现状)。其余经 config
        // scheduling_policy + SwitchPolicyByName 选用。
        engine->RegisterPolicy("priority", std::make_unique<PriorityPolicy>());
        engine->RegisterPolicy("round_robin", std::make_unique<RoundRobinPolicy>());
        // [value-weighted experiment] 覆盖盲基线 + 两种加权。
        engine->RegisterPolicy("uniform", std::make_unique<UniformPolicy>());
        engine->RegisterPolicy("size_weighted", std::make_unique<SizeWeightedPolicy>());
        engine->RegisterPolicy("rarity_weighted", std::make_unique<RarityWeightedPolicy>());
        // [mab-stage-selection Step 2] seed-selection MAB(SyzVegas Algorithm 2,Exp3-IX)。
        // config fuzzer.scheduling_policy="mab_exp3ix" 选用;reward 经 OnSeedReward 通道
        // (SyzVegas 相对货币 tanh + 累积 σ,无窗口/分位旋钮)。
        // [seed-value signal A — cold-arm rarity prior, A/B knob] α from env
        // REFUZZ_SEED_RARITY_PRIOR_ALPHA (default 0 = pure baseline). α>0 gives new
        // seeds Ĝ₀ = α·(rarity above mean), a decaying foresight head-start. Env
        // (not config) keeps this experimental knob plumbing-free; promote to a
        // config field if the A/B (α=0 vs α>0) shows it's worth keeping.
        double rarity_prior_alpha = 0.0;
        if (const char* e = std::getenv("REFUZZ_SEED_RARITY_PRIOR_ALPHA")) {
            const double v = std::atof(e);
            if (v > 0.0) {
                rarity_prior_alpha = v;
                // Confirm the experimental knob is live so a treatment run can't
                // silently run as baseline (env not propagated to the child).
                std::fprintf(stderr,
                             "[seed-MAB] cold-arm rarity prior ENABLED: alpha=%g\n",
                             rarity_prior_alpha);
            }
        }
        engine->RegisterPolicy(
            "mab_exp3ix", std::make_unique<MabExp3IxPolicy>(rarity_prior_alpha));
        // [config-selected scheduling policy] 默认 priority active;实际 policy 由
        // config 的 fuzzer.scheduling_policy 在 FuzzerLoop ctor 经 SwitchSchedulingPolicy
        // 选用(见 fuzzer_loop.cpp)。catalog 不读 env。
        return engine;
    };
    catalog.Register(std::move(entry));
}

} // namespace refuzz::fuzzer

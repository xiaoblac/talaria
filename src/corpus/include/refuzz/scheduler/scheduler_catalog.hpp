// Copyright 2026 reFuzz project author -------youngkk.
//
// SchedulerEngineCatalog — 调度 engine 的注册表。
//
// 与 MutatorEngineCatalog 对齐（engine 粒度）：
//   LaunchPlan.scheduler_engine (id)
//       → ProfileDefaults 填空
//       → Assembler 遍历 catalog.All() 构造 engine 注入 SchedulerManager
//       → Assembler 调用 manager->SwitchEngineByName(resolved.scheduler_engine)
//
// engine 内部 policy（PriorityPolicy / RoundRobinPolicy 等）按"engine 自治"
// 原则，由 build lambda 在构造时 RegisterPolicy 一次性装齐；Catalog 不额外
// 引入 SchedulerPolicyCatalog。运行时 policy 切换由 engine 自己 lazy apply。

#pragma once

#include "refuzz/catalog/typed_catalog.hpp"
#include "refuzz/scheduler/scheduler_engine.hpp"

#include <cstdint>

namespace refuzz::fuzzer {

class ICorpusStore;  // refuzz/fuzzer/interfaces.hpp
class SeedHorizon;   // refuzz/scheduler/horizon/seed_horizon.hpp — future(seed)
class SeedBand2;     // refuzz/scheduler/horizon/seed_band2.hpp — band-② shadow candidate
class StaticBeliefGraph;  // refuzz/scheduler/horizon/static_belief_graph.hpp — belief-graph prior

struct SchedulerEngineTraits {
    using Product = ISchedulerEngine;

    // [value-weighted policies] 那个"留口子"现在用上了:corpus_store 非空时
    // engine 在 OnSeedAdded 经它读 per-seed cover,维护 size/rarity 加权所需的
    // PC 计数。coverage-blind engine/policy 不读它(留 nullptr 也安全)。
    struct BuildContext {
        const ICorpusStore* corpus_store = nullptr;
        // [seed-future-value] non-owning; engine caches future(seed) at OnSeedAdded.
        // Null (default) = disabled → SeedFutureValue returns 0 (no overhead).
        SeedHorizon*        seed_horizon = nullptr;
        // [future_band2] non-owning band-② shadow candidate; null = off (returns 0).
        SeedBand2*          seed_band2 = nullptr;
        // [belief-graph] non-owning static belief-graph prior; null = off (returns 0).
        StaticBeliefGraph*  belief_graph = nullptr;
    };
};

using SchedulerEngineCatalog = refuzz::catalog::TypedCatalog<SchedulerEngineTraits>;

// 注册内置 scheduler engine。
//
// 注册 id 必须与 engine 类 Name() 返回值严格一致：
//   "priority_scheduler" ↔ PrioritySchedulerEngine::Name()
//
// 构造时内嵌注册所有已知 policy（priority / round_robin），首个 policy
// 为默认 active。运行时由 engine.SwitchPolicyByName 切换,SwitchPolicyByName
// 为 lazy-apply,engine 在下一次 NextSeedId / OnFeedback / OnSeedAdded 入口处
// 内部完成。
void RegisterBuiltinSchedulerEngines(SchedulerEngineCatalog& catalog);

} // namespace refuzz::fuzzer

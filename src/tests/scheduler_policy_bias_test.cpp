// scheduler_policy_bias_test — verifies the value-weighted selection policies
// actually bias as intended (gate before long coverage-over-time runs).
//
// Fixture (discriminates size vs rarity):
//   - 30 "filler" seeds, each covering the SAME 40 common PCs [0,40)
//     → every common PC ends with count ~31 (30 filler + big).
//   - "big"  seed (id 100): covers those same 40 common PCs → size=40, but
//     rarity = 40 * 1/31 ≈ 1.3 (all PCs are common).
//   - "rare" seed (id 200): covers 3 UNIQUE PCs [9000,9003) → size=3, but
//     rarity = 3 * 1/1 = 3.0 (nobody else covers them).
//
// Expectations:
//   uniform          : big ≈ rare ≈ 1/32 (flat).
//   size_weighted    : big >> rare        (40 vs 3).
//   rarity_weighted  : rare > big          (3.0 vs ~1.3) — the inversion.
//   priority         : always the last-added seed (recency/tail) — here = rare.

#include "refuzz/corpus/corpus_store.hpp"
#include "refuzz/program/seed.hpp"
#include "refuzz/program/seed_metadata.hpp"
#include "refuzz/scheduler/engine/priority_scheduler_engine.hpp"
#include "refuzz/scheduler/policy/priority_policy.hpp"
#include "refuzz/scheduler/policy/rarity_weighted_policy.hpp"
#include "refuzz/scheduler/policy/round_robin_policy.hpp"
#include "refuzz/scheduler/policy/size_weighted_policy.hpp"
#include "refuzz/scheduler/policy/uniform_policy.hpp"

#include <cstdint>
#include <cstdio>
#include <map>
#include <vector>

using namespace refuzz::fuzzer;

namespace {

Seed MakeSeed(uint64_t id, std::vector<uint64_t> cover)
{
    Seed s;
    s.seed_id = id;
    s.payload = {1, 2, 3};  // non-empty (AddSeed rejects empty payload)
    CorpusCoverageMetadata cc;
    cc.cover_hashes = std::move(cover);
    s.metadata.Set(std::move(cc));
    return s;
}

// Run NextSeedId N times under `policy`, return freq% of big(100) and rare(200).
struct Freq { double big; double rare; };

Freq RunPolicy(PrioritySchedulerEngine& engine, const char* policy, int iters)
{
    // SwitchPolicyByName is lazy (applied on the next NextSeedId) — fine here:
    // the first of the N draws below applies it, the rest run under `policy`.
    bool ok = engine.SwitchPolicyByName(policy);
    if (!ok) {
        std::printf("  [FAIL] policy not registered: %s\n", policy);
        return {-1, -1};
    }
    std::map<uint64_t, long> tally;
    for (int i = 0; i < iters; ++i) {
        auto id = engine.NextSeedId();
        if (id.has_value()) tally[id->seed_id]++;
    }
    const double big  = 100.0 * static_cast<double>(tally[100]) / iters;
    const double rare = 100.0 * static_cast<double>(tally[200]) / iters;
    std::printf("  %-16s big(id100,size40)=%5.1f%%  rare(id200,size3)=%5.1f%%\n",
                policy, big, rare);
    return {big, rare};
}

}  // namespace

int main()
{
    InMemoryCorpusStore store;
    PrioritySchedulerEngine engine(&store);
    engine.RegisterPolicy("priority", std::make_unique<PriorityPolicy>());
    engine.RegisterPolicy("round_robin", std::make_unique<RoundRobinPolicy>());
    engine.RegisterPolicy("uniform", std::make_unique<UniformPolicy>());
    engine.RegisterPolicy("size_weighted", std::make_unique<SizeWeightedPolicy>());
    engine.RegisterPolicy("rarity_weighted", std::make_unique<RarityWeightedPolicy>());

    std::vector<uint64_t> common;       // 40 common PCs [0,40)
    for (uint64_t pc = 0; pc < 40; ++pc) common.push_back(pc);

    auto add = [&](Seed s) {
        const uint64_t id = s.seed_id;
        store.AddSeed(std::move(s));
        engine.OnSeedAdded(id);  // engine looks up cover from store → seed_cover_/pc_count_
    };

    for (uint64_t i = 1; i <= 30; ++i) add(MakeSeed(i, common));         // fillers
    add(MakeSeed(100, common));                                          // big (common)
    add(MakeSeed(200, {9000, 9001, 9002}));                             // rare (unique)

    const int N = 200000;
    std::printf("scheduler_policy_bias_test (%d draws each):\n", N);
    const Freq uni = RunPolicy(engine, "uniform", N);
    const Freq sz  = RunPolicy(engine, "size_weighted", N);
    const Freq rar = RunPolicy(engine, "rarity_weighted", N);
    RunPolicy(engine, "priority", N);     // expect rare≈100% (last-added tail)
    RunPolicy(engine, "round_robin", N);

    int fails = 0;
    auto check = [&](bool cond, const char* msg) {
        std::printf("  %s %s\n", cond ? "[PASS]" : "[FAIL]", msg);
        if (!cond) ++fails;
    };
    // uniform: big ≈ rare (both ~1/32 ≈ 3.1%), within a loose band.
    check(uni.big > 1.5 && uni.big < 5.0 && uni.rare > 1.5 && uni.rare < 5.0,
          "uniform: big and rare both ~flat (1.5..5%)");
    // size_weighted: big covers 40 PCs, rare 3 → big picked far more than rare.
    check(sz.big > sz.rare * 3.0, "size_weighted: big >> rare (size bias)");
    // rarity_weighted: rare(3 unique, w=3.0) beats big(40 common, w≈1.3) → inversion.
    check(rar.rare > rar.big, "rarity_weighted: rare > big (rarity inversion vs size)");
    // sanity: the SAME rare seed is rarer under size than under rarity.
    check(rar.rare > sz.rare, "rare seed favored more by rarity than by size");

    std::printf("%s (%d failures)\n", fails == 0 ? "ALL OK" : "FAILED", fails);
    return fails == 0 ? 0 : 1;
}

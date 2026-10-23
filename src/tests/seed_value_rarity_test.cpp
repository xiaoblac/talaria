// reFuzz seed-value signal A — RarityScore helper + PrioritySchedulerEngine::
// SeedRarityScore oracle (docs/plans/seed-value-signals.md §2.1).
//
//   rarity(seed) = Σ_{pc ∈ cover} 1 / max(pc_count(pc), 1)
//
// Two layers:
//   (1) the pure RarityScore helper — exact arithmetic on known inputs;
//   (2) the engine seam — same fixture as scheduler_policy_bias_test, asserting
//       SeedRarityScore returns the exact Σ over the live pc_count, that an
//       engine without a corpus_store returns 0, and unknown seeds return 0.

#include "refuzz/corpus/corpus_store.hpp"
#include "refuzz/program/seed.hpp"
#include "refuzz/program/seed_metadata.hpp"
#include "refuzz/scheduler/engine/priority_scheduler_engine.hpp"
#include "refuzz/scheduler/rarity_score.hpp"

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <unordered_map>
#include <vector>

using namespace refuzz::fuzzer;

namespace {

#define CHECK(expr)                                                         \
    do {                                                                    \
        if (!(expr)) {                                                      \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,    \
                         #expr);                                            \
            std::abort();                                                   \
        }                                                                   \
    } while (0)

bool Near(double a, double b) { return std::fabs(a - b) < 1e-9; }

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

} // namespace

int main()
{
    // ---- (1) pure helper ----
    {
        std::unordered_map<uint64_t, uint32_t> empty;
        CHECK(Near(RarityScore({}, empty), 0.0));            // no cover → 0
        CHECK(Near(RarityScore({1, 2, 3}, empty), 3.0));     // missing → cnt 1
    }
    {
        std::unordered_map<uint64_t, uint32_t> pc = {{1, 4}};
        CHECK(Near(RarityScore({1, 1}, pc), 0.5));           // 1/4 + 1/4
    }
    {
        std::unordered_map<uint64_t, uint32_t> pc = {{5, 2}, {6, 0}};
        CHECK(Near(RarityScore({5, 6}, pc), 1.5));           // 1/2 + (0→1)=1.0
    }

    // ---- (2) engine seam ----
    InMemoryCorpusStore store;
    PrioritySchedulerEngine engine(&store);

    std::vector<uint64_t> common;  // 40 common PCs [0,40)
    for (uint64_t pc = 0; pc < 40; ++pc) common.push_back(pc);

    auto add = [&](Seed s) {
        const uint64_t id = s.seed_id;
        store.AddSeed(std::move(s));
        engine.OnSeedAdded(id);  // engine caches cover + bumps pc_count
    };

    for (uint64_t i = 1; i <= 30; ++i) add(MakeSeed(i, common));  // 30 fillers
    add(MakeSeed(100, common));                                  // big (common)
    add(MakeSeed(200, {9000, 9001, 9002}));                      // rare (unique)

    // Each common PC is covered by 30 fillers + big = 31 seeds. The rare seed's
    // 3 PCs are covered by 1 seed each.
    const double big_expected  = 40.0 / 31.0;  // 40 common PCs, count 31 each
    const double rare_expected = 3.0;           // 3 unique PCs, count 1 each

    CHECK(Near(engine.SeedRarityScore(100), big_expected));
    CHECK(Near(engine.SeedRarityScore(200), rare_expected));
    CHECK(Near(engine.SeedRarityScore(1), big_expected));   // a filler == big
    CHECK(engine.SeedRarityScore(200) > engine.SeedRarityScore(100));  // inversion
    CHECK(Near(engine.SeedRarityScore(999), 0.0));          // unknown seed → 0

    // Engine without a corpus_store never caches cover → always 0.
    PrioritySchedulerEngine no_store;
    no_store.OnSeedAdded(100);  // no store → seed_cover_ stays empty
    CHECK(Near(no_store.SeedRarityScore(100), 0.0));

    std::printf("seed_value_rarity_test: OK (big=%.4f rare=%.4f)\n",
                engine.SeedRarityScore(100), engine.SeedRarityScore(200));
    return 0;
}

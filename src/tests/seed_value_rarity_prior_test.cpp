// reFuzz seed-value signal A — cold-arm rarity prior oracle.
//
// The treatment arm of the rarity A/B: when the seed-MAB registers a NEW seed's
// arm, instead of Ĝ₀=0 it starts at Ĝ₀ = α·clamp(rarity/mean_rarity − 1, 0, cap)
// — a decaying foresight head-start for rare-coverage seeds. α=0 (baseline) must
// leave every arm at Ĝ₀=0. This checks the prior is computed, rarity-ordered,
// and off when α=0.

#include "refuzz/scheduler/policy/mab_exp3ix_policy.hpp"
#include "refuzz/scheduler/scheduling_context.hpp"

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <random>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace refuzz::fuzzer;

#define CHECK(expr)                                                         \
    do {                                                                    \
        if (!(expr)) {                                                      \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,    \
                         #expr);                                            \
            std::abort();                                                   \
        }                                                                   \
    } while (0)

namespace {

bool Near(double a, double b) { return std::fabs(a - b) < 1e-9; }

// Register all ready seeds as arms (one Next() pass) under the given α, then
// return the policy so the test can read each arm's Ĝ (= its cold-arm prior,
// since no rewards have been settled yet).
void RegisterAll(MabExp3IxPolicy& pol,
                 const std::unordered_map<uint64_t, std::vector<uint64_t>>& cover,
                 const std::unordered_map<uint64_t, std::uint32_t>& pc_count,
                 std::vector<uint64_t> ready)
{
    std::deque<uint64_t> boosted;
    std::unordered_set<uint64_t> cooled;
    std::size_t cursor = 0;
    std::mt19937_64 rng(123);
    SchedulerContext ctx{ready, boosted, cooled, cursor};
    ctx.seed_cover = &cover;
    ctx.pc_count = &pc_count;
    ctx.rng = &rng;
    (void)pol.Next(ctx);  // one pass registers every ready arm with its prior
}

} // namespace

int main()
{
    // Fixture: 5 "common" seeds (cover 3 PCs each covered by 6 seeds → rarity
    // 3·1/6 = 0.5) and 1 "rare" seed (2 unique PCs covered once → rarity 2·1/1 =
    // 2.0). ready order puts the rare seed LAST so the running mean (0.5) is
    // built from the commons first → its boost = 2.0/0.5 − 1 = 3.0.
    std::unordered_map<uint64_t, std::vector<uint64_t>> cover;
    for (uint64_t id = 1; id <= 5; ++id) cover[id] = {100, 101, 102};
    cover[200] = {9000, 9001};
    std::unordered_map<uint64_t, std::uint32_t> pc_count = {
        {100, 6}, {101, 6}, {102, 6}, {9000, 1}, {9001, 1}};
    const std::vector<uint64_t> ready = {1, 2, 3, 4, 5, 200};

    // α = 2.0 → rare seed Ĝ₀ = 2·3 = 6.0; commons Ĝ₀ = 0 (at/below mean).
    {
        MabExp3IxPolicy pol(/*rarity_prior_alpha=*/2.0);
        RegisterAll(pol, cover, pc_count, ready);
        CHECK(Near(pol.SeedMabGhat(200), 6.0));
        CHECK(Near(pol.SeedMabGhat(1), 0.0));
        CHECK(pol.SeedMabGhat(200) > pol.SeedMabGhat(3));  // rare > common
    }

    // α = 1.0 → linear in α: rare seed Ĝ₀ = 1·3 = 3.0.
    {
        MabExp3IxPolicy pol(/*rarity_prior_alpha=*/1.0);
        RegisterAll(pol, cover, pc_count, ready);
        CHECK(Near(pol.SeedMabGhat(200), 3.0));
        CHECK(Near(pol.SeedMabGhat(2), 0.0));
    }

    // α = 0 (baseline) → every arm Ĝ₀ = 0, no prior at all.
    {
        MabExp3IxPolicy pol;  // default α=0
        RegisterAll(pol, cover, pc_count, ready);
        CHECK(Near(pol.SeedMabGhat(200), 0.0));
        CHECK(Near(pol.SeedMabGhat(1), 0.0));
    }

    // Defensive: missing seed_cover/pc_count → no prior even with α>0.
    {
        MabExp3IxPolicy pol(/*rarity_prior_alpha=*/2.0);
        std::vector<uint64_t> ready2 = {200};
        std::deque<uint64_t> boosted;
        std::unordered_set<uint64_t> cooled;
        std::size_t cursor = 0;
        std::mt19937_64 rng(7);
        SchedulerContext ctx{ready2, boosted, cooled, cursor};
        ctx.rng = &rng;  // seed_cover / pc_count left null
        (void)pol.Next(ctx);
        CHECK(Near(pol.SeedMabGhat(200), 0.0));
    }

    std::printf("seed_value_rarity_prior_test: OK\n");
    return 0;
}

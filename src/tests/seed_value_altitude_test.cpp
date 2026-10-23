// reFuzz seed-value signal C — ComputeStateAltitude oracle.
//
// Verifies the state-space-altitude computation over the syz IR (docs/plans/
// seed-value-signals.md §2.3) and the IMutatorEngine::AnalyzeStateAltitude
// seam. Strategy: generate real programs with SyzV2MutatorEngine, then compare
// ComputeStateAltitude against an INDEPENDENT in-test reference. The reference
// computes producers/consumers/kinds by a direct walk, and max-depth by FORWARD
// longest-path over the uses() edges — the opposite traversal to the impl's
// backward res() walk — so a matching result is a genuine cross-check, not a
// tautology.

#include "refuzz/mutator/linux/syz_v2/engines/syz_v2_engine.hpp"
#include "refuzz/mutator/mutator_manager.hpp"
#include "refuzz/program/artifact.hpp"
#include "refuzz/program/seed.hpp"
#include "refuzz/program/state_altitude.hpp"
#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/state_altitude.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/type.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace {

#define CHECK(expr)                                                         \
    do {                                                                    \
        if (!(expr)) {                                                      \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,    \
                         #expr);                                            \
            std::abort();                                                   \
        }                                                                   \
    } while (0)

namespace syz = refuzz::program::syz;
namespace pr  = refuzz::program;

// Independent const walker over the 4 nesting Arg kinds (separate code from the
// impl's private walker — drift in either is caught by the comparison).
void WalkResultArgs(const syz::Arg* a,
                    const std::function<void(const syz::ResultArg*)>& f)
{
    if (a == nullptr) return;
    switch (a->arg_kind()) {
        case syz::ArgKind::kResult:
            f(static_cast<const syz::ResultArg*>(a));
            break;
        case syz::ArgKind::kPointer:
            WalkResultArgs(syz::as_pointer_arg(a)->res(), f);
            break;
        case syz::ArgKind::kGroup:
            for (const auto& c : syz::as_group_arg(a)->inner()) {
                WalkResultArgs(c.get(), f);
            }
            break;
        case syz::ArgKind::kUnion:
            WalkResultArgs(syz::as_union_arg(a)->option(), f);
            break;
        default:
            break;
    }
}

// Independent reference altitude.
pr::StateAltitude Reference(const syz::Prog& prog)
{
    pr::StateAltitude ref;
    const auto& calls = prog.calls();
    const std::size_t n = calls.size();

    // Producer rets and their call index.
    std::unordered_map<const syz::ResultArg*, std::size_t> producer_call;
    std::unordered_set<std::string> kinds;
    for (std::size_t i = 0; i < n; ++i) {
        const syz::ResultArg* ret = calls[i]->ret();
        if (ret == nullptr) continue;
        if (const syz::ResourceType* rt = syz::as_resource(ret->type())) {
            producer_call.emplace(ret, i);
            ++ref.resource_producers;
            if (rt->desc() != nullptr) kinds.insert(rt->desc()->name());
        }
    }
    ref.distinct_kinds = static_cast<std::uint32_t>(kinds.size());

    // Consumer args and their owning call index.
    std::unordered_map<const syz::ResultArg*, std::size_t> consumer_owner;
    for (std::size_t i = 0; i < n; ++i) {
        for (const auto& arg : calls[i]->args()) {
            WalkResultArgs(arg.get(), [&](const syz::ResultArg* ra) {
                if (ra->res() != nullptr) {
                    ++ref.resource_consumers;
                    consumer_owner.emplace(ra, i);
                }
            });
        }
    }

    // FORWARD longest path: producer ret R at call i → its consumers (R.uses())
    // → each consumer's owning call j → edge i→j. Longest path = max depth.
    std::vector<std::vector<std::size_t>> fwd(n);
    for (const auto& [ret, i] : producer_call) {
        for (const syz::ResultArg* c : ret->uses()) {
            auto it = consumer_owner.find(c);
            if (it != consumer_owner.end()) {
                fwd[i].push_back(it->second);
            }
        }
    }
    std::vector<int> longest(n, -1);
    std::function<int(std::size_t)> lp = [&](std::size_t i) -> int {
        if (longest[i] >= 0) return longest[i];
        longest[i] = 0;  // tentative (acyclic DAG)
        int best = 0;
        for (std::size_t j : fwd[i]) best = std::max(best, lp(j) + 1);
        longest[i] = best;
        return best;
    };
    int max_depth = 0;
    for (std::size_t i = 0; i < n; ++i) max_depth = std::max(max_depth, lp(i));
    ref.max_dependency_depth = static_cast<std::uint32_t>(max_depth);

    return ref;
}

std::size_t TotalResultArgs(const syz::Prog& prog)
{
    std::size_t total = 0;
    for (const auto& call : prog.calls()) {
        if (call->ret() != nullptr) ++total;  // counted as a ResultArg
        for (const auto& arg : call->args()) {
            WalkResultArgs(arg.get(), [&](const syz::ResultArg*) { ++total; });
        }
    }
    return total;
}

void Eq(const pr::StateAltitude& a, const pr::StateAltitude& b)
{
    CHECK(a.resource_producers == b.resource_producers);
    CHECK(a.resource_consumers == b.resource_consumers);
    CHECK(a.distinct_kinds == b.distinct_kinds);
    CHECK(a.max_dependency_depth == b.max_dependency_depth);
}

} // namespace

int main()
{
    const auto& target = syz::Target::linux_amd64();

    std::uint64_t progs_checked = 0;
    std::uint64_t with_chain    = 0;  // progs where a producer feeds a consumer

    // Build the engine ONCE (ChoiceTable build is expensive); the engine's
    // master rng makes successive Generate() calls produce distinct programs.
    auto engine = std::make_unique<refuzz::fuzzer::SyzV2MutatorEngine>(
        target, /*corpus_store=*/nullptr, /*master_seed=*/0xA17ABULL);
    refuzz::fuzzer::MutatorManager manager;
    manager.AddEngine(std::move(engine), /*activate=*/true);
    auto& eng = manager.Handle().Get();

    for (std::uint64_t i = 0; i < 400; ++i) {
        auto res = eng.Generate();
        if (res.status != pr::MutationStatus::kOk || !res.artifact.valid()) {
            continue;
        }
        auto prog = res.artifact.As<syz::Prog>();
        if (!prog || prog->calls().empty()) {
            continue;
        }
        ++progs_checked;

        const pr::StateAltitude got = syz::ComputeStateAltitude(*prog);
        const pr::StateAltitude ref = Reference(*prog);
        Eq(got, ref);

        // Seam: engine.AnalyzeStateAltitude(artifact) must equal the direct fn.
        auto via_seam = eng.AnalyzeStateAltitude(res.artifact);
        CHECK(via_seam.has_value());
        Eq(*via_seam, got);

        // Structural bounds.
        const std::size_t ncalls = prog->calls().size();
        const std::size_t total_ra = TotalResultArgs(*prog);
        CHECK(got.max_dependency_depth <= ncalls);
        CHECK(got.resource_producers <= total_ra);
        CHECK(got.resource_consumers <= total_ra);
        CHECK(got.distinct_kinds <= got.resource_producers);
        // depth>0 ⇔ at least one consumer links to a mapped producer ret.
        if (got.max_dependency_depth > 0) {
            CHECK(got.resource_consumers > 0 && got.resource_producers > 0);
            ++with_chain;
        }
    }

    CHECK(progs_checked > 0);

    // Invalid artifact → no value (non-syz / empty path default).
    {
        refuzz::program::ProgramArtifact invalid;  // default = invalid
        auto engine = std::make_unique<refuzz::fuzzer::SyzV2MutatorEngine>(
            target, /*corpus_store=*/nullptr, /*master_seed=*/1);
        refuzz::fuzzer::MutatorManager manager;
        manager.AddEngine(std::move(engine), /*activate=*/true);
        auto out = manager.Handle().Get().AnalyzeStateAltitude(invalid);
        CHECK(!out.has_value());
    }

    std::printf(
        "seed_value_altitude_test: OK (progs=%llu, with_dependency_chain=%llu)\n",
        static_cast<unsigned long long>(progs_checked),
        static_cast<unsigned long long>(with_chain));
    return 0;
}

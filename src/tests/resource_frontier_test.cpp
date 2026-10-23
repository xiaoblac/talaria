// Copyright 2026 reFuzz project author -------youngkk.
//
// AnalyzeResourceFrontier unit test + the full extraction→model→Future chain.
// Generates real programs, then checks the frontier (produced types + realized
// (type → consumer) edges) against an INDEPENDENT walker, and confirms every
// produced type scores a finite future via the SeedHorizonModel.

#include "refuzz/program/syz/state_altitude.hpp"
#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/type.hpp"
#include "refuzz/program/artifact.hpp"
#include "refuzz/mutator/linux/syz_v2/engines/syz_v2_engine.hpp"
#include "refuzz/mutator/mutator_manager.hpp"
#include "refuzz/scheduler/horizon/seed_horizon_model.hpp"

#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace syz = refuzz::program::syz;
namespace pr  = refuzz::program;

namespace {
// Independent const walker (separate code from the impl's private one).
void Walk(const syz::Arg* a, const std::function<void(const syz::ResultArg*)>& f)
{
    if (a == nullptr) return;
    switch (a->arg_kind()) {
        case syz::ArgKind::kResult: f(static_cast<const syz::ResultArg*>(a)); break;
        case syz::ArgKind::kPointer: Walk(syz::as_pointer_arg(a)->res(), f); break;
        case syz::ArgKind::kGroup:
            for (const auto& c : syz::as_group_arg(a)->inner()) Walk(c.get(), f);
            break;
        case syz::ArgKind::kUnion: Walk(syz::as_union_arg(a)->option(), f); break;
        default: break;
    }
}
}  // namespace

int main()
{
    std::fprintf(stdout, "Running resource_frontier_test...\n");
    const auto& target = syz::Target::linux_amd64();

    refuzz::fuzzer::SeedHorizonModel model;
    model.BuildFromTarget(target);
    model.ComputeMass([](int, int) { return false; }, /*gamma=*/0.5, /*depth=*/1);

    auto engine = std::make_unique<refuzz::fuzzer::SyzV2MutatorEngine>(
        target, /*corpus_store=*/nullptr, /*master_seed=*/0xF1037ULL);
    refuzz::fuzzer::MutatorManager manager;
    manager.AddEngine(std::move(engine), /*activate=*/true);
    auto& eng = manager.Handle().Get();

    std::uint64_t checked = 0, with_prod = 0, with_edge = 0;
    for (std::uint64_t i = 0; i < 400; ++i) {
        auto res = eng.Generate();
        if (res.status != pr::MutationStatus::kOk || !res.artifact.valid()) continue;
        auto prog = res.artifact.As<syz::Prog>();
        if (!prog || prog->calls().empty()) continue;
        ++checked;

        const syz::SeedResourceFrontier fr = syz::AnalyzeResourceFrontier(*prog);

        // ── independent reference: produced names + realized (type,consumer) edges ──
        std::set<std::string> ref_prod;
        std::unordered_map<const syz::ResultArg*, std::string> ptype;
        for (const auto& c : prog->calls()) {
            const syz::ResultArg* ret = c->ret();
            if (ret) {
                if (const syz::ResourceType* rt = syz::as_resource(ret->type())) {
                    if (rt->desc()) {
                        ptype.emplace(ret, rt->desc()->name());
                        ref_prod.insert(rt->desc()->name());
                    }
                }
            }
        }
        // Edge key = the CONSUMER'S declared wanted type (ra->type()), not the
        // producer's type — must match the fixed AnalyzeResourceFrontier.
        (void)ptype;  // produced-set only; edges no longer use producer types
        std::set<std::pair<std::string, std::string>> ref_edge;
        for (const auto& c : prog->calls()) {
            if (!c->meta()) continue;
            const std::string& s = c->meta()->name();
            for (const auto& arg : c->args()) {
                Walk(arg.get(), [&](const syz::ResultArg* ra) {
                    if (!ra->res()) return;
                    const syz::ResourceType* wt = syz::as_resource(ra->type());
                    if (wt && wt->desc()) ref_edge.emplace(wt->desc()->name(), s);
                });
            }
        }

        // ── frontier must equal the independent reference (as sets, no dups) ──
        std::set<std::string> got_prod(fr.produced.begin(), fr.produced.end());
        std::set<std::pair<std::string, std::string>> got_edge(
            fr.realized_edges.begin(), fr.realized_edges.end());
        assert(got_prod == ref_prod);
        assert(got_edge == ref_edge);
        assert(got_prod.size() == fr.produced.size());        // impl emits no dup
        assert(got_edge.size() == fr.realized_edges.size());

        if (!fr.produced.empty()) ++with_prod;
        if (!fr.realized_edges.empty()) ++with_edge;

        // ── full chain: produced names → model ids → finite future ──
        std::vector<int> ids;
        for (const auto& n : fr.produced) {
            const int id = model.ResId(n);
            if (id >= 0) ids.push_back(id);
        }
        const double f = model.Future(ids);
        assert(std::isfinite(f) && f >= 0.0);
    }

    assert(checked > 0 && with_prod > 0);
    std::fprintf(stdout, "  checked=%llu progs, with_producer=%llu, with_edge=%llu\n",
                 static_cast<unsigned long long>(checked),
                 static_cast<unsigned long long>(with_prod),
                 static_cast<unsigned long long>(with_edge));
    std::fprintf(stdout, "resource_frontier_test: OK\n");
    return 0;
}

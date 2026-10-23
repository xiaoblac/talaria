// Signal C — state-space altitude over the syz IR. See header.

#include "refuzz/program/syz/state_altitude.hpp"

#include "refuzz/program/syz/arg.hpp"
#include "refuzz/program/syz/prog.hpp"
#include "refuzz/program/syz/target.hpp"  // SyscallMeta full def (consumer name)
#include "refuzz/program/syz/type.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace refuzz::program::syz {

namespace {

// Const recursive walk over the 4 Arg kinds that can nest a ResultArg
// (pointer pointee, group inner, union option, the leaf itself). Mirrors the
// established walker in result_arg_uses_invariant_test.cpp — kept local so the
// "I wrote my own walker and forgot a kind" trap can't drift in.
void ForEachResultArg(const Arg* a,
                      const std::function<void(const ResultArg*)>& visit)
{
    if (a == nullptr) {
        return;
    }
    switch (a->arg_kind()) {
        case ArgKind::kResult:
            visit(static_cast<const ResultArg*>(a));
            break;
        case ArgKind::kPointer:
            ForEachResultArg(as_pointer_arg(a)->res(), visit);
            break;
        case ArgKind::kGroup:
            for (const auto& child : as_group_arg(a)->inner()) {
                ForEachResultArg(child.get(), visit);
            }
            break;
        case ArgKind::kUnion:
            ForEachResultArg(as_union_arg(a)->option(), visit);
            break;
        default:
            break;  // const / data: no nested ResultArg
    }
}

} // namespace

::refuzz::program::StateAltitude ComputeStateAltitude(const Prog& prog)
{
    ::refuzz::program::StateAltitude alt;
    const auto& calls = prog.calls();
    const std::size_t n = calls.size();

    // (1) Producers: resource-typed call returns. Map ret ptr → call index so
    //     consumers can resolve the producing call for the depth chain.
    std::unordered_map<const ResultArg*, std::size_t> producer_call;
    std::unordered_set<std::string> kinds;
    for (std::size_t i = 0; i < n; ++i) {
        const ResultArg* ret = calls[i]->ret();
        if (ret == nullptr) {
            continue;
        }
        if (const ResourceType* rt = as_resource(ret->type())) {
            producer_call.emplace(ret, i);
            ++alt.resource_producers;
            if (rt->desc() != nullptr) {
                kinds.insert(rt->desc()->name());
            }
        }
    }
    alt.distinct_kinds = static_cast<std::uint32_t>(kinds.size());

    // (2) Consumers: ResultArgs anywhere in the args that reference a producer
    //     (res() != null). Record, per call, the producer-call indices it
    //     depends on (those whose ret we mapped above).
    std::vector<std::vector<std::size_t>> deps(n);
    for (std::size_t i = 0; i < n; ++i) {
        for (const auto& arg : calls[i]->args()) {
            ForEachResultArg(arg.get(), [&](const ResultArg* ra) {
                if (ra->res() == nullptr) {
                    return;
                }
                ++alt.resource_consumers;
                auto it = producer_call.find(ra->res());
                if (it != producer_call.end()) {
                    deps[i].push_back(it->second);
                }
            });
        }
    }

    // (3) Longest producer→consumer chain. deps is acyclic for a valid prog
    //     (producers precede consumers), but guard cycles defensively.
    std::vector<int> depth(n, -1);
    std::vector<char> on_stack(n, 0);
    std::function<int(std::size_t)> dep = [&](std::size_t i) -> int {
        if (depth[i] >= 0) {
            return depth[i];
        }
        if (on_stack[i] != 0) {
            return 0;  // cycle guard (should not happen)
        }
        on_stack[i] = 1;
        int best = 0;
        for (const std::size_t p : deps[i]) {
            best = std::max(best, dep(p) + 1);
        }
        on_stack[i] = 0;
        depth[i] = best;
        return best;
    };
    int max_depth = 0;
    for (std::size_t i = 0; i < n; ++i) {
        max_depth = std::max(max_depth, dep(i));
    }
    alt.max_dependency_depth = static_cast<std::uint32_t>(max_depth);

    return alt;
}

SeedResourceFrontier AnalyzeResourceFrontier(const Prog& prog)
{
    SeedResourceFrontier fr;
    const auto& calls = prog.calls();

    // Producers: resource-typed call returns → the produced-type set.
    std::unordered_set<std::string> produced_seen;
    for (const auto& c : calls) {
        const ResultArg* ret = c->ret();
        if (ret == nullptr) {
            continue;
        }
        if (const ResourceType* rt = as_resource(ret->type())) {
            if (rt->desc() != nullptr &&
                produced_seen.insert(rt->desc()->name()).second) {
                fr.produced.push_back(rt->desc()->name());
            }
        }
    }

    // Realized handoffs: a ResultArg in a call's args that is WIRED to a producer
    // (res() != null) → edge (the CONSUMER'S declared wanted type, this syscall).
    // The key is the consumer's arg type (ra->type()), NOT the producer's type, so
    // a subtype fed into a generic slot realizes the generic (W, consumer) handoff
    // and decays the generic frontier — matching the (W, call) mask key in
    // SeedHorizonModel::ComputeMass. Deduped.
    std::set<std::pair<std::string, std::string>> edge_seen;
    for (const auto& c : calls) {
        if (c->meta() == nullptr) {
            continue;
        }
        const std::string& consumer = c->meta()->name();
        for (const auto& arg : c->args()) {
            ForEachResultArg(arg.get(), [&](const ResultArg* ra) {
                if (ra->res() == nullptr) {
                    return;  // not wired to a producer → no realized handoff
                }
                const ResourceType* wt = as_resource(ra->type());  // consumer-wanted W
                if (wt == nullptr || wt->desc() == nullptr) {
                    return;
                }
                const std::string& w = wt->desc()->name();
                if (edge_seen.emplace(w, consumer).second) {
                    fr.realized_edges.emplace_back(w, consumer);
                }
            });
        }
    }
    return fr;
}

} // namespace refuzz::program::syz

// Copyright 2026 reFuzz project author -------youngkk.
//
// SeedHorizonModel unit test (docs/plans/structural-horizon-seed-value.md:
// SpecHorizon-RD-CORE). A tiny HAND-COMPUTED graph pins the scoring math exactly
// (leaf, hub-discount, inverse-producer, novelty mask, Katz recursion); a real-
// Target pass confirms non-degeneracy + the de-flattening on the live spec.

#include "refuzz/scheduler/horizon/seed_horizon_model.hpp"
#include "refuzz/program/syz/target.hpp"
#include "refuzz/program/syz/type.hpp"

#include <cassert>
#include <cmath>
#include <cstdio>
#include <set>
#include <string>
#include <vector>

using refuzz::fuzzer::SeedHorizonModel;

namespace {
bool close(double a, double b) { return std::fabs(a - b) < 1e-9; }
bool none(int, int) { return false; }  // nothing realized → all handoffs novel
}  // namespace

int main()
{
    std::fprintf(stdout, "Running seed_horizon_model_test...\n");

    // ── hand-computed graph: a generic `fd` hub (2 producers, 3 consumers) and a
    //    specific `special` subtype (1 producer, 1 consumer; chain [fd,special]) ──
    {
        SeedHorizonModel m;
        m.AddResource("fd", {"fd"});
        m.AddResource("special", {"fd", "special"});
        m.AddSyscall("make_fd_a", {"fd"}, {});
        m.AddSyscall("make_fd_b", {"fd"}, {});
        m.AddSyscall("make_special", {"special"}, {});
        m.AddSyscall("use_fd_1", {}, {"fd"});
        m.AddSyscall("use_fd_2", {}, {"fd"});
        m.AddSyscall("use_fd_3", {}, {"fd"});
        m.AddSyscall("use_special", {}, {"special"});  // call id 6
        m.Finalize();

        const int fd = m.ResId("fd"), sp = m.ResId("special");
        assert(fd >= 0 && sp >= 0);
        assert(m.producer_count(fd) == 2 && m.consumer_count(fd) == 3);
        assert(m.producer_count(sp) == 1 && m.consumer_count(sp) == 1);

        // depth 0 (leaf only):
        //   leaf(fd)      = (1/3)*3                 = 1.0 ; nmass = 1.0/2 = 0.5
        //   leaf(special) = (1/3)*3 + (1/1)*1       = 2.0 ; nmass = 2.0/1 = 2.0
        m.ComputeMass(none, /*gamma=*/0.5, /*depth=*/0);
        assert(close(m.nmass(fd), 0.5));
        assert(close(m.nmass(sp), 2.0));
        assert(close(m.Future({fd}), 0.5));
        assert(close(m.Future({sp}), 2.0));  // specific rare type 4x the generic hub

        // novelty mask: realize the (special, use_special) handoff → special's own
        // consumer is no longer novel → leaf(special) = 1.0 (only the fd part).
        auto mask = [&](int r, int s) { return r == sp && s == 6; };
        m.ComputeMass(mask, 0.5, 0);
        assert(close(m.nmass(sp), 1.0));  // novelty decay
        assert(close(m.nmass(fd), 0.5));  // unaffected
    }

    // ── Katz recursion (depth 1): use_special now PRODUCES `derived` ──
    {
        SeedHorizonModel m;
        m.AddResource("fd", {"fd"});
        m.AddResource("special", {"fd", "special"});
        m.AddResource("derived", {"derived"});
        m.AddSyscall("make_fd_a", {"fd"}, {});
        m.AddSyscall("make_fd_b", {"fd"}, {});
        m.AddSyscall("make_special", {"special"}, {});
        m.AddSyscall("use_fd_1", {}, {"fd"});
        m.AddSyscall("use_fd_2", {}, {"fd"});
        m.AddSyscall("use_fd_3", {}, {"fd"});
        m.AddSyscall("use_special", {"derived"}, {"special"});  // produces derived
        m.AddSyscall("use_derived", {}, {"derived"});
        m.Finalize();
        const int fd = m.ResId("fd"), sp = m.ResId("special"), dv = m.ResId("derived");

        m.ComputeMass(none, 0.5, 0);
        assert(close(m.nmass(sp), 2.0));  // depth 0: the new edge is not yet followed
        m.ComputeMass(none, 0.5, 1);
        // depth 1 adds γ * nmass0(derived) = 0.5 * 1.0 to special → 2.5
        assert(close(m.nmass(sp), 2.5));
        assert(close(m.nmass(fd), 0.5));  // fd's consumers produce nothing → no lift
        assert(close(m.nmass(dv), 1.0));
    }

    // ── real spec: non-degeneracy + de-flattening on the live Target ──
    {
        const auto& target = refuzz::program::syz::Target::linux_amd64();
        SeedHorizonModel m;
        m.BuildFromTarget(target);  // the adapter under test
        assert(m.num_resources() > 500);

        m.ComputeMass(none, 0.5, 1);
        std::set<long long> distinct;
        for (int r = 0; r < m.num_resources(); ++r) {
            distinct.insert(std::llround(m.nmass(r) * 1e6));
        }
        assert(distinct.size() > 100);  // Layer-A flat had ~89; this must beat it

        const int fd = m.ResId("fd");
        const int kvmvm = m.ResId("fd_kvmvm");  // 1 producer, specific
        assert(fd >= 0 && kvmvm >= 0);
        assert(m.nmass(kvmvm) > m.nmass(fd));  // rare-specific outranks the fd hub

        std::fprintf(stdout,
                     "  real target: %d resources, %zu distinct nmass; "
                     "nmass(fd_kvmvm)=%.4f > nmass(fd)=%.4f\n",
                     m.num_resources(), distinct.size(), m.nmass(kvmvm), m.nmass(fd));
    }

    std::fprintf(stdout, "seed_horizon_model_test: OK\n");
    return 0;
}

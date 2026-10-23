// Copyright 2026 reFuzz project author -------youngkk.
//
// SeedHorizon component test: the live novelty mask + on-admit future(seed)
// scoring on a hand-computed graph — pre-fold scoring, realized-handoff decay,
// producer independence, and the recompute cadence.

#include "refuzz/scheduler/horizon/seed_horizon.hpp"
#include "refuzz/scheduler/horizon/seed_horizon_model.hpp"
#include "refuzz/program/syz/state_altitude.hpp"  // SeedResourceFrontier

#include <cassert>
#include <cmath>
#include <cstdio>
#include <string>
#include <vector>

using refuzz::fuzzer::SeedHorizon;
using refuzz::fuzzer::SeedHorizonModel;
using refuzz::program::syz::SeedResourceFrontier;

namespace {
bool close(double a, double b) { return std::fabs(a - b) < 1e-9; }

SeedHorizonModel TinyModel()
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
    m.AddSyscall("use_special", {}, {"special"});
    m.Finalize();
    return m;
}
}  // namespace

int main()
{
    std::fprintf(stdout, "Running seed_horizon_test...\n");

    // depth 0, recompute every admit → decay is observable immediately.
    SeedHorizon h(TinyModel(), {/*gamma=*/0.5, /*depth=*/0});

    // empty corpus: special=2.0 (rare specific), fd=0.5 (hub).
    assert(close(h.Score({"special"}), 2.0));
    assert(close(h.Score({"fd"}), 0.5));

    // admit a seed producing `special` that realizes (special → use_special).
    // future returned = the frontier it BORDERED (pre-fold) = 2.0.
    SeedResourceFrontier fr;
    fr.produced = {"special"};
    fr.realized_edges = {{"special", "use_special"}};
    assert(close(h.OnSeedAdmitted(fr), 2.0));

    // after fold (+recompute): special's own consumer realized → leaf drops the
    // (special) term → nmass(special)=1.0 ; fd untouched (no fd handoff realized).
    assert(close(h.Score({"special"}), 1.0));
    assert(close(h.Score({"fd"}), 0.5));

    // realizing an fd consumer decays fd: leaf(fd) = (1/3)*2, nmass = that / 2.
    SeedResourceFrontier fr2;
    fr2.produced = {"fd"};
    fr2.realized_edges = {{"fd", "use_fd_1"}};
    h.OnSeedAdmitted(fr2);
    assert(close(h.Score({"fd"}), (2.0 / 3.0) / 2.0));
    // COHERENT masking: realizing (fd, use_fd_1) ALSO decays special's fd-branch
    // (special borders use_fd_1 via its fd kind) → leaf(special) = (1/3)*2 [fd,
    // use_fd_2/3 novel] + 0 [special-branch already realized] = 2/3.
    assert(close(h.Score({"special"}), 2.0 / 3.0));

    // FRESHNESS (no stale-mask lag): the future RETURNED by OnSeedAdmitted (the
    // value that gets logged) reflects ALL prior seeds' folds immediately — nmass
    // is recomputed before scoring whenever the mask changed.
    {
        SeedHorizon hf(TinyModel(), {0.5, 0});
        SeedResourceFrontier a;  // seed A realizes special's own consumer
        a.produced = {"special"};
        a.realized_edges = {{"special", "use_special"}};
        assert(close(hf.OnSeedAdmitted(a), 2.0));  // scored pre-fold vs empty mask
        // seed B (produces special) admitted next: scored AFTER A's fold → special's
        // special-branch is realized → only the fd-branch remains → 1.0 immediately
        // (under the old cadence this stayed 2.0 until the Nth admit).
        SeedResourceFrontier b;
        b.produced = {"special"};
        assert(close(hf.OnSeedAdmitted(b), 1.0));
    }

    // ── MASK COHERENCE — the producer-vs-consumer key bug (drives the fix) ──
    //    A seed produces `special` (a SUBTYPE of fd, chain [fd,special]) and feeds
    //    it to the fd-consumers use_fd_1/2/3 (which declare-want `fd`). The handoff
    //    realized is keyed on the CONSUMER'S wanted type: (fd, use_fd_i). So every
    //    type bordering those consumers via its `fd` kind — including `special`'s
    //    fd-branch — must DECAY. Expected: special's fd-branch → 0, leaving only its
    //    own special-branch (1.0). Buggy code keys the mask on the producer type
    //    `special`, so the fd-branch never decays → 2.0.
    {
        SeedHorizon h(TinyModel(), {/*gamma=*/0.5, /*depth=*/0});
        SeedResourceFrontier fr;
        fr.produced = {"special"};
        fr.realized_edges = {{"fd", "use_fd_1"}, {"fd", "use_fd_2"}, {"fd", "use_fd_3"}};
        h.OnSeedAdmitted(fr);
        const double got = h.Score({"special"});
        std::fprintf(stdout, "  [mask-coherence] Score(special)=%.4f (correct=1.0)\n", got);
        assert(close(got, 1.0));
    }

    std::fprintf(stdout, "seed_horizon_test: OK\n");
    return 0;
}

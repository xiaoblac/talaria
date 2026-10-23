// Copyright 2026 reFuzz project author -------youngkk.
// Phase-A unit test: StaticBeliefGraph loads graph_M.tsv and scores a seed by unlock potential.

#include "refuzz/scheduler/horizon/static_belief_graph.hpp"

#include <cassert>
#include <cmath>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

static bool close(double a, double b) { return std::fabs(a - b) < 1e-6; }

int main()
{
    const char* p = "/tmp/_static_belief_graph_test.tsv";
    {
        std::ofstream o(p);
        o << "#V_A\tV_B\ttypes\tsource\trho\talpha\tbeta\trarity\tblindness\tmass\tweight\n";
        // CREATE_VCPU borders two frontier edges (unlock 0.36 + 0.30 = 0.66)
        o << "ioctl$KVM_CREATE_VCPU\tioctl$KVM_RUN\tcontainer\tstatic\t0.9\t3.6\t0.4\t1.0\t0.8\t0.5\t0.36\n";
        o << "ioctl$KVM_CREATE_VCPU\tioctl$KVM_GET_REGS\tcontainer\tstatic\t0.9\t3.6\t0.4\t1.0\t0.8\t0.5\t0.30\n";
        // SET_REGS borders one (0.34)
        o << "ioctl$KVM_SET_REGS\tioctl$KVM_RUN\tvalue-defuse-const\tstatic\t0.9\t3.6\t0.4\t0.5\t1.0\t0.75\t0.34\n";
    }

    refuzz::fuzzer::StaticBeliefGraph g;
    assert(g.LoadFromTsv(p));
    assert(g.edges() == 3);
    assert(g.variants() == 2);  // CREATE_VCPU, SET_REGS are the two SOURCE variants

    // a seed containing both high-unlock calls: 0.66 + 0.34 = 1.00
    assert(close(g.Score({"ioctl$KVM_CREATE_VCPU", "ioctl$KVM_SET_REGS"}), 1.00));
    // a seed with only the container source: 0.66
    assert(close(g.Score({"ioctl$KVM_CREATE_VCPU"}), 0.66));
    // an unknown / leaf call (no out-edges) contributes nothing
    assert(close(g.Score({"ioctl$UNKNOWN", "ioctl$KVM_RUN"}), 0.0));

    // [#2 canon] the S/P/R graph_M is $auto-canonicalized; a runtime $auto_X call must resolve to the
    // canonical $X node (Score/Observe canonicalize the lookup so frontier evidence consolidates on one
    // node). $auto_KVM_CREATE_VCPU -> KVM_CREATE_VCPU, same 0.66 unlock as the canonical name.
    assert(close(g.Score({"ioctl$auto_KVM_CREATE_VCPU"}), 0.66));

    // [Phase B] live frontier calibration ------------------------------------------------------------
    // CONFIRM: CREATE_VCPU ran and KVM_RUN reached new frontier. Edge CREATE_VCPU->KVM_RUN: α 3.6->4.6,
    // ρ 0.9->0.92, base 0.36/0.9=0.4 -> weight 0.368. The CREATE_VCPU->KVM_GET_REGS edge is unobserved
    // (GET_REGS not executed), so unlock[CREATE_VCPU] = 0.368 + 0.30 = 0.668.
    // new_by_variant: KVM_RUN produced new PC 1 (coarse fallback here — this graph has no sibling block
    // map, so Observe judges by "B produced any new", and region-precision is exercised separately below).
    g.Observe({"ioctl$KVM_CREATE_VCPU", "ioctl$KVM_RUN"}, {{"ioctl$KVM_RUN", {1}}});
    {
        auto st = g.stats();
        assert(st.confirmed == 1 && st.refuted == 0 && st.observed == 1);
    }
    assert(close(g.Score({"ioctl$KVM_CREATE_VCPU"}), 0.668));
    assert(close(g.Score({"ioctl$KVM_SET_REGS"}), 0.34));  // untouched (SET_REGS did not run)

    // REFUTE: CREATE_VCPU + both targets ran but produced NO new frontier -> both out-edges β++ (ρ
    // drops) AND both targets darken (headroom drops). unlock[CREATE_VCPU] falls below 0.668 (to ~0.465:
    // KVM_RUN edge 0.767*0.4*0.889 + GET_REGS edge 0.72*0.333*0.8).
    g.Observe({"ioctl$KVM_CREATE_VCPU", "ioctl$KVM_RUN", "ioctl$KVM_GET_REGS"}, {});
    {
        auto st = g.stats();
        assert(st.confirmed == 1 && st.refuted == 2 && st.observed == 3);
    }
    {
        const double s = g.Score({"ioctl$KVM_CREATE_VCPU"});
        assert(s > 0.46 && s < 0.47);
    }

    // HEADROOM (distinct from edge ρ): a target running dark with NO source edge touched still lowers its
    // in-edges' value via headroom alone. KVM_RUN has no out-edges, so the edge stats are unchanged, but
    // headroom(KVM_RUN) decays -> Score({CREATE_VCPU}) (which has an edge INTO KVM_RUN) drops further.
    {
        const double before = g.Score({"ioctl$KVM_CREATE_VCPU"});
        g.Observe({"ioctl$KVM_RUN"}, {});                  // KVM_RUN ran dark; no edge has it as source
        assert(g.stats().observed == 3);                   // edge-calibration tallies unchanged
        assert(g.Score({"ioctl$KVM_CREATE_VCPU"}) < before);  // pure headroom decay lowered the in-edge
    }

    // [region-precision] a separate graph in a dir WITH a sibling function_block_map.tsv. The edge A->B
    // carries R = {F_R}. Observe CONFIRMS only when B's new PC maps (FuncOf) into F_R; a new PC in
    // F_other (outside R) REFUTES (A ran, B ran, but the edge's predicted slice stayed dark).
    {
        std::filesystem::create_directories("/tmp/_sbg_rp");
        {
            std::ofstream o("/tmp/_sbg_rp/function_block_map.tsv");
            o << "1000\t5\tF_R\n2000\t5\tF_other\n";  // hex starts: F_R=[0x1000,0x2000), F_other=[0x2000,..)
        }
        {
            std::ofstream o("/tmp/_sbg_rp/graph_M.tsv");
            o << "#V_A\tV_B\ttypes\tsource\trho\talpha\tbeta\trarity\tblindness\tmass\tweight\tr_funcs\n";
            o << "ioctl$A\tioctl$B\tspr:arg\tstatic\t0.9\t9.0\t1.0\t1.0\t1.0\t5\t4.5\tF_R\n";
        }
        refuzz::fuzzer::StaticBeliefGraph rp;
        assert(rp.LoadFromTsv("/tmp/_sbg_rp/graph_M.tsv"));
        assert(rp.region_precise());  // sibling block map loaded -> precise mode
        // IN R: B's new PC 0x1002 is inside F_R -> CONFIRM the specific hypothesis
        rp.Observe({"ioctl$A", "ioctl$B"}, {{"ioctl$B", {0x1002}}});
        assert(rp.stats().confirmed == 1 && rp.stats().refuted == 0);
        // OUTSIDE R: B's new PC 0x2002 is in F_other (not R) -> REFUTE (predicted slice dark)
        rp.Observe({"ioctl$A", "ioctl$B"}, {{"ioctl$B", {0x2002}}});
        assert(rp.stats().confirmed == 1 && rp.stats().refuted == 1);
        // [posterior dump] persist the calibrated (α,β): one row carries the prior snapshot + the shift.
        // prior α0/β0 = 9/1; after 1 confirm (α++) + 1 refute (β++) the posterior is 10/2, kind preserved.
        assert(rp.DumpPosterior("/tmp/_sbg_rp/posterior.tsv"));
        {
            std::ifstream pin("/tmp/_sbg_rp/posterior.tsv");
            std::stringstream buf;
            buf << pin.rdbuf();
            const std::string s = buf.str();
            assert(s.find("ioctl$A\tioctl$B\tspr:arg") != std::string::npos);  // edge row carries its kind
            assert(s.find("\t9\t1\t10\t2\t") != std::string::npos);            // α0/β0=9/1 -> α/β=10/2
        }
        std::filesystem::remove_all("/tmp/_sbg_rp");
    }

    // missing file -> not loaded
    refuzz::fuzzer::StaticBeliefGraph g2;
    assert(!g2.LoadFromTsv("/tmp/_nonexistent_graph.tsv"));

    std::remove(p);
    std::printf("static_belief_graph_test OK (edges=%zu variants=%zu)\n", g.edges(), g.variants());
    return 0;
}

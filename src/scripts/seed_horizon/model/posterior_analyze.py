#!/usr/bin/env python3
# Copyright 2026 reFuzz project author -------youngkk.
#
# Read the CALIBRATED belief posterior a campaign dumps at shutdown (logs/belief_posterior.tsv, written by
# StaticBeliefGraph::DumpPosterior) and report, PER P-KIND, how the live frontier moved each edge's prior.
# Unlike the offline-union D2 (saturation-biased), this is the IN-LOOP incremental calibration: Observe
# bumped α (confirm: B's new frontier landed in the edge's slice R) / β (refute) AS IT HAPPENED, before
# saturation. The validation: do the VERIFIED kinds (value/flag/existence) get confirmed (ρ_post > ρ0,
# positive shift) more than weak?  cols: V_A V_B types alpha0 beta0 alpha beta rho0 rho_post obs
import collections
import sys

POST = sys.argv[1] if len(sys.argv) > 1 else "run/seed_horizon/campaign_67d89496/belief_posterior.tsv"


def main():
    by = collections.defaultdict(list)   # kind -> [(rho0, rho_post, obs)]
    n = 0
    for ln in open(POST):
        if ln.startswith("#"):
            continue
        c = ln.rstrip("\n").split("\t")
        if len(c) < 10:
            continue
        kind = c[2].split(":")[-1]
        rho0, rhop, obs = float(c[7]), float(c[8]), float(c[9])
        by[kind].append((rho0, rhop, obs))
        n += 1
    print(f"# belief posterior: {n} edges  ({POST})")
    print(f"# per-kind frontier calibration (obs>0 = the edge was actually exercised; shift = ρ_post - ρ0)")
    print(f"  {'kind':12} {'edges':>6} {'observed':>9} {'mean_ρ0':>8} {'mean_ρpost':>11} {'mean_shift':>11} {'%confirmed':>11}")
    order = ("value", "flag", "exist-alloc", "exist", "threshold", "weak")
    for k in list(order) + [x for x in by if x not in order]:
        rows = by.get(k)
        if not rows:
            continue
        obsv = [r for r in rows if r[2] > 0]                  # only edges the frontier actually touched
        if not obsv:
            print(f"  {k:12} {len(rows):6} {0:9}  (never exercised)")
            continue
        mr0 = sum(r[0] for r in obsv) / len(obsv)
        mrp = sum(r[1] for r in obsv) / len(obsv)
        conf = sum(1 for r in obsv if r[1] > r[0]) / len(obsv)
        print(f"  {k:12} {len(rows):6} {len(obsv):9} {mr0:8.3f} {mrp:11.3f} {mrp-mr0:+11.3f} {conf:11.2f}")
    # headline: verified vs weak shift among exercised edges
    def shifts(kinds):
        return [r[1] - r[0] for k in kinds for r in by.get(k, ()) if r[2] > 0]
    ver = shifts(("value", "flag", "exist-alloc", "exist", "threshold"))
    wk = shifts(("weak",))
    if ver and wk:
        print(f"\n  >> VERIFIED mean shift {sum(ver)/len(ver):+.3f} (n={len(ver)})  vs  "
              f"WEAK {sum(wk)/len(wk):+.3f} (n={len(wk)})  — verified should be more positive if the grading is real")


if __name__ == "__main__":
    main()

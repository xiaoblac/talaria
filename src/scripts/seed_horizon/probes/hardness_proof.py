#!/usr/bin/env python3
# Copyright 2026 reFuzz project author -------youngkk.
#
# PROVE the S/P/R dependencies are HARD-TO-FUZZ-TO, using the graph + a real 5h fuzz run's coverage.
# The argument is self-normalizing and causal-in-structure:
#   For each dependency edge A--establishes P on S-->R owned-by B, the GATE's HOST function (where the
#   branch lives) is on B's normal path — a fuzzer that runs B reaches it. The region R *behind* the
#   gate is reached only if the precondition (field F == the value A sets at runtime) holds. So if, in
#   a real run, the HOSTS are well covered but the R INTERIORS stay dark, the barrier is the
#   precondition, not reachability => the dependency is hard to fuzz to without A.
# Coverage = 5h gcc-KASAN run (corpus_pc.txt) mapped via the matching gcc map (function_block_map.gcc).
# Names are config/compiler-stable, so clang-analysis R names join gcc-covered names; R funcs that are
# inlined away in gcc (not gcc symbols) are EXCLUDED (measured over gcc-symbol R only -> no false dark).
import collections
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # scripts/seed_horizon (substrate + angles)
from substrate.pcbridge import load_block_map, pc_to_func

SH = "run/seed_horizon"
COV = sys.argv[1] if len(sys.argv) > 1 else \
    "run/speed_compare/edge_compare_5h_20260617a/D_refuzz_run_01/corpus_pc.txt"
GCCMAP = f"{SH}/function_block_map.gcc.tsv"   # matches the 5h gcc-KASAN run


def isfield(l):
    return l.startswith("struct.") or l.startswith("@")


def rec(s):
    return s not in ("?", "icall", "", "-")


def main():
    func_pcs, starts_pc, starts_fn = load_block_map(GCCMAP)
    universe = set(starts_fn)                                   # measurable (gcc-instrumented) functions
    covered = set()
    n_pc = 0
    for ln in open(COV):
        s = ln.split()
        if not s:
            continue
        try:
            pc = int(s[0], 0)
        except ValueError:
            continue
        n_pc += 1
        f = pc_to_func(pc, starts_pc, starts_fn)
        if f:
            covered.add(f)
    print(f"# 5h fuzz run: {n_pc} covered PCs -> {len(covered)} distinct functions "
          f"({100*len(covered)//max(1,len(universe))}% of {len(universe)} gcc-instrumented)")

    # the dependency-gated keys = (field,S) present on BOTH a writer (A establishes) and a gate (B checks)
    wkeys, gkeys = set(), set()
    for ln in open(f"{SH}/all_writes.tsv"):
        c = ln.rstrip("\n").split("\t")
        if c[0] == "WRITE" and len(c) > 4 and isfield(c[2]) and rec(c[4]):
            wkeys.add((c[2], c[4]))
    hosts, rfuncs = set(), set()
    rmass = 0
    fnblk = {f: 0 for f in universe}
    for ln in open(GCCMAP):
        c = ln.rstrip("\n").split("\t")
        if len(c) > 2:
            fnblk[c[2]] = int(c[1])
    gate_rows = []
    for ln in open(f"{SH}/all_gates.tsv"):
        c = ln.rstrip("\n").split("\t")
        if c[0] == "GATE" and len(c) > 7 and isfield(c[2]) and rec(c[3]):
            gkeys.add((c[2], c[3]))
            gate_rows.append((c[1], c[2], c[3], [] if c[7] == "-" else c[7].split(",")))
    coupled = wkeys & gkeys
    for host, F, S, region in gate_rows:
        if (F, S) in coupled:
            hosts.add(host)
            rfuncs.update(region)
    print(f"# dependency-gated couplings: {len(coupled)} (field,S) keys; {len(hosts)} gate-host fns, "
          f"{len(rfuncs)} R-interior fns")

    # restrict both sides to the measurable (gcc-symbol) universe, then compare coverage.
    H = hosts & universe
    R = rfuncs & universe
    hc = len(H & covered)
    rc = len(R & covered)
    print(f"\n# === THE PROOF: gate reached, interior dark ===")
    print(f"#   gate-HOST functions covered : {hc:5}/{len(H):5}  ({100*hc//max(1,len(H))}%)  <- B is fuzzed, gate evaluated")
    print(f"#   R-INTERIOR functions covered: {rc:5}/{len(R):5}  ({100*rc//max(1,len(R))}%)  <- behind the precondition gate")
    ratio = (rc / max(1, len(R))) / max(1e-9, hc / max(1, len(H)))
    print(f"#   interior/host coverage ratio: {ratio:.2f}  (<<1 => the precondition is the barrier, NOT reachability)")
    # baseline: a generic non-gated comparison — coverage of ALL measurable funcs
    print(f"#   (baseline: whole-kernel covered fraction = {100*len(covered)//max(1,len(universe))}%)")


if __name__ == "__main__":
    main()

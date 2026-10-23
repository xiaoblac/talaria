#!/usr/bin/env python3
# Copyright 2026 reFuzz project author -------youngkk.
#
# Candidate region audit.
import bisect
import collections
import os
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from resolve.candidates import build_candidate_run

SH = "run/seed_horizon"
COV_RUNS = [("r1", "/tmp/rfz_67d89496_d01/corpus_pc.txt"),
            ("r2", "/tmp/rfz_aa388926_d01/corpus_pc.txt")]


def load_function_map(sh=SH):
    starts, names, blocks, name_blocks = [], [], [], {}
    rows = []
    with open(os.path.join(sh, "function_block_map.tsv")) as f:
        for ln in f:
            c = ln.rstrip("\n").split("\t")
            if len(c) < 3:
                continue
            try:
                rows.append((int(c[0], 16), int(c[1]), c[2]))
            except ValueError:
                continue
    rows.sort()
    for addr, nb, nm in rows:
        starts.append(addr)
        names.append(nm)
        blocks.append(nb)
        name_blocks[nm] = nb
    return starts, names, blocks, name_blocks


def covered_functions(path, starts, names):
    cov = set()
    if not os.path.exists(path):
        return cov
    with open(path) as f:
        for ln in f:
            ln = ln.strip()
            if not ln:
                continue
            try:
                pc = int(ln, 16)
            except ValueError:
                continue
            i = bisect.bisect_right(starts, pc) - 1
            if i >= 0:
                cov.add(names[i])
    return cov


def dispatch_mode(rec):
    if rec.trace:
        return "field-forward"
    if rec.leaves and rec.leaves != rec.entry_handlers:
        return "table"
    if rec.demands:
        return "runtime-empty"
    if rec.entry_handlers:
        return "entry-only"
    return "none"


def main():
    run = build_candidate_run(SH, ".")
    starts, names, _blocks, name_blocks = load_function_map(SH)
    cov_sets = [(tag, covered_functions(path, starts, names)) for tag, path in COV_RUNS]
    cov_union = set().union(*[c for _t, c in cov_sets]) if cov_sets else set()

    records = []
    for rec in run.records.values():
        region = set(rec.region)
        r_blocks = sum(name_blocks.get(fn, 0) for fn in region)
        cov_hits = {tag: len(region & cset) for tag, cset in cov_sets}
        cov_union_hit = len(region & cov_union)
        cov_frac = (cov_union_hit / len(region)) if region else 0.0
        records.append({
            "v": rec.spec.name,
            "base": rec.spec.base,
            "conf": rec.confidence,
            "C": len(rec.anchor_rows),
            "E": len(rec.entry_handlers),
            "L": len(rec.leaves),
            "Rf": len(region),
            "Rb": r_blocks,
            "src": "+".join(sorted({run.reg_rows[row][0] for row in rec.anchor_rows})) or "-",
            "mode": dispatch_mode(rec),
            "rt": int(rec.fail_class == "legit_runtime" or rec.confidence == "value-unresolved"),
            "cv": rec.spec.discriminant,
            "covU": cov_union_hit,
            "covfrac": cov_frac,
            "cov": cov_hits,
            "L_set": sorted(rec.leaves),
        })

    out = f"{SH}/region_audit.tsv"
    with open(out, "w") as f:
        f.write("#variant\tbase\tconfidence\tC\tE\tL\tR_funcs\tR_blocks\tsource\t"
                "dispatch_mode\truntime_dynamic\tdiscriminant\tcov_union_hit\tcov_frac\t"
                "cov_r1\tcov_r2\tleaves\n")
        for r in records:
            f.write("\t".join(str(x) for x in [
                r["v"], r["base"], r["conf"], r["C"], r["E"], r["L"], r["Rf"], r["Rb"],
                r["src"], r["mode"], r["rt"], "-" if r["cv"] is None else r["cv"],
                r["covU"], f"{r['covfrac']:.2f}", r["cov"].get("r1", 0), r["cov"].get("r2", 0),
                ",".join(r["L_set"])[:120] or "-",
            ]) + "\n")

    n = len(records)
    by_conf = collections.defaultdict(list)
    for r in records:
        by_conf[r["conf"]].append(r)

    print(f"# FIXPOINT: converged in {run.rounds} round(s); "
          f"{sum(1 for r in run.records.values() if r.entry_handlers)} variants with entry context")
    for i, sat in enumerate(run.per_round):
        print(f"#   round {i}: " + ", ".join(f"{X}={lab}(n={n})" for X, lab, n in sat))
    print(f"#   negative-cache: {sorted(run.neg_cache)}\n")
    print(f"# REGION AUDIT — {n} variants  (wrote {out})")
    print(f"# corpus coverage: " + ", ".join(f"{t}={len(c)} funcs" for t, c in cov_sets) +
          f"  union={len(cov_union)}")
    print(f"# have-entry-context(E>0)={sum(1 for r in records if r['E']>0)}  "
          f"have-candidate(L>0)={sum(1 for r in records if r['L']>0)}\n")

    order = ["unique-candidate", "small-candidate", "large-candidate",
             "value-unresolved", "entry-only-empty", "no-context"]
    print(f"# {'CONFIDENCE':20} {'n':>5} {'%':>5}  {'medL':>4} {'medRf':>5} {'medRb':>6}  "
          f"{'cov%':>5}  {'medCovFrac':>10}")
    for conf in order + [c for c in by_conf if c not in order]:
        rs = by_conf.get(conf)
        if not rs:
            continue
        medL = int(statistics.median(r["L"] for r in rs))
        medRf = int(statistics.median(r["Rf"] for r in rs))
        medRb = int(statistics.median(r["Rb"] for r in rs))
        with_region = [r for r in rs if r["Rf"] > 0]
        cov_rate = (sum(1 for r in with_region if r["covU"] > 0) / len(with_region)) if with_region else 0.0
        med_cf = statistics.median([r["covfrac"] for r in with_region]) if with_region else 0.0
        print(f"  {conf:20} {len(rs):5} {100*len(rs)/n:5.1f}  {medL:4} {medRf:5} {medRb:6}  "
              f"{100*cov_rate:5.1f}  {med_cf:10.2f}")


if __name__ == "__main__":
    main()

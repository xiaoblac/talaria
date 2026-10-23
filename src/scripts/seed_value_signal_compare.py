#!/usr/bin/env python3
# Copyright 2026 reFuzz project author -------youngkk.
#
# seed_value_signal_compare.py — offline analysis of the in-loop seed-value shadow.
#
# Joins the three sidecars a shadow campaign emits (logs/ dir):
#   seed_value_shadow.jsonl          per mutation outcome: future, future_cht, mab_ghat, ...
#   seed_lineage_yield.jsonl         per ROOT seed, value-realized yield, unit = distinct BLOCK
#   seed_lineage_yield_cluster.jsonl per ROOT seed, value-realized yield, unit = distinct CLUSTER
#
# and answers, with NO external deps (stdlib only):
#   1. signal liveness + redundancy  — are future / future_cht / mab_ghat alive and orthogonal?
#   2. burst compression             — does cluster-unit de-bias the block-unit yield (§5.2a)?
#   3. value-oracle calibration      — does each signal predict a root's lineage yield, and
#                                      crucially does FORWARD predict DOWNSTREAM (E[mass]) while
#                                      BACKWARD predicts DIRECT (P(new))? + partial-beyond-backward.
#   4. near-term preview             — the WEAK reach oracle (rare_cov_gain) from shadow alone;
#                                      backward wins this by category, so it is NOT the verdict.
#
# The cluster-downstream column is the de-biased E[mass] oracle — the headline target.
#
# Usage:  scripts/seed_value_signal_compare.py <logs_dir | run_dir>
#
# Caveats it will print honestly: lineage files dump on flush/shutdown (may be absent mid-run);
# future_cht is all-zero on a binary built before that column; near-term reach ties backward by
# construction (wrong oracle for a value signal).

import json
import math
import os
import sys
from collections import defaultdict


# ----------------------------------------------------------------------------- io
def load_jsonl(path):
    rows = []
    if not path or not os.path.isfile(path):
        return rows
    with open(path) as f:
        for ln in f:
            ln = ln.strip()
            if not ln:
                continue
            try:
                rows.append(json.loads(ln))
            except Exception:
                pass  # live partial last line / truncated flush
    return rows


def find_logs(arg):
    """Accept a logs dir directly, or a run dir containing logs/."""
    if os.path.isdir(os.path.join(arg, "logs")):
        return os.path.join(arg, "logs")
    return arg


# ------------------------------------------------------------------- statistics
def _rank(xs):
    """Average (tie-aware) ranks, 1-based."""
    order = sorted(range(len(xs)), key=lambda i: xs[i])
    ranks = [0.0] * len(xs)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and xs[order[j + 1]] == xs[order[i]]:
            j += 1
        avg = (i + j) / 2.0 + 1.0  # 1-based average rank for the tie block
        for k in range(i, j + 1):
            ranks[order[k]] = avg
        i = j + 1
    return ranks


def pearson(a, b):
    n = len(a)
    if n < 3:
        return float("nan")
    ma = sum(a) / n
    mb = sum(b) / n
    num = sum((x - ma) * (y - mb) for x, y in zip(a, b))
    da = math.sqrt(sum((x - ma) ** 2 for x in a))
    db = math.sqrt(sum((y - mb) ** 2 for y in b))
    if da == 0 or db == 0:
        return float("nan")
    return num / (da * db)


def spearman(a, b):
    """Rank correlation. Pairs are taken positionally (a[i], b[i])."""
    if len(a) != len(b) or len(a) < 3:
        return float("nan")
    return pearson(_rank(a), _rank(b))


def partial_spearman(x, y, z):
    """Spearman of x~y controlling for z (rank partial-correlation formula).
    'does x predict y BEYOND z' — here z = backward (mab_ghat)."""
    rxy, rxz, ryz = spearman(x, y), spearman(x, z), spearman(y, z)
    if any(math.isnan(r) for r in (rxy, rxz, ryz)):
        return float("nan")
    den = math.sqrt((1 - rxz * rxz) * (1 - ryz * ryz))
    if den == 0:
        return float("nan")
    return (rxy - rxz * ryz) / den


def median(xs):
    s = sorted(xs)
    n = len(s)
    if n == 0:
        return 0.0
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2.0


def fmt(x):
    return "  nan " if (x is None or (isinstance(x, float) and math.isnan(x))) else f"{x:+.3f}"


# ----------------------------------------------------------------------- loaders
def per_seed_signals(shadow):
    """seed_id -> {future, future_cht, mab_ghat, n} aggregated across its rows.
    future/future_cht are admit-time constants (median); mab_ghat drifts (median, robust)."""
    by = defaultdict(lambda: defaultdict(list))
    for r in shadow:
        sid = r.get("seed_id")
        if sid is None:
            continue
        for k in ("future", "future_cht", "mab_ghat", "rare_cov_gain", "cov_gain"):
            if k in r:
                by[sid][k].append(r[k])
    out = {}
    for sid, d in by.items():
        out[sid] = {
            "future": median(d["future"]) if d["future"] else 0.0,
            "future_cht": median(d["future_cht"]) if d["future_cht"] else 0.0,
            "mab_ghat": median(d["mab_ghat"]) if d["mab_ghat"] else 0.0,
            "n": len(d["future"]) or len(d["mab_ghat"]),
        }
    return out


def yield_by_root(rows):
    """root -> {direct, downstream, total} (P(new), E[mass], all)."""
    out = {}
    for r in rows:
        root = r.get("root")
        if root is None:
            continue
        out[root] = {
            "direct": r.get("direct", 0),
            "downstream": r.get("downstream", 0),
            "total": r.get("total", 0),
        }
    return out


# --------------------------------------------------------------------- sections
def sec_inputs(shadow, yb, yc):
    print("=" * 78)
    print("1. INPUTS")
    print(f"  shadow rows               : {len(shadow)}  (distinct seeds: "
          f"{len({r.get('seed_id') for r in shadow})})")
    print(f"  lineage yield (block)     : {len(yb)} roots"
          + ("" if yb else "   [absent — dumps on flush/shutdown]"))
    print(f"  lineage yield (cluster)   : {len(yc)} roots"
          + ("" if yc else "   [absent — dumps on flush/shutdown]"))


def sec_liveness(sig):
    print("=" * 78)
    print("2. SIGNAL LIVENESS + REDUNDANCY  (per distinct seed)")
    fut = [s["future"] for s in sig.values()]
    cht = [s["future_cht"] for s in sig.values()]
    gh = [s["mab_ghat"] for s in sig.values()]

    def desc(name, xs):
        nz = sum(1 for x in xs if x != 0)
        dist = len({round(x, 6) for x in xs})
        print(f"  {name:10}: n={len(xs)} distinct={dist} nonzero={nz} "
              f"min={min(xs):.4g} max={max(xs):.4g} median={median(xs):.4g}")

    desc("future", fut)
    desc("future_cht", cht)
    desc("mab_ghat", gh)
    if all(x == 0 for x in cht):
        print("  NOTE future_cht all-zero → run used a binary without it, or horizon off.")
    print("  redundancy (Spearman):")
    print(f"    future~future_cht = {fmt(spearman(fut, cht))}   "
          f"future~mab_ghat = {fmt(spearman(fut, gh))}   "
          f"future_cht~mab_ghat = {fmt(spearman(cht, gh))}")
    print("    (low |r| = the forward signals carry something backward does not)")


def sec_burst(yb, yc):
    print("=" * 78)
    print("3. BURST COMPRESSION  (block-unit vs cluster-unit yield, §5.2a)")
    if not yb or not yc:
        print("  SKIP — need both lineage files.")
        return
    roots = set(yb) | set(yc)
    sb = sum(yb.get(r, {}).get("total", 0) for r in roots)
    sc = sum(yc.get(r, {}).get("total", 0) for r in roots)
    print(f"  roots={len(roots)}  Σblock_total={sb}  Σcluster_total={sc}  "
          f"overall_compression={ (sc / sb) if sb else float('nan'):.3f}  (lower = more de-bias)")
    ratios = [yc.get(r, {}).get("total", 0) / yb[r]["total"]
              for r in yb if yb[r]["total"] > 0]
    if ratios:
        print(f"  per-root cluster/block ratio: median={median(ratios):.3f}  "
              f"min={min(ratios):.3f} max={max(ratios):.3f}")
    print("  tail — top-10 roots by BLOCK total (the jackpots; should compress most):")
    print(f"    {'root':>10} {'block':>7} {'cluster':>8} {'ratio':>6}")
    for r in sorted(yb, key=lambda r: yb[r]["total"], reverse=True)[:10]:
        bt = yb[r]["total"]
        ct = yc.get(r, {}).get("total", 0)
        print(f"    {r:>10} {bt:>7} {ct:>8} {(ct / bt if bt else 0):>6.3f}")


def _join(sig, ymap):
    """roots present in both signal table and yield map → aligned columns."""
    roots = [r for r in ymap if r in sig]
    cols = {
        "future": [sig[r]["future"] for r in roots],
        "future_cht": [sig[r]["future_cht"] for r in roots],
        "mab_ghat": [sig[r]["mab_ghat"] for r in roots],
        "direct": [ymap[r]["direct"] for r in roots],
        "downstream": [ymap[r]["downstream"] for r in roots],
        "total": [ymap[r]["total"] for r in roots],
    }
    return roots, cols


def sec_calibration(sig, ymap, label):
    print("=" * 78)
    print(f"4. VALUE-ORACLE CALIBRATION  (signal -> lineage yield, unit = {label})")
    if not ymap:
        print("  SKIP — no lineage yield file.")
        return
    roots, c = _join(sig, ymap)
    print(f"  joined roots (signal ∩ yield): {len(roots)}")
    if len(roots) < 8:
        print("  too few roots for stable correlation — let the campaign run longer "
              "(needs depth>=2 lineage; 25min is far too short).")
        return
    print("  Spearman(signal, yield):")
    print(f"    {'':10} {'direct(Pnew)':>13} {'downstream(Emass)':>18} {'total':>8}")
    for s in ("future", "future_cht", "mab_ghat"):
        print(f"    {s:10} {fmt(spearman(c[s], c['direct'])):>13} "
              f"{fmt(spearman(c[s], c['downstream'])):>18} {fmt(spearman(c[s], c['total'])):>8}")
    print("  thesis check: FORWARD (future/future_cht) should beat itself on DOWNSTREAM>direct;")
    print("               BACKWARD (mab_ghat) should be the reverse (direct>downstream).")
    print("  partial Spearman BEYOND backward  (does forward add over mab_ghat?):")
    for s in ("future", "future_cht"):
        print(f"    {s:10} ~downstream | mab_ghat = "
              f"{fmt(partial_spearman(c[s], c['downstream'], c['mab_ghat']))}   "
              f"~total | mab_ghat = {fmt(partial_spearman(c[s], c['total'], c['mab_ghat']))}")


def sec_nearterm(shadow):
    print("=" * 78)
    print("5. NEAR-TERM PREVIEW  (rare_cov_gain — the WEAK reach oracle, NOT the verdict)")
    print("  backward is itself a reach proxy → it wins this by category; future is a VALUE")
    print("  signal whose real oracle is §4 (downstream yield). Read this only as a sanity gauge.")
    rows = [r for r in shadow if "rare_cov_gain" in r]
    if len(rows) < 30:
        print("  SKIP — too few rows.")
        return

    def terc(key):
        sr = sorted(rows, key=lambda r: r.get(key, 0))
        k = len(sr) // 3
        for name, grp in (("LOW", sr[:k]), ("MID", sr[k:2 * k]), ("HIGH", sr[2 * k:])):
            rcg = sum(g.get("rare_cov_gain", 0) for g in grp) / max(1, len(grp))
            cg = sum(g.get("cov_gain", 0) for g in grp) / max(1, len(grp))
            it = sum(1 for g in grp if g.get("interesting")) / max(1, len(grp))
            print(f"    {key:10} {name:4}: rare_cg={rcg:8.2f}  cov_g={cg:6.2f}  interesting={it:.3f}")

    for key in ("future", "future_cht", "mab_ghat"):
        if any(key in r for r in rows):
            terc(key)


def main():
    if len(sys.argv) != 2:
        print(__doc__.strip().split("Usage:")[1].strip() if "Usage:" in __doc__ else
              "usage: seed_value_signal_compare.py <logs_dir | run_dir>")
        sys.exit(2)
    logs = find_logs(sys.argv[1])
    shadow = load_jsonl(os.path.join(logs, "seed_value_shadow.jsonl"))
    yb = yield_by_root(load_jsonl(os.path.join(logs, "seed_lineage_yield.jsonl")))
    yc = yield_by_root(load_jsonl(os.path.join(logs, "seed_lineage_yield_cluster.jsonl")))
    if not shadow:
        print(f"no seed_value_shadow.jsonl under {logs}")
        sys.exit(1)
    sig = per_seed_signals(shadow)

    sec_inputs(shadow, yb, yc)
    sec_liveness(sig)
    sec_burst(yb, yc)
    sec_calibration(sig, yc, "CLUSTER (de-biased E[mass] oracle)")
    sec_calibration(sig, yb, "BLOCK (raw, for contrast)")
    sec_nearterm(shadow)
    print("=" * 78)


if __name__ == "__main__":
    main()

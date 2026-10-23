#!/usr/bin/env python3
# seed_value_shadow_analyze.py — offline go/no-go analysis for the seed-value
# signal shadow stream (docs/plans/seed-value-signals.md).
#
# UNIT = THE SEED, NOT THE EVENT. A seed-value signal is a claim about a seed's
# capacity to lead, over MANY mutations, to new places — a rate over draws, not
# a per-draw outcome. A single mutation's cov_gain is ~pure noise (most are 0),
# so correlating the signal against per-EVENT yield buries any real effect in
# within-seed variance the signal cannot explain. (Empirically: rarity vs
# cov_gain was ρ=0.04 per-event but ρ=0.16 per-seed — the per-event harness
# falsely killed signal A.) So we aggregate every seed's mutations first, then
# correlate at the seed level.
#
# Each signal is judged against its OWN target, at the seed level:
#   A (rarity)   → hit_rate       (fraction of the seed's mutations with new cov)
#   B (unstable) → abnormal_rate  (fraction abnormal: crash|timeout|leak|...)
#   C (altitude) → rare_cov_gain  (mean rarity-weighted footprint = reached-deep);
#                  C's SIGNAL is the PRE-minimize altitude (post-minimize is
#                  flattened to ~0 — no variance), pre_* fields.
#
# Go/no-go (a signal must pass ALL):
#   [0] monotonic : Spearman(signal, target) ≥ --mono (rank-based; immune to the
#                   heavy-tail mean inflation that fooled the old lift gate).
#   [1] saturation: partial Spearman(signal, target | mean_t) > 0 — cov_gain
#                   decays as the global map fills, so later-mutated seeds look
#                   worse regardless of value; the signal must survive controlling
#                   for WHEN the seed was mutated.
#   [2] increment : partial Spearman(signal, target | mab_ghat) > 0 — predict
#                   beyond what the MAB already learned. N/A if mab_ghat constant.
# Plus informational: top-decile concentration (extreme-finder lens) + a tercile
# effect size (NOT a gate — means are heavy-tail-fooled, which is the whole point).
#
# GO means "the correlation survives the controls → graduate to an A/B policy
# test", NOT "confirmed strong". The Spearman magnitude is printed so a weak GO
# (e.g. ρ≈0.15) is never mistaken for a strong one.
#
# Pure stdlib (no numpy/scipy/network) to match the repo's tooling discipline.

import argparse
import json
import math
import sys
from collections import defaultdict

ABNORMAL_KEYS = ("crash", "timeout", "resource_leak", "contract",
                 "prio_inv", "stack_of")


def load_rows(path):
    rows = []
    try:
        f = open(path)
    except OSError as e:
        print(f"cannot open {path}: {e}", file=sys.stderr)
        return None
    with f:
        for ln in f:
            ln = ln.strip()
            if not ln:
                continue
            try:
                rows.append(json.loads(ln))
            except json.JSONDecodeError:
                pass  # tolerate a torn final line (mid-flush kill)
    return rows


def _row_unstable(r):
    u = float(r.get("union_pc", 0))
    return (float(r.get("unstable_pc", 0)) / u) if u > 0 else 0.0


def _row_abnormal(r):
    return 1.0 if any(int(r.get(k, 0)) for k in ABNORMAL_KEYS) else 0.0


def _row_pre_altitude(r):
    # C's signal = the PRE-minimize resource graph (post-minimize is flattened to
    # ~0). Fall back to the live fields for JSONL predating the pre_* columns.
    if r.get("pre_valid", 0):
        return (float(r.get("pre_res_prod", 0)) + float(r.get("pre_res_cons", 0))
                + float(r.get("pre_depth", 0)))
    return (float(r.get("res_prod", 0)) + float(r.get("res_cons", 0))
            + float(r.get("depth", 0)))


# ---- aggregate events → seeds (the correct unit) -------------------------

def aggregate_seeds(rows):
    """Group mutation events by parent seed_id; signals are seed properties
    (mean over the seed's rows, ~constant modulo pc_count drift), targets are
    rates over the seed's mutations."""
    g = defaultdict(list)
    for r in rows:
        g[r.get("seed_id")].append(r)
    seeds = []
    for sid, rs in g.items():
        n = len(rs)
        def mean(f):
            return sum(f(r) for r in rs) / n
        seeds.append({
            "seed_id": sid,
            "n": n,
            # targets (rates over the seed's mutations)
            "hit_rate": sum(1 for r in rs if float(r.get("cov_gain", 0)) > 0) / n,
            "mean_cov": mean(lambda r: float(r.get("cov_gain", 0))),
            "abnormal_rate": mean(_row_abnormal),
            "rare_cov_gain": mean(lambda r: float(r.get("rare_cov_gain",
                                                        r.get("cov_gain", 0)))),
            # saturation control: when, on average, this seed was mutated
            "mean_t": mean(lambda r: float(r.get("t", 0))),
            # signals (seed properties)
            "rarity": mean(lambda r: float(r.get("rarity", 0))),
            "unstable": mean(_row_unstable),
            "altitude": mean(_row_pre_altitude),
            "mab_ghat": mean(lambda r: float(r.get("mab_ghat", 0))),
            # carry one representative pre/post for the minimize-impact report
            "_pre": next((r for r in rs if r.get("pre_valid", 0)), rs[0]),
        })
    return seeds


# (name, signal_key, target_key, target_label)
SIGNALS = [
    ("A_rarity",   "rarity",   "hit_rate",      "hit_rate"),
    ("B_unstable", "unstable", "abnormal_rate", "abnormal_rate"),
    ("C_altitude", "altitude", "rare_cov_gain", "rare_cov_gain (pre-min signal)"),
]


# ---- stats (stdlib) ------------------------------------------------------

def _ranks(xs):
    order = sorted(range(len(xs)), key=lambda i: xs[i])
    ranks = [0.0] * len(xs)
    i = 0
    while i < len(xs):
        j = i
        while j + 1 < len(xs) and xs[order[j + 1]] == xs[order[i]]:
            j += 1
        avg = (i + j) / 2.0 + 1.0  # average rank for ties (1-based)
        for k in range(i, j + 1):
            ranks[order[k]] = avg
        i = j + 1
    return ranks


def _pearson(a, b):
    n = len(a)
    if n < 3:
        return None
    ma, mb = sum(a) / n, sum(b) / n
    va = sum((x - ma) ** 2 for x in a)
    vb = sum((x - mb) ** 2 for x in b)
    if va == 0.0 or vb == 0.0:
        return None
    return sum((a[i] - ma) * (b[i] - mb) for i in range(n)) / math.sqrt(va * vb)


def spearman(xs, ys):
    if len(xs) < 3:
        return None
    return _pearson(_ranks(xs), _ranks(ys))


def partial_spearman(s, t, z):
    """Spearman(s,t) controlling for z, via rank-Pearson partial correlation."""
    if len(s) < 5:
        return None
    rs, rt, rz = _ranks(s), _ranks(t), _ranks(z)
    r_st, r_sz, r_tz = _pearson(rs, rt), _pearson(rs, rz), _pearson(rt, rz)
    if None in (r_st, r_sz, r_tz):
        return None
    denom = math.sqrt((1 - r_sz ** 2) * (1 - r_tz ** 2))
    return (r_st - r_sz * r_tz) / denom if denom else None


def concentration(sig, tgt, frac=0.1):
    """Fraction of total target captured by the top `frac` of seeds by signal.
    `frac` under no relationship; >frac = the high-signal seeds hold more than
    their share (extreme-finder lens, robust to non-monotonicity)."""
    n = len(sig)
    total = sum(tgt)
    if n < 10 or total <= 0:
        return None
    k = max(1, int(n * frac))
    order = sorted(range(n), key=lambda i: sig[i], reverse=True)[:k]
    return sum(tgt[i] for i in order) / total


def tercile_effect(sig, tgt):
    """Top-tercile mean(target) / bottom-tercile mean(target). Informational
    effect size only — means are exactly what heavy tails fool, so this is NOT
    a gate; it sits next to the rank stats for interpretation."""
    n = len(sig)
    if n < 9:
        return None
    order = sorted(range(n), key=lambda i: sig[i])
    q = n // 3
    bot = [tgt[i] for i in order[:q]]
    top = [tgt[i] for i in order[-q:]]
    bm, tm = sum(bot) / len(bot), sum(top) / len(top)
    if bm == 0.0:
        return (float("inf") if tm > 0 else None, tm, bm)
    return (tm / bm, tm, bm)


def _mag(rho):
    a = abs(rho)
    return "strong" if a >= 0.4 else "moderate" if a >= 0.2 else \
           "weak" if a >= 0.1 else "negligible"


# ---- per-signal report (seed level) --------------------------------------

def analyze_signal(seeds, name, sig_key, tgt_key, tgt_label, mono_thresh):
    sig = [s[sig_key] for s in seeds]
    tgt = [s[tgt_key] for s in seeds]
    mt = [s["mean_t"] for s in seeds]
    ghat = [s["mab_ghat"] for s in seeds]
    n = len(seeds)

    sp = spearman(sig, tgt)
    psp_t = partial_spearman(sig, tgt, mt)
    ghat_const = (max(ghat) - min(ghat)) < 1e-12 if ghat else True
    psp_g = None if ghat_const else partial_spearman(sig, tgt, ghat)
    conc = concentration(sig, tgt)
    eff = tercile_effect(sig, tgt)

    cond_mono = sp is not None and sp >= mono_thresh
    cond_sat = psp_t is not None and psp_t > 0.0
    cond_inc = ghat_const or (psp_g is not None and psp_g > 0.0)
    verdict = "GO" if (cond_mono and cond_sat and cond_inc) else "NO-GO"

    print(f"\n=== {name}  (target={tgt_label}) ===")
    print(f"  seeds={n}")
    sp_s = f"{sp:.3f}" if sp is not None else "N/A"
    print(f"  [0] monotonic : Spearman(sig,tgt)={sp_s}  "
          f"{'PASS' if cond_mono else 'fail'} (need ≥{mono_thresh})")
    pt_s = f"{psp_t:.3f}" if psp_t is not None else "N/A"
    print(f"  [1] saturation: partial(sig,tgt|mean_t)={pt_s}  "
          f"{'PASS' if cond_sat else 'fail'} (need >0 — not a time artifact)")
    if ghat_const:
        print("  [2] increment : N/A — mab_ghat constant (MAB off this run)")
    else:
        pg_s = f"{psp_g:.3f}" if psp_g is not None else "N/A"
        print(f"  [2] increment : partial(sig,tgt|mab_ghat)={pg_s}  "
              f"{'PASS' if (psp_g is not None and psp_g > 0) else 'fail'}")
    if conc is not None:
        print(f"  [i] top-decile: captures {conc*100:.1f}% of total target "
              f"({conc*10:.2f}× fair share)")
    if eff and eff[0] is not None:
        print(f"  [i] tercile   : top/bottom mean = {eff[0]:.2f} "
              f"(top={eff[1]:.3f} bot={eff[2]:.3f}; effect size, not a gate)")
    tag = f"  [ρ={sp:.3f} {_mag(sp)}]" if sp is not None else ""
    print(f"  --> {verdict}{tag}")
    return verdict


def minimize_impact_report(seeds):
    """Phase 1: how much resource-chain structure minimize destroys, and whether
    seeds that HAD a chain are more productive to mutate (per-seed hit_rate)."""
    pv = [s for s in seeds if s["_pre"].get("pre_valid", 0)]
    print("\n=== minimize impact (Phase 1) ===")
    if not pv:
        print("  no pre-minimize altitude in this JSONL (binary predates Phase 1?)")
        return
    ns = len(pv)
    def pre(s, k):
        return s["_pre"].get(k, 0)
    had_chain = sum(1 for s in pv if pre(s, "pre_depth") > 0)
    survived = sum(1 for s in pv if pre(s, "depth") > 0)
    flattened = sum(1 for s in pv
                    if pre(s, "pre_depth") > 0 and pre(s, "depth") == 0)
    mean = lambda f: sum(f(s) for s in pv) / ns
    print(f"  seeds with pre-altitude   : {ns}")
    print(f"  pre_depth>0 (had a chain) : {had_chain}  ({100*had_chain/ns:.1f}%)")
    print(f"  post depth>0 (survived)   : {survived}")
    print(f"  FLATTENED (pre>0 → post=0): {flattened}"
          + (f"  ({100*flattened/had_chain:.0f}% of chained seeds)" if had_chain else ""))
    print(f"  mean depth    : pre={mean(lambda s: pre(s,'pre_depth')):.2f}"
          f"  post={mean(lambda s: pre(s,'depth')):.2f}")
    print(f"  mean res_cons : pre={mean(lambda s: pre(s,'pre_res_cons')):.2f}"
          f"  post={mean(lambda s: pre(s,'res_cons')):.2f}")
    # Is the destroyed structure valuable? Per-SEED hit_rate, chained vs flat.
    chained = [s for s in pv if pre(s, "pre_depth") > 0]
    flat = [s for s in pv if pre(s, "pre_depth") == 0]
    if chained and flat:
        cm = sum(s["hit_rate"] for s in chained) / len(chained)
        fm = sum(s["hit_rate"] for s in flat) / len(flat)
        print(f"  hit_rate: chained(n={len(chained)})={cm:.3f}  "
              f"flat(n={len(flat)})={fm:.3f}  "
              f"→ {'chained higher' if cm > fm else 'NO benefit (flat ≥ chained)'}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("jsonl", help="path to seed_value_shadow.jsonl")
    ap.add_argument("--min-n", type=int, default=3,
                    help="minimum mutations per seed for a stable hit_rate "
                         "(seeds mutated fewer times are dropped)")
    ap.add_argument("--mono", type=float, default=0.10,
                    help="minimum Spearman for the monotonicity gate")
    args = ap.parse_args()

    rows = load_rows(args.jsonl)
    if rows is None:
        return 1
    if not rows:
        print(f"no rows in {args.jsonl}", file=sys.stderr)
        return 1

    all_seeds = aggregate_seeds(rows)
    seeds = [s for s in all_seeds if s["n"] >= args.min_n]
    abn = sum(_row_abnormal(r) for r in rows)
    cov = sum(1 for r in rows if float(r.get("cov_gain", 0)) > 0)
    print(f"seed_value_shadow_analyze: {len(rows)} mutation events → "
          f"{len(all_seeds)} seeds ({len(seeds)} with n≥{args.min_n}); "
          f"{cov} events cov_gain>0, {int(abn)} abnormal")

    # Diagnostic only: the per-EVENT correlation (the WRONG unit) for contrast,
    # to make the unit effect visible where it bit us.
    ev_sp = spearman([float(r.get("rarity", 0)) for r in rows],
                     [float(r.get("cov_gain", 0)) for r in rows])
    if ev_sp is not None:
        print(f"  [diagnostic] per-EVENT Spearman(rarity,cov_gain)={ev_sp:.3f} "
              f"— the wrong unit; contrast with per-seed below")

    if len(seeds) < 10:
        print(f"\ntoo few seeds with n≥{args.min_n} ({len(seeds)}) for seed-level "
              f"stats; let the run mature or lower --min-n", file=sys.stderr)

    verdicts = {}
    for (name, sk, tk, lbl) in SIGNALS:
        verdicts[name] = analyze_signal(seeds, name, sk, tk, lbl, args.mono)

    minimize_impact_report(seeds)

    print("\n=== summary ===")
    for k, v in verdicts.items():
        print(f"  {k:12s} {v}")
    print("\nGO = correlation survives the controls → worth an A/B policy test, "
          "NOT confirmed strong (see ρ). Judge each signal independently; do not "
          "combine before each passes alone (docs/plans/seed-value-signals.md).")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Compare exec-oracle per-call.jsonl runs for the threaded per-call-timeout work.

Focuses on the three success criteria of the per-call-attr-timeout + end-drain
work (docs project_threaded_percall_timeout_attr):
  1. heavy syscalls (syz_mount_image$*, ...) ref_pc recovered from ~0 (per_call=50
     flat) toward the per_call=5000 baseline.
  2. FUSE program tail calls stay executed + carry coverage.
  3. global mean jaccard ~0.92+.

Usage:
  analyze_percall_timeout.py LABEL=run/exec-oracle-X/per-call.jsonl [LABEL2=...] ...
The FIRST label is treated as the reference baseline for ratio columns.
"""
import json
import sys
from collections import defaultdict

FUSE_REQS = {2469, 2473, 2530, 2538, 2545}
HEAVY_PREFIXES = ("syz_mount_image$",)


def load(path):
    rows = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def family(sc):
    # group syz_mount_image$ocfs2 etc by full variant name
    return sc


def summarize(rows):
    js = [r["jaccard"] for r in rows if r.get("cover_available")]
    mean_j = sum(js) / len(js) if js else 0.0
    heavy = defaultdict(lambda: [0, 0, 0])  # sc -> [ref_pc, syz_pc, n]
    total_ref = total_syz = 0
    for r in rows:
        total_ref += r["ref_pc_count"]
        total_syz += r["syz_pc_count"]
        sc = r["syscall"]
        if any(sc.startswith(p) for p in HEAVY_PREFIXES):
            h = heavy[sc]
            h[0] += r["ref_pc_count"]
            h[1] += r["syz_pc_count"]
            h[2] += 1
    return dict(n=len(rows), mean_j=mean_j, jn=len(js),
                total_ref=total_ref, total_syz=total_syz, heavy=heavy)


def fuse_tail(rows):
    out = {}
    for r in rows:
        if r["req_id"] in FUSE_REQS:
            out[(r["req_id"], r["call_idx"])] = (
                r["syscall"], r["ref_executed"], r["ref_pc_count"],
                r["syz_pc_count"], round(r.get("jaccard", 0.0), 3))
    return out


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    runs = []
    for a in sys.argv[1:]:
        label, path = a.split("=", 1)
        runs.append((label, summarize(load(path)), fuse_tail(load(path))))

    print("=" * 78)
    print("GLOBAL")
    print("  %-12s %8s %10s %14s %14s" % ("label", "rows", "mean_jacc", "total_ref_pc", "total_syz_pc"))
    for label, s, _ in runs:
        print("  %-12s %8d %10.4f %14d %14d" % (label, s["n"], s["mean_j"], s["total_ref"], s["total_syz"]))

    print("=" * 78)
    print("HEAVY syscalls — ref_pc per variant (and syz_pc baseline)")
    variants = sorted({sc for _, s, _ in runs for sc in s["heavy"]})
    hdr = "  %-26s" % "syscall" + "".join(" %14s" % l for l, _, _ in runs)
    print(hdr)
    for sc in variants:
        line = "  %-26s" % sc[:26]
        for _, s, _ in runs:
            ref, syz, n = s["heavy"].get(sc, [0, 0, 0])
            line += " %8d/%-5d" % (ref, n)
        print(line)
    print("  (cell = total_ref_pc / n_calls;  syz_pc baseline per variant below)")
    for sc in variants:
        line = "  %-26s" % ("  syz:" + sc[:21])
        for _, s, _ in runs:
            ref, syz, n = s["heavy"].get(sc, [0, 0, 0])
            line += " %14d" % syz
        print(line)

    print("=" * 78)
    print("FUSE tail (reqs %s) — per (req,call): syscall ref_exec ref_pc syz_pc jacc" % sorted(FUSE_REQS))
    for label, _, ft in runs:
        print("--- %s ---" % label)
        for k in sorted(ft):
            sc, rex, rpc, spc, j = ft[k]
            mark = "" if (rex and rpc > 0) else "  <-- tail not executed/empty" if not rex else "  <-- executed but 0 cov"
            print("  req=%-5d call=%-2d %-22s ref_exec=%-5s ref_pc=%-7d syz_pc=%-7d j=%.3f%s"
                  % (k[0], k[1], sc[:22], rex, rpc, spc, j, mark))


if __name__ == "__main__":
    main()

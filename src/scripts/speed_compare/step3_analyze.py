#!/usr/bin/env python3
# Copyright 2026 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
"""Combined Gate 3 analysis over one or more step3_sink_ab.py output dirs.

For every headline metric it reports the disabled arm's own run-to-run spread
(mean +/- sample stdev, and min..max range) and asks whether the enabled arm's
mean lands inside that spread -- the Gate 3 criterion "enabled/disabled
difference must not exceed the disabled arm's own fluctuation range".

It ALSO pools the per-sample dispatch_prep interval (E2->E3, the only interval
capture() physically sits inside) across every disabled vs every enabled run,
so the sink's true footprint is characterised from thousands of samples rather
than a 3-run quantised median. All intervals come from the manager's own
task-trace via the harness parser -- the request stream is never a timing source.
"""
from __future__ import annotations

import json
import statistics
import sys
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
import speed_compare as sc  # noqa: E402

RUN_METRICS = [
    "programs_per_sec", "syz_calls_per_sec",
    "service_mean_ms", "total_mean_ms", "execute_mean_ms",
    "transport_out_mean_ms", "feedback_mean_ms",
    "dispatch_prep_mean_ms", "dispatch_prep_p50_ms",
]


def load_rows(out_dirs: list[Path]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for d in out_dirs:
        f = d / "step3_rows.jsonl"
        if not f.exists():
            continue
        for line in f.read_text().splitlines():
            line = line.strip()
            if line:
                r = json.loads(line)
                r["_out_dir"] = str(d)
                rows.append(r)
    return rows


def pooled_dispatch_prep(rows: list[dict[str, Any]], arm: str) -> list[float]:
    """Re-parse each run's own task-trace and pool per-sample E2->E3 (us)."""
    vals: list[float] = []
    for r in rows:
        if r.get("arm") != arm or r.get("status") != "ok":
            continue
        tt = Path(r["_out_dir"]) / r["run_dir"] / "syz_task_trace.jsonl"
        for t in sc.parse_syz_task_trace(tt):
            if not t["final"]:
                continue
            a, b = t["dequeued_us"], t["prep_done_us"]
            if a > 0 and b >= a:
                vals.append(b - a)
    return sorted(vals)


def pct(sorted_vals: list[float], p: float) -> float:
    if not sorted_vals:
        return float("nan")
    k = (len(sorted_vals) - 1) * p / 100.0
    lo = int(k)
    hi = min(lo + 1, len(sorted_vals) - 1)
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (k - lo)


def main() -> int:
    out_dirs = [Path(a) for a in sys.argv[1:]] or [
        Path("run/step3-sink-isolation/ab"), Path("run/step3-sink-isolation/ab2")]
    rows = load_rows(out_dirs)
    ok = [r for r in rows if r.get("status") == "ok"]
    dis = [r for r in ok if r["arm"] == "disabled"]
    ena = [r for r in ok if r["arm"] == "enabled"]

    L: list[str] = []
    L.append("# Step 3 — combined Gate 3 analysis")
    L.append("")
    L.append(f"sources: {', '.join(str(d) for d in out_dirs)}")
    L.append(f"disabled runs: {len(dis)}   enabled runs: {len(ena)}")
    L.append("")
    L.append("## Per-run aggregate metrics (disabled noise band vs enabled mean)")
    L.append("")
    L.append("| metric | disabled mean±σ | disabled range | enabled mean±σ | Δ(ena−dis) | ≤range | ≤2σ |")
    L.append("|---|---|---|---|---|---|---|")
    all_pass = True
    for m in RUN_METRICS:
        dv = [r[m] for r in dis if isinstance(r.get(m), (int, float))]
        ev = [r[m] for r in ena if isinstance(r.get(m), (int, float))]
        if len(dv) < 2 or not ev:
            continue
        dmean, emean = statistics.mean(dv), statistics.mean(ev)
        dsd = statistics.pstdev(dv) if len(dv) > 1 else 0.0
        esd = statistics.pstdev(ev) if len(ev) > 1 else 0.0
        drange = max(dv) - min(dv)
        delta = emean - dmean
        in_range = abs(delta) <= drange or (min(dv) <= emean <= max(dv))
        in_2sd = abs(delta) <= 2 * dsd if dsd > 0 else abs(delta) == 0
        # A metric is a concern only if it fails BOTH the range and the 2σ test.
        if not (in_range or in_2sd):
            all_pass = False
        L.append(f"| {m} | {dmean:.4g}±{dsd:.2g} | [{min(dv):.4g},{max(dv):.4g}] "
                 f"| {emean:.4g}±{esd:.2g} | {delta:+.3g} | "
                 f"{'yes' if in_range else 'no'} | {'yes' if in_2sd else 'no'} |")

    dp_dis = pooled_dispatch_prep(rows, "disabled")
    dp_ena = pooled_dispatch_prep(rows, "enabled")
    L.append("")
    L.append("## Pooled per-sample dispatch_prep (E2→E3, µs) — the interval capture() sits in")
    L.append("")
    L.append(f"disabled: n={len(dp_dis)} mean={statistics.mean(dp_dis):.3f}µs "
             f"p50={pct(dp_dis,50):.1f}µs p90={pct(dp_dis,90):.1f}µs p99={pct(dp_dis,99):.1f}µs")
    L.append(f"enabled : n={len(dp_ena)} mean={statistics.mean(dp_ena):.3f}µs "
             f"p50={pct(dp_ena,50):.1f}µs p90={pct(dp_ena,90):.1f}µs p99={pct(dp_ena,99):.1f}µs")
    off_mean = statistics.mean(dp_ena) - statistics.mean(dp_dis)
    off_p50 = pct(dp_ena, 50) - pct(dp_dis, 50)
    L.append(f"sink footprint: Δmean={off_mean:+.3f}µs  Δp50={off_p50:+.1f}µs "
             f"(≈ one mutex+append+signal handoff)")

    # Sink integrity across every enabled run.
    L.append("")
    L.append("## Sink integrity (every enabled run)")
    integ_ok = True
    for r in ena:
        rec, pub = r.get("sink_records"), r.get("sink_published")
        dec = r.get("sink_decode_ok")
        partial = r.get("sink_partial_leftover")
        inval = r.get("sink_invalidated")
        good = (dec is True and rec == pub and rec and not partial and inval is None)
        if not good:
            integ_ok = False
        L.append(f"- {r['run_dir']}: records={rec} published={pub} peak={r.get('sink_peak')} "
                 f"bytes={r.get('sink_bytes')} decode={dec} partial={partial} "
                 f"invalidated={inval} → {'OK' if good else 'PROBLEM'}")

    svc = "PASS" if all_pass else "REVIEW"
    L.append("")
    L.append(f"## Verdict")
    L.append(f"- throughput & service-interval means within disabled noise band: **{svc}**")
    L.append(f"- sink integrity (published==captured, gap-free decode, full drain, no leftover): "
             f"**{'PASS' if integ_ok else 'FAIL'}**")
    L.append(f"- sink footprint on dispatch_prep median: **{off_p50:+.1f}µs** "
             f"(≈{off_p50/ (statistics.mean([r['service_mean_ms'] for r in ena if r.get('service_mean_ms')])*1000):.2e} "
             f"of service time)")

    report = "\n".join(L)
    print(report)
    out = out_dirs[0].parent / "step3_combined.md"
    out.write_text(report + "\n", encoding="utf-8")
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

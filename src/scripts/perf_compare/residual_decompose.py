#!/usr/bin/env python3
"""Decompose the unattributed CPU residual in the closure ledgers.

Reuses paired_exec_analyze's parsing + windowing exactly, then:
  1. splits VM busy into /proc/stat fields (u/n/s/hi/si) inside the closure
     window, plus context fields (idle/iowait/steal);
  2. compares tracked process CPU (pc+ch+shared) against the user/system
     split to bound how much of the residual must be system time;
  3. produces a 60s bucket time series of residual rate vs completion rate
     to test whether the residual scales with throughput or is flat.

Usage: residual_decompose.py syz=<log> rfz=<log>   (any subset)
"""

import math
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, "/workspace/talaria/scripts/perf_compare")
import paired_exec_analyze as paired  # noqa: E402

BUCKET_US = 60_000_000

MARKERS = {
    "syz": dict(exec_marker="[SyzExecCPU]", exec_worker_field="wid",
                role_marker="[SyzRoleCPU]", role_worker_field=None,
                vm_marker="[SyzCPU]"),
    "rfz": dict(exec_marker="[RfzExecCPU]", exec_worker_field="w",
                role_marker="[RfzRoleCPU]", role_worker_field="w",
                vm_marker="[RfzCPU]"),
}


def windows(ledger):
    """Reproduce compute_cpu_closure's per-epoch persistent windows."""
    out = []
    for epoch in sorted(
        set(ledger.exec_samples) | set(ledger.role_samples) | set(ledger.vm_samples)
    ):
        exec_by = ledger.exec_samples.get(epoch, {})
        role_by = ledger.role_samples.get(epoch, {})
        vm = ledger.vm_samples.get(epoch, [])
        if not exec_by or not role_by or not vm:
            continue
        persistent = [*role_by.values(), vm]
        if any(len(s) < 2 for s in persistent):
            continue
        start = max(s[0].timestamp_us for s in persistent)
        end = min(s[-1].timestamp_us for s in persistent)
        if end <= start:
            continue
        out.append((epoch, start, end, exec_by, role_by, vm))
    return out


VM_FIELDS = {
    "u": lambda s: s.user,
    "n": lambda s: s.nice,
    "s": lambda s: s.system,
    "i": lambda s: s.idle,
    "w": lambda s: s.iowait,
    "hi": lambda s: s.irq,
    "si": lambda s: s.softirq,
    "st": lambda s: s.steal,
}
EXEC_FIELDS = {
    "done": lambda s: s.done,
    "pc": lambda s: s.process_cpu_us,
    "ch": lambda s: s.children_cpu_us,
    "ex": lambda s: s.execution_cpu_us,
}
ROLE_FIELDS = {"cpu": lambda s: s.cpu_us, "done": lambda s: s.completed}


def bucket_deltas(streams, fields, start, end):
    """Per-bucket summed deltas across consecutive same-stream samples."""
    acc = defaultdict(lambda: defaultdict(int))
    for samples in streams:
        for prev, cur in zip(samples, samples[1:]):
            if cur.timestamp_us < prev.timestamp_us:
                continue
            vals = {f: g(cur) - g(prev) for f, g in fields.items()}
            if any(v < 0 for v in vals.values()):
                continue  # counter reset boundary
            mid = (prev.timestamp_us + cur.timestamp_us) // 2
            if not (start <= mid <= end):
                continue
            b = (mid - start) // BUCKET_US
            for f, v in vals.items():
                acc[b][f] += v
    return acc


def pearson(xs, ys):
    n = len(xs)
    if n < 3:
        return math.nan
    mx = sum(xs) / n
    my = sum(ys) / n
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    sxx = sum((x - mx) ** 2 for x in xs)
    syy = sum((y - my) ** 2 for y in ys)
    if sxx <= 0 or syy <= 0:
        return math.nan
    return sxy / math.sqrt(sxx * syy)


def analyze(name, path):
    ledger = paired.parse_cpu_ledger(Path(path), name, **MARKERS[name])
    print(f"\n{'='*74}\n{name}: {path}\n{'='*74}")
    total = defaultdict(float)
    coverage_us = 0
    series = defaultdict(lambda: defaultdict(float))
    for epoch, start, end, exec_by, role_by, vm in windows(ledger):
        hz = {s.hz for s in vm if start <= s.timestamp_us <= end}
        if len(hz) != 1:
            continue
        t2us = 1_000_000.0 / hz.pop()
        vm_d = paired._counter_delta(vm, start, end, VM_FIELDS,
                                     lambda s: s.timestamp_us)
        exec_ds = [
            paired._counter_delta(s, start, end, EXEC_FIELDS,
                                  lambda s: s.timestamp_us,
                                  include_generation_baselines=True)
            for s in exec_by.values()
        ]
        role_ds = [
            paired._counter_delta(s, start, end, ROLE_FIELDS,
                                  lambda s: s.timestamp_us,
                                  include_generation_baselines=True)
            for s in role_by.values()
        ]
        coverage_us += end - start
        for f in VM_FIELDS:
            total[f] += vm_d.values[f] * t2us
        for d in exec_ds:
            for f in ("done", "pc", "ch", "ex"):
                total[f] += d.values[f]
        for d in role_ds:
            total["shared"] += d.values["cpu"]
            total["shared_done"] += d.values["done"]

        vb = bucket_deltas([vm], VM_FIELDS, start, end)
        eb = bucket_deltas(exec_by.values(), EXEC_FIELDS, start, end)
        rb = bucket_deltas(role_by.values(), ROLE_FIELDS, start, end)
        for b in set(vb) | set(eb) | set(rb):
            row = series[(epoch, b)]
            for f in VM_FIELDS:
                row[f] += vb[b][f] * t2us
            for f in EXEC_FIELDS:
                row[f] += eb[b][f]
            row["shared"] += rb[b]["cpu"]

    busy = total["u"] + total["n"] + total["s"] + total["hi"] + total["si"]
    tracked = total["pc"] + total["ch"] + total["shared"]
    residual = busy - tracked - total["hi"] - total["si"]
    user_side = total["u"] + total["n"]
    cov_s = coverage_us / 1e6

    def row(label, us, denom=busy):
        cores = us / coverage_us if coverage_us else math.nan
        pct = us * 100.0 / denom if denom else math.nan
        print(f"  {label:<34} {us/1e6:>10.1f} s  {cores:>7.4f} cores  {pct:>6.2f}%")

    print(f"coverage window: {cov_s:.1f} s   done={int(total['done'])}"
          f" shared_done={int(total['shared_done'])}")
    print("-- /proc/stat busy split (percent of busy) --")
    row("user (u)", total["u"])
    row("nice (n)", total["n"])
    row("system (s)", total["s"])
    row("hardirq (hi)", total["hi"])
    row("softirq (si)", total["si"])
    row("BUSY total", busy)
    print("-- excluded from busy (context) --")
    row("idle", total["i"])
    row("iowait", total["w"])
    row("steal", total["st"])
    print("-- tracked process CPU --")
    row("loop parents (pc)", total["pc"])
    row("reaped children (ch)", total["ch"])
    row("  of which execution body (ex)", total["ex"])
    row("shared runner/daemon", total["shared"])
    row("TRACKED total", tracked)
    print("-- residual --")
    row("residual (busy - tracked - hi - si)", residual)
    print("-- user/system bound --")
    print(f"  total user-side ticks (u+n)      = {user_side/1e6:>10.1f} s")
    print(f"  tracked total                    = {tracked/1e6:>10.1f} s")
    ker_min = residual - user_side
    print(f"  => residual that MUST be system  = {ker_min/1e6:>10.1f} s"
          f" ({ker_min*100/busy:.1f}% of busy, {ker_min/coverage_us:.3f} cores)")
    print(f"  => untracked user upper bound    = {user_side/1e6:>10.1f} s"
          f" ({user_side*100/busy:.1f}% of busy)")
    if total["done"]:
        print(f"  residual per completed program   = {residual/total['done']/1000:.2f} ms")

    keys = sorted(series)
    resid_rate, done_rate, busy_rate = [], [], []
    for k in keys:
        r = series[k]
        b_busy = r["u"] + r["n"] + r["s"] + r["hi"] + r["si"]
        b_tracked = r["pc"] + r["ch"] + r["shared"]
        b_resid = b_busy - b_tracked - r["hi"] - r["si"]
        if b_busy <= 0:
            continue
        resid_rate.append(b_resid / BUCKET_US)
        done_rate.append(r["done"] / (BUCKET_US / 1e6))
        busy_rate.append(b_busy / BUCKET_US)
    if resid_rate:
        n = len(resid_rate)
        mean_r = sum(resid_rate) / n
        sd_r = math.sqrt(sum((x - mean_r) ** 2 for x in resid_rate) / n)
        print(f"-- 60s buckets: n={n} resid cores mean={mean_r:.3f} sd={sd_r:.3f} "
              f"min={min(resid_rate):.3f} max={max(resid_rate):.3f}")
        print(f"   corr(resid, done/s) = {pearson(resid_rate, done_rate):+.3f}   "
              f"corr(resid, busy)   = {pearson(resid_rate, busy_rate):+.3f}")


if __name__ == "__main__":
    for arg in sys.argv[1:]:
        name, path = arg.split("=", 1)
        analyze(name, path)

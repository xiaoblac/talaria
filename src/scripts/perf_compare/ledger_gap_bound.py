#!/usr/bin/env python3
"""Bound the ledger's own structural losses inside the closure window.

Two mechanisms lose CPU without any kernel-thread explanation:
  (A) generation truncation -- a loop parent dies between its last 5s sample and
      its exit; that tail is never emitted, and the successor's baseline only
      recovers the successor's own birth->first-sample cost.
  (B) sampling-edge truncation -- the first/last partial interval of each stream
      relative to the common window.
Quantify both so the residual can be attributed to them or ruled clear of them.

Usage: ledger_gap_bound.py syz=<log> rfz=<log>   (any subset)
"""

import sys
from pathlib import Path

sys.path.insert(0, "/workspace/talaria/scripts/perf_compare")
import paired_exec_analyze as paired  # noqa: E402

MARKERS = {
    "syz": dict(exec_marker="[SyzExecCPU]", exec_worker_field="wid",
                role_marker="[SyzRoleCPU]", role_worker_field=None,
                vm_marker="[SyzCPU]"),
    "rfz": dict(exec_marker="[RfzExecCPU]", exec_worker_field="w",
                role_marker="[RfzRoleCPU]", role_worker_field="w",
                vm_marker="[RfzCPU]"),
}


def analyze(name, path):
    led = paired.parse_cpu_ledger(Path(path), name, **MARKERS[name])
    print(f"\n{'='*74}\n{name}: ledger structural loss bound\n{'='*74}")
    for epoch in sorted(led.exec_samples):
        exec_by = led.exec_samples[epoch]
        role_by = led.role_samples.get(epoch, {})
        vms = led.vm_samples.get(epoch, [])
        if not role_by or not vms:
            continue
        persistent = [*role_by.values(), vms]
        start = max(s[0].timestamp_us for s in persistent)
        end = min(s[-1].timestamp_us for s in persistent)
        win = end - start
        print(f"epoch {epoch}: window {win/1e6:.1f}s  exec IDs={len(exec_by)}")

        gen_events = []
        rate_samples = []
        lifetimes = []
        for w, samples in sorted(exec_by.items()):
            sel = [s for s in samples if start <= s.timestamp_us <= end]
            if len(sel) < 2:
                continue
            lifetimes.append((w, len(sel),
                              (sel[-1].timestamp_us - sel[0].timestamp_us) / 1e6))
            for prev, cur in zip(sel, sel[1:]):
                dt = cur.timestamp_us - prev.timestamp_us
                dpc = cur.process_cpu_us - prev.process_cpu_us
                dch = cur.children_cpu_us - prev.children_cpu_us
                if dpc < 0 or dch < 0 or dt <= 0:
                    gen_events.append((w, prev.timestamp_us,
                                       prev.process_cpu_us, prev.children_cpu_us,
                                       cur.timestamp_us, cur.process_cpu_us,
                                       cur.children_cpu_us))
                    continue
                rate_samples.append((dpc + dch) / dt)

        if rate_samples:
            rate_samples.sort()
            n = len(rate_samples)
            mean_rate = sum(rate_samples) / n
            p50 = rate_samples[n // 2]
            p90 = rate_samples[int(n * 0.9)]
            print(f"  per-ID (pc+ch) rate: mean={mean_rate:.3f} p50={p50:.3f} "
                  f"p90={p90:.3f} cores  (n={n} intervals)")
        else:
            mean_rate = p90 = 0.0

        gaps = [(ev[4] - ev[1]) for ev in gen_events]
        recovered = sum(ev[5] + ev[6] for ev in gen_events)
        if gen_events:
            gaps.sort()
            total_gap = sum(gaps)
            print(f"  generation boundaries: {len(gen_events)}  "
                  f"gap sum={total_gap/1e6:.1f}s  "
                  f"p50={gaps[len(gaps)//2]/1e6:.1f}s max={gaps[-1]/1e6:.1f}s")
            print(f"    baseline CPU credited to successors: {recovered/1e6:.1f}s")
            print(f"    UPPER BOUND on lost predecessor tail "
                  f"(gap x mean rate): {total_gap*mean_rate/1e6:.1f}s "
                  f"(x p90 rate: {total_gap*p90/1e6:.1f}s)")

        edge = 0
        for samples in persistent:
            sel = [s for s in samples if start <= s.timestamp_us <= end]
            if sel:
                edge += (sel[0].timestamp_us - start) + (end - sel[-1].timestamp_us)
        print(f"  persistent-stream edge gap total: {edge/1e6:.2f}s")

        covered = 0
        for w, samples in exec_by.items():
            sel = [s for s in samples if start <= s.timestamp_us <= end]
            if len(sel) >= 2:
                covered += sel[-1].timestamp_us - sel[0].timestamp_us
        concurrent = covered / win if win else 0
        print(f"  summed exec-ID sampled coverage = {covered/1e6:.0f}s "
              f"=> {concurrent:.2f} loop parents observed on average")
        print(f"  exec-ID lifetimes (id, samples, span_s): "
              f"{sorted(lifetimes, key=lambda x: -x[2])[:8]}")


if __name__ == "__main__":
    for arg in sys.argv[1:]:
        name, path = arg.split("=", 1)
        analyze(name, path)

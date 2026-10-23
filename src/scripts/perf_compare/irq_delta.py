#!/usr/bin/env python3
"""Delta /proc/softirqs and /proc/interrupts across the capture window."""

import sys
from pathlib import Path


def parse_counter_file(path):
    """Return {label: total_across_cpus}. Works for softirqs and interrupts."""
    out = {}
    lines = Path(path).read_text(errors="replace").splitlines()
    if not lines:
        return out
    for line in lines[1:]:
        if ":" not in line:
            continue
        label, rest = line.split(":", 1)
        label = label.strip()
        total = 0
        trailing = []
        for tok in rest.split():
            if tok.lstrip("-").isdigit():
                total += int(tok)
            else:
                trailing.append(tok)
        if trailing:
            label = f"{label} ({' '.join(trailing)})"
        out[label] = total
    return out


def report(name, directory, seconds):
    d = Path(directory)
    for kind, fb, fa in (("softirq", "si.before", "si.after"),
                         ("interrupt", "int.before", "int.after")):
        pb, pa = d / fb, d / fa
        if not (pb.is_file() and pa.is_file()):
            print(f"[{name}] missing {kind} snapshots")
            continue
        b, a = parse_counter_file(pb), parse_counter_file(pa)
        rows = []
        for k in a:
            delta = a[k] - b.get(k, 0)
            if delta > 0:
                rows.append((k, delta))
        rows.sort(key=lambda x: -x[1])
        total = sum(v for _, v in rows)
        print(f"\n-- {name} {kind} counts over {seconds:.0f}s "
              f"(total {total} = {total/seconds:.0f}/s) --")
        for k, v in rows[:12]:
            print(f"   {k:<34} {v:>10}  {v/seconds:>9.0f}/s  {v*100.0/total:5.1f}%")


if __name__ == "__main__":
    for arg in sys.argv[1:]:
        name, directory, secs = arg.split("=", 2)
        report(name, directory, float(secs))

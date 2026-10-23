#!/usr/bin/env python3
"""Render the final static coverage-over-time comparison figure.

Reads the merged CSV produced by `cov-compare` (elapsed_sec + one
<label>_pc column per tool; cells are empty past a tool's last real
sample) and draws ONE figure with both lines on a shared X axis. Each
line stops at the tool's own last sample (empty cells are skipped), so
there is no misleading flat extrapolation.

This is the end-of-run deliverable. During the run, cov-compare's live
mode shows the two tools as separate side-by-side panels instead.

X-axis (t=0): both curves are anchored at FIRST FUZZ EXEC. syz's "fuzz time
ms" is already boot/machine-check-excluded; cov-compare re-bases reFuzz's
coverage metric log to its fuzz-phase start (read from the co-located
run_summary.json) so the boot + machine-check plateau is dropped, not counted
as fuzzing time. The merged CSV this reads is therefore already aligned.

Y-axis caveat (by design): the default speed_compare plot is syzkaller
"coverage" (syz_corpus_cover) vs reFuzz "corpus_pc". Both are corpus-admitted
coverage curves, but strict equality still belongs to the PC-set artifacts
after address normalization and optional allow-list cropping.
"""
import argparse
import csv

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

CAVEAT = ("Y = corpus-admitted coverage (syz_corpus_cover vs reFuzz corpus_pc); "
          "strict equality belongs to PC-set Jaccard after PC normalization/filtering.")


def load(csv_path):
    with open(csv_path, newline="") as f:
        rows = list(csv.reader(f))
    if not rows:
        raise SystemExit(f"{csv_path}: empty")
    header = rows[0]
    names = header[1:]
    xs = []
    cols = {n: [] for n in names}
    for r in rows[1:]:
        if not r:
            continue
        try:
            x = float(r[0])
        except ValueError:
            continue
        xs.append(x)
        for i, n in enumerate(names, start=1):
            cell = r[i].strip() if i < len(r) else ""
            cols[n].append(float(cell) if cell != "" else None)
    return xs, names, cols


def xy(xs, ys):
    xx, yy = [], []
    for x, y in zip(xs, ys):
        if y is not None:
            xx.append(x)
            yy.append(y)
    return xx, yy


def label_of(col):
    return col[:-3] if col.endswith("_pc") else col


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True, help="merged CSV from cov-compare")
    ap.add_argument("--out", default="coverage_compare.png")
    ap.add_argument("--title", default="Coverage over time — reFuzz vs syzkaller")
    ap.add_argument("--dual-y", action="store_true",
                    help="give each of two series its own Y axis (shape focus)")
    args = ap.parse_args()

    xs, names, cols = load(args.csv)
    fig, ax = plt.subplots(figsize=(9, 5))
    colors = ["#1f77b4", "#d62728", "#2ca02c", "#9467bd"]

    if args.dual_y and len(names) == 2:
        axes = [ax, ax.twinx()]
        for axis, name, color in zip(axes, names, colors):
            xx, yy = xy(xs, cols[name])
            axis.plot(xx, yy, color=color, label=label_of(name))
            axis.set_ylabel(f"{label_of(name)} distinct PC", color=color)
            axis.tick_params(axis="y", labelcolor=color)
    else:
        for name, color in zip(names, colors):
            xx, yy = xy(xs, cols[name])
            ax.plot(xx, yy, color=color, label=label_of(name))
        ax.set_ylabel("distinct PC")
        ax.legend(loc="lower right")

    ax.set_xlabel("elapsed since first fuzz exec (s)")
    ax.set_title(args.title)
    ax.grid(True, linestyle=":", alpha=0.5)
    fig.text(0.5, -0.02, CAVEAT, ha="center", va="top", fontsize=8, color="#555555", wrap=True)
    fig.tight_layout()
    fig.savefig(args.out, dpi=130, bbox_inches="tight")
    print(f"coverage comparison figure -> {args.out}")


if __name__ == "__main__":
    main()

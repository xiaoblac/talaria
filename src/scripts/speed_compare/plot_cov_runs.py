#!/usr/bin/env python3
"""plot_cov_runs.py — 把一个内核的 n 次 run 聚合成一张覆盖率-时间图。

现有 plot_cov_compare.py 只画一次 run 的一对曲线。这里做跨 run 聚合：每侧
中位数线 + min-max 带。

为什么是中位数+min-max，不是均值±标准差:
    n=3。三个点算标准差没有意义（自由度 2），而 min-max 带诚实地表达了
    "我们只看到这三条曲线，它们落在这个范围里"。均值±SD 会让读者以为背后有
    一个被估计出来的分布。

为什么不做显著性检验:
    n=3 撑不起。这张图主张的是"reFuzz 的曲线在 min-max 带不重叠的区间里高于
    syzkaller"，这是可以看出来的；不是"p<0.05"。要检验就得把 run 数提到 5 以上。

输入是 speed_compare.py 产出的 D_cov_{tag}_run_NN.csv，形状:
    elapsed_sec,<label>_pc[,<label>_pc...]
每次 run 一个目录，所以按目录收集。
"""
from __future__ import annotations

import argparse
import csv
import math
import re
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def read_csv(path: Path) -> tuple[list[float], dict[str, list[float | None]]]:
    """返回 (elapsed 列, {列名: 值列})。空格子读成 None，不是 0。

    空格子的语义是"这一侧在这个时刻已经没有样本了"（两侧结束时间不同），
    读成 0 会让曲线在末尾掉到地板，读成前值会平推一条假的水平线。None 让
    下游 aggregate 跳过它。
    """
    with path.open(newline="", encoding="utf-8") as f:
        rows = list(csv.reader(f))
    if not rows:
        raise ValueError(f"{path} 是空的")
    header = rows[0]
    if header[0] != "elapsed_sec":
        raise ValueError(f"{path} 第一列是 {header[0]!r}，不是 elapsed_sec")
    elapsed: list[float] = []
    cols: dict[str, list[float | None]] = {h: [] for h in header[1:]}
    for r in rows[1:]:
        if not r or not r[0].strip():
            continue
        elapsed.append(float(r[0]))
        for i, h in enumerate(header[1:], start=1):
            cell = r[i].strip() if i < len(r) else ""
            cols[h].append(float(cell) if cell else None)
    return elapsed, cols


def side_of(colname: str) -> str:
    """把列名归到 refuzz / syzkaller。列名形如 'syzkaller_(corpus)_pc'。"""
    low = colname.lower()
    if "refuzz" in low or low.startswith("rfz"):
        return "refuzz"
    if "syz" in low:
        return "syzkaller"
    return colname


def step_sample(grid: list[float], xs: list[float],
                ys: list[float | None]) -> list[float | None]:
    """把一条曲线重采样到公共时间栅格，用阶梯保持（不插值）。

    覆盖率是单调不减的累积量，取"到 t 为止最后一个已知值"才是它的真实语义；
    线性插值会在两个样本之间编造出内核从未报告过的中间覆盖率。
    栅格点早于该 run 第一个样本，或晚于最后一个样本 → None（不外推）。
    """
    out: list[float | None] = []
    i = 0
    last: float | None = None
    n = len(xs)
    last_x = xs[-1] if n else None
    for t in grid:
        while i < n and xs[i] <= t:
            if ys[i] is not None:
                last = ys[i]
            i += 1
        # 超出这条 run 的覆盖范围就不给值，避免把短的那条 run 平推到 48h
        # 末尾、伪装成"它也跑到了那里"。
        out.append(last if (last_x is not None and t <= last_x) else None)
    return out


def aggregate(curves: list[list[float | None]]) -> tuple[
        list[float | None], list[float | None], list[float | None], list[int]]:
    """逐栅格点算 (中位数, min, max, 有效 run 数)。"""
    med: list[float | None] = []
    lo: list[float | None] = []
    hi: list[float | None] = []
    cnt: list[int] = []
    for j in range(len(curves[0]) if curves else 0):
        vals = [c[j] for c in curves if c[j] is not None]
        cnt.append(len(vals))
        if not vals:
            med.append(None); lo.append(None); hi.append(None)
            continue
        vals.sort()
        m = len(vals)
        med.append(vals[m // 2] if m % 2 else (vals[m // 2 - 1] + vals[m // 2]) / 2)
        lo.append(vals[0])
        hi.append(vals[-1])
    return med, lo, hi, cnt


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", type=Path, nargs="+", required=True,
                    help="每次 run 的输出目录（含 D_cov_*.csv）")
    ap.add_argument("--tag", default="corpus",
                    help="corpus（PC）或 edge，对应 D_cov_<tag>_run_NN.csv")
    ap.add_argument("--kernel", required=True, help="图标题里的内核版本")
    ap.add_argument("--out", type=Path, required=True, help="输出 PNG")
    ap.add_argument("--csv-out", type=Path, default=None,
                    help="同时导出聚合后的 CSV")
    ap.add_argument("--grid-step", type=float, default=60.0,
                    help="公共时间栅格步长（秒）")
    args = ap.parse_args()

    # 收集：每个 run 目录里找 D_cov_<tag>_run_*.csv
    per_side: dict[str, list[tuple[list[float], list[float | None]]]] = {}
    used: list[str] = []
    for d in args.run_dir:
        hits = sorted(d.glob(f"D_cov_{args.tag}_run_*.csv"))
        if not hits:
            print(f"  [跳过] {d} 里没有 D_cov_{args.tag}_run_*.csv")
            continue
        for csv_path in hits:
            elapsed, cols = read_csv(csv_path)
            if len(elapsed) < 2:
                print(f"  [跳过] {csv_path} 只有 {len(elapsed)} 个样本")
                continue
            for cname, vals in cols.items():
                per_side.setdefault(side_of(cname), []).append((elapsed, vals))
            used.append(str(csv_path))

    if not per_side:
        raise SystemExit("没有可用数据")

    # 公共栅格取所有 run 的最短末点：超过它就有 run 没数据了，画出来会是
    # 逐渐变细的样本量，视觉上却仍是一条实线。截断比标注更诚实。
    ends = [e[-1] for curves in per_side.values() for e, _ in curves]
    t_end = min(ends)
    steps = max(2, int(t_end / args.grid_step) + 1)
    grid = [i * args.grid_step for i in range(steps)]

    fig, ax = plt.subplots(figsize=(9, 5.5))
    colors = {"refuzz": "#d62728", "syzkaller": "#1f77b4"}
    summary: dict[str, tuple] = {}

    for side in sorted(per_side, key=lambda s: s != "refuzz"):
        curves = [step_sample(grid, e, v) for e, v in per_side[side]]
        med, lo, hi, cnt = aggregate(curves)
        c = colors.get(side, "#666666")
        xs = [t for t, m in zip(grid, med) if m is not None]
        ms = [m for m in med if m is not None]
        los = [l for l, m in zip(lo, med) if m is not None]
        his = [h for h, m in zip(hi, med) if m is not None]
        n_runs = len(curves)
        ax.plot([x / 3600 for x in xs], ms, color=c, lw=1.9,
                label=f"{side} (median, n={n_runs})")
        ax.fill_between([x / 3600 for x in xs], los, his, color=c, alpha=0.18,
                        linewidth=0, label=f"{side} min–max")
        summary[side] = (n_runs, ms[-1] if ms else 0,
                         los[-1] if los else 0, his[-1] if his else 0)

    metric = "corpus-admitted PCs" if args.tag == "corpus" else "corpus edges"
    ax.set_xlabel("fuzzing time (hours, anchored at first fuzz exec)")
    ax.set_ylabel(metric)
    ax.set_title(f"Coverage over time — Linux {args.kernel}  "
                 f"({args.tag}, {t_end/3600:.1f}h)")
    ax.grid(alpha=0.25, linestyle=":")
    ax.legend(loc="lower right", fontsize=8)
    ax.set_xlim(left=0)
    ax.set_ylim(bottom=0)

    caveat = ("Median line with min–max band over independent runs; no significance "
              "test at this n.\nY = corpus-admitted coverage; strict set equality "
              "belongs to PC-set Jaccard after normalization.")
    fig.text(0.01, 0.005, caveat, fontsize=6.5, color="#555555", va="bottom")
    fig.tight_layout(rect=(0, 0.055, 1, 1))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(args.out, dpi=170)
    print(f"图 → {args.out}")

    for side, (n, m, l, h) in summary.items():
        print(f"  {side}: n={n}  final median={m:,.0f}  min={l:,.0f}  max={h:,.0f}")
    if len(summary) == 2 and "refuzz" in summary and "syzkaller" in summary:
        r, s = summary["refuzz"], summary["syzkaller"]
        if s[1] > 0:
            print(f"  中位数终值比: {r[1]/s[1]:.3f}×")
        # 带重叠 → 这个内核上不能主张分离。宁可让脚本说出来，也不要让读图的人
        # 自己判断两条阴影有没有碰上。
        if r[2] <= s[3] and s[2] <= r[3]:
            print("  [注意] 终点 min-max 带重叠 —— 这个内核上不足以主张分离")

    if args.csv_out:
        args.csv_out.parent.mkdir(parents=True, exist_ok=True)
        sides = sorted(per_side, key=lambda s: s != "refuzz")
        agg = {}
        for side in sides:
            curves = [step_sample(grid, e, v) for e, v in per_side[side]]
            agg[side] = aggregate(curves)
        with args.csv_out.open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            hdr = ["elapsed_sec"]
            for s in sides:
                hdr += [f"{s}_median", f"{s}_min", f"{s}_max", f"{s}_n"]
            w.writerow(hdr)
            for j, t in enumerate(grid):
                row: list = [f"{t:.3f}"]
                for s in sides:
                    med, lo, hi, cnt = agg[s]
                    row += ["" if med[j] is None else f"{med[j]:.0f}",
                            "" if lo[j] is None else f"{lo[j]:.0f}",
                            "" if hi[j] is None else f"{hi[j]:.0f}",
                            cnt[j]]
                w.writerow(row)
        print(f"聚合 CSV → {args.csv_out}")

    print(f"用到 {len(used)} 个 CSV:")
    for u in used:
        print(f"    {u}")


if __name__ == "__main__":
    main()

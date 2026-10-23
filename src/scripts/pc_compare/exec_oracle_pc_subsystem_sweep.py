#!/usr/bin/env python3
"""[Exp C++] 全 syscall × errno-pair 子系统级 PC 根因 sweep。

把 exec_oracle_pc_subsystem_diff.py 的 (按 errno-pair 隔离 + 源文件子系统分类)
方法批量套到 jsonl 的所有 (syscall, syz_err, ref_err) 组,一次性算完,出两份:

  --out-csv  机器友好,每 (syscall, errno-pair) 一行:counts / structural% /
             real% / top-3 ref_only 真路径子系统 / top-3 syz_only 真路径子系统
             / verdict_hint。可在 numbers / Excel 里排序。
  --out-txt  人读,每 syscall 一块,内部按 errno-pair 排开,每个 errno-pair 给
             top 子系统(`*` 真路径)+ 真路径里 top 函数。

性能要点:全 jsonl unique PC 去重后**一次性** addr2line,把每 PC 的
(func, file:line) 缓存,再分组分类 — 避免 (syscall, errno-pair) × 数百组重复
addr2line 同一个 PC。

数据源 / vmlinux 路径见 docs/plans/kcov-structural-noise/02_pc_subsystem_rootcause_method.md。
"""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path


# 跟 pc_subsystem_diff.py 同步;有变化时一起改。
STRUCTURAL_PREFIXES = (
    "mm", "lib/maple_tree", "lib/xarray", "lib/radix-tree",
    "arch/x86", "include", "kernel/rcu", "lib/find_bit",
)
REAL_PATH_SUBSYSTEMS = ("arch/x86/kvm",)


def is_structural(sub: str) -> bool:
    if sub in REAL_PATH_SUBSYSTEMS:
        return False
    return any(sub == p or sub.startswith(p + "/") or sub == p
               for p in STRUCTURAL_PREFIXES)


def parse_pcs_hex(s: str) -> set[str]:
    """每个 PC 是 16 个 hex 字符的定长块。返回 hex 字符串 set。"""
    if not s or len(s) % 16 != 0:
        return set()
    return {s[i:i + 16] for i in range(0, len(s), 16)}


def subsystem(path: str, kroot_marker: str = "/linux-") -> str:
    """源文件路径 → 子系统标签(top-level 目录 + 二级)。
    跟 pc_subsystem_diff.py 同源逻辑,但去 `:line`、跳版本号目录。"""
    if path in ("??", "", None):
        return "?"
    if kroot_marker in path:
        rel = path.split(kroot_marker, 1)[1]
        rel = rel.split("/", 1)[1] if "/" in rel else rel
    else:
        rel = path
    rel = rel.split(":", 1)[0]
    parts = rel.split("/")
    top = parts[0]
    if len(parts) > 3 and parts[0] == "arch" and parts[1] == "x86" and parts[2] == "kvm":
        return "arch/x86/kvm"
    if top in ("fs", "lib", "kernel", "arch", "block", "drivers",
               "security", "virt", "net", "ipc", "crypto", "sound"):
        if len(parts) > 1:
            return f"{top}/{parts[1].split('.')[0]}"
        return top
    return top


@dataclass
class GroupAcc:
    """一个 (syscall, syz_err, ref_err) 组的聚合。"""
    syscall: str
    syz_err: int
    ref_err: int
    records: int = 0
    syz_union: set[str] = field(default_factory=set)
    ref_union: set[str] = field(default_factory=set)
    per_rec_jac_sum: float = 0.0
    per_rec_jac_n: int = 0


def iter_records(path: Path):
    with path.open("r", encoding="utf-8") as f:
        for ln, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def addr2line_bulk(vmlinux: Path, pcs: list[str], batch: int = 30_000):
    """bulk addr2line: hex-string PC list → list of (func, file:line)。
    保留输入顺序。"""
    out: list[tuple[str, str]] = []
    for start in range(0, len(pcs), batch):
        chunk = pcs[start:start + batch]
        inp = "\n".join("0x" + p for p in chunk) + "\n"
        proc = subprocess.run(
            ["addr2line", "-f", "-e", str(vmlinux)],
            input=inp, capture_output=True, text=True, timeout=1200,
        )
        lines = proc.stdout.splitlines()
        # addr2line -f outputs: func / file:line (两行一对)。
        for i in range(len(chunk)):
            func = lines[2 * i].strip() if 2 * i < len(lines) else "??"
            fl = lines[2 * i + 1].strip() if 2 * i + 1 < len(lines) else "??"
            out.append((func, fl))
    return out


def compute_verdict_hint(g: GroupAcc, ref_real_pct: float, syz_real_pct: float,
                        ref_only_n: int, syz_only_n: int,
                        jac: float) -> str:
    """快速 verdict 提示。要复核,不是结论。

    规则(顺序敏感):
      - errno_match + 两侧 ref_only/syz_only 都低 → ok_aligned
      - errno_match + ref_only_n 远大于 syz_only_n + ref real% < 30 → structural_noise
      - errno_match + ref real% >= 50 → real_path_ref_extra (reFuzz 多走真路径)
      - errno_mismatch + 哪边 real% 高 → real_path_<side>_missing
      - 两侧 PC 太少 → low_signal
    """
    errno_match = (g.syz_err == g.ref_err)
    if (ref_only_n + syz_only_n) < 20:
        return "low_signal"
    if errno_match:
        if jac >= 0.7:
            return "ok_aligned"
        if ref_only_n > 0 and syz_only_n > 0 and \
                ref_only_n / max(1, syz_only_n) >= 3 and ref_real_pct < 30:
            return "structural_noise_ref_superset"
        if ref_real_pct >= 50:
            return "real_path_ref_extra"
        if syz_real_pct >= 50:
            return "real_path_syz_extra"
        return "structural_mixed"
    else:
        # errno 不一致:syz 早返 / ref 早返 → 看哪边 real% 主导
        if ref_real_pct >= 50 and syz_real_pct < 50:
            return "real_path_ref_completed"  # ref 走完 SUT, syz 早返
        if syz_real_pct >= 50 and ref_real_pct < 50:
            return "real_path_syz_completed"
        if ref_real_pct >= 30 and syz_real_pct >= 30:
            return "real_path_both"
        return "errno_mismatch_structural"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--jsonl", type=Path, required=True)
    ap.add_argument("--vmlinux", type=Path, required=True)
    ap.add_argument("--out-csv", type=Path, required=True)
    ap.add_argument("--out-txt", type=Path, required=True)
    ap.add_argument("--min-records", type=int, default=3,
                    help="errno-pair 至少这么多 records 才出现在 TXT (默认 3),"
                         "CSV 不过滤")
    ap.add_argument("--topn-sub-csv", type=int, default=3,
                    help="CSV 里 top-N real-path 子系统列(默认 3)")
    ap.add_argument("--topn-sub-txt", type=int, default=10)
    ap.add_argument("--topn-func-txt", type=int, default=12)
    ap.add_argument("--include-non-pseudo", action="store_true",
                    help="不只 syz_*,所有 syscall 都扫")
    args = ap.parse_args()

    if not args.jsonl.exists() or not args.vmlinux.exists():
        print("error: missing input", file=sys.stderr)
        return 2

    # ---- pass 1: 收集分组 + 全 PC universe ----
    groups: dict[tuple[str, int, int], GroupAcc] = {}
    pc_universe: set[str] = set()
    total_recs = 0
    cover_recs = 0

    for rec in iter_records(args.jsonl):
        total_recs += 1
        name = rec.get("syscall", "")
        if not name:
            continue
        if not args.include_non_pseudo and not name.startswith("syz_"):
            # 老规矩:默认只看 pseudo;真 syscall 数量太多噪音大
            # 但 ptrace / openat 是真 syscall 且重要,容户自己加 --include-non-pseudo
            continue
        if not rec.get("cover_available"):
            continue
        if rec.get("kcov_buffer_overflow"):
            continue
        cover_recs += 1
        syz_err = int(rec.get("syz_err", 0))
        ref_err = int(rec.get("ref_err", 0))
        key = (name, syz_err, ref_err)
        g = groups.get(key)
        if g is None:
            g = GroupAcc(syscall=name, syz_err=syz_err, ref_err=ref_err)
            groups[key] = g
        g.records += 1
        syz = parse_pcs_hex(rec.get("syz_pcs_hex", ""))
        ref = parse_pcs_hex(rec.get("ref_pcs_hex", ""))
        g.syz_union |= syz
        g.ref_union |= ref
        pc_universe.update(syz)
        pc_universe.update(ref)
        # per-record jaccard
        if syz or ref:
            jac = len(syz & ref) / len(syz | ref)
            g.per_rec_jac_sum += jac
            g.per_rec_jac_n += 1

    print(f"records: total={total_recs} cover_eligible={cover_recs}", file=sys.stderr)
    print(f"groups (syscall × errno-pair): {len(groups)}", file=sys.stderr)
    print(f"unique PCs to symbolize: {len(pc_universe)}", file=sys.stderr)

    # ---- pass 2: bulk addr2line ----
    pc_list = sorted(pc_universe)
    print(f"running addr2line on {len(pc_list)} PCs (KASAN vmlinux, 慢约 1-3min)…",
          file=sys.stderr)
    a2l_pairs = addr2line_bulk(args.vmlinux, pc_list)
    pc_meta: dict[str, tuple[str, str, str]] = {}  # pc → (func, file:line, sub)
    for pc, (func, fl) in zip(pc_list, a2l_pairs):
        sub = subsystem(fl)
        pc_meta[pc] = (func, fl, sub)

    # ---- pass 3: per-group 分类 + 输出 ----
    def classify_pcs(pcs: set[str]):
        """返回 (sub_count, sub_func_count, structural_n, real_n)。
        sub_func_count: {sub: Counter(func -> n)}"""
        sub_ct: Counter = Counter()
        sub_fn: dict[str, Counter] = defaultdict(Counter)
        s_n = r_n = 0
        for pc in pcs:
            func, fl, sub = pc_meta.get(pc, ("?", "?", "?"))
            sub_ct[sub] += 1
            sub_fn[sub][func] += 1
            if is_structural(sub):
                s_n += 1
            else:
                r_n += 1
        return sub_ct, sub_fn, s_n, r_n

    # CSV
    csv_fields = [
        "syscall", "syz_err", "ref_err", "errno_match", "records",
        "syz_pc", "ref_pc", "common", "ref_only", "syz_only",
        "union_jaccard", "per_rec_jac_avg",
        "ref_only_structural_pct", "ref_only_real_pct",
        "syz_only_structural_pct", "syz_only_real_pct",
        "top1_ref_real_sub", "top1_ref_real_n",
        "top2_ref_real_sub", "top2_ref_real_n",
        "top3_ref_real_sub", "top3_ref_real_n",
        "top1_ref_real_func",
        "top1_syz_real_sub", "top1_syz_real_n",
        "top2_syz_real_sub", "top2_syz_real_n",
        "top3_syz_real_sub", "top3_syz_real_n",
        "top1_syz_real_func",
        "verdict_hint",
    ]

    rows = []
    txt_by_syscall: dict[str, list[dict]] = defaultdict(list)

    def top_real_subs(sub_ct: Counter, sub_fn: dict[str, Counter], k: int):
        """top-k real-path subsystems with (sub_name, count, top_func)."""
        out = []
        for sub, n in sub_ct.most_common():
            if is_structural(sub):
                continue
            top_fn = sub_fn[sub].most_common(1)
            top_fn_name = top_fn[0][0] if top_fn else "?"
            out.append((sub, n, top_fn_name))
            if len(out) >= k:
                break
        return out

    for key, g in groups.items():
        syz_only = g.syz_union - g.ref_union
        ref_only = g.ref_union - g.syz_union
        common = g.syz_union & g.ref_union
        union = g.syz_union | g.ref_union
        u_jac = len(common) / len(union) if union else 1.0
        per_rec_jac_avg = (g.per_rec_jac_sum / g.per_rec_jac_n
                           if g.per_rec_jac_n else 0.0)

        ref_sub_ct, ref_sub_fn, ref_s, ref_r = classify_pcs(ref_only)
        syz_sub_ct, syz_sub_fn, syz_s, syz_r = classify_pcs(syz_only)
        ref_tot = max(1, ref_s + ref_r)
        syz_tot = max(1, syz_s + syz_r)
        ref_struct_pct = 100.0 * ref_s / ref_tot
        ref_real_pct = 100.0 * ref_r / ref_tot
        syz_struct_pct = 100.0 * syz_s / syz_tot
        syz_real_pct = 100.0 * syz_r / syz_tot

        ref_top = top_real_subs(ref_sub_ct, ref_sub_fn, args.topn_sub_csv)
        syz_top = top_real_subs(syz_sub_ct, syz_sub_fn, args.topn_sub_csv)

        def cell(top_list, idx, field):
            if idx >= len(top_list):
                return ""
            sub, n, fn = top_list[idx]
            if field == "sub":
                return sub
            if field == "n":
                return str(n)
            if field == "fn":
                return fn
            return ""

        verdict = compute_verdict_hint(
            g, ref_real_pct, syz_real_pct,
            len(ref_only), len(syz_only), u_jac)

        row = {
            "syscall": g.syscall,
            "syz_err": g.syz_err,
            "ref_err": g.ref_err,
            "errno_match": int(g.syz_err == g.ref_err),
            "records": g.records,
            "syz_pc": len(g.syz_union),
            "ref_pc": len(g.ref_union),
            "common": len(common),
            "ref_only": len(ref_only),
            "syz_only": len(syz_only),
            "union_jaccard": f"{u_jac:.4f}",
            "per_rec_jac_avg": f"{per_rec_jac_avg:.4f}",
            "ref_only_structural_pct": f"{ref_struct_pct:.1f}",
            "ref_only_real_pct": f"{ref_real_pct:.1f}",
            "syz_only_structural_pct": f"{syz_struct_pct:.1f}",
            "syz_only_real_pct": f"{syz_real_pct:.1f}",
            "top1_ref_real_sub": cell(ref_top, 0, "sub"),
            "top1_ref_real_n":   cell(ref_top, 0, "n"),
            "top2_ref_real_sub": cell(ref_top, 1, "sub"),
            "top2_ref_real_n":   cell(ref_top, 1, "n"),
            "top3_ref_real_sub": cell(ref_top, 2, "sub"),
            "top3_ref_real_n":   cell(ref_top, 2, "n"),
            "top1_ref_real_func": cell(ref_top, 0, "fn"),
            "top1_syz_real_sub": cell(syz_top, 0, "sub"),
            "top1_syz_real_n":   cell(syz_top, 0, "n"),
            "top2_syz_real_sub": cell(syz_top, 1, "sub"),
            "top2_syz_real_n":   cell(syz_top, 1, "n"),
            "top3_syz_real_sub": cell(syz_top, 2, "sub"),
            "top3_syz_real_n":   cell(syz_top, 2, "n"),
            "top1_syz_real_func": cell(syz_top, 0, "fn"),
            "verdict_hint": verdict,
        }
        rows.append(row)

        # 给 TXT 也保留更 rich 的快照
        txt_by_syscall[g.syscall].append({
            "key": key, "row": row,
            "ref_sub_ct": ref_sub_ct, "ref_sub_fn": ref_sub_fn,
            "syz_sub_ct": syz_sub_ct, "syz_sub_fn": syz_sub_fn,
            "ref_s": ref_s, "ref_r": ref_r,
            "syz_s": syz_s, "syz_r": syz_r,
        })

    # ---- 写 CSV(按 ref_only 倒序) ----
    rows.sort(key=lambda r: (-r["ref_only"], -r["syz_only"], r["syscall"]))
    args.out_csv.parent.mkdir(parents=True, exist_ok=True)
    with args.out_csv.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=csv_fields, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)

    # ---- 写 TXT(按 syscall 块,内部 errno-pair 按 records 倒序) ----
    syscalls_sorted = sorted(
        txt_by_syscall.keys(),
        key=lambda s: -sum(item["row"]["records"] for item in txt_by_syscall[s]),
    )

    args.out_txt.parent.mkdir(parents=True, exist_ok=True)
    bar_eq = "═" * 78
    bar_dash = "─" * 78
    with args.out_txt.open("w", encoding="utf-8") as f:
        # SUMMARY
        f.write("# PC 子系统级根因 sweep — exec_oracle_pc_subsystem_sweep.py\n")
        f.write("# 方法:docs/plans/kcov-structural-noise/02_pc_subsystem_rootcause_method.md\n")
        f.write(f"# 数据:{args.jsonl}\n")
        f.write(f"# vmlinux:{args.vmlinux}\n#\n")
        f.write(f"# 总 records (cover_available + non-overflow):{cover_recs}\n")
        f.write(f"# 总 (syscall × errno-pair) 组:{len(groups)}\n")
        f.write(f"# 总 unique PC (跨所有组,addr2line 已 dedup):{len(pc_universe)}\n#\n")
        f.write("# 列读法:\n")
        f.write("#   ref_only / syz_only:union 后的差集 PC 数\n")
        f.write("#   union_jaccard:整个 errno-pair pool union 后的 jaccard\n")
        f.write("#   per_rec_jac:逐 record 算 jaccard 再平均;跟 union 背离 ⇒ noise 散开\n")
        f.write("#   structural% / real%:差集 PC 按源文件路径分类后的占比\n")
        f.write("#     structural 前缀 = " + ", ".join(STRUCTURAL_PREFIXES) +
                " (except " + ", ".join(REAL_PATH_SUBSYSTEMS) + ")\n")
        f.write("#     real-path = 其它(fs/super、block/bdev、kernel/signal、drivers/… 等)\n")
        f.write("#   verdict_hint:粗判,要复核 — 不是结论\n#\n")
        f.write("# 排序:syscall 按总 records 倒序;每 syscall 内 errno-pair 按 records 倒序\n")
        f.write("\n")

        # verdict summary table
        v_ct = Counter(r["verdict_hint"] for r in rows)
        f.write("## verdict_hint 全局分布\n")
        for v, n in v_ct.most_common():
            f.write(f"  {v:38s}  {n:5d} 组\n")
        f.write("\n")

        for name in syscalls_sorted:
            items = sorted(txt_by_syscall[name],
                           key=lambda it: -it["row"]["records"])
            tot_rec = sum(it["row"]["records"] for it in items)
            f.write(bar_eq + "\n")
            f.write(f"{name}    total_records={tot_rec}  errno_pairs={len(items)}\n")
            f.write(bar_dash + "\n")
            for it in items:
                row = it["row"]
                f.write(
                    f"  (syz={row['syz_err']:>3}, ref={row['ref_err']:>3})  "
                    f"recs={row['records']:>4}  "
                    f"syz_pc={row['syz_pc']:>5}  ref_pc={row['ref_pc']:>5}  "
                    f"common={row['common']:>5}  "
                    f"u_jac={row['union_jaccard']:>6}  "
                    f"verdict={row['verdict_hint']}\n"
                )
                if row["records"] < args.min_records:
                    continue  # 跳过太小的子集详情
                # ref_only block
                f.write(f"    ref_only={row['ref_only']}  "
                        f"structural={row['ref_only_structural_pct']}%  "
                        f"real={row['ref_only_real_pct']}%\n")
                top = it["ref_sub_ct"].most_common(args.topn_sub_txt)
                for sub, n in top:
                    mark = "*" if not is_structural(sub) else " "
                    f.write(f"      {mark} {n:5d}  {sub}\n")
                # 真路径子系统里的 top funcs
                real_subs = [s for s, _ in it["ref_sub_ct"].most_common()
                             if not is_structural(s)]
                shown = 0
                for sub in real_subs:
                    for fn, c in it["ref_sub_fn"][sub].most_common(5):
                        f.write(f"        {c:4d}  {sub:22s} {fn}\n")
                        shown += 1
                        if shown >= args.topn_func_txt:
                            break
                    if shown >= args.topn_func_txt:
                        break
                # syz_only block
                f.write(f"    syz_only={row['syz_only']}  "
                        f"structural={row['syz_only_structural_pct']}%  "
                        f"real={row['syz_only_real_pct']}%\n")
                top = it["syz_sub_ct"].most_common(args.topn_sub_txt)
                for sub, n in top:
                    mark = "*" if not is_structural(sub) else " "
                    f.write(f"      {mark} {n:5d}  {sub}\n")
                real_subs = [s for s, _ in it["syz_sub_ct"].most_common()
                             if not is_structural(s)]
                shown = 0
                for sub in real_subs:
                    for fn, c in it["syz_sub_fn"][sub].most_common(5):
                        f.write(f"        {c:4d}  {sub:22s} {fn}\n")
                        shown += 1
                        if shown >= args.topn_func_txt:
                            break
                    if shown >= args.topn_func_txt:
                        break
                f.write("\n")
            f.write("\n")

    print(f"out_csv = {args.out_csv}")
    print(f"out_txt = {args.out_txt}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

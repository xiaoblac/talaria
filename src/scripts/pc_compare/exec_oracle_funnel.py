#!/usr/bin/env python3
"""固定分析链路(funnel)总入口 —— 一条命令跑完 ①②③④⑤,吐出按 union_jaccard 升序、
已标注 ⑤ 一致性裁决的候选清单。

链路顺序(见 scripts/pc_compare/README.md §2;Jaccard 卡在 ④,④ 在 ⑤ 之前):

  ① 闸门     读 exec-oracle-report.json(若有)→ 全局 jaccard_mean + 分布带
  ②③ 分桶    读 per-call.jsonl → 6 桶计数 + EXEC-GAP(漏 PC)+ errno-mismatch top
  ④ Jaccard  调 exec_oracle_pc_subsystem_sweep.py → per-(syscall,errno-pair) union/per-call jaccard
  ⑤ 一致性   调 exec_oracle_layered_diff.py → 函数级语义分歧裁决(semantic[_fail]_*.tsv)
  ── join ──  对"同结果桶"(matched-success/fail)按 union_jaccard 升序排,标 ⑤ 裁决
  ⑥⑦        诊断(subsystem_diff)/ 验证(同 trace 重放)由人手动,footer 给命令模板

为什么 Jaccard 在 ④ 而非 ⑤:Jaccard 在 PC 粒度上敏感,能同时抓"跳过整个函数"和"进了同
函数但少干活"两类偷工;⑤ 的函数级一致性特异但盲(进同函数即判一致)。先撒敏感网(④)再用
⑤ 逐候选分类——⑤ 判 SEM@0.9 = 高置信"跳过函数"真分歧;⑤ 判 no-sem 但 ④ Jaccard 低 =
"同函数深度差"或块抖动,需 ⑥ set-diff 才能分。

效率:sweep 与 layered_diff 各做一遍 bulk addr2line(KASAN vmlinux ~1-3min/遍),共两遍。
迭代时用 --skip-subtools 复用已存在的 sweep.csv + funcdiff/,不重符号化。

用法:
  python3 scripts/pc_compare/exec_oracle_funnel.py \\
    --jsonl run/exec-oracle-<ts>/per-call.jsonl \\
    --vmlinux .../vmlinux --out-dir run/exec-oracle-<ts>/funnel
"""
from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from exec_oracle_layered_diff import population, parse_ints  # noqa: E402

SWEEP_PY = HERE / "exec_oracle_pc_subsystem_sweep.py"
LAYERED_PY = HERE / "exec_oracle_layered_diff.py"


def run_subtool(argv: list[str]) -> None:
    print(f"[funnel] $ {' '.join(argv)}", file=sys.stderr)
    subprocess.run(argv, check=True)


# ── ① 闸门 ────────────────────────────────────────────────────────────────────
def stage1_gate(jsonl: Path, report: Path | None, emit) -> None:
    path = report or (jsonl.parent / "exec-oracle-report.json")
    emit("\n[① 闸门] 全局保真度(整体够不够 / 有没有粗暴回归)")
    if not path.exists():
        emit(f"   (无 {path.name};跳过 —— 单跑分析层时正常)")
        return
    try:
        r = json.loads(path.read_text())
        g = r.get("ship_gate_passed", {})
        cov = g.get("coverage", {})
        dist = cov.get("jaccard_distribution", {}) or {}
        emit(f"   total/compared : {r.get('request_total')}/{r.get('request_compared')}")
        emit(f"   coverage gate  : status={cov.get('status')} "
             f"jaccard_mean={cov.get('jaccard_mean', 0.0):.4f} passed={cov.get('passed')}")
        if dist.get("sample_count", 0):
            emit(f"   jaccard 分布   : p25={dist.get('p25', 0):.3f} p50={dist.get('p50', 0):.3f} "
                 f"p95={dist.get('p95', 0):.3f}  low(<0.5)={dist.get('low_band_count', 0)} "
                 f"high(>=0.9)={dist.get('high_band_count', 0)}")
        emit(f"   overall gate   : {g.get('overall')}")
    except Exception as e:  # best-effort:闸门读不出不该挡住后面的分析
        emit(f"   (读取 {path} 失败:{e})")


# ── ②③ 分桶 + 路由 ──────────────────────────────────────────────────────────
def stage23_buckets(jsonl: Path, emit, top: int) -> Counter:
    popN, filt = Counter(), Counter()
    gap_calls, gap_pc = Counter(), defaultdict(set)
    errno_pairs: dict[str, Counter] = defaultdict(Counter)
    with jsonl.open() as fh:
        for line in fh:
            if not line.strip():
                continue
            r = json.loads(line)
            pop, ok = population(r)
            if not ok:
                filt[pop] += 1
                continue
            popN[pop] += 1
            sc = r.get("syscall", "?")
            if pop == "gap":
                gap_calls[sc] += 1
                if r.get("cover_available"):
                    gap_pc[sc] |= parse_ints(r.get("syz_pcs_hex", "") or "")
            elif pop == "errno_mis":
                errno_pairs[sc][(r.get("syz_err"), r.get("ref_err"))] += 1

    emit("\n[②③ 分桶 + 路由] errno 只分人群,不当判决")
    emit(f"   排除 998 / 空槽       : {filt['filt_998']} / {filt['filt_none']}")
    emit(f"   EXEC-GAP  syz✓ ref✗   : {popN['gap']:6}   ← ③a 能力缺口(不算 Jaccard,看漏 PC)")
    emit(f"   ref-only  ref✓ syz✗   : {popN['ref_only_exec']:6}")
    emit(f"   errno-mismatch        : {popN['errno_mis']:6}   ← ③b 行为分歧(Jaccard 预期低)")
    emit(f"   matched-success (0,0) : {popN['ms']:6}   ← ④⑤ 主战场(成功路径有没有偷工)")
    emit(f"   matched-fail   (e,e)  : {popN['mf']:6}   ← ④⑤")
    if gap_calls:
        emit("   EXEC-GAP top(③a 手动看漏 PC):")
        for sc, c in gap_calls.most_common(min(top, 10)):
            emit(f"      {sc:44} {c:4} calls   漏 {len(gap_pc.get(sc, set()))} PC")
    if errno_pairs:
        emit("   errno-mismatch top(③b 按 errno-pair):")
        emn = Counter({sc: sum(c.values()) for sc, c in errno_pairs.items()})
        for sc, c in emn.most_common(min(top, 10)):
            ps = " ".join(f"(s{a},r{b})={n}" for (a, b), n in errno_pairs[sc].most_common(2))
            emit(f"      {sc:44} {c:4}  {ps}")
    return popN


# ── ⑤ 裁决读取 ────────────────────────────────────────────────────────────────
def read_semantic(path: Path) -> dict[str, list]:
    """semantic[_fail]_<档>.tsv → {syscall: [(func, subsys, s, r, n, sample_pc), ...]}。
    行按 (s, N) 降序,故首行 = 该 syscall 最强的语义分歧函数。"""
    d: dict[str, list] = defaultdict(list)
    if not path.exists():
        return d
    with path.open() as fh:
        for line in fh:
            if line.startswith("#") or not line.strip():
                continue
            p = line.rstrip("\n").split("\t")
            if len(p) < 7:
                continue
            d[p[0]].append((p[1], p[2], float(p[3]), float(p[4]), int(p[5]), p[6]))
    return d


# ── ④⑤ join:同结果桶按 Jaccard 升序 + ⑤ 裁决 ────────────────────────────────
def stage45_join(out: Path, emit, top: int) -> list[dict]:
    fd = out / "funcdiff"
    sem = {
        "ms": (read_semantic(fd / "semantic_0.9.tsv"),
               read_semantic(fd / "semantic_0.5.tsv")),
        "mf": (read_semantic(fd / "semantic_fail_0.9.tsv"),
               read_semantic(fd / "semantic_fail_0.5.tsv")),
    }
    cands: list[dict] = []     # 两边都有 cover、可比 → 进 ④⑤ 排序
    asym: list[dict] = []      # ③c 覆盖不可比(KCOV 单边/双边空)→ 剔出排序,单列
    with (out / "sweep.csv").open() as fh:
        for row in csv.DictReader(fh):
            if row.get("errno_match") != "1":     # 只看"同结果"桶(④⑤ 主战场)
                continue
            sc = row["syscall"]
            bucket = "ms" if (row["syz_err"] == "0" and row["ref_err"] == "0") else "mf"
            syz_pc, ref_pc = int(row["syz_pc"]), int(row["ref_pc"])
            rec = {
                "syscall": sc, "bucket": bucket,
                "syz_err": row["syz_err"], "ref_err": row["ref_err"],
                "records": int(row["records"]),
                "syz_pc": syz_pc, "ref_pc": ref_pc,
                "union_jaccard": float(row["union_jaccard"]),
                "per_call_jaccard": float(row["per_rec_jac_avg"]),
                "sem_09": 0, "sem_05": 0, "top_func": "-", "top_subsys": "-",
            }
            # ③c 覆盖不可比:两边都执行 + 同 errno(本该可比),但 KCOV 单边/双边空。
            # 和空集比 jaccard 恒 0(双空恒 1),不是路径分歧 → 不进 ④⑤,单列计数。
            #   empty-ref  = 只有 reFuzz 空(worker 侧可疑,执行了却没采到覆盖)
            #   empty-syz  = 只有 syz 空(多半上游测量假象,如 syz_pkey_set)
            #   both-empty = 两边都没采到(handler 可能早返回,信息量低)
            if syz_pc == 0 or ref_pc == 0:
                rec["verdict"] = ("both-empty" if syz_pc == 0 and ref_pc == 0
                                  else "empty-syz" if syz_pc == 0 else "empty-ref")
                asym.append(rec)
                continue
            # 可比 → 标 ⑤ 裁决
            s09, s05 = sem[bucket]
            n09, n05 = len(s09.get(sc, [])), len(s05.get(sc, []))
            top_list = s05.get(sc) or s09.get(sc) or []
            rec["sem_09"], rec["sem_05"] = n09, n05
            rec["top_func"] = top_list[0][0] if top_list else "-"
            rec["top_subsys"] = top_list[0][1] if top_list else "-"
            rec["verdict"] = (f"SEM@0.9x{n09}" if n09 else
                              f"SEM@0.5x{n05}" if n05 else "no-sem->6")
            cands.append(rec)
    cands.sort(key=lambda c: (c["union_jaccard"], -c["records"]))
    asym.sort(key=lambda c: (c["verdict"], -(c["syz_pc"] + c["ref_pc"])))

    cols = ["syscall", "bucket", "syz_err", "ref_err", "records", "syz_pc", "ref_pc",
            "union_jaccard", "per_call_jaccard", "verdict", "sem_09", "sem_05",
            "top_func", "top_subsys"]
    with (out / "candidates.tsv").open("w") as fo:
        fo.write("#" + "\t".join(cols) + "\n")
        for c in cands + asym:           # 可比 + 覆盖不可比都写,verdict 区分
            fo.write("\t".join(str(c[k]) for k in cols) + "\n")

    # ③c 覆盖不可比:在 ④⑤ 排序前先剔出来单列(不静默丢)。否则 empty-syz 的 jaccard=0
    # 会霸榜(syz_pkey_set 案例);empty-ref 反而是 worker 侧值得查的真信号。
    if asym:
        ac = Counter(c["verdict"] for c in asym)
        emit("\n[③c 覆盖不可比(KCOV 单边/双边空;已从 ④⑤ 排序剔除,见 candidates.tsv)]")
        emit(f"   empty-ref(仅 reFuzz 空,worker 可疑)={ac.get('empty-ref', 0)}   "
             f"empty-syz(仅 syz 空,多半上游假象)={ac.get('empty-syz', 0)}   "
             f"both-empty={ac.get('both-empty', 0)}")
        show = [c for c in asym if c["verdict"] == "empty-ref"][:10]
        if show:
            emit("   empty-ref top(reFuzz 执行了却 0 覆盖 → 优先查):")
            for c in show:
                bk = "MS" if c["bucket"] == "ms" else "MF"
                emit(f"      {bk} {c['syscall'][:44]:44} N={c['records']:<4} "
                     f"syz_pc={c['syz_pc']} ref_pc={c['ref_pc']}")

    sem09_total = sum(1 for c in cands if c["sem_09"])
    nosem_lowjac = sum(1 for c in cands if not c["sem_05"] and c["union_jaccard"] < 0.7)
    emit("\n[④⑤ 同结果桶:Jaccard 撒网 → ⑤ 一致性裁决]  (可比候选,candidates.tsv)")
    emit(f"   matched 候选(syscall×errno-pair): {len(cands)}   "
         f"⑤ 判 SEM@0.9 高置信: {sem09_total}   no-sem 但 jac<0.7(→⑥): {nosem_lowjac}")
    emit("   按 union_jaccard 升序(最不齐在最上)。verdict=⑤裁决;")
    emit("   SEM@0.9 = 高置信'跳过整个函数'真分歧;no-sem->6 = 函数级判一致但 Jaccard 低,")
    emit("   多半'进同函数但少干活'或块抖动,需 ⑥ set-diff 看 PC 才能定。")

    # SEM@0.9 是最高置信信号,但它的 union_jaccard 可能不低(进了部分函数),纯按 Jaccard
    # 升序会把它埋在表外 → 单列一份不受排序埋没的清单,优先看。
    sem09_list = sorted([c for c in cands if c["sem_09"]],
                        key=lambda c: (-c["sem_09"], c["union_jaccard"]))
    if sem09_list:
        emit("\n   ── 高置信 SEM@0.9(⑤ 判'跳过整个函数';优先看,不受 Jaccard 排序埋没)──")
        for c in sem09_list:
            bk = "MS" if c["bucket"] == "ms" else "MF"
            emit(f"      {bk} {c['syscall'][:40]:40} u_jac={c['union_jaccard']:.3f} "
                 f"sem09={c['sem_09']} top={c['top_func']} ({c['top_subsys']})")
        emit("")

    emit("   ── 全候选按 union_jaccard 升序(最不齐在最上)──")
    emit(f"   {'#':>3} {'u_jac':>6} {'pcall':>6} {'bkt':>3} {'N':>5} "
         f"{'syscall':40} {'verdict':11} top_divergent_func")
    for i, c in enumerate(cands[:top], 1):
        bk = "MS" if c["bucket"] == "ms" else "MF"
        tf = c["top_func"] if c["top_func"] == "-" else f"{c['top_func']} ({c['top_subsys']})"
        emit(f"   {i:>3} {c['union_jaccard']:>6.3f} {c['per_call_jaccard']:>6.3f} "
             f"{bk:>3} {c['records']:>5} {c['syscall'][:40]:40} {c['verdict']:11} {tf}")
    return cands


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--jsonl", type=Path, required=True)
    ap.add_argument("--vmlinux", type=Path, required=True)
    ap.add_argument("--out-dir", type=Path, required=True)
    ap.add_argument("--report", type=Path,
                    help="oracle exec-oracle-report.json(默认找 jsonl 同目录)")
    ap.add_argument("--top", type=int, default=40)
    ap.add_argument("--min-calls", type=int, default=3)
    ap.add_argument("--pseudo-only", action="store_true",
                    help="④ sweep 只看 syz_*(默认含真 syscall,与 ⑤ 一致)")
    ap.add_argument("--skip-subtools", action="store_true",
                    help="复用已存在 sweep.csv + funcdiff/,不重跑 addr2line(迭代用)")
    args = ap.parse_args()

    if not args.jsonl.exists():
        print(f"error: missing --jsonl {args.jsonl}", file=sys.stderr)
        return 2
    out = args.out_dir
    out.mkdir(parents=True, exist_ok=True)

    OUT: list[str] = []
    def emit(s: str = "") -> None:
        print(s)
        OUT.append(s)

    emit("=" * 92)
    emit("PC 对比 · 固定分析链路(funnel:闸门 → 分桶 → Jaccard → 一致性 → 候选清单)")
    emit(f"输入:{args.jsonl}")
    emit("=" * 92)

    stage1_gate(args.jsonl, args.report, emit)
    stage23_buckets(args.jsonl, emit, args.top)

    if not args.skip_subtools:
        emit("\n[④] sweep:per-(syscall,errno-pair) Jaccard(addr2line pass 1/2)…")
        sweep_argv = [sys.executable, str(SWEEP_PY), "--jsonl", str(args.jsonl),
                      "--vmlinux", str(args.vmlinux),
                      "--out-csv", str(out / "sweep.csv"),
                      "--out-txt", str(out / "sweep.txt")]
        if not args.pseudo_only:
            sweep_argv.append("--include-non-pseudo")
        run_subtool(sweep_argv)
        emit("[⑤] layered_diff:函数级一致性(addr2line pass 2/2)…")
        run_subtool([sys.executable, str(LAYERED_PY), "--jsonl", str(args.jsonl),
                     "--vmlinux", str(args.vmlinux), "--out-dir", str(out / "funcdiff"),
                     "--min-calls", str(args.min_calls), "--top", str(args.top)])
    else:
        emit("\n[④⑤] --skip-subtools:复用已存在 sweep.csv + funcdiff/")

    if not (out / "sweep.csv").exists():
        emit("\nERROR: 缺 sweep.csv,无法 join;去掉 --skip-subtools 重跑。")
        (out / "funnel_report.txt").write_text("\n".join(OUT) + "\n", encoding="utf-8")
        return 2
    stage45_join(out, emit, args.top)

    emit("\n[⑥ 诊断 / ⑦ 验证] 对上面 top 候选(尤其 SEM@0.9 与 no-sem->6):")
    emit("   ⑥ 看 PC 长什么样 / 定位根分支(只对 1-3 个候选手动跑):")
    emit("      python3 scripts/pc_compare/exec_oracle_pc_subsystem_diff.py \\")
    emit(f"        --jsonl {args.jsonl} --vmlinux {args.vmlinux} \\")
    emit("        --syscall <syscall> --errno-pair <syz>,<ref> --out-dir <drill>")
    emit("   ⑦ 改 worker/sandbox 后,同一条冻结 trace 重放重量(目标 Jaccard 升、SEM 降、别处不回归):")
    emit("      SKIP_CAPTURE=1 TRACE_DIR=<冻结trace> RUN_DIR=run/after \\")
    emit("        bash scripts/pc_compare/exec_oracle_full_smoke.sh")
    emit("      python3 scripts/pc_compare/exec_oracle_funnel.py \\")
    emit("        --jsonl run/after/per-call.jsonl --vmlinux <vmlinux> --out-dir run/after/funnel")

    (out / "funnel_report.txt").write_text("\n".join(OUT) + "\n", encoding="utf-8")
    print(f"\nwrote {out}/funnel_report.txt + candidates.tsv (+ sweep.csv / sweep.txt / funcdiff/)",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

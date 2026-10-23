#!/usr/bin/env python3
"""per-call.jsonl 的**函数级一致性**分析器(PC 主轴 / 逐 call 配对 / 跨 call 一致性)。

第一性原理:**PC 是行为一致性的唯一裁判,errno 只是 PC 的有损投影**。
  · errno 相同 ≠ 行为一致(reFuzz 可能偷工/stub 照样返回成功)。
  · errno 不同 ≠ 行为不一致(reFuzz 的错误返回是自己设计的,管线差异)。
所以判决只能来自 PC;errno 只用来"分在哪个人群上证一致"。

三个关键决定:
  1. 粒度=**函数(调用图)**,不是基本块。"进入函数 F"=有人调了它;函数内走不同块=
     数据/状态依赖(循环/which case),多半噪声。两边都进 tomoyo_check_acl/mas_store →
     函数级判共同,块级噪声(mm/maple/lockdep/学习态)凭空消失。
  2. 配对=**逐 call**(同一 req_id/call_idx,两边跑同一 trace),消除跨程序状态混合。
  3. 判决=**跨 call 一致性**:对一个 syscall 的所有 matched call,比每个函数 F 两边的
     **进入率** s=syz进F占比 / r=reFuzz进F占比。s 高 r≈0 = 分歧;两边都高 = 一致;中间 = 噪声。

残差再拆:**infra**(分配器/数据结构/位图/LSM学习态=状态噪声) vs **semantic**(fs/net/drivers
等语义子系统=候选真分歧)。

**"syz 稳稳进入"的门槛是扫描的**(一次跑出三档):无拦截 / 0.5 / 0.9 —— 看门槛对发现的影响。

用法:
  python3 scripts/pc_compare/exec_oracle_layered_diff.py \\
    --jsonl run/exec-oracle-<ts>/per-call.jsonl \\
    --vmlinux .../vmlinux  --out-dir run/exec-oracle-<ts>/funcdiff
输出:终端 + <out-dir>/report.txt(人读)+ semantic[_fail]_{raw,0.5,0.9}.tsv
(matched-success / matched-fail 各三档,机读;funnel 据此给候选标 ⑤ 裁决)。
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from exec_oracle_pc_subsystem_diff import subsystem, is_structural  # noqa: E402

# "syz 稳稳进入"门槛扫描(name, syz_min);reFuzz "稳不进" 固定 r <= R_ABSENT。
SWEEP = [("无拦截(syz进过即算)", 0.0), ("0.5(过半)", 0.5), ("0.9(稳稳进入)", 0.9)]
R_ABSENT = 0.1


def parse_ints(h: str) -> set[int]:
    if not h or len(h) % 16 != 0:
        return set()
    return {int(h[i:i + 16], 16) for i in range(0, len(h), 16)}


def addr2line_ff(vmlinux: Path, addrs: list[int]) -> dict[int, tuple[str, str]]:
    out: dict[int, tuple[str, str]] = {}
    for i in range(0, len(addrs), 50000):
        chunk = addrs[i:i + 50000]
        inp = "\n".join("0x%x" % a for a in chunk) + "\n"
        p = subprocess.run(["addr2line", "-f", "-e", str(vmlinux)],
                           input=inp, capture_output=True, text=True)
        ls = p.stdout.splitlines()
        for j, a in enumerate(chunk):
            out[a] = (ls[2 * j].strip() if 2 * j < len(ls) else "??",
                      ls[2 * j + 1].strip() if 2 * j + 1 < len(ls) else "??")
    return out


# 系统机制子系统:进入与否取决于**时序/调度/CPU 状态**(睡没睡、跨没跨 CPU、异步跑没跑完),
# 不是语义工作 → 噪声。注意不含 kernel/kthread(kthread_blkcg 是 blkcg 真发现,别误杀)。
MECH_SUBSYS = {"kernel/time", "kernel/smp", "kernel/workqueue", "kernel/irq_work"}
# 异步**唤醒回调**:等待事件发生时被异步触发(在 waker 路径上),进与否取决于事件/唤醒有没有
# 在时序窗口内发生 = 时序机制。按**函数名**剥(不能整个 fs/eventpoll·fs/select 剥——
# epoll/poll syscall 本身是语义)。
WAKE_FUNC = re.compile(
    r"wake_function$|^pollwake|^__pollwake|^ep_poll_callback|^ep_pm_stay_awake|"
    r"^ep_autoremove|^__wake_up_common|woken_wake")
# cgroup 计账 / blkcg:进入与否取决于**挂了哪些 cgroup 控制器 + 调度时序**,不是语义工作。
# 实证(2026-05-30):把 reFuzz 的 cgroup io 控制器修对(io.max=1、membership ✓)后,
# 这些函数的覆盖**纹丝不动**——证明它们不由 cgroup 成员驱动,是计账基础设施 → 噪声。
# 按函数名剥(blkcg 跨 block/blk-cgroup·kernel/kthread·kernel/cgroup 多个子系统)。
CGROUP_ACCT_FUNC = re.compile(
    r"blkcg|blk_cgroup|kthread_blkcg|rstat|cgroup_base_stat|__cgroup_account")


def is_infra(func: str, fl: str) -> bool:
    """基础设施=进入与否取决于累积分配/学习历史或时序调度,非语义工作 → 噪声:
      · 分配器/数据结构/位图/RCU(mm、lib/maple·xarray·radix、arch、kernel/rcu);
      · LSM 学习态(security/tomoyo);
      · 系统机制(kernel/time·smp·workqueue·irq_work = 时序/IPI/异步);
      · 异步唤醒回调(*_wake_function / pollwake / ep_poll_callback … = 时序触发);
      · cgroup 计账 / blkcg(blkcg_* / css_rstat / cgroup_base_stat … = 控制器+调度依赖)。
    语义(fs/net/drivers/block/具体子系统)= 候选真分歧。"""
    if WAKE_FUNC.search(func) or CGROUP_ACCT_FUNC.search(func):
        return True
    sub = subsystem(fl)
    return (sub.startswith("security/tomoyo") or is_structural(sub)
            or sub.startswith(("mm/", "lib/")) or sub in MECH_SUBSYS)


def population(r):
    se, re_ = bool(r.get("syz_executed")), bool(r.get("ref_executed"))
    serr, rerr = r.get("syz_err"), r.get("ref_err")
    if serr == 998 or rerr == 998:
        return "filt_998", False
    if not se and not re_:
        return "filt_none", False
    if se and not re_:
        return "gap", True
    if re_ and not se:
        return "ref_only_exec", True
    if serr != rerr:
        return "errno_mis", True
    return ("ms" if serr == 0 else "mf"), True


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--jsonl", type=Path, required=True)
    ap.add_argument("--vmlinux", type=Path, required=True)
    ap.add_argument("--min-calls", type=int, default=3)
    ap.add_argument("--top", type=int, default=40)
    ap.add_argument("--out-dir", type=Path)
    args = ap.parse_args()

    OUT = []                                   # 同时落 report.txt
    def emit(s=""):
        print(s)
        OUT.append(s)

    # ── Pass 1:过滤 + 人群计数 + 收集 distinct PC ───────────────────────────
    filt = Counter(); popN = Counter()
    gap_calls = Counter(); gap_pcs: dict[str, set[int]] = defaultdict(set)
    errno_pairs: dict[str, Counter] = defaultdict(Counter)
    all_pcs: set[int] = set(); n_lines = 0
    with args.jsonl.open() as fh:
        for line in fh:
            n_lines += 1
            r = json.loads(line)
            pop, ok = population(r)
            if not ok:
                filt[pop] += 1; continue
            popN[pop] += 1; sc = r["syscall"]
            if pop == "gap":
                gap_calls[sc] += 1
                if r.get("cover_available"):
                    gap_pcs[sc] |= parse_ints(r.get("syz_pcs_hex", "") or "")
                continue
            if pop == "errno_mis":
                errno_pairs[sc][(r.get("syz_err"), r.get("ref_err"))] += 1
            if r.get("cover_available"):
                all_pcs |= parse_ints(r.get("syz_pcs_hex", "") or "")
                all_pcs |= parse_ints(r.get("ref_pcs_hex", "") or "")
    print(f"[func-consistency] lines={n_lines} distinct_pcs={len(all_pcs)} symbolizing…",
          file=sys.stderr)
    pc2ff = addr2line_ff(args.vmlinux, sorted(all_pcs))
    pc2f = {p: ff[0] for p, ff in pc2ff.items()}
    f2file: dict[str, str] = {}; f2sample: dict[str, int] = {}
    for p, (f, fl) in pc2ff.items():
        f2file.setdefault(f, fl); f2sample.setdefault(f, p)

    # ── Pass 2:逐 call 配对,按人群聚合每个函数两边的"进入次数" ───────────────
    N = defaultdict(Counter)
    syz_pres = defaultdict(lambda: defaultdict(Counter))
    ref_pres = defaultdict(lambda: defaultdict(Counter))
    with args.jsonl.open() as fh:
        for line in fh:
            r = json.loads(line)
            pop, ok = population(r)
            if not ok or pop in ("gap", "ref_only_exec") or not r.get("cover_available"):
                continue
            sc = r["syscall"]
            sf = {pc2f.get(p, "??") for p in parse_ints(r.get("syz_pcs_hex", "") or "")}
            rf = {pc2f.get(p, "??") for p in parse_ints(r.get("ref_pcs_hex", "") or "")}
            N[pop][sc] += 1
            for f in sf:
                syz_pres[pop][sc][f] += 1
            for f in rf:
                ref_pres[pop][sc][f] += 1

    # 每人群:把每个 (sc,f) 的 (s,r,n) 抽出来,后面 proof + 扫描都基于它
    def records(pop):
        recs = []
        for sc, n in N[pop].items():
            if n < args.min_calls:
                continue
            for f, sp in syz_pres[pop][sc].items():
                if f == "??":
                    continue
                recs.append((sc, f, sp / n, ref_pres[pop][sc][f] / n, n))
        return recs

    # ── 输出 ────────────────────────────────────────────────────────────────
    comparable = sum(popN.values())
    emit("=" * 84)
    emit("PC 对比 · 函数级一致性报告(PC 主轴 / 逐 call 配对 / 跨 call 一致性)")
    emit(f"输入:{args.jsonl}")
    emit("=" * 84)
    emit("\n[Layer 0] 过滤(排除不可比 call,口径透明)")
    emit(f"  per-call 记录总数            : {n_lines}")
    emit(f"  排除 · 998 哨兵(从未写入)   : {filt['filt_998']}")
    emit(f"  排除 · 两边都没执行(空槽)   : {filt['filt_none']}")
    emit(f"  → 可比 call                  : {comparable}")

    emit("\n[Layer 1] 人群(errno 只分人群,不当判决)")
    emit(f"  EXEC-GAP       syz✓ reFuzz✗  : {popN['gap']:6}   ← 最硬:reFuzz 缺能力")
    emit(f"  ref-only-exec  reFuzz✓ syz✗  : {popN['ref_only_exec']:6}")
    emit(f"  errno-mismatch 都✓ errno≠    : {popN['errno_mis']:6}   ← 行为分歧,单列")
    emit(f"  matched-success (0,0)        : {popN['ms']:6}   ← 主战场:成功路径是否一致")
    emit(f"  matched-fail   (e,e)         : {popN['mf']:6}")
    if gap_calls:
        emit("\n  EXEC-GAP 明细:")
        for sc, c in gap_calls.most_common(args.top):
            emit(f"     {sc:44} {c:4} calls   漏 {len(gap_pcs.get(sc, set()))} PC")
    if errno_pairs:
        emit("\n  errno-mismatch top(按 errno-pair):")
        emn = Counter({sc: sum(c.values()) for sc, c in errno_pairs.items()})
        for sc, c in emn.most_common(args.top):
            ps = " ".join(f"(s{a},r{b})={n}" for (a, b), n in errno_pairs[sc].most_common(3))
            emit(f"     {sc:44} {c:4}  {ps}")

    for pop, title in (("ms", "matched-SUCCESS(主战场:成功路径是否一致 / 有没有偷工)"),
                       ("mf", "matched-FAIL(同 errno 失败:是否以同样方式失败)")):
        recs = records(pop)
        emit("\n" + "=" * 84)
        emit(f"[Layer 2] 函数级一致性 · {title}")
        emit("=" * 84)
        # 一致性证明:syz 稳进(s≥0.5)的函数里,reFuzz 也稳进(r≥0.5)的占比
        stable = [t for t in recs if t[2] >= 0.5]
        common = sum(1 for t in stable if t[3] >= 0.5)
        emit(f"  一致性证明:syz 稳进(s≥0.5)的 {len(stable)} 个(syscall×函数)中,")
        emit(f"             reFuzz 也稳进(r≥0.5)= {common} ({common/(len(stable) or 1):.1%})  ← 越高 reFuzz 越忠实")

        # 门槛扫描:syz_min ∈ {0, 0.5, 0.9},reFuzz 稳不进 r≤0.1
        emit(f"\n  「syz 稳稳进入」门槛扫描(reFuzz 稳不进 r≤{R_ABSENT};分歧=syz进/reFuzz不进):")
        emit(f"    {'门槛':22} {'语义真分歧':>10} {'infra噪声':>10}")
        sem_by_level = {}
        for name, smin in SWEEP:
            div = [t for t in recs if t[2] >= smin and t[3] <= R_ABSENT]
            sem = [t for t in div if not is_infra(t[1], f2file.get(t[1], "??"))]
            infra = len(div) - len(sem)
            sem.sort(key=lambda t: (t[2], t[4]), reverse=True)
            sem_by_level[name] = sem
            emit(f"    {name:22} {len(sem):>10} {infra:>10}")

        # 详表:用 0.5 档(过半即算)展开语义真分歧,标注是否进 0.9 档(稳稳)
        sem05 = sem_by_level["0.5(过半)"]
        s09 = {(t[0], t[1]) for t in sem_by_level["0.9(稳稳进入)"]}
        if sem05:
            emit(f"\n  语义真分歧明细(s≥0.5 档;★=同时进 0.9 稳稳档;top {args.top}):")
            emit(f"  {'★':1} {'syscall':36} {'function':26} {'subsys':16} {'s%':>4} {'r%':>4} {'N':>4}")
            for sc, f, s, rr, n in sem05[:args.top]:
                star = "★" if (sc, f) in s09 else " "
                emit(f"  {star} {sc:36} {f:26} {subsystem(f2file.get(f,'??')):16} "
                     f"{s*100:3.0f}% {rr*100:3.0f}% {n:>4}")
        else:
            emit("\n  (无语义真分歧 —— 结果相同时 reFuzz 执行忠实;残差全是 infra/时序噪声)")

        # 三档各落一份 TSV(机读):matched-success → semantic_<档>.tsv;
        # matched-fail → semantic_fail_<档>.tsv。funnel(exec_oracle_funnel.py)读这两组
        # 给同结果桶的候选标 ⑤ 裁决(SEM@0.9 / SEM@0.5 / no-sem)。
        if args.out_dir:
            args.out_dir.mkdir(parents=True, exist_ok=True)
            prefix = "semantic" if pop == "ms" else "semantic_fail"
            for name, _ in SWEEP:
                tag = name.split("(")[0]
                with (args.out_dir / f"{prefix}_{tag}.tsv").open("w") as fo:
                    fo.write("#syscall\tfunction\tsubsystem\tsyz_rate\tref_rate\tN\tsample_pc\n")
                    for sc, f, s, rr, n in sem_by_level[name]:
                        fo.write(f"{sc}\t{f}\t{subsystem(f2file.get(f,'??'))}\t{s:.2f}\t"
                                 f"{rr:.2f}\t{n}\t0x{f2sample.get(f,0):x}\n")

    if args.out_dir:
        (args.out_dir / "report.txt").write_text("\n".join(OUT) + "\n", encoding="utf-8")
        print(f"\nwrote {args.out_dir}/report.txt + semantic[_fail]_{{无拦截,0.5,0.9}}.tsv",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

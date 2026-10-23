#!/usr/bin/env python3
"""Per-syscall PC 分歧的 **子系统级** 根因定位器。

回答的问题:对某个 syscall,reFuzz replay 和 syzkaller capture 各自把覆盖
**落在内核哪个子系统的哪些函数**上 —— 从而区分:

  * 真路径分歧(fs/super、block/bdev、net/... = SUT 行为差,worker/sandbox bug)
  * 结构性 noise(mm、lib/maple_tree、arch/x86 instrumentation = reFuzz 进程
    地址空间 / fork-mm / 拆解足迹,upstream executor 不背)

与 `exec_oracle_syscall_pc_diff.py` 的两点关键区别(E1 efs 案例证明缺一不可):

  1. **按 errno-pair 隔离**(--errno-pair syz,ref):同一 syscall 的不同 errno
     结果是不同的路径群体。把它们 union 在一起会把分歧稀释掉(efs union
     jaccard 0.86,但 (16,22) 子集只有 ~0.31,真信号全在子集里)。
  2. **按源文件路径分类**,不用函数名启发式。clusterer 的 FAMILY_RULES 经
     实测对 actionable 无判别力(bucket PC 79.4% 也出现在 actionable),且
     OTHER 高达 37-50%。源文件路径(fs/super vs mm)是干净的子系统真值。

⚠ 辩证提醒:本工具给的是 **集合证据**(哪些函数被执行到),不是 **时序证据**。
要断言"上游先挂载成功再写文件"这类因果/顺序结论,必须回 trace 看该 req 的
调用序列(call_idx 顺序 / 同镜像重复 mount 次数),不能只凭子系统覆盖。

用法:
  # 1) 先看某 syscall 的 errno-pair 分布(选哪个子集分析)
  python3 scripts/pc_compare/exec_oracle_pc_subsystem_diff.py \\
    --jsonl run/exec-oracle-<ts>/per-call.jsonl --syscall syz_mount_image$efs \\
    --vmlinux /path/vmlinux --list-pairs

  # 2) 隔离一个 errno-pair,union 两侧 only-PC,addr2line 按子系统拆
  python3 scripts/pc_compare/exec_oracle_pc_subsystem_diff.py \\
    --jsonl run/exec-oracle-<ts>/per-call.jsonl --syscall syz_mount_image$efs \\
    --vmlinux /path/vmlinux --errno-pair 16,22 --topn-func 25
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path


def parse_pcs_hex(s: str) -> set[str]:
    """每个 PC 是 16 个 hex 字符的定长块。"""
    if not s or len(s) % 16 != 0:
        return set()
    return {s[i:i + 16] for i in range(0, len(s), 16)}


def load_records(jsonl: Path, syscall: str):
    recs = []
    with jsonl.open() as fh:
        for line in fh:
            r = json.loads(line)
            if r.get("syscall") != syscall:
                continue
            if not r.get("cover_available"):
                continue
            recs.append(r)
    return recs


def addr2line(vmlinux: Path, addrs: list[str]) -> dict[str, tuple[str, str]]:
    """addr -> (func, source_path)。一次性批量,无 inline 展开(子系统够用)。"""
    if not addrs:
        return {}
    proc = subprocess.run(
        ["addr2line", "-f", "-e", str(vmlinux), *("0x" + a for a in addrs)],
        capture_output=True, text=True,
    )
    lines = proc.stdout.splitlines()
    out: dict[str, tuple[str, str]] = {}
    # addr2line -f 输出每地址两行: func / file:line
    for i, addr in enumerate(addrs):
        func = lines[2 * i].strip() if 2 * i < len(lines) else "??"
        fl = lines[2 * i + 1].strip() if 2 * i + 1 < len(lines) else "??"
        out[addr] = (func, fl)
    return out


# 源文件路径 -> 子系统标签(取相对内核根的前一两级目录)
def subsystem(path: str, kroot_marker: str = "/linux-") -> str:
    if kroot_marker in path:
        # .../linux-6.19.13/fs/super.c:123 -> fs/super
        rel = path.split(kroot_marker, 1)[1]
        rel = rel.split("/", 1)[1] if "/" in rel else rel  # 去掉版本号目录
    else:
        rel = path
    rel = rel.split(":", 1)[0]  # 去 :line
    parts = rel.split("/")
    top = parts[0]
    if len(parts) > 3 and parts[0] == "arch" and parts[1] == "x86" and parts[2] == "kvm":
        return "arch/x86/kvm"
    if top in ("fs", "lib", "kernel", "arch", "block", "drivers",
               "security", "virt", "net", "ipc", "crypto", "sound"):
        if len(parts) > 1:
            return f"{top}/{parts[1].split('.')[0]}"
        return top
    return top  # include / ? 等


# 子系统是否属于"结构性 noise"(reFuzz 进程地址空间足迹,非 SUT 路径)
STRUCTURAL_PREFIXES = ("mm", "lib/maple_tree", "lib/xarray", "lib/radix-tree",
                       "arch/x86", "include", "kernel/rcu", "lib/find_bit")
REAL_PATH_SUBSYSTEMS = ("arch/x86/kvm",)


def is_structural(sub: str) -> bool:
    if sub in REAL_PATH_SUBSYSTEMS:
        return False
    return any(sub == p or sub.startswith(p) for p in STRUCTURAL_PREFIXES)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--jsonl", type=Path, required=True)
    ap.add_argument("--syscall", required=True)
    ap.add_argument("--vmlinux", type=Path, required=True)
    ap.add_argument("--errno-pair", help="只取 (syz_err,ref_err)=a,b 的记录,如 16,22")
    ap.add_argument("--list-pairs", action="store_true",
                    help="只打印该 syscall 的 errno-pair 分布后退出")
    ap.add_argument("--topn-sub", type=int, default=20)
    ap.add_argument("--topn-func", type=int, default=20)
    ap.add_argument("--out-dir", type=Path)
    args = ap.parse_args()

    recs = load_records(args.jsonl, args.syscall)
    if not recs:
        print(f"no cover_available records for {args.syscall}", file=sys.stderr)
        return 2

    # errno-pair 分布
    pairs = Counter((r["syz_err"], r["ref_err"]) for r in recs)
    if args.list_pairs:
        print(f"{args.syscall}: {len(recs)} cover_available records")
        print(f"{'(syz,ref)':14} {'n':>5} {'avg_jac':>8}")
        jac_by = defaultdict(list)
        for r in recs:
            if r.get("syz_executed") and r.get("ref_executed"):
                jac_by[(r["syz_err"], r["ref_err"])].append(r.get("jaccard", 1.0))
        for p, n in pairs.most_common():
            js = jac_by.get(p, [])
            aj = sum(js) / len(js) if js else float("nan")
            print(f"{str(p):14} {n:>5} {aj:>8.3f}")
        return 0

    if args.errno_pair:
        a, b = (int(x) for x in args.errno_pair.split(","))
        recs = [r for r in recs if r["syz_err"] == a and r["ref_err"] == b]
        if not recs:
            print(f"no records for errno-pair {args.errno_pair}", file=sys.stderr)
            return 2

    # union both-only PC sets across selected records; track per-record jaccard
    syz_u: set[str] = set()
    ref_u: set[str] = set()
    per_rec_jac = []
    for r in recs:
        syz = parse_pcs_hex(r["syz_pcs_hex"])
        ref = parse_pcs_hex(r["ref_pcs_hex"])
        syz_u |= syz
        ref_u |= ref
        uni = len(syz | ref)
        if uni:
            per_rec_jac.append(len(syz & ref) / uni)
    syz_only = syz_u - ref_u
    ref_only = ref_u - syz_u
    union = len(syz_u | ref_u)

    print("=" * 72)
    print(f"syscall      = {args.syscall}")
    print(f"errno-pair   = {args.errno_pair or 'ALL'}   records = {len(recs)}")
    print(f"syz_pc(u)={len(syz_u)} ref_pc(u)={len(ref_u)} common={len(syz_u & ref_u)}")
    print(f"syz_only={len(syz_only)} ref_only={len(ref_only)}")
    print(f"union jaccard      = {len(syz_u & ref_u) / union:.4f}" if union else "n/a")
    if per_rec_jac:
        print(f"per-record jaccard = {sum(per_rec_jac) / len(per_rec_jac):.4f} "
              f"(diverges from union ⇒ 分歧逐记录散开)")
    print("=" * 72)

    a2l = addr2line(args.vmlinux, list(syz_only | ref_only))

    for tag, pcs in (("ref_only (reFuzz 跑了/上游没跑)", ref_only),
                     ("syz_only (上游跑了/reFuzz 没跑)", syz_only)):
        sub_ct = Counter()
        func_by_sub: dict[str, Counter] = defaultdict(Counter)
        struct_n = real_n = 0
        for p in pcs:
            func, fl = a2l.get(p, ("??", "??"))
            sub = subsystem(fl)
            sub_ct[sub] += 1
            func_by_sub[sub][func] += 1
            if is_structural(sub):
                struct_n += 1
            else:
                real_n += 1
        tot = struct_n + real_n or 1
        print(f"\n##### {tag}: {len(pcs)} PC")
        print(f"      structural={struct_n} ({struct_n/tot:.0%})  "
              f"real-path={real_n} ({real_n/tot:.0%})")
        print(f"  -- top {args.topn_sub} subsystems --")
        for sub, c in sub_ct.most_common(args.topn_sub):
            mark = "  " if is_structural(sub) else "* "  # * = 真路径
            print(f"    {mark}{c:5d}  {sub}")
        # 真路径子系统的具体函数(去掉结构性,聚焦可 actionable 的)
        real_subs = [s for s, _ in sub_ct.most_common() if not is_structural(s)]
        print(f"  -- top funcs in real-path subsystems --")
        shown = 0
        for sub in real_subs:
            for func, c in func_by_sub[sub].most_common(6):
                print(f"    {c:4d}  {sub:18} {func}")
                shown += 1
                if shown >= args.topn_func:
                    break
            if shown >= args.topn_func:
                break

    if args.out_dir:
        args.out_dir.mkdir(parents=True, exist_ok=True)
        for name, pcs in (("syz_only", syz_only), ("ref_only", ref_only),
                          ("common", syz_u & ref_u)):
            (args.out_dir / f"{name}.txt").write_text(
                "\n".join("0x" + p for p in sorted(pcs)) + "\n")
        print(f"\nwrote PC lists under {args.out_dir}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())

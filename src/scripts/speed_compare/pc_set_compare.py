#!/usr/bin/env python3
"""PC-set 对比 — reFuzz vs syzkaller 覆盖 PC 集合的 Jaccard / 差集 / 子系统分桶。

speed_compare.py 的 ②收集PC对比 / ③过滤PC 步骤。回答"两个工具执行到的内核 PC
是否一样深":不是比各自的 distinct-PC 总数(单位不可比),而是对齐到同一 PC
地址空间后比**集合**。

输入(两侧都是 `0x<hex>` 一行一个 PC):
  --refuzz-pcs : reFuzz 侧(refuzz-exec-replayer -dump-pc-set,**原始 KCOV PC**)
  --syz-pcs    : syz 侧(execprog -pcset_out / manager /rawcover,均 PreviousInstructionPC 空间)

对齐(关键):syz 两条取数路径都套了 PreviousInstructionPC(amd64: pc-=5,见
pkg/cover/backend/pc.go);reFuzz 存原始 KCOV PC。所以
  refuzz_pc - instr_len == syz_pc   (amd64 instr_len=5)
本工具把 reFuzz 每个 PC 减 instr_len 后再比。arm C(两侧喂逐字节相同 corpus)对齐
正确时 Jaccard 应 ≈1.0 —— 这是对齐 + reFuzz 执行保真度的自带校验闸。

差集分桶(--vmlinux 时):复用 exec_oracle_pc_subsystem_diff.py 的子系统分类,把
  reFuzz∖syz : 多为结构性噪声(mm/、arch/x86 = reFuzz 进程地址空间/拆解足迹)
  syz∖reFuzz : 真路径子系统 = reFuzz 没跑到的**真执行深度差**
分开报。jaccard_realpath = 把差集里的结构性噪声 PC 从对称差里剔除后的 Jaccard
(common PC 视为真路径:两侧都跑到的 PC 不会是 reFuzz-only 结构噪声)。
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

# 复用 exec_oracle 的子系统分类(住 scripts/pc_compare/;import 安全 —— 其 main() 有 __main__ guard)。
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "pc_compare"))
try:
    from exec_oracle_pc_subsystem_diff import is_structural, subsystem
    _HAVE_SUBSYS = True
except Exception:  # pragma: no cover - 退化为仅 raw Jaccard
    _HAVE_SUBSYS = False


PC_TOKEN_RE = re.compile(r"0x[0-9a-fA-F]+|[0-9a-fA-F]{8,}")


def load_pc_file(path: Path) -> set[int]:
    """读 PC 文件 → set[int]。

    支持两类常见格式:
      - `0x<hex>` / line
      - syzkaller focus pcs: `0x<pc>:0x<weight>` / line
    """
    pcs: set[int] = set()
    with path.open() as fh:
        for raw in fh:
            line = raw.split("#", 1)[0].strip()
            if not line or line.startswith("#"):
                continue
            m = PC_TOKEN_RE.search(line)
            if m is None:
                continue
            token = m.group(0)
            base = 16
            try:
                pcs.add(int(token, base))
            except ValueError:
                pass
    return pcs


def load_pc_files(paths: list[Path]) -> set[int]:
    pcs: set[int] = set()
    for path in paths:
        pcs |= load_pc_file(path)
    return pcs


def addr2line_stdin(vmlinux: Path, addrs: list[int]) -> dict[int, str]:
    """addr -> source path(file:line)。地址走 stdin(不走 argv)→ 不受 ARG_MAX 限,
    可处理十万级 PC。-f 输出每地址两行(func / file:line),我们只取 file:line。"""
    if not addrs:
        return {}
    inp = "".join(f"0x{a:x}\n" for a in addrs)
    proc = subprocess.run(
        ["addr2line", "-e", str(vmlinux), "-f"],
        input=inp, capture_output=True, text=True,
    )
    lines = proc.stdout.splitlines()
    out: dict[int, str] = {}
    for i, a in enumerate(addrs):
        fl = lines[2 * i + 1].strip() if 2 * i + 1 < len(lines) else "??"
        out[a] = fl
    return out


def classify(pcs: set[int], vmlinux: Path | None) -> tuple[int, int, Counter]:
    """→ (structural_count, realpath_count, subsystem Counter)。无 vmlinux 时返回
    (0, len(pcs), 空) —— 全部当 real-path(jaccard_realpath 退化为 jaccard)。"""
    if not pcs or vmlinux is None or not _HAVE_SUBSYS:
        return 0, len(pcs), Counter()
    a2l = addr2line_stdin(vmlinux, sorted(pcs))
    sub_ct: Counter = Counter()
    struct_n = real_n = 0
    for pc in pcs:
        sub = subsystem(a2l.get(pc, "??"))
        sub_ct[sub] += 1
        if is_structural(sub):
            struct_n += 1
        else:
            real_n += 1
    return struct_n, real_n, sub_ct


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--refuzz-pcs", type=Path, required=True,
                    help="reFuzz PC dump(原始 KCOV PC,0x<hex>/line)")
    ap.add_argument("--syz-pcs", type=Path, required=True,
                    help="syz PC dump(PreviousInstructionPC 空间,0x<hex>/line)")
    ap.add_argument("--vmlinux", type=Path, default=None,
                    help="带 debuginfo 的 vmlinux(addr2line 子系统分桶;省略=仅 raw Jaccard)")
    ap.add_argument("--instr-len", type=int, default=5,
                    help="reFuzz→syz 对齐平移量 = instructionLen(arch);amd64=5(默认)")
    ap.add_argument("--filter-pcs", type=Path, action="append", default=[],
                    help="可选 PC allow-list(与比较域同空间);可重复。给出则两侧都只留这些文件并集内 PC")
    ap.add_argument("--label", default="", help="结果标注(如 'arm C run 1')")
    ap.add_argument("--domain", default="pc_set",
                    help="structured comparison domain name, e.g. corpus_pc/raw_all_pc/edge")
    ap.add_argument("--out-json", type=Path, default=None)
    ap.add_argument("--out-dir", type=Path, default=None,
                    help="写 refuzz_only.txt / syz_only.txt / common.txt(sorted 0x<hex>/line)")
    ap.add_argument("--topn-sub", type=int, default=15)
    args = ap.parse_args()

    if not args.refuzz_pcs.exists():
        print(f"pc_set_compare: refuzz-pcs not found: {args.refuzz_pcs}", file=sys.stderr)
        return 2
    if not args.syz_pcs.exists():
        print(f"pc_set_compare: syz-pcs not found: {args.syz_pcs}", file=sys.stderr)
        return 2

    vmlinux = args.vmlinux if (args.vmlinux and args.vmlinux.exists()) else None
    if args.vmlinux and vmlinux is None:
        print(f"pc_set_compare: vmlinux not found, skipping buckets: {args.vmlinux}", file=sys.stderr)
    if vmlinux and not shutil.which("addr2line"):
        print("pc_set_compare: addr2line not on PATH; skipping subsystem buckets", file=sys.stderr)
        vmlinux = None
    if vmlinux and not _HAVE_SUBSYS:
        print("pc_set_compare: exec_oracle_pc_subsystem_diff import failed; skipping buckets",
              file=sys.stderr)
        vmlinux = None

    # 对齐:reFuzz 原始 KCOV PC 减 instr_len 进 syz PreviousInstructionPC 空间。
    refuzz = {pc - args.instr_len for pc in load_pc_file(args.refuzz_pcs)}
    syz = load_pc_file(args.syz_pcs)
    refuzz_unfiltered_n = len(refuzz)
    syz_unfiltered_n = len(syz)
    filter_n = 0

    if args.filter_pcs:
        missing = [p for p in args.filter_pcs if not p.exists()]
        if missing:
            print("pc_set_compare: filter-pcs not found: " +
                  ", ".join(str(p) for p in missing), file=sys.stderr)
            return 2
        flt = load_pc_files(args.filter_pcs)
        filter_n = len(flt)
        refuzz &= flt
        syz &= flt

    common = refuzz & syz
    refuzz_only = refuzz - syz
    syz_only = syz - refuzz
    union = refuzz | syz
    jaccard = len(common) / len(union) if union else 0.0

    r_struct, r_real, r_sub = classify(refuzz_only, vmlinux)
    s_struct, s_real, s_sub = classify(syz_only, vmlinux)
    # common 视为真路径(两侧都到的 PC 不会是 reFuzz-only 结构噪声)→ 只从对称差剔噪声。
    denom_real = len(common) + r_real + s_real
    jaccard_realpath = len(common) / denom_real if denom_real else 0.0

    result = {
        "label": args.label,
        "domain": args.domain,
        "instr_len": args.instr_len,
        "filter_pcs": [str(p) for p in args.filter_pcs],
        "filter_pcs_count": filter_n,
        "refuzz_pcs_unfiltered": refuzz_unfiltered_n,
        "syz_pcs_unfiltered": syz_unfiltered_n,
        "refuzz_pcs": len(refuzz),
        "syz_pcs": len(syz),
        "common": len(common),
        "union": len(union),
        "jaccard": round(jaccard, 4),
        "refuzz_only": len(refuzz_only),
        "syz_only": len(syz_only),
        "refuzz_only_structural": r_struct,
        "refuzz_only_realpath": r_real,
        "syz_only_structural": s_struct,
        "syz_only_realpath": s_real,           # = reFuzz 没跑到的真路径深度差
        "jaccard_realpath": round(jaccard_realpath, 4),
        "subsystem_buckets": bool(vmlinux),
        "refuzz_only_top_subsystems": r_sub.most_common(args.topn_sub),
        "syz_only_top_subsystems": s_sub.most_common(args.topn_sub),
        "vmlinux": str(vmlinux) if vmlinux else "",
    }

    tag = f" [{args.label}]" if args.label else ""
    print("=" * 72)
    print(f"PC-set compare{tag}  (instr_len={args.instr_len})")
    if args.filter_pcs:
        print(f"  filter_pcs={filter_n}  files={len(args.filter_pcs)}")
    print(f"  refuzz={len(refuzz)}  syz={len(syz)}  common={len(common)}  union={len(union)}")
    print(f"  jaccard          = {jaccard:.4f}")
    if vmlinux:
        print(f"  jaccard_realpath = {jaccard_realpath:.4f}  (结构噪声从对称差剔除后)")
    print(f"  reFuzz\\syz = {len(refuzz_only)}"
          + (f"  (structural={r_struct} / real-path={r_real})" if vmlinux else ""))
    print(f"  syz\\reFuzz = {len(syz_only)}"
          + (f"  (structural={s_struct} / real-path={s_real} ← 真深度差)" if vmlinux else ""))
    if vmlinux:
        def show(title: str, sub_ct: Counter) -> None:
            if not sub_ct:
                return
            print(f"  -- {title} top {args.topn_sub} 子系统 (* = 真路径) --")
            for sub, c in sub_ct.most_common(args.topn_sub):
                mark = "  " if is_structural(sub) else "* "
                print(f"    {mark}{c:6d}  {sub}")
        show("reFuzz\\syz", r_sub)
        show("syz\\reFuzz", s_sub)
    print("=" * 72)

    if args.out_json:
        args.out_json.parent.mkdir(parents=True, exist_ok=True)
        args.out_json.write_text(json.dumps(result, indent=2) + "\n")
        print(f"pc_set_compare: json → {args.out_json}", file=sys.stderr)
    if args.out_dir:
        args.out_dir.mkdir(parents=True, exist_ok=True)

        def dump(name: str, pcs: set[int]) -> None:
            (args.out_dir / f"{name}.txt").write_text(
                "".join(f"0x{p:x}\n" for p in sorted(pcs)))
        dump("refuzz_only", refuzz_only)
        dump("syz_only", syz_only)
        dump("common", common)
        print(f"pc_set_compare: PC lists → {args.out_dir}/", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())

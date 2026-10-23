# Copyright 2026 reFuzz project author -------youngkk.
#
# PC-BRIDGE — the gcc↔clang seam that makes the static M OBSERVABLE from a runtime KCOV bitmap.
# Our analysis (clang `.bc`) names FUNCTIONS; KCOV reports absolute PCs of the gcc vmlinux. The bridge
# joins them by NAME + ADDRESS RANGE via `function_block_map.tsv` (PC -> function, from
# refuzz_kernel_block_map on the gcc vmlinux): a function spans [its first instrumented PC, the next
# function's first PC), so any coverage PC maps to its containing function. (Exact BB-PC equality does
# NOT work — KCOV PCs sit mid-function at a spread offset, not at BB starts.)
#
# This gives: region(set of funcs) -> gcc PC-set  [for mass + the edge-firing observation], and
# coverage bitmap -> set of covered functions [the dynamic signal that bumps the Beta posterior].
import bisect
import collections

KERNEL_LO = 0xffffffff81000000      # filter coverage garbage (stray tiny values)


def load_block_map(path):
    """Returns (func_pcs: {func -> sorted[PC]}, starts_pc: sorted[PC], starts_fn: parallel[func])."""
    func_pcs = collections.defaultdict(list)
    for ln in open(path):
        c = ln.rstrip("\n").split("\t")
        if len(c) >= 3:
            try:
                func_pcs[c[2]].append(int(c[0], 16))
            except ValueError:
                pass
    for f in func_pcs:
        func_pcs[f].sort()
    starts = sorted((pcs[0], f) for f, pcs in func_pcs.items())
    return dict(func_pcs), [p for p, _ in starts], [f for _, f in starts]


def load_coverage(path):
    out = set()
    for ln in open(path):
        s = ln.strip()
        if not s:
            continue
        try:
            v = int(s, 16)
        except ValueError:
            continue
        if v >= KERNEL_LO:
            out.add(v)
    return out


def pc_to_func(pc, starts_pc, starts_fn):
    i = bisect.bisect_right(starts_pc, pc) - 1
    return starts_fn[i] if i >= 0 else None


def covered_functions(cov_pcs, starts_pc, starts_fn):
    return {f for f in (pc_to_func(c, starts_pc, starts_fn) for c in cov_pcs) if f}


def region_pcs(funcs, func_pcs):
    out = set()
    for f in funcs:
        out.update(func_pcs.get(f, ()))
    return out


def variant_region_pcs(bind, func_pcs):
    """variant -> set of gcc KCOV PCs of its value-narrowed region (handler + region roots).
       Drives BOTH mass (len) and the edge-firing observation (region ∩ coverage)."""
    out = {}
    for v, t in bind.items():
        funcs = {t[0]} | {x for x in t[2].split(",") if x}
        out[v] = region_pcs(funcs, func_pcs)
    return out

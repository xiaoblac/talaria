#!/usr/bin/env python3
# Copyright 2026 reFuzz project author -------youngkk.
#
# seed_horizon_implicit_defuse.py — extract IMPLICIT def-use edges: the ②/④-confluence signal that
# dynamic coverage CANNOT sample as an edge. Handler A writes `struct.X+off = V` (def of a specific
# value); handler B branches on `struct.X+off == V` (use guarded by that value) => executing A
# unlocks B's V-guarded region. These couple two variants through SHARED KERNEL STATE, invisible to
# coverage-novelty (each looks like independent code). Aggregated over every linked kernel `.bc`, restricted
# to NAMED struct fields, hub-deflattened (drop locks/lists/refcounts touched by many handlers).
#
# Out: run/seed_horizon/implicit_defuse_edges.tsv  (def_handler, use_handler, loc, value)

import collections
import glob
import os
import subprocess

SH = "run/seed_horizon"
ENG = f"{SH}/ir_defuse"


def is_struct_loc(loc):
    # named struct field only; drops `i64+24`, `?+0`, `[4 x ...]+N` generic pointer-arithmetic noise.
    return loc.startswith("struct.") and "+" in loc


defs = collections.defaultdict(set)        # loc -> {(handler, V)}
uses = collections.defaultdict(set)        # loc -> {(handler, V)}
loc_handlers = collections.defaultdict(set)

for bc in sorted(glob.glob(f"{SH}/kernel_linked/**/*.bc", recursive=True)):
    cache = bc[:-3] + ".defuse.tsv"
    if not os.path.exists(cache) or os.path.getmtime(cache) < os.path.getmtime(bc):
        with open(cache, "w") as f:
            subprocess.run([ENG, bc], stdout=f, stderr=subprocess.DEVNULL)
    for ln in open(cache):
        c = ln.rstrip("\n").split("\t")
        if len(c) < 4 or not is_struct_loc(c[2]):
            continue
        if c[0] == "WRITE" and c[3].lstrip("-").isdigit():
            loc_handlers[c[2]].add(c[1])
            defs[c[2]].add((c[1], int(c[3]) & 0xFFFFFFFF))
        elif c[0] == "BRANCHUSE":
            loc_handlers[c[2]].add(c[1])
            for x in c[3].split(","):
                if x.lstrip("-").isdigit():
                    uses[c[2]].add((c[1], int(x) & 0xFFFFFFFF))

# hub-deflatten: a field touched by >12 handlers is a generic lock/list/refcount/flag, not a
# specific state-machine coupling.
HUB = {loc for loc, hs in loc_handlers.items() if len(hs) > 12}

edges = set()
for loc in set(defs) & set(uses):
    if loc in HUB:
        continue
    use_by_val = collections.defaultdict(set)
    for h, v in uses[loc]:
        use_by_val[v].add(h)
    for hA, vA in defs[loc]:
        for hB in use_by_val.get(vA, ()):
            if hA != hB:
                edges.add((hA, hB, loc, vA))

with open(f"{SH}/implicit_defuse_edges.tsv", "w") as f:
    f.write("#def_handler\tuse_handler\tloc\tvalue\n")
    for a, b, loc, v in sorted(edges):
        f.write(f"{a}\t{b}\t{loc}\t{v}\n")

pairs = {(a, b) for a, b, _, _ in edges}
print(f"# implicit def-use edges -> {SH}/implicit_defuse_edges.tsv")
print(f"# edges={len(edges)}  distinct def->use handler pairs={len(pairs)}")
print(f"# named-struct locs: def={len(defs)} use={len(uses)} hubs-dropped={len(HUB)}")
oc = collections.Counter(a for a, _, _, _ in edges)
print("# top def handlers (unlock the most use-regions):")
for h, n in oc.most_common(8):
    print(f"#   {h:34} unlocks {n}")

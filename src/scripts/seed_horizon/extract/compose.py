#!/usr/bin/env python3
# Copyright 2026 reFuzz project author -------youngkk.
#
# seed_horizon_compose.py — diagnostic subsystem CMD-candidate report.
#
# This is not an authoritative variant -> handler binder. It has no global resource context or
# provenance proof. It is kept only for local inspection of extracted REG/CMD facts.
#
# This script is kept for quick per-subsystem inspection of extracted ③/④ facts:
#   ③ reg.tsv  : device/resource -> fops -> ioctl/open/read/write handler
#   ④ cmd.tsv  : cmd-value -> (handler, dominator-owned region, region roots)   [incl. 4f nested]
#   syz side   : horizon_model.json (produces/consumes/uses) + consts.gen.hpp
# Output: each matching variant -> best local CMD candidate + explicit resource relations.
#
# Usage: seed_horizon_compose.py <reg.tsv> <cmd.tsv> <variant-name-prefix>   e.g. ... ioctl$KVM

import collections
import json
import re
import sys

SH = "run/seed_horizon"
REG = sys.argv[1] if len(sys.argv) > 1 else f"{SH}/kernel_facts_linked/reg.tsv"
CMD = sys.argv[2] if len(sys.argv) > 2 else f"{SH}/kernel_facts_linked/cmd.tsv"
VARPAT = sys.argv[3] if len(sys.argv) > 3 else "ioctl$KVM"

# consts: NAME -> 32-bit value (ioctl cmd / sockopt optname encoding)
consts = {}
for ln in open("program/include/refuzz/program/syz/generated/consts.gen.hpp"):
    m = re.search(r'kSyzConst_(\w+)\s*=\s*(-?\d+)', ln)
    if m:
        consts[m.group(1)] = int(m.group(2)) & 0xFFFFFFFF


def cval(suf):
    # variant $-suffix -> const value; sockopt names carry a family prefix (inet_sctp_SCTP_X),
    # so try the full suffix then strip leading _-parts until a known const matches.
    if suf in consts:
        return consts[suf]
    parts = suf.split("_")
    for i in range(1, len(parts)):
        c = "_".join(parts[i:])
        if c in consts:
            return consts[c]
    return None

# ④ cmd: value -> [ {handler, owned, excl, depth, roots} ]
cmd = collections.defaultdict(list)
for ln in open(CMD):
    c = ln.rstrip("\n").split("\t")
    if c[0] != "CMD" or len(c) < 8:
        continue
    cmd[int(c[2]) & 0xFFFFFFFF].append(
        {"handler": c[1], "owned": int(c[4]), "excl": c[5], "depth": c[6], "roots": c[7]})

# ③ reg: ioctl-handler -> (kind, dev, fops), used only to display the candidate dispatch table.
hand2dev = {}
for ln in open(REG):
    c = ln.rstrip("\n").split("\t")
    if c[0] != "REG" or len(c) < 5:
        continue
    m = re.search(r'ioctl=(\S+)', c[4])
    if m and m.group(1) != "-":
        hand2dev[m.group(1)] = (c[1], c[2], c[3])

# syz side: resources
hm = json.load(open(f"{SH}/horizon_model.json"))
prod = collections.defaultdict(set)
cons = collections.defaultdict(set)
for s in hm["syscalls"]:
    for r in s.get("produces") or []:
        prod[r].add(s["name"])
    for r in (set(s.get("consumes") or []) | set(s.get("uses") or [])):
        cons[r].add(s["name"])

rows = []
nbound = 0
for s in hm["syscalls"]:
    v = s["name"]
    if VARPAT not in v:                       # contains (family substring), not just startswith
        continue
    suf = v.split("$", 1)[1] if "$" in v else ""
    cv = cval(suf)
    hits = cmd.get(cv, []) if cv is not None else []
    best = min(hits, key=lambda r: r["owned"]) if hits else None  # local diagnostic candidate
    if best:
        handler, owned, roots = best["handler"], best["owned"], best["roots"]
    else:
        handler, owned, roots = "-", 0, ""
    disp = hand2dev.get(handler, ("", "", "-"))[2]
    # explicit (resource) relations among same-subsystem variants
    mycons = set(s.get("consumes") or []) | set(s.get("uses") or [])
    myprod = set(s.get("produces") or [])
    needs = sorted({p for r in mycons for p in prod[r] if p != v and VARPAT in p})
    unlocks = sorted({c for r in myprod for c in cons[r] if c != v and VARPAT in c})
    if handler != "-":
        nbound += 1
    rel = (("needs:" + ",".join(needs[:3])) if needs else "") + \
          ((" unlocks:" + ",".join(unlocks[:3])) if unlocks else "")
    rows.append((v, cv, handler, owned, disp, rel, roots))

print(f"# {VARPAT} variants: {len(rows)}  local-cmd-candidates: {nbound}")
print("#variant\tcmd\tcandidate_handler\towned\tdispatcher\trelations\troots")
for r in sorted(rows, key=lambda r: (r[2] == "-", r[0])):
    print(f"{r[0]}\t{r[1]}\t{r[2]}\t{r[3]}\t{r[4]}\t{r[5]}\t{r[6][:70]}")

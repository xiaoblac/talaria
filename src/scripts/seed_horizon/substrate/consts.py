# Copyright 2026 reFuzz project author -------youngkk.
# Generic: the syzkaller const map (NAME -> 32-bit value) + the variant-suffix -> const resolver.
import re

CONSTS_HPP = "program/include/refuzz/program/syz/generated/consts.gen.hpp"


def u32(s):
    return int(s) & 0xFFFFFFFF if s.lstrip("-").isdigit() else None


def load_consts(path=CONSTS_HPP):
    consts = {}
    for ln in open(path):
        m = re.search(r'kSyzConst_(\w+)\s*=\s*(-?\d+)', ln)
        if m:
            consts[m.group(1)] = int(m.group(2)) & 0xFFFFFFFF
    return consts


def cval(suf, consts):
    # sockopt names carry a family prefix (inet_sctp_SCTP_X); try full suffix, then strip leading parts.
    if suf in consts:
        return consts[suf]
    parts = suf.split("_")
    for i in range(1, len(parts)):
        c = "_".join(parts[i:])
        if c in consts:
            return consts[c]
    return None

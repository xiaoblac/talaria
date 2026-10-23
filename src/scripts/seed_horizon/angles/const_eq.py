# Copyright 2026 reFuzz project author -------youngkk.
#
# Angle: CONSTANT value-equality def-use (the original, hard-won lens).
#   producer = `WRITE struct.X+off = c` (a handler stores a constant into a named field)
#   consumer = `BRANCH struct.X+off == c` (a handler's path is guarded by that field == that constant)
#   coupling key = (loc, value); EQUALITY is encoded as SAME KEY (the substrate joins on key identity).
# Deep facts come from `kernel_linked/*.defuse.tsv` (whole-function), shallow value-narrowed facts from linked `cmd.tsv`
# (CMDWRITE/CMDUSE, scoped to a specific cmd region). Tier A: an exact constant match is high precision.
import glob

from substrate.consts import u32
from substrate.ir_angle import IRAngle

NAME = "value-defuse-const"
FIELD_HUB = 12          # drop (loc,value) sites touched by > 12 variants (generic state)
BASE_PRECISION = 0.9    # exact constant match -> high Beta prior


def _struct(c, idx):
    return len(c) > idx and c[idx].startswith("struct.")


class ConstEq(IRAngle):
    name = NAME
    field_hub = FIELD_HUB
    base_precision = BASE_PRECISION
    base_blindness = 1.0          # constant state-coupling: the dynamic-can't-sample bet (the gold)

    def writer_facts(self, SH):
        fn_w, hc_w = {}, {}
        for f in glob.glob(f"{SH}/kernel_linked/**/*.defuse.tsv", recursive=True):
            for ln in open(f):
                c = ln.rstrip("\n").split("\t")
                if c and c[0] == "WRITE" and _struct(c, 2):
                    x = u32(c[3]) if len(c) > 3 else None
                    if x is not None:
                        fn_w.setdefault(c[1], set()).add((c[2], x))
        for f in glob.glob(f"{SH}/kernel_facts_linked/cmd.tsv"):
            for ln in open(f):
                c = ln.rstrip("\n").split("\t")
                if c and c[0] == "CMDWRITE" and _struct(c, 3):
                    cv = u32(c[2]) if len(c) > 2 else None
                    x = u32(c[4]) if len(c) > 4 else None
                    if cv is not None and x is not None:
                        hc_w.setdefault((c[1], cv), set()).add((c[3], x))
        return fn_w, hc_w

    def reader_facts(self, SH):
        fn_r, hc_r = {}, {}
        for f in glob.glob(f"{SH}/kernel_linked/**/*.defuse.tsv", recursive=True):
            for ln in open(f):
                c = ln.rstrip("\n").split("\t")
                if c and c[0] == "BRANCHUSE" and _struct(c, 2) and len(c) > 3:
                    for p in c[3].split(","):
                        x = u32(p)
                        if x is not None:
                            fn_r.setdefault(c[1], set()).add((c[2], x))
        for f in glob.glob(f"{SH}/kernel_facts_linked/cmd.tsv"):
            for ln in open(f):
                c = ln.rstrip("\n").split("\t")
                if c and c[0] == "CMDUSE" and _struct(c, 3) and len(c) > 4:
                    cv = u32(c[2])
                    if cv is None:
                        continue
                    for p in c[4].split(","):
                        x = u32(p)
                        if x is not None:
                            hc_r.setdefault((c[1], cv), set()).add((c[3], x))
        return fn_r, hc_r

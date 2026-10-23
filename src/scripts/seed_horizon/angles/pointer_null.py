# Copyright 2026 reFuzz project author -------youngkk.
#
# Angle: POINTER-EXISTENCE def-use (the second lens — proves the template generalizes beyond equality).
#   producer = `WRITE struct.X+off = <non-null>` (a handler establishes a sub-object: const!=0 or an
#              alloc/arg `nonconst`)
#   consumer = `BRANCH struct.X+off == 0` (a handler's path is gated on that pointer being non-null)
#   coupling key = (loc,)  -- loc-only; "the field was set" ⋈ "the field was null-checked". A looser
#   match than constant-equality (we don't know the exact pointer), so a lower Beta prior. SAME
#   substrate (membership / attribute / couple / deflatten) — only this vocabulary differs.
import glob

from substrate.consts import u32
from substrate.ir_angle import IRAngle

NAME = "pointer-exist"
FIELD_HUB = 12
BASE_PRECISION = 0.7     # loc-only, presumed-non-null -> looser than const_eq's 0.9


def _struct(c, idx):
    return len(c) > idx and c[idx].startswith("struct.")


class PointerNull(IRAngle):
    name = NAME
    field_hub = FIELD_HUB
    base_precision = BASE_PRECISION
    base_blindness = 0.6          # pointer-existence: partly dynamic-observable, partly not

    def writer_facts(self, SH):
        # field SET to non-null: a constant != 0, or a nonconst alloc/arg. key = (loc,)
        fn_w, hc_w = {}, {}
        for f in glob.glob(f"{SH}/kernel_linked/**/*.defuse.tsv", recursive=True):
            for ln in open(f):
                c = ln.rstrip("\n").split("\t")
                if c and c[0] == "WRITE" and _struct(c, 2) and len(c) > 3:
                    x = u32(c[3])
                    if x == 0:                       # writing NULL doesn't establish existence
                        continue
                    fn_w.setdefault(c[1], set()).add((c[2],))
        for f in glob.glob(f"{SH}/kernel_facts_linked/cmd.tsv"):
            for ln in open(f):
                c = ln.rstrip("\n").split("\t")
                if c and c[0] == "CMDWRITE" and _struct(c, 3) and len(c) > 4:
                    cv = u32(c[2])
                    if cv is None or u32(c[4]) == 0:
                        continue
                    hc_w.setdefault((c[1], cv), set()).add((c[3],))
        return fn_w, hc_w

    def reader_facts(self, SH):
        # null-check: a branch on the field that compares against 0. key = (loc,)
        fn_r, hc_r = {}, {}
        for f in glob.glob(f"{SH}/kernel_linked/**/*.defuse.tsv", recursive=True):
            for ln in open(f):
                c = ln.rstrip("\n").split("\t")
                if c and c[0] == "BRANCHUSE" and _struct(c, 2) and len(c) > 3:
                    if 0 in {u32(p) for p in c[3].split(",")}:
                        fn_r.setdefault(c[1], set()).add((c[2],))
        for f in glob.glob(f"{SH}/kernel_facts_linked/cmd.tsv"):
            for ln in open(f):
                c = ln.rstrip("\n").split("\t")
                if c and c[0] == "CMDUSE" and _struct(c, 3) and len(c) > 4:
                    cv = u32(c[2])
                    if cv is not None and 0 in {u32(p) for p in c[4].split(",")}:
                        hc_r.setdefault((c[1], cv), set()).add((c[3],))
        return fn_r, hc_r

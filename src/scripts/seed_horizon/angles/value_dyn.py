# Copyright 2026 reFuzz project author -------youngkk.
#
# Angle E3: RUNTIME-VALUE state coupling — the value-state mechanism's dynamic half (Demystifying's
# ~67% of state writes are runtime expressions, not constants, so const_eq (E2) can't confirm them).
# This ATTRIBUTES those couplings rather than leaving them unexplained: a field written with a runtime
# value, branched on by another variant => the state coupling EXISTS; whether the write hits the guard
# is a runtime fact -> the value is dynamic's to learn (a handoff, not a confirmed edge).
#   producer = `WRITE F = <nonconst>` (runtime/arg value into named field F)   key = loc
#   consumer = `BRANCH F` (any guard on F)                                     key = loc
# LOW precision (loc-only, value unconfirmed) + HIGH blindness (runtime value) -> stays in the prior
# as the value-dyn HANDOFF layer (not the differentiated subset); completes value-state attribution.
import glob

from substrate.consts import u32
from substrate.ir_angle import IRAngle

NAME = "value-defuse-dyn"
FIELD_HUB = 12
BASE_PRECISION = 0.3      # handoff: field written (runtime) & branched -> coupling exists, value unconfirmed
BASE_BLINDNESS = 0.9      # runtime value -> dynamic-blind on whether the write reaches the guard


class ValueDyn(IRAngle):
    name = NAME
    field_hub = FIELD_HUB
    base_precision = BASE_PRECISION
    base_blindness = BASE_BLINDNESS

    def writer_facts(self, SH):
        fn_w, hc_w = {}, {}
        for f in glob.glob(f"{SH}/kernel_linked/**/*.defuse.tsv", recursive=True):
            for ln in open(f):
                c = ln.rstrip("\n").split("\t")
                if c and c[0] == "WRITE" and len(c) > 3 and c[2].startswith("struct.") \
                        and u32(c[3]) is None:                       # NONCONST (const is E2's job)
                    fn_w.setdefault(c[1], set()).add(c[2])           # key = loc
        for f in glob.glob(f"{SH}/kernel_facts_linked/cmd.tsv"):
            for ln in open(f):
                c = ln.rstrip("\n").split("\t")
                if c and c[0] == "CMDWRITE" and len(c) > 4 and c[3].startswith("struct.") \
                        and u32(c[4]) is None:
                    cv = u32(c[2])
                    if cv is not None:
                        hc_w.setdefault((c[1], cv), set()).add(c[3])
        return fn_w, hc_w

    def reader_facts(self, SH):
        fn_r, hc_r = {}, {}
        for f in glob.glob(f"{SH}/kernel_linked/**/*.defuse.tsv", recursive=True):
            for ln in open(f):
                c = ln.rstrip("\n").split("\t")
                if c and c[0] == "BRANCHUSE" and len(c) > 3 and c[2].startswith("struct."):
                    fn_r.setdefault(c[1], set()).add(c[2])           # key = loc (any guard on the field)
        for f in glob.glob(f"{SH}/kernel_facts_linked/cmd.tsv"):
            for ln in open(f):
                c = ln.rstrip("\n").split("\t")
                if c and c[0] == "CMDUSE" and len(c) > 4 and c[3].startswith("struct."):
                    cv = u32(c[2])
                    if cv is not None:
                        hc_r.setdefault((c[1], cv), set()).add(c[3])
        return fn_r, hc_r

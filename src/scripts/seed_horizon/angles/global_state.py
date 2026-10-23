# Copyright 2026 reFuzz project author -------youngkk.
#
# Angle E9: GLOBAL / SINGLETON state — a variant writes a constant into a GLOBAL, another branches on
# that global (state coupled through module-global / singleton state, not through a shared fd object).
#   producer = `WRITE @g+off = c`   consumer = `BRANCH @g+off == c`   key = (@g+off, c)  (constant match)
# Facts: ir_defuse now emits `@g+off` locs additively (globalLoc; struct.X facts unchanged → golden held).
# resource_scoped=False: a global couples variants that share NO fd object — the same-resource `cred`
# must NOT apply (it would sink real global couplings); generic globals (kmalloc_caches, jiffies) are
# handled by the field-hub deflatten instead (a global touched by >12 variants = infrastructure noise).
import glob

from substrate.consts import u32
from substrate.ir_angle import IRAngle

NAME = "global-state"
FIELD_HUB = 12
BASE_PRECISION = 0.85     # constant global state-machine match (mirrors const_eq, on global identity)
BASE_BLINDNESS = 0.85     # cross-call global value -> dynamic rarely sets the right global state -> blind


class GlobalState(IRAngle):
    name = NAME
    field_hub = FIELD_HUB
    base_precision = BASE_PRECISION
    base_blindness = BASE_BLINDNESS
    resource_scoped = False        # globals couple across resources -> exempt from same-resource cred

    def writer_facts(self, SH):
        fn_w, hc_w = {}, {}
        for f in glob.glob(f"{SH}/kernel_linked/**/*.defuse.tsv", recursive=True):
            for ln in open(f):
                c = ln.rstrip("\n").split("\t")
                if c and c[0] == "WRITE" and len(c) > 3 and c[2].startswith("@"):
                    x = u32(c[3])
                    if x is not None:
                        fn_w.setdefault(c[1], set()).add((c[2], x))
        return fn_w, hc_w

    def reader_facts(self, SH):
        fn_r, hc_r = {}, {}
        for f in glob.glob(f"{SH}/kernel_linked/**/*.defuse.tsv", recursive=True):
            for ln in open(f):
                c = ln.rstrip("\n").split("\t")
                if c and c[0] == "BRANCHUSE" and len(c) > 3 and c[2].startswith("@"):
                    for p in c[3].split(","):
                        x = u32(p)
                        if x is not None:
                            fn_r.setdefault(c[1], set()).add((c[2], x))
        return fn_r, hc_r

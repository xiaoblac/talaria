# Copyright 2026 reFuzz project author -------youngkk.
#
# Angle E7: RELATIONAL / THRESHOLD guard (⊇ E8 refcount). A variant sets a field to a constant; another
# variant's path is gated on that field by a RELATIONAL comparison (`F > k`, `F < k`, `F != k`) — a
# threshold/count/refcount coupling. const_eq (E2) only catches `F == k` exactly (and accidentally
# `F op k` when the written value equals k); E7's distinct slice is `WRITE F=c` ⋈ `F op k` where c
# satisfies the relation with a DIFFERENT k (e.g. write 5, guard `>3`). Verifying `c op k` precisely
# would need a predicate join (the one extension couple()'s same-key model can't do); for ATTRIBUTION
# we do the same-key HANDOFF — the relational coupling EXISTS; whether the value clears the threshold
# is dynamic's. Facts: ir_defuse emits `BRANCHREL <fn> <loc> <pred> <k>` (additive; BRANCHUSE intact).
#   producer = `WRITE F = c`   consumer = `BRANCHREL F ...`   key = loc
import glob

from substrate.consts import u32
from substrate.ir_angle import IRAngle

NAME = "relational"
FIELD_HUB = 12
BASE_PRECISION = 0.3      # handoff: threshold coupling exists, value-vs-threshold unconfirmed -> dynamic
BASE_BLINDNESS = 0.85     # whether a runtime value clears a threshold -> dynamic-blind


def _struct_or_global(loc):
    return loc.startswith("struct.") or loc.startswith("@")


class Relational(IRAngle):
    name = NAME
    field_hub = FIELD_HUB
    base_precision = BASE_PRECISION
    base_blindness = BASE_BLINDNESS

    def writer_facts(self, SH):
        fn_w, hc_w = {}, {}
        for f in glob.glob(f"{SH}/kernel_linked/**/*.defuse.tsv", recursive=True):
            for ln in open(f):
                c = ln.rstrip("\n").split("\t")
                if c and c[0] == "WRITE" and len(c) > 3 and _struct_or_global(c[2]) \
                        and u32(c[3]) is not None:                # const write (sets the threshold field)
                    fn_w.setdefault(c[1], set()).add(c[2])        # key = loc
        return fn_w, hc_w

    def reader_facts(self, SH):
        fn_r, hc_r = {}, {}
        for f in glob.glob(f"{SH}/kernel_linked/**/*.defuse.tsv", recursive=True):
            for ln in open(f):
                c = ln.rstrip("\n").split("\t")
                if c and c[0] == "BRANCHREL" and len(c) > 2 and _struct_or_global(c[2]):
                    fn_r.setdefault(c[1], set()).add(c[2])        # relational guard on the field
        return fn_r, hc_r

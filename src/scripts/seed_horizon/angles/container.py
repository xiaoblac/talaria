# Copyright 2026 reFuzz project author -------youngkk.
#
# Angle E4: CONTAINER MEMBERSHIP — the dominant kernel cross-syscall pattern (object inserted into a
# collection, looked up by a later call), which value-equality is structurally blind to (the
# collection's list/idr writes are generic and hub-deflattened; the lookup gate is on a local).
#   producer = `CONTAINER INS` (idr_alloc/xa_store/... into collection field `struct.X+off`)
#   consumer = `CONTAINER LKP` (idr_find/xa_load/... from the SAME collection field)
#   coupling key = the collection field (struct.X+off); SAME KEY == both touch the same collection.
# Facts come from ir_defuse's `CONTAINER` emission (arg0 GEP of the idr/xarray API). Only idr/xarray
# (real call pairs both sides); list/rbtree/hash lookups are inline macros — out of reach here.
import glob

from substrate.ir_angle import IRAngle

NAME = "container"
FIELD_HUB = 40            # a collection EXISTS to be looked up by many -> high fanout is REAL (per-object
                          # table), unlike generic state; cross-subsystem leakage handled by cred. >40 = generic.
BASE_PRECISION = 0.9      # named-API insert⋈lookup on the SAME typed collection field = a genuine
                          # data-structure dependency (looked-up object must have been inserted)
BASE_BLINDNESS = 0.8      # create->lookup-BY-ID: the matching id is value-dependent -> dynamic rarely
                          # passes the right id -> the post-lookup region is dynamic-blind (chicken-egg)


def _ins(SH, want):
    facts = {}
    for f in glob.glob(f"{SH}/kernel_linked/**/*.defuse.tsv", recursive=True):
        for ln in open(f):
            c = ln.rstrip("\n").split("\t")
            if c and c[0] == "CONTAINER" and len(c) > 3 and c[2] == want:
                facts.setdefault(c[1], set()).add(c[3])      # key = collection field (struct.X+off)
    return facts


class Container(IRAngle):
    name = NAME
    field_hub = FIELD_HUB
    base_precision = BASE_PRECISION
    base_blindness = BASE_BLINDNESS

    def writer_facts(self, SH):
        return _ins(SH, "INS"), {}

    def reader_facts(self, SH):
        return _ins(SH, "LKP"), {}

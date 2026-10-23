# Copyright 2026 reFuzz project author -------youngkk.
#
# Angle E6: FUNCTION-POINTER INSTALL (handler-dispatch state). A variant installs a handler into a
# struct fptr field; another variant's region dispatches through that field => the installed handler
# determines which code the second runs (set a callback in one syscall, trigger it in another).
#   producer = `WRITE struct.X+off` where the field is a fptr field (i.e. it's ICALL'd somewhere)
#   consumer = `ICALL ... struct.X+off` (indirect call through the field — ir_defuse already resolves
#              the fptr field via the load's GEP; no engine change needed)
#   coupling key = the fptr field (struct.X+off); SAME KEY == install ⋈ dispatch on it.
import glob

from substrate.consts import u32
from substrate.ir_angle import IRAngle

NAME = "fptr-install"
FIELD_HUB = 40            # a popular ops field is dispatched from many sites -> high fanout is REAL
BASE_PRECISION = 0.8      # field provably a fptr (ICALL'd) + written -> likely an install (some copy/clear noise)
BASE_BLINDNESS = 0.7      # install->dispatch: WHICH handler (the value) is runtime -> semi dynamic-blind


def _fptr_fields(SH):
    s = set()
    for f in glob.glob(f"{SH}/kernel_linked/**/*.defuse.tsv", recursive=True):
        for ln in open(f):
            c = ln.rstrip("\n").split("\t")
            if c and c[0] == "ICALL" and len(c) > 2 and c[2].startswith("struct."):
                s.add(c[2])
    return s


class FptrInstall(IRAngle):
    name = NAME
    field_hub = FIELD_HUB
    base_precision = BASE_PRECISION
    base_blindness = BASE_BLINDNESS

    def writer_facts(self, SH):
        fptr = _fptr_fields(SH)                                  # only fields that are dispatched through
        fn_w, hc_w = {}, {}
        for f in glob.glob(f"{SH}/kernel_linked/**/*.defuse.tsv", recursive=True):
            for ln in open(f):
                c = ln.rstrip("\n").split("\t")
                if c and c[0] == "WRITE" and len(c) > 3 and c[2] in fptr:
                    fn_w.setdefault(c[1], set()).add(c[2])       # install into the fptr field
        for f in glob.glob(f"{SH}/kernel_facts_linked/cmd.tsv"):
            for ln in open(f):
                c = ln.rstrip("\n").split("\t")
                if c and c[0] == "CMDWRITE" and len(c) > 4 and c[3] in fptr:
                    cv = u32(c[2])
                    if cv is not None:
                        hc_w.setdefault((c[1], cv), set()).add(c[3])
        return fn_w, hc_w

    def reader_facts(self, SH):
        fn_r, hc_r = {}, {}
        for f in glob.glob(f"{SH}/kernel_linked/**/*.defuse.tsv", recursive=True):
            for ln in open(f):
                c = ln.rstrip("\n").split("\t")
                if c and c[0] == "ICALL" and len(c) > 2 and c[2].startswith("struct."):
                    fn_r.setdefault(c[1], set()).add(c[2])       # dispatch through the fptr field
        return fn_r, hc_r

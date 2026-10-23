#!/usr/bin/env python3
# Copyright 2026 reFuzz project author -------youngkk.
#
# CLASSIFY the precondition KIND of every S/P/R coupling — "A establishes P on S -> B checks P".
# Don't tunnel on constant-equality: P has KINDS, and most are NOT value-protocols.
#   The kind = (what A establishes on F: write value-op) x (what B checks on F: gate predicate).
#   A  value-protocol : A: F=const C        B: F == C        verifiable static handshake (we specialize this)
#   B  existence      : A: F=alloc()/ptr    B: if(F)/F!=0    decidable structural (A must run to make F live)
#   B  flag           : A: F|=BIT           B: F & FLAG      decidable structural (A sets the capability bit)
#   C1 threshold      : A: F=N              B: F </> K       partial (static iff N,K both const)
#   C2 runtime-wall   : A: F=arg/computed   B: F == C        the real wall -> honest dynamic handoff
#   D  mixed/other    : establish != check                  candidate FALSE coupling (field-touch, no protocol)
# Needs ir_defuse with the write-op split (storeVal: call/load/0) + the gate predicate col (eq/ne/rel/and/
# nonzero). Reads run/seed_horizon/all_writes.tsv + all_gates.tsv (the full-target sweep).
import collections
import os
import sys

SH = sys.argv[1] if len(sys.argv) > 1 else "run/seed_horizon"


def isfield(l):
    return l.startswith("struct.") or l.startswith("@")


def rec(s):
    return s not in ("?", "icall", "", "-")


def isconc(p):
    if p.startswith("mask&") or p.startswith("bit|") or p.startswith("asmbit"):
        return True
    try:
        int(p)
        return True
    except ValueError:
        return False


def wkind(v):                                    # what A ESTABLISHES on F (storeVal vocabulary)
    if v.startswith("mask&") or v.startswith("bit|") or v.startswith("asmbit"):
        return "flag"
    try:
        return "clear" if int(v) == 0 else "value"
    except ValueError:
        pass
    return {"call": "existence", "load": "linkage", "arg": "runtime"}.get(v, "computed")


def tier(W, GL):                                 # W = write-kinds set; GL = [(predset, has_nonzero_reqval)]
    g_eqnz = any("eq" in p and nz for p, nz in GL)                                   # F == nonzero const
    g_and = any("and" in p for p, nz in GL)                                          # bitmask / flag
    g_rel = any("rel" in p for p, nz in GL)                                          # threshold / ordering
    g_exists = any(("nonzero" in p) or ("ne" in p) or ("eq" in p and not nz) for p, nz in GL)  # !=0 / ==0
    if "value" in W and g_eqnz:
        return "A  value-protocol (A:F=C   -> B:F==C)"
    if "flag" in W and g_and:
        return "B  flag          (A:F|=BIT -> B:F&FLAG)"
    if (W & {"existence", "linkage"}) and g_exists:
        return "B  existence     (A:F=alloc-> B:if(F))"
    if g_rel and (W & {"value", "computed", "arg", "linkage"}):
        return "C1 threshold      (A:F=N    -> B:F</>K)"
    if (W & {"runtime", "computed"}) and g_eqnz:
        return "C2 runtime-wall   (A:F=arg  -> B:F==C)"
    return "D  mixed/other     (establish != check)"


def main():
    writers = collections.defaultdict(set)
    gates = collections.defaultdict(list)
    for ln in open(os.path.join(SH, "all_writes.tsv")):
        c = ln.rstrip("\n").split("\t")
        if c[0] == "WRITE" and len(c) > 4 and isfield(c[2]) and rec(c[4]):
            writers[(c[2], c[4])].add(wkind(c[3]))
    for ln in open(os.path.join(SH, "all_gates.tsv")):
        c = ln.rstrip("\n").split("\t")
        if c[0] == "GATE" and len(c) > 9 and isfield(c[2]) and rec(c[3]):
            hasnz = any(isconc(x) and x not in ("0", "0x0") for x in c[4].split(","))
            gates[(c[2], c[3])].append((set(c[9].split(",")), hasnz))

    dist = collections.Counter()
    for key in set(writers) & set(gates):
        dist[tier(writers[key], gates[key])] += 1
    tot = sum(dist.values())
    print(f"# precondition-KIND taxonomy over {tot} coupled (field,S) keys")
    print("#   A=verifiable static handshake | B=decidable structural | C=value-dependent | D=ambiguous")
    for k, n in sorted(dist.items()):
        print(f"  {n:5} ({100*n//tot:2}%)  {k}")
    A = sum(v for k, v in dist.items() if k.startswith("A"))
    B = sum(v for k, v in dist.items() if k.startswith("B"))
    print(f"\n# SPECIALIZED today (value-protocol c_P=1.0): {A} ({100*A//tot}%)")
    print(f"# DECIDABLE but in the fuzzy bucket (tier B):  {B} ({100*B//tot}%)  <- the recall gap")


if __name__ == "__main__":
    main()

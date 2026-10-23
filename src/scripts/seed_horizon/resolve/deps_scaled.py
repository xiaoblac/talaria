#!/usr/bin/env python3
"""Scaled variant-level state-dependency edges.

For each bound variant: resolve its cmd -> the (bound or delegated) dispatcher whose cmd-region dispatches it,
attribute that region's facts + the anchor-bounded CALL-closure (each fact keeps its OWN local terminal anchor),
then join across variants (value-compat scalar def-use + membership), fd-scoped by the syzkaller fd resource.
Produces the ACTUAL directed-edge yield (the real 'fires' denominator) + an edge sample for precision.
"""
import sys, collections, glob
sys.path.insert(0, "scripts/seed_horizon")
from model.variant import load_variant_consts, cmd_discriminant

DF = "run/seed_horizon/deps_facts"
CLOSURE_DEPTH = 4
INFRA_FRAC = 0.5          # fd anchor WRITTEN by > this frac of a fd-type's variants = infra -> drop (per fd-type)
INFRA_GLOBAL = 0.05       # global scalar WRITTEN by > this frac of ALL variants = infra (lock/panic/owner) -> drop

# common infrastructure the closure must NOT descend into (allocators/locking/printk/rcu/mm/sched): every handler
# reaches these, so their struct/global anchors (task_struct/page/slab/rw_semaphore/@lock/@panic) are shared
# terminals that the anchor-bounded discipline can't filter -> they must be excluded at the closure, not the anchor.
INFRA_FN = ("kmalloc", "kfree", "kmem_cache", "kvmalloc", "kvfree", "vmalloc", "vfree", "__alloc", "slab", "slub",
            "_raw_spin", "spin_lock", "spin_unlock", "spin_trylock", "mutex_lock", "mutex_unlock", "down_", "up_",
            "rwsem", "printk", "vprintk", "rcu_", "call_rcu", "synchronize_rcu", "refcount_", "kref_", "get_page",
            "put_page", "free_page", "alloc_page", "__page", "folio_", "sched_", "schedule", "kobject_", "__wake",
            "wake_up", "prepare_to_wait", "finish_wait", "cond_resched", "msleep", "__asan", "__sanitizer",
            "memset", "memcpy", "memmove", "warn_", "panic", "dump_stack", "capable", "current_", "fault_in",
            "might_", "__check", "lock_acquire", "lock_release", "__lock", "preempt_")
def is_infra_fn(fn):
    return any(x in fn for x in INFRA_FN)

def regint(s):
    try: return int(s) & 0xFFFFFFFF
    except ValueError: return None

def numvals(s):
    out = set()
    for x in s.split(","):
        try: out.add(int(x, 0) & 0xFFFFFFFF)
        except ValueError: pass
    return out

def stype(a):
    return a.split("+", 1)[0] if a.startswith("struct.") else None

# HEURISTIC stopgap for the §11.1 residue: per-op / iterator / request-scoped structs type-match across cmds
# (each case allocates its OWN instance) -> false cross-syscall edges.  The clean fix needs object-lifetime
# analysis (freed-within-cmd vs persists), which is the §11.1 wall; this name filter captures the dominant classes.
TRANSIENT = ("path", "trans_handle", "xa_state", "struct.request+", "blk_mq", "struct.bio+", "struct.page+",
             "folio", "kiocb", "iov_iter", "msghdr", "_control+", "dir_context", "extent_state", "delayed_ref",
             "btrfs_key", "btrfs_ordered", "readahead", "scan_control", "_iter+", "_batch+", "reclaim_state")
def transient(a):
    return not a.startswith("@") and any(t in a for t in TRANSIENT)

# infra state (boot/entropy/refcount/seqlock) written once + read everywhere: the writer-count filter misses it
# (few writers), so name it out.
INFRA_ANCHOR = ("system_state", "crng", "pool_offset", "jiffies", "random", "refcount_struct", "kref", "seqcount",
                "@boot", "static_key", "reserved", "@init_", "@runtime")
def infra(a):
    return any(x in a for x in INFRA_ANCHOR)

def load_facts():
    facts = collections.defaultdict(list)      # fn -> [(regionInt|None, kind, anchor, valstr, S)]
    rcalls = collections.defaultdict(set)      # (fn, regionInt) -> callees
    fwd = collections.defaultdict(set)         # fn -> callees
    fn_cmds = collections.defaultdict(set)     # fn -> {regionInt}
    fdobj = set()                              # struct types the dispatcher touches IN a cmd-region = fd-objects
    for path in glob.glob(DF + "/*.tsv"):
        cur = None
        for ln in open(path):
            p = ln.rstrip("\n").split("\t"); t = p[0]
            if t == "RBB":
                cur = regint(p[2]) if len(p) > 2 else None
                if cur is not None: fn_cmds[p[1]].add(cur)
            elif t == "WRITE" and len(p) >= 4:
                facts[p[1]].append((cur, "W", p[2], p[3], p[4] if len(p) > 4 else ""))
                if cur is not None and stype(p[2]): fdobj.add(stype(p[2]))
            elif t == "BRANCHUSE" and len(p) >= 4:
                facts[p[1]].append((cur, "G", p[2], p[3], ""))
                if cur is not None and stype(p[2]): fdobj.add(stype(p[2]))
            elif t == "BRANCHREL" and len(p) >= 5:
                facts[p[1]].append((cur, "G", p[2], p[4], ""))
                if cur is not None and stype(p[2]): fdobj.add(stype(p[2]))
            elif t == "CONTAINER" and len(p) >= 4:   facts[p[1]].append((cur, p[2], p[3], "", ""))  # p[2]=INS|LKP
            elif t == "CALL" and len(p) >= 3:
                fwd[p[1]].add(p[2])
                if cur is not None: rcalls[(p[1], cur)].add(p[2])
    return facts, rcalls, fwd, fn_cmds, fdobj

def main():
    facts, rcalls, fwd, fn_cmds, fdobj = load_facts()
    dispatchers = collections.defaultdict(set)
    for fn, cvs in fn_cmds.items():
        for cv in cvs: dispatchers[cv].add(fn)

    def closure(start):
        seen = set(); frontier = set(x for x in start if not is_infra_fn(x))
        for _ in range(CLOSURE_DEPTH):
            nxt = set()
            for g in frontier:
                if g in seen: continue
                seen.add(g)
                for c in fwd.get(g, ()):
                    if not is_infra_fn(c): nxt.add(c)     # bound to subsystem: never descend into infra
            frontier = nxt - seen
            if not frontier: break
        return seen

    def find_dispatcher(F, CV):
        if CV in fn_cmds.get(F, ()): return F, "inline"
        tgt = dispatchers.get(CV, ())
        if not tgt: return None, None
        seen = {F}; frontier = {F}
        for _ in range(3):                             # delegation is shallow (X_ioctl -> X_handler)
            nxt = set()
            for f in frontier:
                for c in fwd.get(f, ()):
                    if c in tgt: return c, "delegation"
                    if c not in seen and len(seen) < 400: seen.add(c); nxt.add(c)
            frontier = nxt
        return None, None

    def attribute(D, CV):
        W = collections.defaultdict(set); G = collections.defaultdict(set); INS = set(); LKP = set()
        def add(kind, anchor, val, S):
            if anchor.startswith("?"): return
            if kind == "W":
                if not (S.startswith("arg:") or S.startswith("@")): return  # persistent object identity only
                v = regint(val)
                if v is not None: W[anchor].add(v)
            elif kind == "G": G[anchor] |= numvals(val)
            elif kind == "INS": INS.add(anchor)
            elif kind == "LKP": LKP.add(anchor)
        for (region, kind, anchor, val, S) in facts.get(D, ()):
            if region == CV: add(kind, anchor, val, S)              # inline (dispatcher's own cmd-region)
        for g in closure(rcalls.get((D, CV), set())):              # sunk (anchor-bounded closure)
            for (region, kind, anchor, val, S) in facts.get(g, ()):
                add(kind, anchor, val, S)
        return W, G, INS, LKP

    vc = load_variant_consts()
    h = None; rows = []
    for ln in open("run/seed_horizon/candidate_trace.tsv"):
        if ln.startswith("#"):
            if h is None: h = ln.lstrip("#").rstrip().split("\t")
            continue
        rows.append(dict(zip(h, ln.rstrip("\n").split("\t"))))
    bound = [r for r in rows if r.get("fail_stage") == "candidate" and r.get("final")]

    node = {}; census = collections.Counter()
    for r in bound:
        v = r["variant"]; F = (r["final"].split(",")[0]).strip(); base = v.split("$")[0]
        CV = cmd_discriminant(v, base, vc)
        if CV is None: census["no-cmd-value(genl/plain/auto->other model)"] += 1; continue
        CV &= 0xFFFFFFFF
        D, shape = find_dispatcher(F, CV)
        if D is None: census["blob(no dispatcher for cmd)"] += 1; continue
        census["attributable:" + shape] += 1
        W, G, INS, LKP = attribute(D, CV)
        node[v] = (W, G, INS, LKP, r.get("ctx_res", ""), shape)
    print("=== census (denominator): " + "  ".join(f"{k}={v}" for k, v in census.most_common()) + f"  | total={len(bound)} ===")

    # anchor-indexed join
    WA = collections.defaultdict(dict); GA = collections.defaultdict(dict)
    INSA = collections.defaultdict(set); LKPA = collections.defaultdict(set)
    ftof = {}; shapeof = {}
    for v, (W, G, INS, LKP, ft, shape) in node.items():
        ftof[v] = ft; shapeof[v] = shape
        for a, vals in W.items(): WA[a][v] = vals
        for a, vals in G.items(): GA[a][v] = vals
        for a in INS: INSA[a].add(v)
        for a in LKP: LKPA[a].add(v)

    # infra filter: fd anchor written by > INFRA_FRAC of an fd-type's variants = infra (per fd-type)
    ftpop = collections.Counter(ftof.values())
    dropped = set()
    for a in list(WA):
        if a.startswith("@"):
            if len(WA[a]) > INFRA_GLOBAL * len(node):          # global written by too many variants = infra
                dropped.add((a, "*"))
        else:
            byft = collections.Counter(ftof.get(v) for v in WA[a])
            for ft, n in byft.items():
                if ft and ftpop[ft] and n > INFRA_FRAC * ftpop[ft]:
                    dropped.add((a, ft))
    def kept(a, v):
        return ((a, "*") if a.startswith("@") else (a, ftof.get(v))) not in dropped

    scope = lambda a: "global" if a.startswith("@") else "fd"
    edges = []
    for a in set(WA) & set(GA):
        if infra(a):
            continue   # boot/entropy/refcount/seqlock infra state
        if scope(a) == "fd" and (transient(a) or stype(a) not in fdobj):
            continue   # persistent object identity: dispatcher-touched fd-object struct, minus per-op transients
        for va, wv in WA[a].items():
            for vb, gv in GA[a].items():
                if va == vb: continue
                if not kept(a, va): continue
                if scope(a) == "fd" and ftof.get(va) != ftof.get(vb): continue
                if wv & gv:
                    edges.append((va, vb, a, "scalar", scope(a), tuple(sorted(wv & gv))))
    for a in set(INSA) & set(LKPA):
        for va in INSA[a]:
            for vb in LKPA[a]:
                if va == vb: continue
                if scope(a) == "fd" and ftof.get(va) != ftof.get(vb): continue
                edges.append((va, vb, a, "member", scope(a), ()))

    producers = set(e[0] for e in edges) | set(e[1] for e in edges)
    attributed = collections.Counter(shapeof.values())
    firing = collections.Counter(shapeof[v] for v in node if v in producers)
    print(f"=== SCALED edge-join: attributed variants={len(node)}  edges={len(edges)} "
          f"(scalar={sum(1 for e in edges if e[3]=='scalar')}, member={sum(1 for e in edges if e[3]=='member')}) ===")
    for s in ("inline", "delegation"):
        att = attributed[s]; fir = firing[s]
        print(f"  {s:11}: attributed {att:5}  produce-edge {fir:5}  ({100*fir//att if att else 0}%)")
    tot_att = len(node); tot_fir = len(set(v for v in node if v in producers))
    print(f"  TOTAL     : attributed {tot_att:5}  produce-edge {tot_fir:5}  ({100*tot_fir//tot_att if tot_att else 0}%)")
    loope = [e for e in edges if "loop_device+192" in e[2]]
    print(f"  [validate] loop lo_state edges: {len(loope)}  e.g. " +
          "; ".join(f"{e[0].split('$')[-1]}->{e[1].split('$')[-1]}" for e in loope[:4]))
    import os
    outp = os.path.join(os.path.dirname(__file__), "..", "..", "..", "run", "seed_horizon", "dep_edges.tsv")
    with open(outp, "w") as o:
        o.write("#V_A\tV_B\tanchor\tmech\tscope\tvalue\n")
        for e in sorted(edges):
            o.write(f"{e[0]}\t{e[1]}\t{e[2]}\t{e[3]}\t{e[4]}\t{','.join(map(str,e[5]))}\n")
    print(f"  wrote {len(edges)} edges -> run/seed_horizon/dep_edges.tsv")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""v1a: cmd-level state-dependency edges from recognizer facts (anchor x payload).

Consumes a single-batch default-mode ir_defuse extraction (stream order, with per-BB RBB cmd-region markers):
    RBB   <fn> <region>              # region of the facts that follow: <cmdval> | common | ? | -
    WRITE <fn> <anchor> <val> <S> [<srcfield>]
    BRANCHUSE <fn> <loc> <vals>      # gate: branch condition reads <loc> vs constants <vals>
    BRANCHREL <fn> <loc> <pred> <val>
    CONTAINER <fn> <INS|LKP> <anchor>
    CALL  <fn> <callee> direct

A "cmd" node = (dispatcher_fn, cmdval).  Attribution of a fact to a cmd:
  - INLINE  (in the dispatcher): tagged by RBB region == cmdval  (region mode); any region (fn mode).
  - SUNK    (in a called sub-fn): reached by ANCHOR-BOUNDED CALL-closure from the cmd's region-tagged calls;
            the sunk write keeps its OWN local terminal anchor (loop_configure's `lo->lo_state` -> loop_device+192),
            and the join only fires on anchor match -- so blk_mq_init's request_queue writes never couple to a
            loop_device gate (discipline #1: anchor-bounded, not depth-bounded).

Edge A -> B on anchor iff A writes a value V that B's gate tests for (V in gate-values) -- A produces the value
that lets B proceed (value-compat).  scope = fd (struct.X) | global (@g).  fd-scoped anchors are filtered by
handler-internal cmd-count (discipline #2: a field touched by most cmds = infra, dropped).

  --mode fn      before: fn-level attribution -> every cmd of D gets D's whole fact set -> complete bipartite blob
  --mode region  after:  cmd-region attribution -> directed {producers} -> {consumers}
"""
import sys, argparse, collections, os

CLOSURE_DEPTH = int(os.environ.get("DEPTH", "4"))
INFRA_CMD_FRAC = float(os.environ.get("FRAC", "0.6"))   # fd anchor WRITTEN by > this frac of a dispatcher's cmds = infra

def numvals(s):
    out = set()
    for x in s.split(","):
        x = x.strip()
        try: out.add(int(x, 0) & 0xFFFFFFFF)
        except ValueError: pass
    return out

def load(path):
    writes, gates, calls, conts = [], [], [], []
    cur = "-"
    for ln in open(path):
        f = ln.rstrip("\n").split("\t")
        t = f[0]
        if t == "RBB":
            cur = f[2] if len(f) > 2 else "-"
        elif t == "WRITE" and len(f) >= 4:
            writes.append((f[1], cur, f[2], f[3]))                 # fn, region, anchor, val
        elif t == "BRANCHUSE" and len(f) >= 4:
            gates.append((f[1], cur, f[2], numvals(f[3])))         # fn, region, loc, {vals}
        elif t == "BRANCHREL" and len(f) >= 5:
            gates.append((f[1], cur, f[2], numvals(f[4])))
        elif t == "CALL" and len(f) >= 3:
            calls.append((f[1], cur, f[2]))                        # fn, region, callee
        elif t == "CONTAINER" and len(f) >= 4:
            conts.append((f[1], cur, f[2], f[3]))                  # fn, region, op, anchor
    return writes, gates, calls, conts

def is_cmd(r): return r not in ("-", "common", "?", "")

def scope_of(anchor): return "global" if anchor.startswith("@") else "fd"

def build(writes, gates, calls, conts, mode):
    callgraph = collections.defaultdict(set)          # fn -> {callee}   (closure)
    cmd_calls = collections.defaultdict(set)          # (fn, cmd) -> {callee}  (cmd entry points)
    for fn, region, callee in calls:
        callgraph[fn].add(callee)
        if is_cmd(region): cmd_calls[(fn, region)].add(callee)

    writes_by_fn = collections.defaultdict(list)
    for fn, region, anchor, val in writes: writes_by_fn[fn].append((region, anchor, val))
    gates_by_fn = collections.defaultdict(list)
    for fn, region, loc, vals in gates: gates_by_fn[fn].append((region, loc, vals))
    conts_by_fn = collections.defaultdict(list)
    for fn, region, op, anchor in conts: conts_by_fn[fn].append((region, op, anchor))

    dispatchers = collections.defaultdict(set)        # fn -> {cmd}
    for lst in (writes, gates, calls, conts):
        for row in lst:
            if is_cmd(row[1]): dispatchers[row[0]].add(row[1])

    def closure(start):
        seen, frontier = set(), set(start)
        for _ in range(CLOSURE_DEPTH):
            nxt = set()
            for g in frontier:
                if g in seen: continue
                seen.add(g); nxt |= callgraph.get(g, set())
            frontier = nxt - seen
            if not frontier: break
        return seen

    # per anchor: writers[anchor][cmdkey] = {vals}, gaters[anchor][cmdkey] = {vals}, membership INS/LKP sets
    W = collections.defaultdict(lambda: collections.defaultdict(set))
    G = collections.defaultdict(lambda: collections.defaultdict(set))
    INS = collections.defaultdict(set); LKP = collections.defaultdict(set)

    for D, cmds in dispatchers.items():
        for C in cmds:
            key = (D, C)
            sunk = closure(callgraph[D] if mode == "fn" else cmd_calls.get((D, C), set()))
            # inline (dispatcher's own BBs)
            for (region, anchor, val) in writes_by_fn[D]:
                if mode == "fn" or region == C:
                    try: W[anchor][key].add(int(val, 0) & 0xFFFFFFFF)
                    except ValueError: pass
            for (region, loc, vals) in gates_by_fn[D]:
                if mode == "fn" or region == C:
                    G[loc][key] |= vals
            for (region, op, anchor) in conts_by_fn[D]:
                if mode == "fn" or region == C:
                    (INS if op == "INS" else LKP)[anchor].add(key)
            # sunk (called sub-fns keep their own local anchor)
            for g in sunk:
                for (region, anchor, val) in writes_by_fn[g]:
                    try: W[anchor][key].add(int(val, 0) & 0xFFFFFFFF)
                    except ValueError: pass
                for (region, loc, vals) in gates_by_fn[g]:
                    G[loc][key] |= vals
                for (region, op, anchor) in conts_by_fn[g]:
                    (INS if op == "INS" else LKP)[anchor].add(key)

    # fn-node shape (table dispatch, the clean 16%): each entry-handler fn -- a "root" reached only via an
    # indirect dispatch table (no incoming direct CALL) and NOT an inline-switch dispatcher -- is one node.  The
    # closure collects its reachable payload with each fact's own local anchor (GEM: i915_gem_create_ioctl reaches
    # the INS in drm_gem_handle_create_tail -> a producer on drm_file+136).  No cmd-region needed; same in both modes.
    called = set(callee for _, _, callee in calls)
    allfns = (set(w[0] for w in writes) | set(g[0] for g in gates)
              | set(c[0] for c in calls) | set(c[0] for c in conts))
    for F in (allfns - set(dispatchers) - called):
        key = (F, "fn")
        for g in (closure(callgraph.get(F, set())) | {F}):
            for (region, anchor, val) in writes_by_fn[g]:
                try: W[anchor][key].add(int(val, 0) & 0xFFFFFFFF)
                except ValueError: pass
            for (region, loc, vals) in gates_by_fn[g]:
                G[loc][key] |= vals
            for (region, op, anchor) in conts_by_fn[g]:
                (INS if op == "INS" else LKP)[anchor].add(key)

    # discipline #2 (region mode only; fn mode keeps the raw blob for the before/after contrast):
    # drop fd anchors WRITTEN by > INFRA_CMD_FRAC of a dispatcher's cmds = infra.  Counts WRITERS, not gaters:
    # lo_state is READ by many cmds (all check "bound") but WRITTEN by few (SET_FD/CONFIGURE/CLR_FD) -> healthy;
    # a lock/refcount is written (acquired) by every cmd -> infra.
    dropped = set()   # (anchor, dispatcher) infra pairs -- per-DISPATCHER, not global: a field over-written
    if mode == "region":                                        # in handler X must not kill the anchor for Y
        for anchor in list(W):
            if scope_of(anchor) != "fd": continue
            touch = collections.Counter()
            for key in W[anchor]:
                touch[key[0]] += 1
            for D, n in touch.items():
                if dispatchers[D] and n > INFRA_CMD_FRAC * len(dispatchers[D]):
                    dropped.add((anchor, D))
        for (anchor, D) in dropped:
            for tbl in (W, G):
                for key in [k for k in list(tbl.get(anchor, {})) if k[0] == D]:
                    tbl[anchor].pop(key, None)

    # scalar def-use edges: A writes V, B gates for V (value-compat)
    edges = set()
    for anchor in set(W) & set(G):
        for a, wv in W[anchor].items():
            for b, gv in G[anchor].items():
                if a == b: continue
                if scope_of(anchor) == "fd" and a[0] != b[0]:
                    continue   # fd-scoped scalar def-use: same handler (= same fd type/instance-scope)
                if wv & gv:
                    edges.add((a, b, anchor, "scalar", scope_of(anchor), tuple(sorted(wv & gv))))
    # membership edges: A inserts container, B looks it up
    for anchor in set(INS) & set(LKP):
        for a in INS[anchor]:
            for b in LKP[anchor]:
                if a == b: continue
                edges.add((a, b, anchor, "member", scope_of(anchor), ()))
    return edges, dropped

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input")
    ap.add_argument("--triple", action="store_true", help="run the loop CONFIGURE/CLR_FD -> CHANGE_FD acceptance")
    args = ap.parse_args()
    facts = load(args.input)
    res = {m: build(*facts, m) for m in ("fn", "region")}
    for m in ("fn", "region"):
        edges, dropped = res[m]
        print(f"[{m:6}] edges={len(edges)}  (scalar={sum(1 for e in edges if e[3]=='scalar')}, "
              f"member={sum(1 for e in edges if e[3]=='member')})  infra-anchors-dropped={len(dropped)}")

    if args.triple:
        LO = "lo_ioctl"
        CONFIGURE, CLR_FD, CHANGE_FD = "19466", "19457", "19462"
        A_pos, A_neg, B = (LO, CONFIGURE), (LO, CLR_FD), (LO, CHANGE_FD)
        ANCHOR = "struct.loop_device+192"
        def has(mode, a, b):
            return any(e[0] == a and e[1] == b and e[2] == ANCHOR and e[3] == "scalar" for e in res[mode][0])
        print("\n=== ACCEPTANCE TRIPLE (loop lo_state = loop_device+192) ===")
        pos_r = has("region", A_pos, B); neg_r = has("region", A_neg, B)
        pos_f = has("fn", A_pos, B);     neg_f = has("fn", A_neg, B)
        nb = sum(1 for e in res["fn"][0] if e[2] == ANCHOR and e[3] == "scalar")
        na = sum(1 for e in res["region"][0] if e[2] == ANCHOR and e[3] == "scalar")
        print(f"  before (fn-level, blob):  CONFIGURE->CHANGE_FD={pos_f}  CLR_FD->CHANGE_FD={neg_f}  "
              f"(both true = complete bipartite; {nb} undirected edges on lo_state)")
        print(f"  after  (cmd-region):      CONFIGURE->CHANGE_FD={pos_r}  CLR_FD->CHANGE_FD={neg_r}  "
              f"({na} directed producer->consumer edges on lo_state)")
        ok = pos_r and (not neg_r)
        print(f"  POSITIVE must appear: {'PASS' if pos_r else 'FAIL (CALL-closure did not sink into loop_configure)'}")
        print(f"  NEGATIVE must be gone: {'PASS' if not neg_r else 'FAIL (value-compat leaked: 2 matched gate 1)'}")
        print(f"  TRIPLE: {'ALL GREEN' if ok else 'NOT GREEN'}")
        # show the actual lo_state edges in region mode for audit
        print("  --- region-mode edges on loop_device+192 (producer -> consumer, on value) ---")
        for e in sorted(res["region"][0]):
            if e[2] == ANCHOR and e[3] == "scalar":
                print(f"      {e[0][1]} -> {e[1][1]}   val={e[5]}")

if __name__ == "__main__":
    main()

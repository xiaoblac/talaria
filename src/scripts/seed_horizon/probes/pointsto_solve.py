#!/usr/bin/env python3
# Copyright 2026 reFuzz project author -------youngkk.
#
# Batch-scoped driver + validation for the Step 4 general points-to Fixpoint (resolve/pointsto_fixpoint.py).
#
# It loads ONE linked batch's four constraint tables (streamed + batch-filtered so the multi-GB full tables
# never enter memory), runs the side-by-side solver, writes the Step-4 output tuples/stats/derivations, and
# checks three worked examples the plan calls out:
#
#   (a) tun_fops + 80  -> tun_chr_ioctl        (ADDR_OF + STORE_OBJECT into a field cell)
#   (b) container_of negative offset            (signed field-offset algebra returns to the parent object)
#   (c) an indirect call                        (points-to of a function pointer -> CallTarget -> arg flow)
#
# Nothing here consults struct-type whitelists, handler names, resource names, or variant suffixes; the
# solver decides purely from object identity + byte offsets. The existing candidate resolver is untouched.
import argparse
import io
import json
import os
from pathlib import Path
import sys
import tokenize

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from resolve.pointsto_fixpoint import (  # noqa: E402
    DYN, Constraints, Policy, Solver, load_constraints, load_seeds, render_obj)

DEFAULT_SH = "run/seed_horizon"
DEFAULT_BATCH = "drivers__net__built-in.000"


def render_node(node):
    return node if isinstance(node, str) else "MEM:" + render_obj(node)


def find_object(constraints, suffix):
    """Return the single object id ending with `suffix` (e.g. ':global:tun_fops'), or None."""
    hit = [oid for oid in constraints.obj_size if oid.endswith(suffix)]
    return hit[0] if len(hit) == 1 else (hit[0] if hit else None)


# ----- output writers -------------------------------------------------------------------------------------

def write_points_to(path, solver):
    rows = []
    for node, objs in solver.pt.items():
        if isinstance(node, str):
            for o in objs:
                rows.append((node, render_obj(o)))
    rows.sort()
    with open(path, "w") as out:
        out.write("#value\tobject\n")
        for value, obj in rows:
            out.write(f"{value}\t{obj}\n")
    return len(rows)


def write_memory_points_to(path, solver):
    rows = []
    for node, objs in solver.pt.items():
        if not isinstance(node, str):
            for o in objs:
                rows.append((render_obj(node), render_obj(o)))
    rows.sort()
    with open(path, "w") as out:
        out.write("#object\ttarget\n")
        for obj, target in rows:
            out.write(f"{obj}\t{target}\n")
    return len(rows)


def write_call_targets(path, solver):
    rows = sorted(solver.calltargets)
    with open(path, "w") as out:
        out.write("#callsite\tfunction\tkind\n")
        for callsite, fname, kind in rows:
            out.write(f"{callsite}\t{fname}\t{kind}\n")
    return len(rows)


def write_derivations(path, solver, targets):
    """Write the full predecessor chain for a bounded, named set of tuples (the validation targets plus one
    representative reason per indirect call target). Labeled as representative -- provenance first-writer is
    not canonicalized across hash seeds."""
    with open(path, "w") as out:
        out.write("#target\tstep\trule\tnode\tobject\tconstraint_id\n")
        for label, node, obj in targets:
            chain = solver.derivation_chain(node, obj)
            if not chain:
                out.write(f"{label}\t-\tNO_DERIVATION\t{render_node(node)}\t{render_obj(obj)}\t-\n")
            for i, (rule, cnode, cobj, cid) in enumerate(chain):
                out.write(f"{label}\t{i}\t{rule}\t{render_node(cnode)}\t{render_obj(cobj)}\t{cid or '-'}\n")


# ----- validations ----------------------------------------------------------------------------------------

def validate_store_object(constraints, solver, report):
    """(a) mempt[(tun_fops, 80)] must contain the tun_chr_ioctl function object."""
    root = find_object(constraints, ":global:tun_fops")
    ioctl = find_object(constraints, ":function:tun_chr_ioctl")
    if not root or not ioctl:
        report.append(("store_object(tun_fops+80)", "SKIP", "tun_fops/tun_chr_ioctl not in this batch"))
        return None
    cell = solver._mk_field((root, 0), 80)
    targets = solver.pt.get(cell, set())
    ok = (ioctl, 0) in targets
    detail = (f"MemPt({render_obj(cell)}) = "
              f"{sorted(render_obj(o) for o in targets) if len(targets) <= 6 else str(len(targets)) + ' targets'}")
    report.append(("store_object(tun_fops+80)", "PASS" if ok else "FAIL", detail))
    return ("store_object(tun_fops+80->tun_chr_ioctl)", cell, (ioctl, 0)) if ok else None


def validate_container_of(constraints, solver, report):
    """(b) A negative constant FIELD_ADDR keeps the root and subtracts the offset. Show both the algebra
    (tun_fops+80 then -80 returns to base) and, if present, a real resolved negative-GEP instance."""
    root = find_object(constraints, ":global:tun_fops")
    algebra_ok = False
    if root:
        forward = solver._mk_field((root, 0), 80)
        back = solver._mk_field(forward, -80)
        algebra_ok = (back == (root, 0))
        report.append(("negative-offset algebra", "PASS" if algebra_ok else "FAIL",
                       f"{render_obj((root, 0))} +80 -> {render_obj(forward)} -80 -> {render_obj(back)}"))

    # Prefer a real negative GEP that resolves on a NAMED (global/stack/function) root, not an opaque
    # unknown site, so the demonstration is a genuine container_of-style adjustment.
    chosen = None
    fallback = None
    for dst, src, k, _cid in constraints.field:
        if k >= 0:
            continue
        for (r, off) in solver.pt.get(src, ()):
            if off is DYN:
                continue
            res = solver._mk_field((r, off), k)
            if res[1] is DYN or res[0] != r or res not in solver.pt.get(dst, ()):
                continue
            cand = (dst, src, k, r, off, res)
            if ":object:unknown:" not in r:
                chosen = cand
                break
            fallback = fallback or cand
        if chosen:
            break
    chosen = chosen or fallback
    if chosen:
        dst, src, k, r, off, res = chosen
        report.append(("negative-offset data instance", "PASS",
                       f"gep {k}: {render_obj((r, off))} -> {render_obj(res)} (root preserved)"))
        return ("container_of(neg-offset)", dst, res)
    report.append(("negative-offset data instance", "INFO",
                   "no in-batch negative GEP had a resolved base (formals lack in-batch callers); "
                   "algebra above proves the signed arithmetic"))
    return None


def validate_indirect_call(constraints, solver, report):
    """(c) At least one indirect callsite resolves to a function and wires actual->formal. Show the callee
    value's resolved functions and one argument that flowed into the callee's formal."""
    indirect = [(cs, fn) for (cs, fn, kind) in solver.calltargets if kind == "indirect"]
    if not indirect:
        report.append(("indirect call", "INFO", "no indirect callsite resolved to an in-batch function"))
        return None
    # Prefer a callsite that also demonstrates argument flow.
    callee_val = {cs: v for cs, v in constraints.indirect}
    best = None
    for cs, fn in indirect:
        formals = constraints.formals.get(fn, {})
        actuals = constraints.actuals.get(cs, {})
        flow = None
        for idx, actual in actuals.items():
            formal = formals.get(idx)
            if formal is not None and solver.pt.get(actual) and \
                    solver.pt.get(actual, set()) <= solver.pt.get(formal, set()):
                flow = (idx, actual, formal)
                break
        if flow:
            best = (cs, fn, flow)
            break
        if best is None:
            best = (cs, fn, None)
    cs, fn, flow = best
    cv = callee_val.get(cs, "-")
    funcs = sorted(constraints.func_name[o[0]] for o in solver.pt.get(cv, ())
                   if o[1] == 0 and o[0] in constraints.func_name)
    report.append(("indirect call target", "PASS",
                   f"callsite {cs} via {cv}: targets={funcs[:8]}"
                   f"{'...' if len(funcs) > 8 else ''}"))
    if flow:
        idx, actual, formal = flow
        report.append(("indirect call arg-flow", "PASS",
                       f"arg#{idx} {actual} -> formal {formal}: "
                       f"Pt(actual) ⊆ Pt(formal) ({len(solver.pt.get(formal, ()))} objs)"))
    else:
        report.append(("indirect call arg-flow", "INFO",
                       "resolved target has no pointer-typed argument flow to demonstrate"))
    # derivation target: why the callee pointer `cv` points at a concrete function object
    deriv_obj = next((o for o in solver.pt.get(cv, ())
                      if o[1] == 0 and o[0] in constraints.func_name), None)
    return ("indirect_call_target", cv, deriv_obj) if deriv_obj else None


def validate_seed_chain(constraints, solver, report):
    """Consume-the-seeds acceptance (plan 3.5): from a syz root, walk the four-edge composition over the
    closure -- ObjectId -> Install(dispatch object) -> Dispatch(op) -> handler -- and show a real multi-layer
    object/field/call chain. Prefer fd_tun (same batch as the tun sample); else any seeded root that reaches
    a handler."""
    if solver.seeds is None or not solver.install_edges:
        report.append(("seed consumption", "SKIP", "no in-scope registration seeds for this batch"))
        return None

    roots = sorted({e[0] for e in solver.install_edges})
    preferred = [r for r in roots if r == "fd_tun"] or [r for r in roots if "tun" in r]
    ordered = preferred + [r for r in roots if r not in preferred]
    chosen = None
    for root_id in ordered:
        disp = solver.root_dispatch_objects(root_id)
        handlers = {d: solver.dispatch_handlers(d) for d in disp}
        if any(handlers[d] for d in disp):
            chosen = (root_id, disp, handlers)
            break
    if not chosen:
        report.append(("seed consumption", "INFO",
                       f"{len(roots)} roots seeded but none reached a handler in this batch"))
        return None

    root_id, disp, handlers = chosen
    lines = []
    for d in disp:
        ops = handlers[d]
        named = {op: sorted(h) for op, h in ops.items() if not op.startswith("@")}
        offs = {op: sorted(h) for op, h in ops.items() if op.startswith("@")}
        lines.append(f"{d.split(':')[-1]} field-name{named} byte-offset{offs}")
    report.append(("seed consumption: 4-edge chain", "PASS",
                   f"root {root_id} -> install {[d.split(':')[-1] for d in disp]} -> " + " | ".join(lines)))
    # derivation target: the Install MemPt tuple root_object@0 -> dispatch_object
    root_obj = "seed:object:root:" + root_id
    return ("seed_install(%s)" % root_id, (root_obj, 0), (disp[0], 0)) if disp else None


def write_applied_seeds(path, solver):
    with open(path, "w") as out:
        out.write("#root\troot_object\tdispatch_object\top_key\thandler\tsource\n")
        rows = []
        for root_id, root_obj, disp, _sid in solver.install_edges:
            handlers = solver.dispatch_handlers(disp)
            if not handlers:
                rows.append((root_id, root_obj, disp, "-", "-", "install-only"))
            for op, hs in handlers.items():
                src = "dispatch_field" if not op.startswith("@") else "store_object"
                for h in sorted(hs):
                    rows.append((root_id, root_obj, disp, op, h, src))
        for r in sorted(set(rows)):
            out.write("\t".join(r) + "\n")
    return len(solver.install_edges)


def assert_no_struct_whitelist(engine_path, report):
    """Confirm the engine carries no struct-name whitelist and never keys behavior on the struct_type
    column. Tokenize so only real CODE identifiers are inspected -- comments/docstrings (which legitimately
    say 'never uses a struct whitelist') are excluded."""
    src = Path(engine_path).read_text()
    code_names = set()
    try:
        for tok in tokenize.generate_tokens(io.StringIO(src).readline):
            if tok.type == tokenize.NAME:
                code_names.add(tok.string)
    except tokenize.TokenError:
        pass
    banned = {"_TYPE_UNION_PROVIDER_STRUCTS", "PROVIDER_STRUCTS", "struct_type",
              "whitelist", "WHITELIST"}
    hits = sorted(banned & code_names)
    report.append(("engine has no struct whitelist", "PASS" if not hits else "FAIL",
                   "no struct-name gating in engine code" if not hits
                   else f"banned identifiers in code: {hits}"))


# ----- deterministic self-test ----------------------------------------------------------------------------

def build_selftest():
    """A hand-written constraint set that exercises every transfer function the plan's three samples need,
    with a fixed expected answer (independent of any kernel batch / hash seed):

        &T stored funcA at T+80;  p = &T+80;  f = *p             -> f must resolve to funcA   (table load)
        q = p-80                                                 -> q must return to T@0      (container_of)
        indirect call through f, actual &G, returns &H           -> CallTarget + arg/return flow
    """
    C = Constraints()
    T = "sym:object:global:selftest_table"
    fa = "sym:object:function:selftest_funcA"
    G = "sym:object:global:selftest_arg"
    H = "sym:object:global:selftest_ret"
    C.obj_size.update({T: 4096, fa: 0, G: 8, H: 8})
    C.func_name[fa] = "selftest_funcA"
    vT, vfa, vG, vH = "v:base_T", "v:addr_funcA", "v:addr_G", "v:addr_H"
    p80, f, q = "v:gep_T+80", "v:load_p80", "v:gep_p80-80"
    formal, res, cs = "v:funcA.formal0", "v:cs.result", "cs:indirect"
    C.addr_of = [(vT, T, 0, "s1"), (vfa, fa, 0, "s2"), (vG, G, 0, "s3"), (vH, H, 0, "s4")]
    C.store_object = [(T, 80, vfa, "s5")]                 # T.slot80 = &funcA
    C.field = [(p80, vT, 80, "s6"), (q, p80, -80, "s7")]  # p = &T+80 ; q = p-80
    C.load = [(f, p80, "s8")]                             # f = *p
    C.indirect = [(cs, f)]                                # call through f
    C.actuals[cs] = {0: vG}
    C.results[cs] = res
    C.formals["selftest_funcA"] = {0: formal}
    C.returns["selftest_funcA"] = [vH]
    expect = [
        ("table load  f = *(&T+80) -> funcA", f, (fa, 0)),
        ("container_of (&T+80)-80 -> T@0", q, (T, 0)),
        ("indirect arg  &G -> funcA formal#0", formal, (G, 0)),
        ("indirect return  funcA -> callsite result", res, (H, 0)),
    ]
    return C, fa, cs, expect


def run_selftest():
    C, fa, cs, expect = build_selftest()
    solver = Solver(C, Policy()).solve()
    print("=== engine self-test (synthetic constraints, deterministic) ===")
    failed = 0
    for label, node, obj in expect:
        ok = obj in solver.pt.get(node, set())
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
        failed += not ok
    ct = (cs, "selftest_funcA", "indirect") in solver.calltargets
    print(f"  [{'PASS' if ct else 'FAIL'}] indirect CallTarget wired on-the-fly")
    failed += not ct
    print(f"[selftest] {failed} FAIL")
    return 1 if failed else 0


# ----- main -----------------------------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--sh", default=DEFAULT_SH)
    ap.add_argument("--batch", default=DEFAULT_BATCH,
                    help="linked batch id to solve (comma-separated for several)")
    ap.add_argument("--out", default=None, help="output dir (default <sh>/pointsto/<batch>)")
    ap.add_argument("--unknown", default="opaque", choices=["opaque", "drop"])
    ap.add_argument("--field-dynamic", default="root_dyn", choices=["root_dyn", "drop"])
    ap.add_argument("--no-saturate", action="store_true", help="disable size-based offset saturation")
    ap.add_argument("--max-tuples", type=int, default=None,
                    help="honest safety valve: stop after this many points-to tuples (sets truncated=true)")
    ap.add_argument("--selftest", action="store_true",
                    help="run the deterministic synthetic mechanism check and exit")
    ap.add_argument("--no-seeds", action="store_true",
                    help="do not consume registration_seeds.tsv / api_summaries.tsv")
    args = ap.parse_args()

    if args.selftest:
        return run_selftest()

    batches = set(args.batch.split(","))
    out = Path(args.out) if args.out else Path(args.root) / args.sh / "pointsto" / args.batch
    out.mkdir(parents=True, exist_ok=True)

    policy = Policy(unknown=args.unknown, field_dynamic=args.field_dynamic,
                    saturate_by_size=not args.no_saturate, provenance=True)

    print(f"[load] batches={sorted(batches)} sh={args.sh}")
    constraints = load_constraints(args.sh, batches, args.root)
    print(f"[load] {json.dumps(constraints.summary(), sort_keys=True)}")

    seeds = None
    if not args.no_seeds:
        keep_objs = set(constraints.obj_size)
        keep_funcs = set(constraints.func_name.values())
        seeds = load_seeds(args.sh, keep_objs, keep_funcs, args.root)
        print(f"[seeds] {json.dumps(seeds.summary(), sort_keys=True)}")

    solver = Solver(constraints, policy, seeds).solve(max_tuples=args.max_tuples)
    solver_stats = solver.stats.as_dict()        # snapshot: validation's _mk_field calls bump counters
    if solver_stats["truncated"]:
        print(f"[warn] fixpoint TRUNCATED at {args.max_tuples} tuples (not converged) -- large-batch "
              f"blow-up; see full-run scaling notes")
    print(f"[solve] {json.dumps(solver_stats, sort_keys=True)}")

    # outputs
    n_pt = write_points_to(out / "points_to.tsv", solver)
    n_mem = write_memory_points_to(out / "memory_points_to.tsv", solver)
    n_call = write_call_targets(out / "indirect_call_targets.tsv", solver)

    report = []
    t_store = validate_store_object(constraints, solver, report)
    t_cont = validate_container_of(constraints, solver, report)
    t_ind = validate_indirect_call(constraints, solver, report)
    t_seed = validate_seed_chain(constraints, solver, report)
    assert_no_struct_whitelist(
        os.path.join(args.root, "scripts/seed_horizon/resolve/pointsto_fixpoint.py"), report)

    deriv_targets = [t for t in (t_store, t_cont, t_ind, t_seed) if t]
    write_derivations(out / "fixpoint_derivations.tsv", solver, deriv_targets)
    n_seed = write_applied_seeds(out / "applied_seeds.tsv", solver) if seeds is not None else 0

    stats = {
        "batches": sorted(batches),
        "policy": policy.as_dict(),
        "constraints": constraints.summary(),
        "seeds": seeds.summary() if seeds is not None else None,
        "solver": solver_stats,
        "outputs": {
            "points_to.tsv": n_pt,
            "memory_points_to.tsv": n_mem,
            "indirect_call_targets.tsv": n_call,
            "applied_seeds.tsv": n_seed,
        },
        "validation": [{"check": c, "result": r, "detail": d} for c, r, d in report],
    }
    (out / "fixpoint_stats.json").write_text(json.dumps(stats, indent=2, sort_keys=True) + "\n")

    print("\n=== validation ===")
    failed = 0
    for check, result, detail in report:
        print(f"  [{result:4}] {check}: {detail}")
        if result == "FAIL":
            failed += 1
    print(f"\n[out] wrote {out}/ (points_to={n_pt} memory={n_mem} call_targets={n_call})")
    print(f"[done] {solver.stats.pops} worklist pops, {solver.stats.wall_seconds:.2f}s, "
          f"peak RSS {solver.stats.peak_rss_kb // 1024} MiB, {failed} FAIL")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

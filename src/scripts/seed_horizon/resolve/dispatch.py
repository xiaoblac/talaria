#!/usr/bin/env python3
# Copyright 2026 reFuzz project author -------youngkk.
#
# RECURSIVE dispatch resolver.  The kernel dispatch chain is an arbitrary-depth tree, not a 2-level
# (anchor -> project ops field -> match cmd) pipeline.  The extractor already emits the whole tree:
#   CMD(handler, value, origin, depth)      = dispatcher `origin`'s OWN scoped table  value->handler
#   CMDBRIDGE(origin, from, to, argidx)     = an unconditional call edge  from -> to  (wrapper chain)
#   CMDICALL(origin, from, struct.X+off)    = a field-forward edge: `from` dispatches through obj->X.field,
#                                             resolved by the variant's CONTEXT binding for struct.X
# The flat binder read only ~depth 0-1 and did a 1-hop `origin in allowed` check, so it missed every
# deeper level (DRM driver tables, sockopt level/optname).  This walks the tree instead, scoped by
# origin (so values never collide globally), consuming the variant's discriminants level by level,
# resolving field-forwards through a generalized context, until leaf handlers; uniqueness at the leaf.
import collections
import os
import re

SH = "run/seed_horizon"

# Per-row key transforms. `iocnr` is the existing DRM direction-insensitive key; `mask:N` is emitted when
# the switch/if condition is proven to be a direct `cmd & N`. Untagged sibling rows remain full-value.
_IOC_NR_MASK = 0x3FFFFFFF
_EMPTY = frozenset()

# A/B toggle (REFUZZ_NO_BRIDGE=1 disables CMD_BRIDGE delegation-following) -- lets the 0-perturbation
# check compute the pre-change baseline without editing.  Default: follow.
_FOLLOW_BRIDGES = os.environ.get("REFUZZ_NO_BRIDGE") != "1"

RESOLVER_PASSES = (
    ("scoped_precise", True, False, False),
    ("unscoped_collapse", False, False, False),
    ("field_bridge", False, False, True),
    ("inline_leaf", False, True, False),
)
_PASS_NAMES = {name for name, _resource_rule, _inline_leaf, _field_bridge in RESOLVER_PASSES}
_configured_passes = os.environ.get("REFUZZ_RESOLVER_PASSES", "").strip()
if _configured_passes:
    ENABLED_RESOLVER_PASSES = frozenset(x.strip() for x in _configured_passes.split(",") if x.strip())
    unknown_passes = ENABLED_RESOLVER_PASSES - _PASS_NAMES
    if unknown_passes:
        raise ValueError(f"unknown REFUZZ_RESOLVER_PASSES: {sorted(unknown_passes)}")
else:
    ENABLED_RESOLVER_PASSES = frozenset(_PASS_NAMES)


def _cmd_files(sh):
    p = f"{sh}/kernel_facts_linked/cmd.tsv"
    if os.path.exists(p) and os.path.getsize(p):
        return [p]
    raise FileNotFoundError(f"missing linked kernel fact file: {p}")


def load_dispatch_graph(sh=SH):
    """cmd_by_origin[origin][value] -> {handler}; bridge[from] -> {to}; icall[node] -> {(struct_kind, off)}.
    icall keeps the field OFFSET (the resolver emits demand(X, off) so a provider reads the right field)
    and is attributed to BOTH the immediate `from` AND the `origin` — hid's `from` is a deeper bridge node
    the worklist can't reach, but the `origin` IS the entry it visits, so the demand still fires there."""
    cmd_by_origin = collections.defaultdict(lambda: collections.defaultdict(set))
    cmd_by_depth = collections.defaultdict(
        lambda: collections.defaultdict(lambda: collections.defaultdict(set)))
    masked_cmd_by_origin = collections.defaultdict(
        lambda: collections.defaultdict(
            lambda: collections.defaultdict(lambda: collections.defaultdict(set))))
    bridge = collections.defaultdict(set)
    icall = collections.defaultdict(set)
    # site-level cmd reachability (P1 gate): for a FIELD_ICALL through struct.X+off in fn, at which BBs is
    # the call, and which cmd values reach each BB (case-specific / * unconditional / NOT-default)?
    field_sites = collections.defaultdict(set)     # (fn, X, off, field) -> {bb}
    reach_star = collections.defaultdict(set)      # fn -> {bb reached by every cmd}
    reach_cmd = collections.defaultdict(set)       # (fn, bb) -> {cmd int}  (case-specific)
    reach_not = {}                                 # (fn, bb) -> {case int}  (default: reached by cmd NOT here)
    callback_bridge = collections.defaultdict(set)  # caller -> {callback}  (handler passed to a helper)
    pending_cmd_icalls = []                         # enriched with FIELD_ICALL field identity after parsing
    field_names = collections.defaultdict(set)      # (fn, struct, off) -> {DWARF field name}
    for f in _cmd_files(sh):
        for ln in open(f):
            c = ln.rstrip("\n").split("\t")
            if c[0] == "CMD" and len(c) >= 8:
                origin = c[1]
                kk = ""
                for extra in c[8:]:
                    if extra.startswith("origin="):
                        origin = extra.split("=", 1)[1]
                    elif extra.startswith("key_kind="):
                        kk = extra.split("=", 1)[1]
                try:
                    v = int(c[2]) & 0xFFFFFFFF
                except ValueError:
                    continue
                try:
                    depth = int(c[6][1:]) if c[6].startswith("d") else 0
                except ValueError:
                    depth = 0
                cmd_by_origin[origin][v].add(c[1])   # exact full-value row
                cmd_by_depth[origin][v][depth].add(c[1])
                mask = None
                if kk == "iocnr":
                    mask = _IOC_NR_MASK
                elif kk.startswith("mask:"):
                    try:
                        mask = int(kk.split(":", 1)[1], 0) & 0xFFFFFFFF
                    except ValueError:
                        pass
                if mask is not None:                 # keep transformed rows separate from exact siblings
                    masked_cmd_by_origin[origin][mask][v & mask][depth].add(c[1])
            elif c[0] == "CMDBRIDGE" and len(c) >= 4:
                bridge[c[2]].add(c[3])
            elif c[0] == "CMDICALL" and len(c) >= 4:
                m = re.match(r"(?:struct\.)?(.+?)\+(\d+)$", c[3])
                kind, off = (m.group(1), int(m.group(2))) if m else \
                    (c[3][len("struct."):] if c[3].startswith("struct.") else c[3], -1)
                origin_fact, from_func = c[1], c[2]   # the dispatcher + the physical icall site
                pending_cmd_icalls.append((kind, off, from_func, origin_fact))
            elif c[0] == "FIELD_ICALL" and len(c) >= 3:   # fn -> struct.X+off <field_name> it calls through
                m = re.match(r"(?:struct\.)?(.+?)\+(\d+)$", c[2])
                if m:                                     # sentinel "__field__" + the DWARF field name for the
                    fname = c[3] if len(c) >= 4 else ""   # op-offset ALIGNMENT gate (forward iff name==op_field)
                    if fname:
                        field_names[(c[1], m.group(1), int(m.group(2)))].add(fname)
                    icall[c[1]].add((m.group(1), int(m.group(2)), c[1], "__field__", fname or None))
            elif c[0] == "FIELD_ICALL_SITE" and len(c) >= 5:   # fn bb struct.X+off field
                m = re.match(r"(?:struct\.)?(.+?)\+(\d+)$", c[3])
                if m:
                    field_sites[(c[1], m.group(1), int(m.group(2)), c[4])].add(c[2])
            elif c[0] == "CMD_REACH" and len(c) >= 4:      # fn <cmd|*> bb
                if c[2] == "*":
                    reach_star[c[1]].add(c[3])
                else:
                    try:
                        reach_cmd[(c[1], c[3])].add(int(c[2]) & 0xFFFFFFFF)
                    except ValueError:
                        pass
            elif c[0] == "CMD_REACH_NOT" and len(c) >= 4:  # fn bb C1,C2,... (default: reached by cmd NOT in Ci)
                try:
                    reach_not[(c[1], c[2])] = {int(x) & 0xFFFFFFFF for x in c[3].split(",") if x}
                except ValueError:
                    pass
            elif c[0] == "CALLBACK_BRIDGE" and len(c) >= 4:  # caller helper callback cmd_from cmd_to [kind]
                if (c[6] if len(c) >= 7 else "cmd") == "cmd":   # only SYSCALL cmd dispatch, not event dispatch
                    callback_bridge[c[1]].add(c[3])
    for kind, off, from_func, origin_fact in pending_cmd_icalls:
        names = field_names.get((from_func, kind, off), set())
        fname = next(iter(names)) if len(names) == 1 else None
        site = (kind, off, from_func, origin_fact, fname)
        icall[from_func].add(site)
        icall[origin_fact].add(site)
    return (cmd_by_origin, bridge, icall, (field_sites, reach_star, reach_cmd, reach_not), callback_bridge,
            masked_cmd_by_origin, cmd_by_depth)


def _cmd_reach_kind(D, X, off, fname, value_set, site_reach):
    """cmd+SITE gate: how does the variant's cmd reach a BB where D forwards through struct.X.<fname>?
      'case'    -- a cmd-SPECIFIC case-block dominates a site: the switch routes this exact cmd here, so the
                   forward is a proven dispatch even when the field name is NOT the syscall op (FE_READ_STATUS
                   -> dvb_frontend_ops.read_status; the op-name changes at the dispatch, the cmd is the proof).
      'general' -- only a `*` (unconditional) or default site: the field is called regardless of cmd, so it
                   is a GENERAL forward that still requires op-alignment to follow (sk_prot->ioctl yes;
                   mmu_notifier.invalidate_range_start for an ioctl no).
      None      -- no FIELD_ICALL_SITE / cmd reaches nothing -> no proof (conservative: don't follow)."""
    field_sites, reach_star, reach_cmd, reach_not = site_reach
    sites = field_sites.get((D, X, off, fname))
    if not sites:
        return None
    vs = {v & 0xFFFFFFFF for v in value_set}
    star = reach_star.get(D, ())
    general = False
    for bb in sites:
        if vs & reach_cmd.get((D, bb), _EMPTY):
            return "case"                          # strongest proof -- a specific case dominates this site
        if bb in star:
            general = True
        cases = reach_not.get((D, bb))
        if cases is not None and (vs - cases):
            general = True
    return "general" if general else None


def _operation_field(field):
    return {
        "unlocked_ioctl": "ioctl",
        "compat_ioctl": "ioctl",
        "read_iter": "read",
        "write_iter": "write",
    }.get(field, field)


def _cmd_path_case(origin, value_set, from_func, cmd_roots):
    if cmd_roots is None:
        return False
    for value in value_set:
        roots = cmd_roots.get((origin, value))
        if roots and from_func in roots:
            return True
    return False


def resolve(entry_handlers, op_field, value_set, ctx, graph, cmd_roots=None, max_nodes=4000):
    """Walk the dispatch tree from entry_handlers. PURE — drives the outer batched fixpoint. Two edges:
      (a) table dispatch  cmd_by_origin[D][v]  — value-gated, scoped to D (no global collision)
      (b) field-forward    icall[D] -> ctx[X][op_field]  — obj->X.field, resolved by context
    When (b) hits a struct-kind X with EMPTY ctx[X], the node does NOT silently become a leaf — it emits
    demand(X, off, op_field) so the fixpoint can recover X's context and re-resolve one level deeper next
    round. A node is a LEAF only when it has no table hop and no satisfiable forward. resolve reports ALL
    unmet demands every call (pure); the FIXPOINT owns negative-caching (new-vs-runtime-empty) and
    quiescence — so the final round's demands are exactly the runtime-empty stops (precision provenance).
    CMDBRIDGE edges are NOT followed (dispatcher callee noise).
    Returns (leaves, trace, demands, resolver_pass); demands = {(X, off, op_field)} of unresolved
    field-forwards. resolver_pass names the first enabled pass that produced a non-empty candidate set,
    or "unresolved" when every enabled pass remained empty.

    GENERAL RESOURCE RULE (two-pass): a forwarder's cmd table cmd_by_origin[D] is the UN-scoped collapse
    of D forwarding through obj->X.field across ALL instances of X -- sock_common_getsockopt collapses
    every proto's getsockopt (do_tcp, sctp, pep, ...) keyed by optname value.  Pass 1 resolves through the
    variant's OWN resource context (ctx[X] = the specific proto/fops this fd/sock installs) and DROPS that
    collapse wherever the resource scoped the forward -- so cross-instance handlers (sctp on a TCP socket)
    never enter.  If pass 1 dead-ends with no leaf (the scoped multi-hop path lacks the depth the collapse
    captured, e.g. MRT6 -> ip_mroute_setsockopt three hops down), pass 2 falls back to the collapse so the
    variant is never left unresolved.  Precision when the resource resolves; recall (honest union) when it
    can't."""
    # Ordered passes; the FIRST non-empty result wins, so each pass only ever affects variants the earlier
    # passes left unresolved -> baseline-resolved variants are byte-identical (0 perturbation).
    #   1 scoped-precise         resource context resolves the forward exactly
    #   2 honest collapse        the un-scoped value-union (recall when the scoped path lacked depth)
    #   3 FIELD_ICALL + bridge   the general delegation facts (inet->sk_ioctl->sk_prot->ioctl); ungated
    #                            field-forwards + cmd-carrying call edges -- applied ONLY to still-unresolved
    #   4 inline-leaf            the dispatcher itself IS the handler (coarse last resort)
    leaves, trace, demands = set(), [], set()
    resolver_pass = "unresolved"
    for pass_name, rr, il, fb in RESOLVER_PASSES:
        if pass_name not in ENABLED_RESOLVER_PASSES:
            continue
        leaves, trace, demands = _walk(entry_handlers, op_field, value_set, ctx, graph, cmd_roots, max_nodes,
                                       resource_rule=rr, inline_leaf=il, field_bridge=fb)
        if leaves:
            resolver_pass = pass_name
            break
    return leaves, trace, demands, resolver_pass


def _walk(entry_handlers, op_field, value_set, ctx, graph, cmd_roots, max_nodes, resource_rule, inline_leaf,
          field_bridge):
    cmd_by_origin, bridge, icall, site_reach, callback_bridge, masked_cmd_by_origin, cmd_by_depth = graph
    visited = set()
    leaves = set()
    trace = []
    demands = set()
    work = list(entry_handlers)
    while work and len(visited) < max_nodes:
        D = work.pop()
        if D in visited:
            continue
        visited.add(D)
        nexts = set()
        cmd_table_missed = False
        cmd_table_matched = False
        forward = set()
        demanded = False
        for (X, off, from_func, origin_fact, fname) in icall.get(D, ()):   # (b) field-forward through context
            if origin_fact == "__field__":
                # cmd+SITE gate.  A CASE-dominated site is a proven cmd-specific dispatch -> follow even when
                # the field name is not the syscall op (the switch routes this cmd here: FE_READ_STATUS ->
                # read_status).  A GENERAL (`*`/default) site is called regardless of cmd -> follow only if
                # op-aligned (sk_prot->ioctl yes; mmu_notifier for an ioctl no).  No reach proof -> don't
                # follow, stop conservatively at the coarse dispatcher / inline-leaf.
                if not field_bridge:
                    continue
                kind = _cmd_reach_kind(D, X, off, fname, value_set, site_reach)
                if not (kind == "case" or
                        (kind == "general" and _operation_field(fname) == op_field)):
                    continue
            else:
                if not fname:
                    continue
                kind = _cmd_reach_kind(from_func, X, off, fname, value_set, site_reach)
                scoped_case = _cmd_path_case(origin_fact, value_set, from_func, cmd_roots)
                if not (scoped_case or kind == "case" or
                        (kind == "general" and _operation_field(fname) == op_field and
                         from_func == origin_fact)):
                    continue
            # Resolve the exact field proven at this call site. Case-scoped CMDICALLs can change operation
            # identity just like FIELD_ICALLs (ioctl -> raw_request/output_report); collapsing them back to
            # op_field would merge distinct slots of the same ops struct after the gate already separated
            # them. General forwards are op-aligned above, so fname == op_field there.
            lookup = fname or op_field
            fields_list = ctx.get(X)
            if fields_list:
                for fields in fields_list:
                    h = fields.get(lookup)
                    if h and h != D:
                        forward.add(h)
                        trace.append((D, f"forward:{X}", h))
            else:                                  # empty ctx[X] -> DEMAND recovery (not a silent leaf)
                demands.add((X, off, lookup))
                demanded = True
        nexts |= forward
        # (a) value-gated cmd table.  Under the resource rule, drop it where the resource already scoped
        # the forward to a concrete handler (forward non-empty AND ctx[X] populated) -- the collapse would
        # only re-add cross-instance pollution.  Pass 2 (resource_rule=False) keeps it as the honest union.
        scoped = resource_rule and bool(forward) and any(
            ctx.get(X) for (X, _o, _f, _of, _fn) in icall.get(D, ())
            if not (_of == "__field__" and not field_bridge))   # FIELD_ICALL inert outside the field pass
        depth_tbl = None if scoped else cmd_by_depth.get(D)
        masked_tbls = None if scoped else masked_cmd_by_origin.get(D)
        if depth_tbl or masked_tbls:
            for v in value_set:
                levels = depth_tbl.get(v) if depth_tbl else None
                hits = set(levels[min(levels)]) if levels else set()
                for mask, masked_tbl in (masked_tbls or {}).items():
                    masked_levels = masked_tbl.get(v & mask)
                    if masked_levels:
                        hits |= set(masked_levels[min(masked_levels)])
                if hits:
                    cmd_table_matched = True
                nexts |= {h for h in hits if h != D}
            if value_set and not cmd_table_matched:
                cmd_table_missed = True
        if _FOLLOW_BRIDGES and field_bridge and not nexts and not demanded:
            # (c) CMD_BRIDGE (field pass only, so a pass-1/2-resolved variant is never perturbed):
            # D didn't route on its own -- it may delegate the cmd to a helper that dispatches THIS operation
            # (inet_ioctl -> sk_ioctl -> sk_prot->ioctl).  Follow the call edge ONLY into a callee that can
            # dispatch op_field: a cmd table, a CMDICALL, or an op-ALIGNED FIELD_ICALL (its field IS op_field).
            # Same alignment gate as the field-forward -- a callee whose only field-icall is a different op
            # (__mmu_notifier's invalidate_range_start for an ioctl variant) is a data helper, NOT a dispatcher.
            for callee in bridge.get(D, ()):
                if callee == D or callee in visited:
                    continue
                # sound edge only: the callee must dispatch THIS operation via an op-ALIGNED FIELD_ICALL (its
                # field IS op_field: sk_ioctl's proto.ioctl).  NOT a bare cmd table (scsi_ioctl), a different-op
                # field-icall (__mmu_notifier's invalidate_range_start), nor a CMDICALL (those are cmd-gated in
                # the forward loop, not here -- __mmu_notifier carries mempolicy-origin CMDICALLs on the SAME
                # misaligned site).  Every real field-forward callee has a named FIELD_ICALL, so this suffices.
                if any(_of == "__field__" and _operation_field(_fn) == op_field
                       for (_X, _o, _f, _of, _fn) in icall.get(callee, ())):
                    nexts.add(callee)
                    trace.append((D, "bridge", callee))
            # (d) CALLBACK_BRIDGE: D passes a handler to a helper that invokes it WITH the cmd (dvb_frontend_
            # ioctl -> dvb_usercopy -> dvb_frontend_do_ioctl).  The recognizer proved BOTH that the cmd flows
            # to the callback AND that the callback dispatches on it (dispatchesOnArg), so the fact is a genuine
            # cmd-dispatch bridge -- follow it; the callback's own cmd table / case-dominated field-forwards
            # (or an inline-leaf for inline cases) then resolve under the gates above.
            for cb in callback_bridge.get(D, ()):
                if cb != D and cb not in visited:
                    nexts.add(cb)
                    trace.append((D, "callback", cb))
        if nexts:
            work.extend(nexts - visited)
        elif cmd_table_missed and not inline_leaf:
            # strict (passes 1 & 2): a cmd-table miss is not a leaf; a pending field-forward waits for ctx
            # recovery (the demand is returned either way, so a later round with bound ctx still refines).
            continue
        else:
            # inline-leaf (pass 3 only): D has a cmd table that missed this value but NO pending field-
            # forward, so D dispatches it inline (its own switch handles/rejects it) -> D IS the handler
            # reached (l2cap_sock_getsockopt on L2CAP_OPTIONS; evdev_ioctl on an inline EVIOC).  Sound:
            # coverage reaches D.  (A pure no-table leaf also lands here in any pass.)
            leaves.add(D)
    return leaves, trace, demands


# ----------------------------------------------------------------------------------------------------
# UNIFORM CONTEXT PROVIDER (Tier 0).  resolve()'s `ctx` answers "for struct X, what ops table does THIS
# variant's fd bind".  It used to carry only "proto" (sk_prot), so every icall that forwards through any
# OTHER struct kind had no context and truncated to a leaf (under-approximation).  This builds the full
# struct-kind-keyed ctx from the entry ops the provenance recognizers ALREADY recovered (res2rows), so
# file_operations / proto_ops field-forwards resolve against the variant's own fd instead of truncating.
# Several registration mechanisms (cdev/misc/anon/chrdev) all install a `file_operations`, so they share
# that one context key — the kernel dispatches through the struct TYPE, not the registration path.
_KIND_TO_STRUCT = {
    "fops": "file_operations", "cdev": "file_operations", "misc": "file_operations",
    "anon": "file_operations", "chrdev": "file_operations",
    "proto_ops": "proto_ops",
}


def build_struct_ctx(resources, reg_rows, res2rows, sock_proto_ctx, ctx_pred, block_dops_ctx=None,
                     variant_rows=()):
    """resources -> {struct_kind: [field_dict]} for resolve().  For each fd/sock resource the variant
    carries, bucket the field-dicts of its anchored REG rows by the CMDICALL struct.X key the resolver
    forwards through: file_operations, proto_ops, proto (sk_prot), and block_device_operations.  The first
    three + block come from rows/recognizers.  ``variant_rows`` carries object context proven only for the
    producing variant when its return resource is generic, so that context never leaks to unrelated fds.
    block_dops_ctx (resource -> [{'ioctl': H}]) is the
    VARIANT-SPECIFIC block-driver ioctl from block-device provenance (fd_loop -> lo_ioctl), NOT a global
    union -- this is why ctx['block_device_operations'] is variant-specific, like sock_proto_ctx."""
    rows_by_struct = collections.defaultdict(set)
    extra = collections.defaultdict(list)

    def add_row(row):
        sk = _KIND_TO_STRUCT.get(reg_rows[row][0])
        if sk and reg_rows[row][3]:
            rows_by_struct[sk].add(row)

    for r in resources:
        if not ctx_pred(r):
            continue
        for row in res2rows.get(r, ()):
            add_row(row)
        for row in sock_proto_ctx.get(r, ()):
            if reg_rows[row][3]:
                rows_by_struct["proto"].add(row)
        if block_dops_ctx:
            for fd in block_dops_ctx.get(r, ()):
                extra["block_device_operations"].append(fd)
    for row in variant_rows:
        add_row(row)
    ctx = {sk: [reg_rows[i][3] for i in rows] for sk, rows in rows_by_struct.items()}
    for sk, dicts in extra.items():
        ctx.setdefault(sk, []).extend(dicts)
    return ctx


# ----------------------------------------------------------------------------------------------------
# Validation: prove the recursion end-to-end on the sockopt chain that the flat binder could not reach.
# ----------------------------------------------------------------------------------------------------
def _validate():
    import json
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from model.variant import build_reg_rows, specific_predicate, resource_kind_map
    from provenance.socket import build_sock_resource_anchors, build_sock_proto_context

    hm = json.load(open(f"{SH}/horizon_model.json"))
    reg_rows = build_reg_rows(SH)
    specific = specific_predicate(hm)
    res_kinds = resource_kind_map(hm)

    def ops_ctx(r):
        k = res_kinds.get(r, set())
        return "fd" in k or "sock" in k or r.startswith(("fd_", "sock_"))

    graph = load_dispatch_graph(SH)
    sock_ops, _ev = build_sock_resource_anchors(hm, reg_rows, specific, ops_ctx)
    sock_proto = build_sock_proto_context(hm, reg_rows, specific, ops_ctx)

    vconsts = {}
    for ln in open(f"{SH}/variant_grammar.jsonl"):
        d = json.loads(ln)
        vconsts[d["name"]] = [int(x) & 0xFFFFFFFF for x in d.get("consts") or []]

    FIELD = {"setsockopt": "setsockopt", "getsockopt": "getsockopt", "ioctl": "ioctl",
             "sendmsg": "sendmsg", "recvmsg": "recvmsg"}

    def sock_of(s):
        for r in (set(s.get("consumes") or []) | set(s.get("uses") or [])):
            if r in sock_ops:
                return r
        return None

    def discrim(base, vals):
        # the structural dispatch key, NOT every const: ioctl=cmd(arg0); sockopt=optname(arg1).
        # (the level arg is consumed inside the proto setsockopt, not a separate table hop)
        if base == "ioctl":
            return set(vals[:1])
        if base in ("setsockopt", "getsockopt"):
            return {vals[1]} if len(vals) >= 2 else set()
        return set(vals)

    tests = ["setsockopt$inet_sctp_SCTP_ADAPTATION_LAYER", "setsockopt$inet_sctp_SCTP_ASSOCINFO",
             "setsockopt$inet_sctp_SCTP_AUTH_CHUNK", "getsockopt$inet_sctp_SCTP_STATUS",
             "setsockopt$inet_tcp_TCP_ULP", "setsockopt$inet_tcp_int", "setsockopt$inet_int",
             "setsockopt$SO_TIMESTAMP"]
    by_name = {s["name"]: s for s in hm["syscalls"]}
    print(f"# dispatch graph: {len(graph[0])} dispatchers, {sum(len(v) for v in graph[1].values())} "
          f"bridges, {sum(len(v) for v in graph[2].values())} icall sites\n")
    for name in tests:
        s = by_name.get(name)
        if not s:
            print(f"  {name}: (not in model)")
            continue
        base = name.split("$", 1)[0]
        field = FIELD.get(base, base)
        r = sock_of(s)
        if not r:
            print(f"  {name}: (no anchored sock)")
            continue
        entry = {reg_rows[row][3].get(field) for row in sock_ops[r] if reg_rows[row][3].get(field)}
        ctx = {"proto": [reg_rows[i][3] for i in sock_proto.get(r, ())]}
        vals = discrim(base, vconsts.get(name, []))
        leaves, trace, _demands, _resolver_pass = resolve(entry, field, vals, ctx, graph)
        prot = sorted({f.get(field) for f in ctx["proto"] if f.get(field)})
        print(f"  {name}")
        print(f"      sock={r}  entry(L1)={sorted(entry)}  sk_prot.{field}={prot}  vals={sorted(vals)}")
        print(f"      -> LEAVES={sorted(leaves)}  ({'UNIQUE' if len(leaves)==1 else str(len(leaves))+' candidates'})")


if __name__ == "__main__":
    _validate()

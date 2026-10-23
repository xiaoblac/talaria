#!/usr/bin/env python3
# Copyright 2026 reFuzz project author -------youngkk.
#
# CONTEXT-RESOLUTION FIXPOINT.  Context recovery and dispatch resolution are mutually recursive: the
# resolver only learns it needs context for struct X when its walk reaches CMDICALL(struct.X), and a
# grounded provider for X needs the already-recovered upper-layer context to answer precisely; once X is
# recovered the resolver advances one level and may demand Y at depth+1.  A flat "recognizers-first,
# resolve-once" pipeline cannot satisfy that cycle — it is forced into under-approximation (any
# struct-kind not pre-built lags the frontier and silently truncates) or ungrounded global type-scan.
#
# This is the `for _round in range(4)` anon loop in build_full_res2rows generalized from entry-anchoring
# to the general (node, context) product: a depth-stratified, population-level BATCHED SEMI-NAIVE fixpoint
#   repeat:
#     run pure resolve() for ALL variants with the current ctx     # in-memory, cheap
#     collect the UNION of unsatisfied struct-kind demands
#     satisfy each demanded struct-kind ONCE via its ContextProvider (the expensive .bc scan, cached)
#     enrich ctx
#   until no new demand
# Monotone ctx/visited on a finite lattice => termination.  Negative-cache honest-empty so it quiesces.
# Never degrade to type-scan.  Record precision-provenance (grounded-unique / grounded-fanout /
# runtime-empty) at each stop so a region's confidence is a function of WHERE in the fixpoint it stopped.
#
# Belief-layer only: this drives region_audit, never the proven binder (which stays |L|==1, 0 regression).
import collections
import os
import re
import sys
import time

SH = "run/seed_horizon"

_T0 = time.perf_counter()


def _trace(msg):
    """Coarse phase/elapsed progress to stderr, gated by env SH_TRACE (off by default).
    Lets a slow candidate run be localized (provenance vs fixpoint vs cold .bc scan) without
    perturbing results or normal-run output. Enable with SH_TRACE=1."""
    if os.environ.get("SH_TRACE"):
        sys.stderr.write(f"[SH +{time.perf_counter() - _T0:7.1f}s] {msg}\n")
        sys.stderr.flush()


# Type-wide providers are valid only when the variant reaches struct.X->field but cannot identify which
# concrete X object/table is installed. Exact DWARF typing prevents type confusion; it does not prove object
# identity. Keep this policy explicit so a typed table such as struct proto cannot become a global union and
# overwrite the socket-specific proto context.
#
# TO ADD A TYPE-WIDE PROVIDER:
#   1. establish that the variant model cannot select a narrower object/table, then append the struct here.
#      The demanded offset comes from CMDICALL/FIELD_ICALL; it is never configured by name or guessed.
#   2. it only fires if a CMDICALL(origin, from, struct.<struct>+off) fact exists (see load_dispatch_graph);
#      with no such fact it is simply never demanded. A struct that IS demanded but has no provider shows as
#      `no-provider` in run_fixpoint's per_round / neg_cache (and under SH_TRACE) -- that is the signal for
#      which struct to add next.
#   3. adding here is INCREMENTAL: already-cached structs are not re-scanned; only the new one's cache is
#      built (from ir_defuse's facts in fields.tsv -- no Python disassembly), once, then reused across runs.
# DON'T add here if the variant DOES pick the driver (variant-SPECIFIC, e.g. fd_loop -> lo_ioctl): supply it
#   as context via a build_*_context fed into build_struct_ctx (like block_device_operations / proto), so a
#   global union does not over-approximate. If extraction is not "ptr at a fixed offset" (signature-based,
#   clang type-merge, ...): write a provide(X, demands_for_X, ctx, root) -> (fields, label) and register it
#   directly in PROVIDERS, with your own exists+nonempty .tsv cache (see read_block_dops_ioctls).
# After a KERNEL REBUILD the caches are stale -- delete them: rm run/seed_horizon/struct_offsets_*.tsv
_TYPE_UNION_PROVIDER_STRUCTS = (
    "v4l2_file_operations", "tty_operations", "hid_ll_driver",
    # DVB sub-ops reached via CALLBACK_BRIDGE (dvb_*_ioctl -> dvb_usercopy -> *_do_ioctl): the fd reaches
    # the ops but does not select the tuner/demod/CA implementation, so the compiled-object union is the
    # honest points-to set.
    "dvb_frontend_ops", "dmx_demux", "dvb_ca_en50221",
)


_TYPED_FIELDS = None       # {struct: {byte_off: {table_global: {handler}}}}


def _load_typed_fields(root="."):
    """Exact global table points-to facts keyed by DWARF struct identity and byte offset.

    Unlike FIELD, TYPEDFIELD never canonicalizes an anonymous LLVM struct by shape. It also retains the
    table global so later providers can refine the abstract object set without changing the fact schema.
    """
    global _TYPED_FIELDS
    if _TYPED_FIELDS is not None:
        return _TYPED_FIELDS
    out = collections.defaultdict(
        lambda: collections.defaultdict(lambda: collections.defaultdict(set)))
    defined = set()
    function_map = os.path.join(root, SH, "function_block_map.tsv")
    if os.path.exists(function_map):
        for line in open(function_map):
            cols = line.rstrip("\n").split("\t")
            if len(cols) >= 3:
                defined.add(cols[2])
    path = os.path.join(root, SH, "kernel_facts_linked", "fields.tsv")
    if os.path.exists(path):
        for line in open(path):
            cols = line.rstrip("\n").split("\t")
            if cols[0] not in {"TYPEDFIELD", "TYPEDSTORE"} or len(cols) < 6:
                continue
            owner, struct, offset, _field, handler = cols[1:6]
            if not offset.lstrip("-").isdigit() or (defined and handler not in defined):
                continue
            owner_kind = "global" if cols[0] == "TYPEDFIELD" else "installer"
            out[struct][int(offset)][f"{owner_kind}:{owner}"].add(handler)
    _TYPED_FIELDS = out
    return out


def read_struct_offsets(struct, offsets, root="."):
    """{off: {handler}} for exact-DWARF globals of ``struct`` at the demanded offsets."""
    offsets = [o for o in offsets if o is not None and o >= 0]
    if not offsets:
        return {}
    typed = _load_typed_fields(root).get(struct, {})
    return {
        off: set().union(*typed[off].values())
        for off in offsets if off in typed and typed[off]
    }


def _offset_provider(struct):
    """ContextProvider over exact-DWARF global objects of one struct type.

    This is a type-level points-to set, not LLVM-shape matching. The table identities remain available in
    _load_typed_fields for later object-sensitive refinement.
    """
    def provide(X, demands_for_X, ctx, root="."):
        # demands_for_X: {(off, op_field)} — the field positions the resolver actually needs
        off_handlers = read_struct_offsets(struct, {off for off, _op in demands_for_X}, root)
        fields, n = [], 0
        for off, op in demands_for_X:
            for h in off_handlers.get(off, ()):
                fields.append({op: h})
                n += 1
        if not fields:
            return [], "runtime-empty"
        return fields, ("typed-unique" if n == 1 else "typed-fanout")
    return provide


# block_device_operations / blk_mq_ops field values come from ir_defuse's OPSFIELD facts: ir_defuse reads
# each field by its DWARF byte offset (named even where clang type-merges the struct) and emits the
# per-global handler, so the offset/signature heuristics that used to live here are gone -- the Python side
# consumes by field NAME only and never disassembles or guesses an offset.
_OPSFIELD = None     # {struct.field: {(ops_global, value)}}, read once from ir_defuse's fields.tsv


def _load_opsfield(root="."):
    global _OPSFIELD
    if _OPSFIELD is not None:
        return _OPSFIELD
    out = collections.defaultdict(set)
    path = os.path.join(root, SH, "kernel_facts_linked", "fields.tsv")
    if os.path.exists(path):
        for ln in open(path):
            c = ln.rstrip("\n").split("\t")
            if c[0] == "OPSFIELD" and len(c) >= 4:
                out[c[2]].add((c[1], c[3]))     # struct.field -> {(ops_global, value)}
    _OPSFIELD = out
    return out


def read_block_dops_ioctls(root="."):
    """The set of block driver .ioctl/.compat_ioctl handlers, from ir_defuse's OPSFIELD facts (per-global
    block-ops field values; ir_defuse reads each field via its DWARF offset -- no Python disassembly)."""
    of = _load_opsfield(root)
    return {val for f in ("block_device_operations.ioctl", "block_device_operations.compat_ioctl")
            for _ops, val in of.get(f, ())}


def read_block_dops_tables(root="."):
    """{ops_global: {ioctl_handler}} from ir_defuse's OPSFIELD facts -- the recognizer needs the ops object
    name as evidence (e.g. @sr_bdops -> sr_block_ioctl); the binder can still consume just the handler set."""
    out = collections.defaultdict(set)
    of = _load_opsfield(root)
    for f in ("block_device_operations.ioctl", "block_device_operations.compat_ioctl"):
        for ops, val in of.get(f, ()):
            out[ops].add(val)
    return dict(out)


# NOTE: block_device_operations is NOT a global provider here. A global union of all 13 block-driver
# ioctl handlers is variant-AGNOSTIC over-approx; the block-device identity IS recoverable per variant
# (fd_loop's cmds pick lo_ioctl), so block_device_operations is supplied as VARIANT-SPECIFIC context via
# provenance.fd.build_block_dops_context (fed into build_struct_ctx), like sock_proto_ctx. read_block_dops_ioctls
# (above) is the field-extraction it builds on.


# Registry keyed by struct-kind. One entry models one kernel mechanism. Add struct-kinds one at a time.
# tty_operations: tty_ioctl forwards through tty->ops->ioctl (offset 96) to the driver's .ioctl
# (uart/pty/vt/...). hid_ll_driver: hidraw_ioctl -> hid_hw_raw_request/output_report through
# hdev->ll_driver (offsets 64/72) to the transport (usbhid/i2c_hid/uhid/...). Both driver-agnostic
# (syz fd_tty/fd_hidraw is generic), so the variant-global-monotone union is the grounded answer.
PROVIDERS = {s: _offset_provider(s) for s in _TYPE_UNION_PROVIDER_STRUCTS}
# block_device_operations: handled as variant-specific context (see note above), not a global provider.

DEFAULT_MAX_ROUNDS = 8


def run_fixpoint(variant_specs, graph, cmd_roots=None, root=".", max_rounds=DEFAULT_MAX_ROUNDS, log=None):
    """Batched semi-naive context fixpoint over ALL variants.
      variant_specs: [{name, entry, op_field, value_set, seed_ctx}]  (seed_ctx = depth-0 ops the fd carries)
    Returns (results, satisfied, neg_cache, rounds, per_round):
      results[name]  = (leaves, trace, demands, resolver_pass)
      # demands of the FINAL round = the runtime-empty stops
      satisfied[X]   = label   # grounded-unique | grounded-fanout | runtime-empty | no-provider
      neg_cache      = {X}     # struct-kinds proven empty / no provider (honest stops, not re-scanned)
      per_round[i]   = [(X, label, n_fields)]   # what each round newly satisfied (convergence proof)"""
    from resolve.dispatch import resolve
    global_ctx = {}                       # X -> [field_dict]  (variant-global monotone)
    neg_cache = set()
    satisfied = {}
    per_round = []
    results = {}
    rounds = 0
    _trace(f"run_fixpoint: {len(variant_specs)} variant specs, max {max_rounds} rounds")
    for rnd in range(max_rounds):
        rounds = rnd + 1
        _trace(f"round {rnd}: resolving {len(variant_specs)} specs "
               f"(ctx={sorted(global_ctx)}, neg={sorted(neg_cache)})")
        all_demands = collections.defaultdict(set)        # X -> {(off, op_field)}
        for spec in variant_specs:
            ctx = {}
            for X, fl in global_ctx.items():              # type-wide context is the weaker default
                ctx[X] = list(fl)
            for X, fl in spec["seed_ctx"].items():        # object-specific variant context overrides it
                ctx[X] = list(fl)
            leaves, trace, demands, resolver_pass = resolve(
                spec["entry"], spec["op_field"], spec["value_set"], ctx, graph, cmd_roots=cmd_roots)
            results[spec["name"]] = (leaves, trace, demands, resolver_pass)
            for (X, off, op) in demands:
                all_demands[X].add((off, op))
        # NEW demands = not yet provided and not negatively cached; the rest are honest runtime-empty stops
        new = {X: d for X, d in all_demands.items() if X not in global_ctx and X not in neg_cache}
        _trace(f"round {rnd}: demanded={sorted(all_demands)} new-to-satisfy={sorted(new)}")
        if not new:
            _trace(f"round {rnd}: no new demands -> quiesced after {rounds} round(s)")
            break
        sat_this = []
        for X, dset in sorted(new.items()):
            prov = PROVIDERS.get(X)
            if prov is None:                              # no recognizer for X -> honest empty, cached
                neg_cache.add(X)
                satisfied[X] = "no-provider"
                sat_this.append((X, "no-provider", 0))
                _trace(f"round {rnd}: provider {X} -> no-provider")
                continue
            t = time.perf_counter()
            fields, label = prov(X, dset, global_ctx, root)
            _trace(f"round {rnd}: provider {X} -> {label} ({len(fields)} field(s)) "
                   f"in {time.perf_counter() - t:.1f}s")
            if fields:
                global_ctx[X] = fields
                satisfied[X] = label
                sat_this.append((X, label, len(fields)))
            else:                                         # provider returned empty -> negative-cache it
                neg_cache.add(X)
                satisfied[X] = "runtime-empty"
                sat_this.append((X, "runtime-empty", 0))
        per_round.append(sat_this)
        if log:
            log(f"round {rnd}: satisfied {sat_this}")
    return results, satisfied, neg_cache, rounds, per_round

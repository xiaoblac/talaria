#!/usr/bin/env python3
# Copyright 2026 reFuzz project author -------youngkk.
#
# Authoritative candidate-region construction.
#
# This module is the only current code path that turns syzkaller variants into
# static candidates. It does not produce point bindings. It returns candidate
# sets and confidence classes.
import collections
import json
import os
import re
from dataclasses import dataclass

from model.schema import CandidateRecord
from model.variant import (
    CMD_BASES, DIRECT_FIELD, FS_BASES, OPEN_BASES, SH,
    build_cmd_rows, build_cmd_syscall_bases, build_reg_rows, build_variant_specs,
    cval, load_consts, load_variant_consts, syscall_base,
)
from provenance.context import build_provenance_context
from resolve.dispatch import build_struct_ctx, load_dispatch_graph
from resolve.fixpoint import run_fixpoint, _trace
from provenance.fd import _cmd_roots


@dataclass
class CandidateRun:
    hm: dict
    reg_rows: list
    records: dict
    provenance: object
    graph: tuple
    cmd_roots: dict
    rounds: int
    per_round: list
    neg_cache: set


def genl_family_key(name):
    return re.sub(r"[^a-z0-9]", "", name.lower())


def genl_family_keys(name):
    return {name.lower(), genl_family_key(name)}


def genl_family_from_resource(resource):
    if not resource.startswith("genl_") or "_family_id" not in resource:
        return None
    fam = resource[len("genl_"):].split("_family_id", 1)[0]
    return fam or None


def genl_family_candidates(suffix, resources):
    candidates = set()
    fam = suffix.split("_CMD_")[0]
    if fam.startswith("auto_"):
        fam = fam[5:]
    if fam:
        candidates.add(fam)
    for r in resources:
        fam = genl_family_from_resource(r)
        if fam:
            candidates.add(fam)
    return candidates


def load_reg_lookup(sh=SH):
    genl = collections.defaultdict(set)
    genl_families = collections.defaultdict(set)
    fs = collections.defaultdict(set)
    genl_raw = []              # (key, cmd, handler) deferred: GENLMUX may arrive after its GENLCMD rows
    genl_mux = set()           # handlers that only FORWARD to sub-commands (tipc_nl_compat_recv), not endpoints
    path = f"{sh}/kernel_facts_linked/cmd.tsv"
    if not os.path.exists(path) or not os.path.getsize(path):
        raise FileNotFoundError(f"missing linked kernel fact file: {path}")
    for ln in open(path):
        c = ln.rstrip("\n").split("\t")
        if c[0] == "GENLCMD" and len(c) >= 4:
            cmd = int(c[2])            # FULL value: genl cmds are u8, but TIPC legacy compat sub-cmds are
            #                            16-bit (0x4102, 0x800b) and collide under &0xff -- so key by the raw
            for key in genl_family_keys(c[1]):   # value both here and at lookup (syz cmd is likewise full)
                genl_raw.append((key, cmd, c[3]))
                genl_families[key].add(c[1])
        elif c[0] == "GENLMUX" and len(c) >= 2:
            genl_mux.add(c[1])
        elif c[0] == "FSMOUNT" and len(c) >= 3:
            fs[c[1]].add(c[2])
    for key, cmd, h in genl_raw:
        if h not in genl_mux:          # drop the outer dispatcher; keep its inner sub-command endpoints
            genl[(key, cmd)].add(h)
    return genl, genl_families, fs


def _entry_resources(spec):
    if spec.base in OPEN_BASES:
        return spec.produced_resources
    return spec.resources


def _cmd_value_for_syscall_multiplexer(spec, consts, variant_consts):
    if spec.auto_kind != "named":
        return None
    cv = cval(spec.suffix, consts, spec.base)
    if cv is not None:
        return cv
    # Fallback: syzkaller already resolved the numeric opcode as the first constant arg (vc[0]).
    # cval() keys on the syz suffix name, which misses (a) bpf refinement suffixes that append a
    # map/prog subtype to the opcode (MAP_CREATE_RINGBUF -> BPF_MAP_CREATE=0), (b) lowercase syz
    # aliases that do not match the KEYCTL_*/F_* const symbol (keyctl$setperm, fcntl$setflags), and
    # (c) numeric suffixes (sysfs$1, prctl$0).  The downstream `syscall_base(h) == spec.base` filter
    # keeps this sound: a spurious vc[0] can only ever anchor a variant to its OWN syscall handler
    # (add_key$keyring -> __se_sys_add_key), never mis-attribute it to a different syscall.  Variants
    # whose opcode is a string (add_key$user) or an implicit 0 (fcntl$dupfd) have vc==[] -> stay None.
    vals = variant_consts.get(spec.name, [])
    if vals:
        return vals[0] & 0xFFFFFFFF
    # quotactl(cmd = flags[quota_cmd_<op>]): the cmd is a flag-set {Q_<OP>_USR/GRP/PRJ}, each equal to
    # QCMD(Q_<OP>, type) = (Q_<OP> << SUBCMDSHIFT) | type with SUBCMDSHIFT=8.  do_quotactl switches on
    # cmds = cmd >> SUBCMDSHIFT, so the extracted CMD rows are keyed by the shifted subcmd -- recover it
    # from any flag-set member (all three share one subcmd).  Flag-set cmds are not in variant_consts.
    if spec.base in ("quotactl", "quotactl_fd"):
        for t in ("_USR", "_GRP", "_PRJ"):
            v = consts.get(spec.suffix + t)
            if v is not None:
                return (v & 0xFFFFFFFF) >> 8
    return None


def _confidence(record, cmd_by_origin, icall):
    if record.leaves:
        if len(record.leaves) == 1:
            return "unique-candidate"
        if len(record.leaves) <= 5:
            return "small-candidate"
        return "large-candidate"
    if not record.entry_handlers:
        return "no-context"
    if not record.leaves:
        if any((h in cmd_by_origin and cmd_by_origin[h]) or h in icall for h in record.entry_handlers):
            return "value-unresolved"
        return "entry-only-empty"
    return "unknown"


def _region_for(record, cmd_roots):
    region = set(record.entry_handlers) | set(record.leaves)
    cv = record.spec.discriminant
    if cv is not None:
        for h in set(record.entry_handlers) | set(record.leaves):
            region |= cmd_roots.get((h, cv), set())
    region.discard("-")
    return region


def build_candidate_run(sh=SH, root="."):
    _trace("build_candidate_run: start")
    hm = json.load(open(os.path.join(sh, "horizon_model.json")))
    consts = load_consts()
    variant_consts = load_variant_consts(sh)
    syscall_bases = build_cmd_syscall_bases(sh)
    cmd_rows, cmd_details = build_cmd_rows(sh)
    _trace("loaded hm/consts/variant_consts/syscall_bases/cmd_rows")
    reg_rows = build_reg_rows(sh)
    _trace(f"build_reg_rows: {len(reg_rows)} rows")
    provenance = build_provenance_context(hm, reg_rows, root)
    _trace(f"build_provenance_context: {len(provenance.res2rows)} anchored resources")
    specs = build_variant_specs(hm, variant_consts, syscall_bases,
                                provenance.specific, provenance.res_kinds, root)
    _trace(f"build_variant_specs: {len(specs)} variants")
    graph = load_dispatch_graph(sh)
    _trace(f"load_dispatch_graph: {len(graph[0])} dispatchers")
    cmd_by_origin, _bridge, icall, _site_reach, _cb_bridge, _masked, _depth = graph
    cmd_roots = _cmd_roots(root)
    _trace(f"_cmd_roots: {len(cmd_roots)} scoped roots")
    genl_lookup, genl_families, fs_lookup = load_reg_lookup(sh)

    records = {}
    fix_specs = []
    for name, spec in specs.items():
        resources = _entry_resources(spec)
        anchor_rows = provenance.context_rows(resources, name)
        entry_handlers = provenance.entry_handlers(resources, spec.field, name)
        record = CandidateRecord(
            spec=spec,
            anchor_rows=set(anchor_rows),
            entry_handlers={h for h in entry_handlers if h and h != "-"},
        )
        records[name] = record
        if spec.field and record.entry_handlers and spec.intent in {"cmd_dispatch", "direct_fd_op"}:
            value_set = ({spec.discriminant}
                         if spec.intent == "cmd_dispatch" and spec.discriminant is not None
                         else set())
            seed_ctx = build_struct_ctx(spec.resources, reg_rows, provenance.res2rows,
                                        provenance.sock_proto_ctx,
                                        lambda r: provenance.specific(r) and provenance.ops_ctx(r),
                                        provenance.block_dops_ctx,
                                        provenance.variant2rows.get(name, ()))
            fix_specs.append({
                "name": name,
                "entry": record.entry_handlers,
                "op_field": spec.field,
                "value_set": value_set,
                "seed_ctx": seed_ctx,
            })

    _trace(f"run_fixpoint: dispatching {len(fix_specs)} dispatch specs")
    results, _satisfied, neg_cache, rounds, per_round = run_fixpoint(
        fix_specs, graph, cmd_roots, root)
    _trace(f"run_fixpoint done: {rounds} round(s)")

    for name, record in records.items():
        spec = record.spec
        if spec.no_dispatch_reason:
            record.resolver_pass = "no_dispatch"
            record.fail_stage, record.fail_class = "s2_no_dispatch", "legit_no_dispatch"
        elif spec.intent in {"cmd_dispatch", "direct_fd_op"}:
            leaves, trace, demands, resolver_pass = results.get(
                name, (set(), [], set(), "unresolved"))
            record.trace = list(trace)
            record.demands = set(demands)
            record.resolver_pass = resolver_pass
            if spec.intent == "cmd_dispatch" and spec.discriminant is None:
                record.leaves = set()
            else:
                record.leaves = set(leaves)
            _classify_fd_dispatch(record, neg_cache, cmd_by_origin, icall)

        elif spec.intent == "syscall_multiplexer":
            record.resolver_pass = "syscall_multiplexer"
            cv = _cmd_value_for_syscall_multiplexer(spec, consts, variant_consts)
            # effective handler = origin (the syscall handler, when the opcode switch lives in a HELPER the
            # handler forwards the opcode to -- do_fcntl/ptrace_request) else the analyzed fn.  Keying on the
            # bare fn would miss those, since syscall_base(do_fcntl) is None.
            hits = ({(d.get("origin") or d["handler"]) for d in cmd_details.get(cv, [])}
                    if cv is not None else set())
            record.leaves = {h for h in hits if syscall_base(h) == spec.base}
            if spec.auto_kind != "named":
                record.fail_stage, record.fail_class = "s6_no_disc", "legit_runtime"
            elif cv is None:
                record.fail_stage, record.fail_class = "s6_no_disc", "model_gap_disc"
            elif record.leaves:
                record.fail_stage, record.fail_class = "candidate", "ok"
            elif hits:
                record.fail_stage, record.fail_class = "s7_no_own", "model_gap_bridge"
            else:
                record.fail_stage, record.fail_class = "s6_no_cmdrow", "model_gap_cmdrow"

        elif spec.intent == "genl_cmd":
            record.resolver_pass = "genl_table"
            cv = cval(spec.suffix, consts)
            fam_candidates = genl_family_candidates(spec.suffix, spec.resources)
            fam_keys = set().union(*(genl_family_keys(fam) for fam in fam_candidates)) if fam_candidates else set()
            anchored_families = set()
            for key in fam_keys:
                anchored_families.update(genl_families.get(key, ()))
            if cv is not None:
                for key in fam_keys:
                    record.leaves.update(genl_lookup.get((key, cv), ()))   # full value (see load_reg_lookup)
            if cv is None:
                record.fail_stage, record.fail_class = "s6_no_disc", "legit_runtime"
            elif record.leaves:
                record.fail_stage, record.fail_class = "candidate", "ok"
            elif anchored_families:
                record.fail_stage, record.fail_class = "s6_no_cmdrow", "model_gap_cmdrow"
            else:
                # the socket IS anchored (netlink_sendmsg) -- what's missing is the whole GENL family's cmd
                # table (no GENLCMD rows for DEVLINK/IPSET/NFSD/... at all).  That's a second-level dispatch
                # -table gap, NOT a fd/sock resource-anchor gap, so it must not share the s4_no_anchor bucket.
                record.fail_stage, record.fail_class = "s6_no_genl_family", "model_gap_cmdrow"

        elif spec.intent == "fs_dispatch":
            record.resolver_pass = "fs_table"
            record.leaves = set(fs_lookup.get(spec.suffix, ())) | set(fs_lookup.get(spec.suffix.split("_")[0], ()))
            if record.leaves:
                record.fail_stage, record.fail_class = "candidate", "ok"
            elif spec.auto_kind in ("auto_generic", "base"):
                # bare VFS fs syscalls (mount/fsmount/fsopen/fspick) take the fs type as a runtime string,
                # not a fixed discriminant -> the per-fs get_tree/init_fs_context dispatch is runtime, exactly
                # like the auto_generic fs variants.  Honest runtime, not a recoverable anchor gap.
                record.fail_stage, record.fail_class = "s6_no_disc", "legit_runtime"
            else:
                record.fail_stage, record.fail_class = "s4_no_anchor", "model_gap_anchor"

        elif spec.intent == "syz_helper":
            record.resolver_pass = "no_dispatch"
            record.fail_stage, record.fail_class = "s2_pseudo", "legit_no_dispatch"
        else:
            record.resolver_pass = "no_dispatch"
            record.fail_stage, record.fail_class = "s2_base", "legit_no_dispatch"

        record.region = _region_for(record, cmd_roots)
        record.confidence = _confidence(record, cmd_by_origin, icall)

    _trace(f"build_candidate_run: done ({len(records)} records)")
    return CandidateRun(
        hm=hm,
        reg_rows=reg_rows,
        records=records,
        provenance=provenance,
        graph=graph,
        cmd_roots=cmd_roots,
        rounds=rounds,
        per_round=per_round,
        neg_cache=neg_cache,
    )


def _classify_fd_dispatch(record, neg_cache, cmd_by_origin, icall):
    spec = record.spec
    has_untyped_fd = bool(spec.resources & {"fd", "sock"})
    if not spec.specific_resources:
        record.fail_stage = "s3_no_ctx"
        record.fail_class = "legit_runtime" if has_untyped_fd else "legit_no_fd"
    elif not record.anchor_rows:
        record.fail_stage = "s4_no_anchor"
        record.fail_class = "model_gap_anchor"
    elif not record.entry_handlers:
        record.fail_stage = "s5_no_field"
        record.fail_class = "legit_dynamic"
    elif spec.intent == "cmd_dispatch" and spec.discriminant is None:
        record.fail_stage = "s6_no_disc"
        record.fail_class = "legit_runtime"
    elif record.leaves:
        record.fail_stage = "candidate"
        record.fail_class = "ok"
    elif record.demands and any(X in neg_cache for (X, _off, _op) in record.demands):
        record.fail_stage = "s7_runtime_empty"
        record.fail_class = "legit_runtime"
    elif any((h in cmd_by_origin and cmd_by_origin[h]) or h in icall for h in record.entry_handlers):
        record.fail_stage = "s7_no_recursive_candidate"
        record.fail_class = "model_gap_bridge"
    else:
        record.fail_stage = "s7_entry_only_empty"
        record.fail_class = "model_gap_bridge"

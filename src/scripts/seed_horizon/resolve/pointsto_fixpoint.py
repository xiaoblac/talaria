#!/usr/bin/env python3
# Copyright 2026 reFuzz project author -------youngkk.
#
# GENERAL POINTS-TO FIXPOINT (Step 4).
#
# A field-sensitive, inclusion-based (Andersen-style) points-to solver over the batch-generic constraints
# emitted by the Step 2 extractor (objects.tsv / points_to_constraints.tsv / memory_constraints.tsv /
# call_constraints.tsv). It is a SIDE-BY-SIDE solver: it consumes only object identity and byte offsets, and
# it never looks at a struct-type whitelist, a handler name, a resource name, or a variant suffix. The
# existing resolve/fixpoint.py (the struct-provider context fixpoint) is left untouched.
#
# Model
# -----
#   * An abstract object is a pair  (root_object_id, signed_byte_offset).  A base object is (root, 0); a
#     field sub-object is (root, K).  Two globals / allocas / unknown-sites of the SAME llvm struct type stay
#     distinct because their root_object_id strings differ -- struct_type/field_name are metadata only and
#     are never used to merge objects (see the plan: "struct type only as field metadata, never as object
#     identity").
#   * Memory is one cell per abstract object.  A memory cell is itself a node in the points-to graph (a
#     pseudo-node whose points-to set is MemPt(object)).  This is the standard reduction that turns LOAD/STORE
#     into copy edges that are added on-the-fly as the pointer's points-to set grows (Andersen).
#   * The call graph is built on-the-fly: a new CallTarget wires actual->formal and return->result copy edges
#     (requirement 6).  Direct CALL_TARGET facts are wired unconditionally at load time.
#
# Node representation
# -------------------
#   * A VALUE node is the value-id string (e.g. "batch:B:ssa:f:i3").
#   * A MEMORY-CELL node is the abstract-object tuple (root, off).
#   Distinguish by isinstance(node, str).  pt maps both kinds of node to a set of abstract objects.
#
# Termination
# -----------
#   Field GEPs in a copy cycle (linked-list p = p->next) would otherwise generate unbounded offsets.  Offset
#   saturation collapses an out-of-extent offset to the object's dynamic field (root, DYN); with object size
#   from DataLayout this bounds the distinct offsets per root, so the monotone worklist reaches a fixpoint.
#   Saturation is a COUNTED policy dimension, not a silent drop.
#
# Explicit policy dimensions (requirement 7)
# ------------------------------------------
#   UNKNOWN_ADDR       -> opaque per-site object (never type-merged); policy.unknown = opaque | drop
#   FIELD_ADDR_DYNAMIC -> (root, DYN) preserving root identity; policy.field_dynamic = root_dyn | drop
#   offset saturation  -> policy.saturate_by_size (default on) + hard caps
#   Every one of these is tallied in Stats so nothing is dropped without a number attached.
import collections
import os
import resource
import sys
import time


# ----- abstract-object offset algebra ---------------------------------------------------------------------

class _Dyn:
    """The single 'dynamic / unknown field' offset sentinel.

    Used as the offset component of an abstract object when the concrete byte offset is not statically known
    (a dynamic-index GEP) or was saturated for termination. It is NOT a type union: (root, DYN) is still a
    field OF THAT ROOT object, distinct from every other root."""
    __slots__ = ()

    def __repr__(self):
        return "DYN"


DYN = _Dyn()

# Hard offset caps guarantee termination even when an object's size is unknown. HARD_CAP is wide enough to
# keep every real kernel struct offset exact (and the KASAN shadow arithmetic, if it ever reaches a GEP,
# saturates rather than distorting). UNKNOWN_CAP bounds cyclic growth on size-unknown roots.
HARD_CAP = 1 << 21
UNKNOWN_CAP = 1 << 16


def render_obj(obj):
    """Stable text form 'root@offset' for an abstract object (offset may be the DYN sentinel)."""
    root, off = obj
    return f"{root}@{off}"


# ----- policy ---------------------------------------------------------------------------------------------

class Policy:
    """Explicit knobs for the imprecise constraint classes. Defaults are the honest, non-type-union choices;
    every alternative is still object-identity preserving. See module header."""

    def __init__(self, unknown="opaque", field_dynamic="root_dyn",
                 saturate_by_size=True, provenance=True):
        assert unknown in ("opaque", "drop")
        assert field_dynamic in ("root_dyn", "drop")
        self.unknown = unknown
        self.field_dynamic = field_dynamic
        self.saturate_by_size = saturate_by_size
        self.provenance = provenance

    def as_dict(self):
        return {
            "unknown": self.unknown,
            "field_dynamic": self.field_dynamic,
            "saturate_by_size": self.saturate_by_size,
            "provenance": self.provenance,
        }


# ----- raw constraint container ---------------------------------------------------------------------------

class Constraints:
    """Parsed, still-declarative constraints for one or more batches. Filled by the loader; consumed by
    Solver. Keeping this separate from Solver lets a driver load once and solve under several policies."""

    def __init__(self):
        # objects
        self.obj_size = {}                       # root -> byte size (int; <=0 means unknown)
        self.func_name = {}                      # function root object id -> function symbol name
        self.n_unknown_obj = 0
        # points-to base / transfer
        self.addr_of = []                        # (dst_value, root, off, cid)
        self.unknown_addr = []                   # (dst_value, unknown_root, cid)
        self.copy = []                           # (dst, src, cid)
        self.field = []                          # (dst, src, K, cid)
        self.field_dyn = []                      # (dst, src, cid)
        # memory
        self.load = []                           # (dst, ptr, cid)
        self.store = []                          # (ptr, src, cid)
        self.store_object = []                   # (object, off, src, cid)
        self.memcpy = []                         # (dst_ptr, src_ptr, cid)  -- counted, not modeled in v1
        # calls
        self.actuals = collections.defaultdict(dict)   # callsite -> {index: value}
        self.results = {}                              # callsite -> result_value
        self.formals = collections.defaultdict(dict)   # func_name -> {index: formal_value}
        self.returns = collections.defaultdict(list)   # func_name -> [return_value]
        self.direct = []                               # (callsite, func_name)
        self.indirect = []                             # (callsite, callee_value)

    def summary(self):
        return {
            "objects": len(self.obj_size),
            "functions": len(self.func_name),
            "unknown_objects": self.n_unknown_obj,
            "addr_of": len(self.addr_of),
            "unknown_addr": len(self.unknown_addr),
            "copy": len(self.copy),
            "field_addr": len(self.field),
            "field_addr_dynamic": len(self.field_dyn),
            "load": len(self.load),
            "store": len(self.store),
            "store_object": len(self.store_object),
            "memcpy": len(self.memcpy),
            "call_actual": sum(len(v) for v in self.actuals.values()),
            "call_result": len(self.results),
            "function_formal": sum(len(v) for v in self.formals.values()),
            "return_value": sum(len(v) for v in self.returns.values()),
            "call_target_direct": len(self.direct),
            "call_callee_value": len(self.indirect),
        }


# ----- streaming TSV loader (batch-filtered) --------------------------------------------------------------

def _rows(path, keep_batch):
    """Yield split rows of a constraint TSV whose owning batch is in keep_batch. Every data row's
    constraint_id is 'batch:<B>:...' and <B> contains no ':' (batch ids use '__' and '.'), so the owning
    batch is line[6:first-colon-after-6]. Streaming keeps the multi-GB full tables off the heap; only the
    selected batch's rows are split and retained. keep_batch=None keeps everything (full-run mode)."""
    with open(path) as fh:
        for line in fh:
            if keep_batch is not None:
                if not line.startswith("batch:"):
                    continue                     # special:/sym: object rows are not batch-owned; skip
                end = line.find(":", 6)
                if end < 0 or line[6:end] not in keep_batch:
                    continue
            elif line.startswith("#"):
                continue
            yield line.rstrip("\n").split("\t")


def load_constraints(sh, batches, root="."):
    """Build a Constraints from the four Step-2 TSVs, restricted to `batches` (a set of batch ids) or all
    batches when batches is None. Column layouts match points-to-constraint-schema.md."""
    C = Constraints()
    base = os.path.join(root, sh)

    # objects.tsv: object_id kind scope symbol parent byte_offset type size batch function ...
    for c in _rows(os.path.join(base, "objects.tsv"), batches):
        if len(c) < 9:
            continue
        oid, kind, size = c[0], c[1], c[7]
        try:
            C.obj_size[oid] = int(size)
        except ValueError:
            C.obj_size[oid] = 0
        if kind == "function":
            C.func_name[oid] = c[3] if c[3] not in ("", "-") else _name_after(oid, ":function:")
        elif kind == "unknown":
            C.n_unknown_obj += 1

    # points_to: cid kind dst src object_id byte_offset offset_kind struct field batch ...
    for c in _rows(os.path.join(base, "points_to_constraints.tsv"), batches):
        if len(c) < 7:
            continue
        cid, kind = c[0], c[1]
        if kind == "ADDR_OF":
            C.addr_of.append((c[2], c[4], _int(c[5]), cid))
        elif kind == "UNKNOWN_ADDR":
            C.unknown_addr.append((c[2], c[4], cid))
        elif kind == "COPY":
            C.copy.append((c[2], c[3], cid))
        elif kind == "FIELD_ADDR":
            C.field.append((c[2], c[3], _int(c[5]), cid))
        elif kind == "FIELD_ADDR_DYNAMIC":
            C.field_dyn.append((c[2], c[3], cid))

    # memory: cid kind dst pointer src object_id byte_offset size batch ...
    for c in _rows(os.path.join(base, "memory_constraints.tsv"), batches):
        if len(c) < 8:
            continue
        cid, kind = c[0], c[1]
        if kind == "LOAD":
            C.load.append((c[2], c[3], cid))
        elif kind == "STORE":
            C.store.append((c[3], c[4], cid))
        elif kind == "STORE_OBJECT":
            C.store_object.append((c[5], _int(c[6]), c[4], cid))
        elif kind in ("MEMCPY", "MEMMOVE"):
            C.memcpy.append((c[2], c[4], cid))

    # call: cid kind callsite caller callee target_object index value result_value batch ...
    for c in _rows(os.path.join(base, "call_constraints.tsv"), batches):
        if len(c) < 9:
            continue
        kind = c[1]
        if kind == "CALL_TARGET":
            C.direct.append((c[2], c[4]))
        elif kind == "CALL_CALLEE_VALUE":
            C.indirect.append((c[2], c[7]))
        elif kind == "CALL_ACTUAL":
            C.actuals[c[2]][_int(c[6])] = c[7]
        elif kind == "CALL_RESULT":
            C.results[c[2]] = c[8]
        elif kind == "FUNCTION_FORMAL":
            C.formals[c[4]][_int(c[6])] = c[7]
        elif kind == "RETURN_VALUE":
            C.returns[c[4]].append(c[7])
    return C


def _int(text):
    try:
        return int(text)
    except (ValueError, TypeError):
        return 0


def _name_after(text, marker):
    i = text.rfind(marker)
    return text[i + len(marker):] if i >= 0 else text


# ----- kernel-specific seeds / summaries (Step 3 input) ---------------------------------------------------

class Seeds:
    """The Step-3 recognizer output projected onto the points-to engine (plan 2.6 / recognizer-seed-schema).

    registration_seeds.tsv carries the composite ROOT_INSTALL(root, dispatch_object). Per the Step-3 schema
    this Step-4 loader splits it into ObjectSeed(root, synthetic_object) + Install(synthetic_object,
    dispatch_object): the synthetic object is the abstract kernel object a variant of that syz resource
    denotes, and Install records which fops/ops object is mounted on it. dispatch_object_id stays the exact
    Step-2 object identity (never a symbol-name fallback), so the installed object's own field->handler
    edges come for free from the generic STORE_OBJECT closure.

    api_summaries.tsv adds the two dispatch edges the byte-offset closure cannot name on its own:
        dispatch_field (dispatch_object, op-name)   -> handler
        cmd_selector   (dispatcher fn, cmd value)   -> handler
    They are kept as name-keyed relations (op names / cmd values are not byte offsets), consumed and counted,
    never used to merge objects."""

    def __init__(self):
        self.install = []            # (root, dispatch_object_id, dispatch_kind, seed_id)
        self.dispatch_field = []     # (dispatch_object_id, op_name, handler, summary_id)
        self.cmd_selector = []       # (dispatcher_name, cmd_key, handler, summary_id)
        self.install_synthetic = 0   # registration seeds whose dispatch object is not a Step-2 object
        self.install_out_of_scope = 0  # seeds whose dispatch object is outside the loaded batch set

    def summary(self):
        return {
            "install": len(self.install),
            "dispatch_field": len(self.dispatch_field),
            "cmd_selector": len(self.cmd_selector),
            "install_synthetic": self.install_synthetic,
            "install_out_of_scope": self.install_out_of_scope,
        }


def load_seeds(sh, keep_objects, keep_funcs, root="."):
    """Load registration_seeds.tsv + api_summaries.tsv. keep_objects / keep_funcs restrict the seeds to the
    dispatch objects / dispatcher functions actually present in the solved scope (so single-batch chains are
    complete); pass None to keep everything (full-run). Object identity is the exact Step-2 id -- rows whose
    dispatch object is synthetic (cgroup/block context) or out of scope are counted, not silently dropped."""
    S = Seeds()
    base = os.path.join(root, sh)

    reg = os.path.join(base, "registration_seeds.tsv")
    if os.path.exists(reg):
        with open(reg) as fh:
            for line in fh:
                if line.startswith("#"):
                    continue
                c = line.rstrip("\n").split("\t")
                if len(c) < 9:
                    continue
                seed_id, root_id, dispatch_kind, disp_obj, status = c[0], c[3], c[5], c[6], c[8]
                if status == "synthetic" or not (disp_obj.startswith("batch:") or disp_obj.startswith("sym:")):
                    S.install_synthetic += 1
                    continue
                if keep_objects is not None and disp_obj not in keep_objects:
                    S.install_out_of_scope += 1
                    continue
                S.install.append((root_id, disp_obj, dispatch_kind, seed_id))

    api = os.path.join(base, "api_summaries.tsv")
    if os.path.exists(api):
        with open(api) as fh:
            for line in fh:
                if line.startswith("#"):
                    continue
                c = line.rstrip("\n").split("\t")
                if len(c) < 7:
                    continue
                relation, subject, key, target = c[1], c[3], c[4], c[6]
                if relation == "dispatch_field":
                    if keep_objects is None or subject in keep_objects:
                        S.dispatch_field.append((subject, key, target, c[0]))
                elif relation == "cmd_selector":
                    if keep_funcs is None or subject in keep_funcs:
                        S.cmd_selector.append((subject, key, target, c[0]))
    return S


# ----- the solver -----------------------------------------------------------------------------------------

class Stats:
    def __init__(self):
        self.pops = 0
        self.pt_tuples = 0
        self.mem_tuples = 0
        self.value_nodes = 0
        self.mem_nodes = 0
        self.call_targets = 0
        self.call_targets_direct = 0
        self.call_targets_indirect = 0
        self.saturated_offsets = 0
        self.dyn_field_edges = 0
        self.dyn_field_dropped = 0
        self.unknown_dropped = 0
        self.pt_with_unknown = 0
        self.memcpy_unmodeled = 0        # MEMCPY/MEMMOVE recognized but not yet propagated (counted, not dropped silently)
        # kernel-specific Step-3 seed/summary consumption
        self.install_seeds_applied = 0   # ObjectSeed+Install pairs injected from registration_seeds.tsv
        self.roots_seeded = 0            # distinct syz roots given a synthetic kernel object
        self.dispatch_fields_applied = 0  # (dispatch_object, field)->handler from api_summaries.tsv
        self.cmd_selectors_applied = 0    # (dispatcher, cmd)->handler from api_summaries.tsv
        self.roots_reaching_dispatch = 0  # seeded roots whose install slot reaches >=1 dispatch object
        self.roots_reaching_handler = 0   # seeded roots reaching a handler (multi-layer object/field/call chain)
        self.truncated = False           # True iff the max_tuples safety valve stopped the fixpoint early
        self.wall_seconds = 0.0
        self.peak_rss_kb = 0

    def as_dict(self):
        return dict(self.__dict__)


class Solver:
    """Semi-naive worklist solver. Build with Constraints + Policy, call solve()."""

    def __init__(self, constraints, policy=None, seeds=None):
        self.C = constraints
        self.P = policy or Policy()
        self.seeds = seeds                       # optional Step-3 Seeds (kernel-specific ObjectSeed/Install/summary)
        self.stats = Stats()

        # points-to state: node -> set(obj).  node is str (value) or (root, off) tuple (memory cell).
        self.pt = collections.defaultdict(set)
        # static / dynamically-grown copy edges: src_node -> list(dst_node)
        self.copy_edges = collections.defaultdict(list)
        # field edges: src_node -> list((dst_node, K))
        self.field_edges = collections.defaultdict(list)
        # dynamic-offset edges: src_value -> list(dst_value)
        self.dyn_edges = collections.defaultdict(list)
        # load/store: pointer value -> list(dst value) / list(src value)
        self.load_ptr = collections.defaultdict(list)
        self.store_ptr = collections.defaultdict(list)
        # indirect call: callee-pointer value -> list(callsite)
        self.callee_of = collections.defaultdict(list)

        self.calltargets = set()                 # {(callsite, func_name, kind)}
        self._wired = set()                      # {(callsite, func_name)}

        # kernel-specific dispatch relations from api_summaries (name-keyed, not byte offsets)
        self.named_mem = collections.defaultdict(set)   # (dispatch_object_id, op_name) -> {handler_name}
        self.selectors = collections.defaultdict(set)   # (dispatcher_name, cmd_key)    -> {handler_name}
        self.install_edges = []                  # (root, root_object, dispatch_object_id, seed_id) for output

        # derivation: (node, obj) -> (rule, pred_node_or_None, pred_obj_or_None, cid_or_None)
        self.prov = {} if self.P.provenance else None

        self.work = collections.deque()
        self.pending = collections.defaultdict(set)
        self._inq = set()
        self._ntuples = 0                        # live points-to tuple count (for the safety valve)

    # -- offset saturation ---------------------------------------------------------------------------------
    def _mk_field(self, obj, k):
        root, off = obj
        if off is DYN:
            return (root, DYN)
        no = off + k
        sz = self.C.obj_size.get(root, 0)
        if self.P.saturate_by_size and sz > 0:
            if no >= sz or no < -sz:
                self.stats.saturated_offsets += 1
                return (root, DYN)
            return (root, no)
        if -HARD_CAP <= no <= HARD_CAP and (sz > 0 or -UNKNOWN_CAP <= no <= UNKNOWN_CAP):
            return (root, no)
        self.stats.saturated_offsets += 1
        return (root, DYN)

    # -- points-to insertion -------------------------------------------------------------------------------
    def _enqueue(self, node):
        if node not in self._inq:
            self._inq.add(node)
            self.work.append(node)

    def _add(self, node, objs, rule, pred_node, cid):
        """Add a set of objects to node's points-to set (pred_obj == obj: copy/load/store/return)."""
        cur = self.pt[node]
        fresh = None
        pend = self.pending[node]
        for o in objs:
            if o not in cur:
                cur.add(o)
                pend.add(o)
                self._ntuples += 1
                fresh = True
                if self.prov is not None:
                    self.prov.setdefault((node, o), (rule, pred_node, o, cid))
        if fresh:
            self._enqueue(node)

    def _add_one(self, node, obj, rule, pred_node, pred_obj, cid):
        cur = self.pt[node]
        if obj not in cur:
            cur.add(obj)
            self.pending[node].add(obj)
            self._ntuples += 1
            if self.prov is not None:
                self.prov.setdefault((node, obj), (rule, pred_node, pred_obj, cid))
            self._enqueue(node)

    # -- build the initial graph + seeds -------------------------------------------------------------------
    def _build(self):
        C = self.C
        for dst, root, off, cid in C.addr_of:
            self._add_one(dst, (root, off), "ADDR_OF", None, None, cid)
        if self.P.unknown == "opaque":
            for dst, root, cid in C.unknown_addr:
                self._add_one(dst, (root, 0), "UNKNOWN_ADDR", None, None, cid)
        else:
            self.stats.unknown_dropped = len(C.unknown_addr)
        for dst, src, cid in C.copy:
            self.copy_edges[src].append(dst)
        for dst, src, k, cid in C.field:
            self.field_edges[src].append((dst, k))
        if self.P.field_dynamic == "root_dyn":
            for dst, src, cid in C.field_dyn:
                self.dyn_edges[src].append(dst)
            self.stats.dyn_field_edges = len(C.field_dyn)
        else:
            self.stats.dyn_field_dropped = len(C.field_dyn)
        for dst, ptr, cid in C.load:
            self.load_ptr[ptr].append(dst)
        for ptr, src, cid in C.store:
            self.store_ptr[ptr].append(src)
        for obj, off, src, cid in C.store_object:
            # STORE_OBJECT is an unconditional copy edge  src_value -> cell(object, off).
            self.copy_edges[src].append(self._mk_field((obj, 0), off))
        for cs, val in C.indirect:
            self.callee_of[val].append(cs)
        # MEMCPY/MEMMOVE (pointer-bearing aggregate copies) are recognized but not field-expanded in this
        # first engine; count them so the omission is explicit, never a silent drop.
        self.stats.memcpy_unmodeled = len(C.memcpy)
        # Direct call targets are unconditional: wire them immediately.
        for cs, fname in C.direct:
            self._wire_call(cs, fname, "direct")
        if self.seeds is not None:
            self._apply_seeds()

    # -- kernel-specific Step-3 seeds/summaries ------------------------------------------------------------
    def _apply_seeds(self):
        """Inject ObjectSeed + Install (registration_seeds) and the name-keyed dispatch edges
        (api_summaries) so the closure can walk syz-root -> installed dispatch object -> handler."""
        seeded_roots = set()
        for root_id, disp_obj, _kind, sid in self.seeds.install:
            root_obj = "seed:object:root:" + root_id
            root_val = "seed:value:root:" + root_id
            # ObjectSeed: the synthetic kernel object a variant of this resource denotes.
            self._add_one(root_val, (root_obj, 0), "OBJECT_SEED", None, None, sid)
            # Install: the fops/ops object is mounted on the root's dispatch slot (slot 0 -- the exact
            # subsystem byte offset is not carried by the seed; refined against a real load in Step 7).
            self._add_one((root_obj, 0), (disp_obj, 0), "INSTALL", root_val, (root_obj, 0), sid)
            self.install_edges.append((root_id, root_obj, disp_obj, sid))
            seeded_roots.add(root_id)
        self.stats.install_seeds_applied = len(self.seeds.install)
        self.stats.roots_seeded = len(seeded_roots)
        for obj, op, handler, _sid in self.seeds.dispatch_field:
            self.named_mem[(obj, op)].add(handler)
        for disp, key, handler, _sid in self.seeds.cmd_selector:
            self.selectors[(disp, key)].add(handler)
        self.stats.dispatch_fields_applied = len(self.seeds.dispatch_field)
        self.stats.cmd_selectors_applied = len(self.seeds.cmd_selector)

    # -- on-the-fly call wiring ----------------------------------------------------------------------------
    def _wire_call(self, callsite, fname, kind):
        key = (callsite, fname)
        if key in self._wired:
            return
        self._wired.add(key)
        self.calltargets.add((callsite, fname, kind))
        if kind == "direct":
            self.stats.call_targets_direct += 1
        else:
            self.stats.call_targets_indirect += 1
        formals = self.C.formals.get(fname)
        if formals:
            for idx, actual in self.C.actuals.get(callsite, {}).items():
                formal = formals.get(idx)
                if formal is not None:
                    self.copy_edges[actual].append(formal)
                    self._add(formal, self.pt.get(actual, ()), "ARG", actual, None)
        result = self.C.results.get(callsite)
        if result is not None:
            for retval in self.C.returns.get(fname, ()):
                self.copy_edges[retval].append(result)
                self._add(result, self.pt.get(retval, ()), "RET", retval, None)

    # -- main loop -----------------------------------------------------------------------------------------
    def solve(self, max_tuples=None):
        """Run the semi-naive worklist to a fixpoint. max_tuples is an explicit, honest safety valve: if the
        live points-to tuple count exceeds it the solve stops and stats.truncated is set (never a silent
        truncation). It exists because a few large batches exhibit the classic Andersen field x copy-cycle
        blow-up that the full run will address with cycle elimination; it is not needed for small batches."""
        t0 = time.perf_counter()
        self._build()
        pt = self.pt
        pending = self.pending
        while self.work:
            if max_tuples is not None and self._ntuples > max_tuples:
                self.stats.truncated = True
                break
            node = self.work.popleft()
            self._inq.discard(node)
            delta = pending.pop(node, None)
            if not delta:
                continue
            self.stats.pops += 1

            for dst in self.copy_edges.get(node, ()):
                self._add(dst, delta, "COPY", node, None)

            fe = self.field_edges.get(node)
            if fe:
                for dst, k in fe:
                    for o in delta:
                        self._add_one(dst, self._mk_field(o, k), "FIELD_ADDR", node, o, None)

            de = self.dyn_edges.get(node)
            if de:
                for dst in de:
                    for o in delta:
                        self._add_one(dst, (o[0], DYN), "FIELD_ADDR_DYNAMIC", node, o, None)

            ld = self.load_ptr.get(node)
            if ld:
                for o in delta:                  # o is a memory cell `node` now points at
                    for dst in ld:               # dst = *node : add a copy edge cell(o) -> dst
                        self.copy_edges[o].append(dst)
                        self._add(dst, pt.get(o, ()), "LOAD", o, None)

            st = self.store_ptr.get(node)
            if st:
                for o in delta:
                    for src in st:
                        self.copy_edges[src].append(o)
                        self._add(o, pt.get(src, ()), "STORE", src, None)

            co = self.callee_of.get(node)
            if co:
                for o in delta:
                    root, off = o
                    if off == 0 and root in self.C.func_name:
                        fname = self.C.func_name[root]
                        for cs in co:
                            self._wire_call(cs, fname, "indirect")

        self._finalize(t0)
        return self

    def _finalize(self, t0):
        s = self.stats
        s.wall_seconds = time.perf_counter() - t0
        s.peak_rss_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        s.call_targets = len(self.calltargets)
        vt = mt = vn = mn = 0
        contaminated = 0
        for node, objs in self.pt.items():
            if isinstance(node, str):
                vn += 1
                vt += len(objs)
                if any(self._is_unknown(o[0]) for o in objs):
                    contaminated += 1
            else:
                mn += 1
                mt += len(objs)
        s.pt_tuples = vt
        s.mem_tuples = mt
        s.value_nodes = vn
        s.mem_nodes = mn
        s.pt_with_unknown = contaminated
        if self.seeds is not None:
            self._index_dispatch()
            roots = {e[0] for e in self.install_edges}
            reach_disp = reach_handler = 0
            for root_id in roots:
                disp = self.root_dispatch_objects(root_id)
                if disp:
                    reach_disp += 1
                if any(self.dispatch_handlers(d) for d in disp):
                    reach_handler += 1
            s.roots_reaching_dispatch = reach_disp
            s.roots_reaching_handler = reach_handler

    def _index_dispatch(self):
        """One-pass indices for O(1) dispatch-object handler lookup: api_summaries op-name edges by object,
        and STORE_OBJECT byte-offset function values by object."""
        self._named_by_obj = collections.defaultdict(dict)   # obj -> {op_name: {handler}}
        for (obj, op), handlers in self.named_mem.items():
            self._named_by_obj[obj][op] = set(handlers)
        self._func_field = collections.defaultdict(dict)     # obj -> {byte_off: {handler_fn}}
        for node, targets in self.pt.items():
            if isinstance(node, str):
                continue
            root, off = node
            fns = {self.C.func_name[t] for (t, toff) in targets
                   if toff == 0 and t in self.C.func_name}
            if fns:
                self._func_field[root][off] = fns

    def _is_unknown(self, root):
        return ":object:unknown:" in root

    # -- seeded-root dispatch queries (the four-edge composition over the closure) -------------------------
    def root_dispatch_objects(self, root_id):
        """Dispatch objects installed on a seeded syz root: MemPt(root_object @ 0)."""
        cell = ("seed:object:root:" + root_id, 0)
        return sorted({o[0] for o in self.pt.get(cell, ())})

    def dispatch_handlers(self, dispatch_object):
        """Handlers reachable from a dispatch object as {op_key: {handler}}. Two sound sources, unioned:
        api_summaries dispatch_field (op NAME key) and the generic STORE_OBJECT closure (byte-OFFSET key,
        rendered '@<off>'). Op names and byte offsets stay distinct keys -- never merged by struct type."""
        out = {}
        for op, handlers in getattr(self, "_named_by_obj", {}).get(dispatch_object, {}).items():
            out[op] = set(handlers)
        for off, fns in getattr(self, "_func_field", {}).get(dispatch_object, {}).items():
            out["@%s" % off] = set(fns)
        return out

    # -- derivation replay ---------------------------------------------------------------------------------
    def derivation_chain(self, node, obj, limit=64):
        """Walk predecessor links back to a base seed, returning the list of derivation steps for the tuple
        (node -> obj). Requires policy.provenance. Each step is (rule, node, obj, cid)."""
        if self.prov is None:
            return []
        chain = []
        cur = (node, obj)
        seen = set()
        while cur is not None and cur not in seen and len(chain) < limit:
            seen.add(cur)
            rec = self.prov.get(cur)
            if rec is None:
                break
            rule, pred_node, pred_obj, cid = rec
            chain.append((rule, cur[0], cur[1], cid))
            if pred_node is None or pred_obj is None:
                break
            cur = (pred_node, pred_obj)
        return chain

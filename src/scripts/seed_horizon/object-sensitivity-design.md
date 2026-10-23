# On-demand object-sensitivity — relation/schema and fixpoint design

Status: design approved; P1 complete; P2 node arena, incremental installers, complete template
indexing, and real context-body materialization complete; direct receiver watches next
(2026-07-18). Per the decision that
Stage-A convergence requires object-sensitivity (see
`step4-stagea-indirect-and-convergence-findings.md` §13). This document specifies the
object-context **schema/relations** and the **on-demand creation protocol**. P1 implements and
tests the static schema; P2 will connect it to the solver worklist.

## 0. Why (one paragraph, from the diagnosis)

The full-kernel round-3 truncation is a **call-context object merge**, not affine and not
offset-proliferation (affine memory = 0.0001% of tuples; subsumption vs none identical). ~1175
`platform_device` roots merge at a device-model formal; their embedded rb_nodes/kobjects then
reach the **generic container ops** `rb_erase` / `__kobject_del` (memory_constraints.tsv:5067 /
:3115) through a single dedicated callsite, and the self-linking store `node->@8 = other`
connects all 1175 to each other → an ~1175² concrete-memory clique across thousands of cells.
The objects are **distinct upstream** and only merge at the call context, so keying each
callee's context by its **receiver object root** separates them, treats the root cause, and
collapses the quadratic (1175² → 1175). This replaces, for single-receiver functions, the
bootstrap+overflow-deferral+frontier-promotion stack with one object-sensitive fixpoint.

## 1. Non-negotiable invariants (prohibitions)

These hold by construction; every mechanism below is checked against them.

1. **No semantic per-function object cap.** A callee reached by K distinct receiver roots gets
   K contexts. No "top-B roots" cap, no drop, no widening of the root set.
2. **No deferral of direct flow.** Object-sensitivity *separates*; it never drops arg/return
   edges. `deferred_direct_transfers` must be 0 in the final run (the accounting added in §11 of
   the findings stays as the gate).
3. **Never decide sensitivity from a truncated solve.** Receiver-formal selection is *static*
   (§3). Contexts are created the instant a receiver object tuple first reaches a call actual
   (§5) — before any merge can form. There is no detect-from-hotspots step.
4. **No name-based enabling.** Nothing keys on `device` / `kobject` / `rb_erase` / subsystem /
   handler names. Selection is purely structural (dereference reachability).
5. **Soundness of stores.** Stores are never split by "distinct source". Precision comes only
   from a more precise receiver (fewer roots per context), never from discarding may-edges.
6. **Full provenance on any residual union.** Multi-receiver functions and unknown receivers use
   an explicit shared/union context (§3, §7), counted and reported — flow is never silently
   lost.

## 2. Context identity — the `ObjectContext` relation

```
ObjectContext = (callee_function, receiver_formal_index, receiver_root)
context_id     = intern(ObjectContext)                       -- dense, allocated on demand
```

- **`receiver_root`** is an *allocation / global object identity* — the `ObjKey.root` only,
  **never** a byte offset or affine region. Consequences:
  - The embedded `struct device` at `pdev@16` and a pointer to `pdev@0` share the same
    `receiver_root = pdev`. A field of the receiver is still "the same object".
  - `rb_erase` invoked on `dev->some_node` (root `dev`, offset o) keys on `dev`, so the whole
    device's container ops stay in the device's context.
- **Reuse:** `(callee, formal_index, root)` is **globally shared**. Every callsite of `callee`
  that passes `root` into `formal_index` maps to the *same* context. This is 1-object-sensitivity
  (no caller/call-string component): callers with the same receiver **merge**, different
  receivers **separate** — exactly the axis the clique needs.
- **`receiver_root` is identity, not field position.** Only an **explicit `ObjectKind::Unknown`**
  root maps to `SHARED_UNKNOWN`. A `root@DYN`, an affine region, or any other offset of a *known*
  object keeps its **concrete root** — we merely do not know the field, but the object identity
  is known, so it must **not** be downgraded to unknown (downgrading would re-merge the deep
  chain).
- **`SHARED_UNKNOWN` is a real, separate context.** `ObjectContext(F, i, SHARED_UNKNOWN)` has its
  **own** `context_id` (one per `(callee, formal_index)`), distinct from the baseline. It is a
  single conservative union context that receives receivers whose points-to includes an explicit
  unknown root, and external-entry / address-taken invocations (§7). Never per-unknown, never
  dropped, never folded into the baseline.
- **`context_id = 0` is the baseline / no-context identity** — a **distinct** thing from
  `SHARED_UNKNOWN`. The baseline body is retained through P1–P3, but a *selected*
  object-sensitive callsite feeds a concrete or `SHARED_UNKNOWN` context, **never the baseline
  formal**. So the baseline of an object-sensitive `F` is left unfed (a retained template used by
  non-object-sensitive functions and for identity), and unknown/external flow lands in the real
  `SHARED_UNKNOWN` context rather than polluting the baseline.
- **Monotone unknown→concrete:** when a receiver first resolves only to an unknown root and later
  also to a concrete root, the concrete context is created then; the already-added unknown edge
  is **kept** (never deleted) — the fixpoint only adds.

## 3. Receiver-formal selection (fully structural, static)

A formal is a *receiver* if the object passed to it is **used as an object** — directly inside
the callee, **or** by being forwarded into another function's receiver formal. Intra-procedural
reachability alone is wrong: a wrapper that only forwards its pointer argument
(`g(p){ return h(p); }`) has no local dereference, would be judged zero-receiver, and the deep
chain would re-merge in the middle. So receiver-ness is an **inter-procedural backward least
fixpoint** over call-argument forwarding.

```
-- Local dereference base (intra-procedural, owner == F):
LocalDeref(F, v)   ⟺  v reaches (by F-owned copy/field/cast/phi, NON-call edges only, §4.1)
                       the base of a FIELD_ADDR / LOAD-addr / STORE-addr / indirect-callee.

-- Least fixpoint (backward through direct-call forwarding):
ReceiverFormal(F, i) ⟺  LocalDeref(F, formal_i)
                    ∨  ∃ call S in F to G, actual j = value w with formal_i ⤳_F w  (F-flow),
                          such that ReceiverFormal(G, j).
```

`⤳_F` is intra-procedural F-owned value-flow (the same non-call edges). The fixpoint is seeded
by `LocalDeref` and propagated backward over `(caller actual ← callee receiver formal)` until no
change. Indirect calls contribute an edge only for `(site, target)` pairs already resolvable
statically (address-taken → target); dynamically-discovered targets refine it at solve time but
the static seed is conservative (a formal reaching an indirect-callee base is already a receiver
via `LocalDeref`). Emitted as `receiver_formals(function, formal_index)`.

**Version 1 gate:** object-sensitivity is enabled for a function **iff it has exactly one
receiver formal**. Rationale: a unique receiver is an unambiguous "the object this function
operates on" — the rb_erase/kobject/device-cleanup shape. Functions with **≥2 receiver
formals** keep the existing **bootstrap-union** context (accounted separately as
`multi_receiver_union`), and functions with **0 receiver formals** are pure value transformers
that need no object context. No function is chosen or excluded by name; the gate is the arity of
the structural receiver set. (V2 may extend to k-receiver tuples; out of scope here.)

## 4. Node representation — `NodeKey = (template_component, context_id)`

We must **not** clone the whole value space per context. Each object-sensitive function `F`
already owns a bounded intra-procedural subgraph; we clone only that, and we reuse the baseline
copy-SCC.

### 4.1 Templates (built once, before solving)

- **Owned value set** `own(F) = { v : valueOwners[v] == F }` (formals, locals, returns).
- **Owned object set** `ownObj(F) = { o : objectOwners[o] == F }` (stack/local objects).
- **Template components** are the copy-SCC of `F` computed on a **restricted** graph:
  **only `owner == F` ordinary intra-procedural copies** (assignment/cast/phi). It **excludes**
  `CALL_ARGUMENT`, `CALL_RETURN`, and any cross-owner copy. The baseline whole-program SCC must
  **not** be reused directly, because it folds call edges and would merge a formal with values in
  other functions, collapsing the very separation we need. So the template SCC is a per-function,
  call-free component graph over `own(F)`. `templateStackObjects(F) = ownObj(F)`.
- A **template node ordinal** is the index of a component within `templateComponents(F)`.
- **Callsites are not body edges.** A direct/indirect call *inside* `F` is a **call template**
  (an edge `actual ⟶ callee receiver / formals`, `callee return ⟶ result`) that the on-demand
  protocol (§5) realizes by creating the *callee's* context and wiring into it — it is **never**
  instantiated as an ordinary intra-`F` copy edge. Thus instantiating `F`'s template lays down
  `F`'s internal copy/field/load/store edges only; the calls it makes spawn child contexts as
  their receiver roots arrive.

### 4.2 Instantiated nodes

```
NodeKey        = (template_component, context_id)
solver_node(k) = baseNode(context_id) + ordinalWithin(fn(context_id), template_component)
```

- `baseNode(context_id)` is a contiguous node range **allocated when the context is created**
  (dynamic `resizeNodes`), sized `|templateComponents(fn)|`. This is the on-demand analogue of
  today's `contextInfo.baseValue`, but keyed by object and created mid-fixpoint.
- **Baseline / shared nodes are never re-keyed.** A tuple whose value/object is *not* owned by
  `fn(context_id)` (a global, a heap object, another function's value) keeps its baseline node.
  Only `own(F)` / `ownObj(F)` members get context nodes. So global/memory objects stay shared;
  a receiver root `R` is a global/heap object → it stays one shared object, and the *context*
  distinguishes *which* `R` the callee body is specialized for.
- **Stack objects:** `ownObj(F)` members become `(template_stack_object, context_id)` cells, so
  two device-cleanup invocations on distinct roots get distinct local temporaries.
- **SCC reuse:** because a context node is `(baseline_component, context_id)`, the *shape* of
  `F`'s internal dataflow (its component graph and intra-edges) is the baseline template; the
  context only renumbers it. No per-context SCC recomputation.

### 4.3 Origin / rendering

`contextValueOrigins[node] = representative baseline value` (as today), plus a parallel
`nodeContext[node] = context_id` so `renderNode` prints
`ctxObj:<receiver_root>[<callee>:<template_value>]`. This makes acceptance-test inspection and
provenance direct.

### 4.4 Concrete solver interfaces (P2 audit, 2026-07-17)

The existing solver cannot append a context node directly. It currently treats
`node < valueCount_` as "value" and computes every memory node as `valueCount_ + memory_index`.
Once a memory cell has been created, inserting a context node would either renumber that cell or
make the arithmetic classification false. P2 therefore starts with a semantics-preserving node
namespace refactor:

```
SolverNodeKind = BaselineValue | ContextValue | Memory

SolverNodeArena::allocateMemory(memory_index) -> node
SolverNodeArena::allocateContextBlock(context_id, component_origins) -> [base, count)
SolverNodeArena::kind(node)
SolverNodeArena::memoryIndex(node)
SolverNodeArena::context(node)
SolverNodeArena::origin(node)
SolverNodeArena::core(node)
```

- Node ids come from one append-only allocator. Memory and context nodes may interleave; no code
  may derive node kind or memory index by comparing/subtracting `valueCount_`.
- `memoryNodeByIndex[index]` is the reverse map used by alias/memcpy/output paths.
- `ObjectContextNodes` becomes a range/mapping layer over the solver allocator; it must not own
  an independent `nextNode` once used by the production solver.
- Baseline nodes retain context `0`; object contexts use ids `>=1`. Legacy callsite-context
  reporting may continue to print `NONE` as "baseline", but that encoding is converted only at
  the reporting boundary and is not a runtime node identity.

Dynamic template creation also requires a uniform incremental edge-install API. `addCopyEdge`
already replays every tuple currently on its source; the build-only field/load/store insertion
paths do not. Before receiver watches are enabled, P2 must factor the following installers so
each newly installed edge observes both old and future source tuples exactly once:

```
installCopy(src, dst, rule, source)
installField(src, dst, offset/type/policy, source)
installDynamicField(src, dst, type, source)
installStridedField(src, dst, affine/expansion policy, source)
installLoad(pointer, result, source)
installStore(pointer, value, source)
installMemcpyWatch(dst_pointer, src_pointer, size, source)
installIndirectWatch(callee_node, call_instance)
```

The replay operation uses the same per-tuple transfer routine as the worklist loop; it does not
run a second approximate analysis and does not inspect a truncated result.

Calls are instantiated by **call instance**, not by static site alone:

```
CallInstance = (kind, static_site_index, caller_context, target_function?)
ReceiverWatch = (call_instance, callee_function, receiver_formal_index, receiver_actual_node)
CallWireKey = (call_instance, callee_context)
```

- The baseline body creates `(site, context=0)` call instances. Instantiating context `C` for
  function `F` creates call instances `(site, C)` for every direct/indirect call template owned
  by `F`, with actual/result/callee nodes mapped through `ctxNode(., C)`.
- A direct unique-receiver target installs a watch on that instance's receiver actual. Each new
  receiver root creates/reuses `(callee, formal, root)`, instantiates the callee body once, and
  wires every actual and return for that **same caller instance**. Dedup is therefore
  `(site, caller_context, callee_context)`, not `(site, callee_context)`.
- Non-object-sensitive callees retain their existing union/bootstrap path during P2. P3 applies
  the same call-instance interface to dynamically discovered indirect targets; no promoted-site
  clone is part of the final object-sensitive path.
- Runtime call-transfer accounting records solver node ids plus original value ids. Context
  nodes are not synthetic `Database::values`, so reporting must not require cloned value ids.

## 5. On-demand creation protocol (inside the fixpoint)

### 5.1 Direct call

At solver build time, for every direct call site `S: caller → F(actuals)` where `F` is
object-sensitive with receiver formal `i`, install a **receiver watch** on the actual node
`A = valueNode(actual_i)` (same mechanism family as `indirectWatches_`), carrying `(S, F, i)`.

When `A` gains a new tuple `Pt(A) ∋ root@offset`:

```
ensureReceiverContext(F, i, receiverRootOf(root@offset)):        // §2 identity, dedup
    ctx := intern(F, i, root)
    if ctx is new:
        allocate baseNode(ctx); resizeNodes
        instantiateTemplate(F, ctx)      // §5.3 — replays existing source tuples on each edge
    wireCallIntoContext(S, ctx):
        for each actual j of S with a matching formal f_j of F:
            addCopyEdge( valueNode(actual_j) , ctxNode(f_j, ctx) , CallArgument )   // replays
        for each return r of F:
            addCopyEdge( ctxNode(r, ctx) , valueNode(S.result) , CallReturn )       // replays
```

- `receiverRootOf(root@offset)` returns the **concrete `root`** (offset/affine/DYN dropped, since
  identity is known); it returns `SHARED_UNKNOWN` **only** when `root` is an explicit
  `ObjectKind::Unknown` object.
- The **watch waits for a tuple.** "No receiver tuple yet" is *not* unknown and must **not**
  pre-create the union context — a context is created only when a real receiver object arrives.
- **Baseline is never fed by selected callsites.** A selected object-sensitive callsite wires
  into a concrete `(F,i,root)` context or the `(F,i,SHARED_UNKNOWN)` context — **never** the
  baseline formal (`context_id=0`), which stays a retained-but-unfed template (§2). Every
  callsite's flow still lands in *some* context (concrete per root, or `SHARED_UNKNOWN` for an
  explicit-unknown / external receiver), so no direct flow is dropped (invariant #2).
- Because the watch fires per distinct `root`, a callsite passing N roots lands in N contexts —
  it *separates at the actual*, which is exactly what prevents the merged formal.

### 5.2 Indirect call (closed in the same fixpoint — no promotion rounds)

Indirect dispatch already resolves `(indirect_site, target F)` when the callee value's tuple
gains a function object (`wireIndirect`). Extend it: when `(site, F)` is discovered **and** F is
object-sensitive, treat the indirect site like a direct call to F for context purposes — install
the receiver watch on the site's receiver actual and run `ensureReceiverContext` as tuples
arrive. Thus:

- Discovery of the target and creation of its object context happen in **one** fixpoint; there
  is no dependence on a previous round's promotion, and no separate frontier iteration.
- The incremental join is on `(target_function, receiver_root)` — same dedup as direct.

This subsumes the indirect-target frontier for the object-sensitive case; `deferredIndirectPairs`
for these targets goes to 0.

### 5.3 Template instantiation & edge replay

`instantiateTemplate(F, ctx)` walks `F`'s call-free intra-procedural constraints (copies,
field/strided, load/store) and adds each edge with both endpoints re-keyed through
`ctxNode(·, ctx)` for owned members and left baseline for shared members. Each `addCopyEdge` /
field/load/store install **immediately replays existing source tuples** (today's `addCopyEdge`
already iterates `tupleHead_[src]`), so a context created after its inputs already resolved still
converges. Instantiation is idempotent per `ctx` (guarded by "is new").

## 6. Interaction with existing machinery

- **Bootstrap contexts** remain **only** for multi-receiver functions (§3) and are recorded as
  `multi_receiver_union`. Single-receiver functions no longer take bootstrap contexts.
- **Overflow deferral** (`deferFlowSites`) is **removed from the object-sensitive path**: the
  reason it existed (mega-fan-in utilities merging a data arg) is now handled by object-sensitivity
  when that arg is a receiver, or is a genuine value-union for non-receiver args (kept, sound).
  The `deferred_direct_transfers` gate stays and must reach 0.
- **strstr / direct broadcast**: strstr's string arg is a receiver (it is dereferenced), so
  object-sensitivity separates its callers by string root — the original direct-broadcast class
  is handled by the same mechanism, not by callsite contexts.
- **Discovery mode / frontier**: retained as a thin driver only to *enumerate* indirect targets
  for reporting; the actual target closure now happens inside the object-sensitive fixpoint
  (§5.2). If it proves fully redundant it is deleted in a later pass.

## 7. Unknown / conservative union

The `(callee, receiver_formal)` `SHARED_UNKNOWN` context (its own `context_id`, §2) receives
**only**:
- receiver tuples whose `root` is an explicit `ObjectKind::Unknown` object, and
- external-entry / address-taken invocations of `F` (a root/handler entry or an indirect call
  before any receiver root is known) — these get a home in `SHARED_UNKNOWN`, **not** in the
  baseline.

It does **not** receive: a `root@DYN` / affine / non-zero offset of a *known* object (that keeps
its concrete root, §2), nor a "not-resolved-yet" receiver (the watch simply has not fired). If a
receiver's points-to later gains a concrete root, its concrete context is created then and the
earlier unknown edge is kept (monotone, §2) — there is no re-homing bookkeeping.

This guarantees no dropped flow (invariant #6) while keeping unknown receivers from spawning
unbounded contexts, and keeps the baseline uncontaminated (decision, §2).

## 8. Complexity / termination

- Contexts per function ≤ (distinct receiver roots reaching it) + 1 (unknown). Finite: roots are
  a finite static set. No cap needed (invariant #1); the bound is the real object count, and the
  clique it replaces was `roots²`, so total work strictly decreases where a clique existed.
- The fixpoint still only ever **adds** tuples/edges/contexts monotonically → terminates.
- Node space grows on demand; `resizeNodes` already supported.

## 9. New relations / outputs (for the gate and audits)

```
receiver_formals(function, formal_index)                       -- static selection
object_contexts(context_id, callee, formal_index, receiver_root)
object_context_census: per callee — #contexts, #distinct_roots, unknown_union_size,
                       multi_receiver_union(bool), instantiated_template_nodes
clique_reduction: for the round-3 fixture — max distinct_store_roots per cell before/after
```

## 10. Acceptance order (maps the 8 required checks)

1. **Chain isolation** — selftest: two receiver roots `R1,R2` through a 7-hop, single-callsite
   chain `f1→…→f7`, each `fk` single-receiver; assert `fk`'s receiver never holds both `R1` and
   `R2` in one context, for all k.
2. **Cross-caller reuse** — two callers passing the same root `R` into `F` share one
   `context_id`; distinct roots do not.
3. **No N² clique** — N single-receiver container ops storing `node->@8=other` on N distinct
   roots yield O(N) store-cell tuples, not O(N²); assert max `distinct_store_roots` per cell = 1.
4. **Indirect closure in one fixpoint** — an indirect dispatch to `F` with receiver `R` creates
   `(F,i,R)` and closes its body in the same solve, with no promotion input.
5. **Unknown union** — a receiver with an unknown root lands in `SHARED_UNKNOWN`, flow preserved,
   exactly one such context per `(F,i)`.
6. **Determinism / 5-batch** — object-context assignment is a deterministic function of inputs;
   5-batch subset matches across reruns and shows the clique gone.
7. **round-3 reproduction** — the 7,923-target fixture solves with `deferred_direct=0` and
   `truncated=false`.
8. **Full kernel** — `pending=0 && truncated=false` end-to-end.

Acceptance checks 1–5 are unit-level synthetic databases. The completed P1 implementation is
covered by the current **82/82** selftest suite; P2 adds the runtime protocol checks. Checks 6–8
are full-data runs gated in order.

## 11. Implementation phases

- **P0 (this doc).** Schema/relations + protocol — review gate.
- **P1 — complete (82/82 selftests).** Static: add the `receiver_formals`
  **inter-procedural backward fixpoint** (§3), the
  per-function **call-free** `templateComponents(F)` SCC (§4.1), the `object_contexts` interner
  (with the distinct baseline `0` and per-`(F,i)` `SHARED_UNKNOWN` ids, §2), and `nodeContext`.
  Tests cover receiver selection (including a pointer-forwarding wrapper), context identity,
  local copy-SCC collapse, exclusion of call/cross-owner copies, stack-object ordinals,
  `nodeContext`/origin, shared baseline values, and two-root isolation through a deep forwarding
  chain. **No production fixpoint change yet.** Eager context materialization is used **only on
  synthetic/unit fixtures**; it never picks receiver roots from a truncated full-kernel baseline
  (invariant #3). Full-data validation waits for P2's on-demand creation.
- **P2 — in progress.** On-demand: receiver watches + `ensureReceiverContext` + `instantiateTemplate` with
  replay, driven inside `solve()`. Implementation order is: unified node arena (§4.4), incremental
  edge installers/replay, template constraint indexes, direct-call instances + receiver watches,
  then stack-object contexts and accounting. The unified append-only `SolverNodeArena` slice is
  complete; field/dynamic/strided/load/store/memcpy/indirect-watch installers now replay historical
  tuples through the same `apply*` functions used for future worklist tuples. Complete body/call
  constraint indexes and arena-backed context body/stack-object materialization are also complete
  and tested. Production receiver watches are not enabled yet. Acceptance 1–5.
- **P3.** Indirect integration (§5.2); remove single-receiver bootstrap + overflow deferral from
  this path. Acceptance 4, 7.
- **P4.** Full-kernel convergence + gate outputs (§9). Acceptance 6, 8.

Resolved decisions (2026-07-17 review):
- (a) **V1 unique-receiver gate: accepted.** No arbitrary first-of-two choice; `multi_receiver_union`
  is fully accounted and its residual measured.
- (b) **`SHARED_UNKNOWN`: explicit-unknown only.** Only `ObjectKind::Unknown` roots enter it; the
  watch waits for a real tuple (unresolved ≠ unknown); `root@DYN`/affine keep their concrete root;
  a later concrete root spawns its context while the unknown edge is kept (monotone). No re-homing
  bookkeeping.
- (c) **Baseline stays distinct.** `context_id=0` is a separate baseline/no-context identity;
  `(F,i,SHARED_UNKNOWN)` has its own id. The baseline body is retained P1–P3 but selected
  object-sensitive callsites never feed the baseline formal; external-entry / explicit-unknown
  receivers go to the real `SHARED_UNKNOWN` context, not the baseline.

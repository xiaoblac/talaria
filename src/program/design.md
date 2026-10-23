# Program Component Design

## 1. Scope

`program/` owns the **typed program model** of reFuzz: the in-memory program
IR (`Prog` / `Call` / `Arg`), the schema it is built against (`Target` /
`Type` / `SyscallMeta` / `ResourceDesc`), the codecs that move programs
between wire formats, and the structural primitives every other module
builds on (clone, sanitize, minimize-context, serialize-for-exec).

It is the substrate, not the fuzzer. `program/` does not select inputs,
mutate them, drive coverage, or talk to a worker. Those callers live in
`mutator/`, `corpus/`, `executor/`, `crash/`, `feedback/`. They consume
`program/` through three clean entry surfaces:

- a **neutral / target-agnostic** API rooted at `IProgram` / `ProgramArtifact`
  / `IProgCodec` — used by stages, corpus, persistence;
- a **typed V2 IR** rooted at `refuzz::program::syz::Target` / `Prog` /
  `Type` / `Arg` — used by syz mutator, exec-wire encoder, sanitize,
  minimize, repro;
- a **worker-facing C view** rooted at `SyzTargetTables` / `PseudoMeta`
  in `syz/pseudo/target_view.hpp` — consumed only by
  `executor/channel/worker/` for pseudo-call dispatch.

## 2. Component Map

```
              corpus / mutator / repro / executor / tests
                                 │
                                 ▼
                  ┌───── neutral artifact / format API ─────┐
                  │  IProgram / ProgFormat / IProgCodec     │   ① target-agnostic
                  │  ProgramArtifact / ProgramTargetKey     │
                  │  ArtifactMaterializerRegistry           │
                  │  Seed (artifact + bytes)                │
                  └───────────────┬─────────────────────────┘
                                  │
                                  ▼
              ┌────────────── syz typed IR (V2) ─────────────┐
              │  Target  ──── arena ─── Type tree            │   ② class A schema fact
              │     │       (TypeArena, ResourceArena)       │      class B derived index
              │     ├── SyscallMeta[]                        │
              │     ├── Const / Flag / SpecialPointer maps   │
              │     ├── SpecialTypes registry  ──────────────┼──→ ⑤ linux SpecialType bodies
              │     └── ChoiceTable (handle into mutator/)   │      (program/src/syz/linux/)
              │                                              │
              │  Prog ── Call[] ── Arg tree                  │
              │  Encoding (text)  · Exec wire (binary)       │
              │  Clone · Sanitize · Validate · MinimizeCtx   │
              └───────────────┬──────────────────────────────┘
                              │
        ┌─────────────────────┴────────────────────┐
        ▼                                          ▼
  ③ generated schema                    ④ generated worker-facing view
  syz/generated/consts.gen.hpp          syz/pseudo/target_view.hpp
  src/syz/generated/                    syz/pseudo/generated/
   target_linux_amd64_*.gen.cpp           pseudo_meta.gen.hpp
                                          target.gen.hpp
                                          syz_tables.gen.hpp
        │                                          │
        ▼                                          ▼
   tools/syzgen target-cpp                 tools/syzgen pseudo / target
   tools/syzgen consts                     (CMake -pseudo-out)
   (CMake -consts-out)                     consumed by executor/channel/worker/
```

| # | Class                                     | Where                                                                                           |
|---|-------------------------------------------|-------------------------------------------------------------------------------------------------|
| ① | Neutral artifact / format API             | `include/refuzz/program/{artifact,artifact_materializer,raw_bytes_artifact,seed,prog_cache,prog_codec,prog_format,codec_registry,types}.hpp` + `codec/` + `internal/` |
| ② | syz typed IR (V2)                         | `include/refuzz/program/syz/*.hpp` + `src/syz/*.cpp`                                            |
| ③ | syz target schema codegen (class-A fact)  | `src/syz/generated/target_linux_amd64_*.gen.cpp` (schema entities) + `include/refuzz/program/syz/generated/consts.gen.hpp` (consts dict) |
| ④ | Worker-facing pseudo metadata             | `include/refuzz/program/syz/pseudo/target_view.hpp` + `include/refuzz/program/syz/pseudo/generated/{pseudo_meta,target,syz_tables}.gen.hpp` |
| ⑤ | linux SpecialType bodies (class-C code)   | `src/syz/linux/special_types*.cpp` + `src/syz/linux/alg_tables.hpp`                              |
| ⑥ | linux SpecialType domain data             | `include/refuzz/program/syz/linux/generated/usb_ids.gen.hpp` + `src/syz/linux/generated/usb_ids.gen.cpp` (USB / HID device id DB, codegen from `init_vusb_ids.go`) |

## 3. Key Flows

### 3.1 Bytes → ProgramArtifact (corpus load / repro)

```
ArtifactMaterializerFn (built by profile)
  -> ArtifactMaterializerRegistry::dispatch(format, target_key, bytes)
     -> IArtifactMaterializer::Materialize(bytes)
        -> syz: TextDecoder(target).decode(text) -> Prog
                wrap in shared_ptr<const Prog> as typed_view
        -> raw_bytes: store bytes verbatim, no typed_view
  -> ProgramArtifact::Build(format, target, typed_view, typed_type,
                            canonical_bytes, canonical_provider)
```

Both formats produce a `ProgramArtifact`. Typed materializers populate
`typed_view`; bytes-only materializers leave it null. `As<T>()` is the
only typed-view accessor (gated to syz-owned modules per D2).

### 3.2 ProgramArtifact → bytes (persistence / wire emit)

`ProgramArtifact::canonical_payload()` returns `std::shared_ptr<const
std::vector<uint8_t>>`. If the artifact was built from a typed view it
runs the `CanonicalProvider` once (text encode under `std::call_once`)
and caches; if it was built from bytes it returns the stored bytes.
There is one canonical-bytes representation per artifact instance.

### 3.3 Typed mutation substrate

The mutator engine in `mutator/syz_v2/` does not own the IR primitives:

```
MutateTyped(artifact)
  -> artifact.As<Prog>()          // (program/) typed view
  -> Clone(prog, ctx)              // (program/syz/clone.hpp) deep copy
  -> mutator: choose op + arg path, edit clone in place
  -> Sanitize(clone, target)       // (program/syz/sanitize.hpp) repair
  -> Validate(clone, target)       // (program/syz/validation.hpp) gate
  -> ProgramArtifact::Build(format=kSyzProg, target, typed_view=clone,
                            typed_type=typeid(Prog), {}, encode-on-demand)
```

Every step except "choose op" is a `program/` primitive. Mutator policy
(which op, with what weights) lives in `mutator/`; the substrate is
shared.

### 3.4 Typed Prog → exec wire (executor submit)

```
Executor::Submit(prog)
  -> SerializeForExec(prog, target, out)   (program/syz/exec_wire.cpp)
     -> emit Copyin / SetProps / Call / Copyout instruction stream
  -> worker resolves syscall by NR via SyzTargetTables (target_view.hpp)
  -> on the worker side, ExecWireDecode reconstructs an exec-shape
     iterator (program/syz/exec_wire_decode.hpp) for trace replay
```

`serialize_for_exec` is the only allowed encode path on the runtime
hot path; oracle #20 fails the build if a non-Executor / non-repro
caller invokes it.

### 3.5 Target boot (one-time)

```
Target::linux_amd64()                  // singleton, lazily built
  -> arena.reserve_types(...)
  -> tools/syzgen target-cpp output:
       build_resources(target, resources_out)
       fill_types_part_001..011(target, resources, types)
       fill_syscalls(target, types)
       set_consts / set_flag_descs / set_special_pointers / ...
  -> register_special_type("timespec",  syz::linux::TimespecSpecial)
     register_special_type("sockaddr_alg", syz::linux::AlgSockaddrSpecial)
     ... (14 SpecialType callbacks)
  -> Target::finalize()
       build name/nr index, ConstMap, FlagsMap, resourceMap, ctor graph,
       AuxResources sort, timespec synthetic resource, max_real_nr.
```

`finalize()` is the contract that turns class-A schema rows into class-B
indexes. After it runs `Target` is read-only.

## 4. Representation Contract

The same logical program lives in three representations, each serving a
different consumer with non-substitutable requirements:

| Representation     | Held / produced by                                 | Consumers                                          | Why not collapsible                                                                  |
|--------------------|----------------------------------------------------|----------------------------------------------------|--------------------------------------------------------------------------------------|
| Typed Prog         | `syz::Prog` reached via `ProgramArtifact::As<>`    | mutator, sanitize, validate, minimize, repro       | Semantic ops (mutate arg, drop call, resource ref) need O(structure), not O(text)    |
| Canonical text     | `ProgramArtifact::canonical_payload()` — see §3.2  | disk (`payload.bin`), human, dedup hash, equality  | Stable, deterministic, human-readable; the only persistence format                   |
| Exec wire (binary) | `MaterializeExecWire(artifact)` — see §3.4         | worker only                                        | Worker has no parser; varint stream decodes per-syscall in a restricted environment  |

Four rules govern how these representations relate. Each one closes a
class of bugs that surfaced during V1 retirement (canonical text
submitted as exec wire, inflight registries left dangling on conversion
failure, dedup state drifting across restart). Violating any of them
re-opens that class.

### 4.1 Authoritative source is the typed view

`ProgramArtifact::As<Prog>()` is the single authoritative representation.
Canonical text and exec wire are **derived caches**, never peers. A
program is mutated only in its typed form; the other two representations
are read-only views computed from the typed source.

Corollary on `Seed`: when `Seed.artifact != nullptr`, `Seed.payload` is a
cache of the canonical text derived from the artifact. It is
informational — **not** an input the worker may consume directly. The
only legitimate case for `Seed.payload` to carry worker-bound bytes is
`Seed.artifact == nullptr` (bytes-only V1 / raw-AFL fallback), and that
case must be opt-in via an explicit profile capability bit. Producers
that admit a seed with `artifact != nullptr` are responsible for
normalizing `Seed.payload` to the canonical-text cache before it enters
any filter / hash / equality consumer; otherwise different admission
paths leave the in-memory cache in mutually inconsistent representations
(e.g. runtime admit holding exec wire, boot load holding canonical text),
and any byte-level filter downstream observes drift.

### 4.2 Transformation boundaries have single owners

Each conversion has exactly one named owner at one named boundary. No
other code may produce the target representation.

| Conversion              | Owner                                       | Boundary (see)        |
|-------------------------|---------------------------------------------|-----------------------|
| typed → canonical text  | `ProgramArtifact::canonical_payload()`      | §3.2                  |
| typed → exec wire       | `MaterializeExecWire` → `LowerToExecWire`   | §3.4 (executor submit)|
| bytes → typed (inbound) | `MakeArtifactFromCanonicalPayload`          | §3.1 (corpus / repro) |

Stages, mutators, admission dispatchers, and minimize drivers MUST NOT
roll their own canonical-text or exec-wire encoder. Oracle #20 already
enforces the exec-wire side at build time (`serialize_for_exec` may only
be called from executor / repro contexts); the canonical-text side is
enforced by convention plus the fact that `ProgramArtifact` exposes no
public text-encoder accessor — invoking `TextEncoder` directly from a
non-`program/` translation unit is the structural violation.

### 4.3 Horizontal conversion is illegal

Canonical text and exec wire are siblings, not interconvertible directly.
A consumer holding canonical bytes that needs wire bytes (or vice versa)
MUST go through the typed source:

```
canonical text  →  MakeArtifactFromCanonicalPayload  →  typed Prog  →  MaterializeExecWire  →  exec wire
```

Skipping the typed step — e.g. submitting canonical text to the worker
as if it were wire, or hashing wire bytes into a dedup index whose other
entries are canonical-text hashes — is a category error. The two
representations agree on program semantics only through the typed source;
their byte streams are not comparable. Any code that appears to need a
direct canonical↔wire conversion is signaling that an upstream producer
forgot to attach (or normalize from) an `artifact`; fix the producer,
not the conversion.

### 4.4 Conversion failure produces a terminal event

`MaterializeExecWire`, `MakeArtifactFromCanonicalPayload`, and any future
materializer return `std::expected<..., MaterializeError>`. The boundary
that invokes a materializer for an in-flight task is responsible for:

1. Logging the failure and incrementing a per-boundary metric.
2. **Synthesizing a terminal event** for the task — an `Abnormal` event
   carrying the original `executor_id` and trace, pushed to the same
   event queue as worker-produced events. Consumers waiting on the task
   observe an abnormal completion through their existing event handler;
   no new control flow is needed at the consumer.
3. Releasing inflight-registry / artifact-cache entries keyed on that
   `executor_id`.

Silently dropping the task is forbidden. The artifact-first pipeline
relies on inflight registries (channel dispatcher, reexec consumer,
minimize driver, fault-inject stage) that expect every submitted
`executor_id` to resolve to exactly one terminal event; a silent drop
leaks the registry slot and stalls any waiter.

## 5. Concurrency Model

- `Target` is constructed once (`linux_amd64()` singleton), then read-only
  for the lifetime of the process. No locks.
- `Prog` / `Call` / `Arg` instances are **not** thread-safe. Cross-thread
  hand-off goes through `Clone` (deep copy, deterministic by single
  `CloneCtx`) or through a `ProgramArtifact` (immutable snapshot).
- `ProgramArtifact` is immutable post-construction. `canonical_payload()`
  is the only synchronization point — `std::call_once` over the
  provider — and is safe to call from any thread.
- SpecialType callbacks run inside the mutator/encode call stack of
  whichever thread owns the `Prog`. They must not capture mutable shared
  state outside `Target`.

## 6. Adaptation to syzkaller

`program/` is the layer where reFuzz's module shape meets syzkaller's
description language. Three knobs map a syzkaller-class workload onto
the neutral substrate.

### 6.1 Two views of the same target

syzkaller exports one `prog.Target`. reFuzz consumes it as **two**
independent surfaces:

- a typed C++ `Target` (`syz/target.hpp`) — full schema, used by
  text codec / mutator / sanitize / validate / exec-wire encode.
- a flat C `SyzTargetTables` (`syz/pseudo/target_view.hpp`) — narrow,
  POD, no virtuals, no exceptions — used only by the worker for
  pseudo-call dispatch (NR base, max real NR, pseudo metadata table).

Both views are produced by the same `tools/syzgen` Go program against
the same syzkaller checkout (pinned via `.syzkaller-pin`), but emitted
under different headers and built separately. The worker therefore
never depends on the typed IR shape; the typed IR never depends on
the C view.

> Boundary debt: the worker driver currently includes `syz/target.hpp`
> for an `id → nr` translation. This is recorded as audit row #4 +
> `milestones/3.10-typed-program-pipeline.md:88-90`. The cleanup —
> moving `id → nr` into `SyzTargetTables` — is a separate, scheduled
> PR; nothing in `program/` is allowed to assume the worker holds a
> typed Target.

### 6.2 Codegen split: schema dict vs worker view

`tools/syzgen` writes two output trees, controlled by two CMake variables:

| Variable                 | Tree                                                            | Subcommands                            |
|--------------------------|-----------------------------------------------------------------|----------------------------------------|
| `REFUZZ_SYZ_CONSTS_DIR`  | `program/include/refuzz/program/syz/generated/`                 | `consts`, `target-cpp` (schema entities go to `program/src/syz/generated/`) |
| `REFUZZ_SYZ_PSEUDO_DIR`  | `program/include/refuzz/program/syz/pseudo/generated/`          | `pseudo`, `target`                     |

`syz_regen` runs both. `syz_verify` re-runs both into a tempdir and
diffs against the checked-in tree (byte-equal contract). `runAll`
emits the union: consts dict + pseudo meta + target identity +
aggregation include. The V1 IR table emitters (flags / types /
resources / syscall_table headers) were retired with the V1 IR; they
are physically gone from `tools/syzgen/main.go` so `syz_regen` cannot
silently resurrect them.

### 6.3 SpecialType injection

syzkaller's `Target.SpecialTypes` is a `map[string]func(...)` of
domain-aware constructors (timespec, sockaddr_alg, netfilter, USB,
…). reFuzz mirrors this via `Target::register_special_type(name, fn)`
+ `Target::find_special_type(name)`. The bodies live in
`program/src/syz/linux/` and talk back to the IR through the
`Target::IGen` vtable so they compose with the generic generator
without knowing about its internals. Domain reference data (USB / HID
device IDs) is codegen'd from upstream `init_vusb_ids.go` into
`syz/linux/generated/usb_ids.gen.hpp` — that is data, not callback
code, and stays out of the schema dict.

### 6.4 Two formats, one artifact

A v2 syz seed carries `seed.artifact = ProgramArtifact{format=kSyzProg,
typed_view=Prog}`. A bytes-only seed (legacy AFL, custom format) carries
the same `ProgramArtifact` shape with no typed_view; the mutator's
`Mutate(seed)` path reads canonical bytes verbatim. The corpus store,
codec registry, and persistence layer treat both shapes uniformly —
the only place that branches is the per-format materializer.

## 7. Extension Points

| Need                                | Where to extend                                                                                                |
|-------------------------------------|----------------------------------------------------------------------------------------------------------------|
| New wire format (e.g. SQL-diff)     | Implement `IProgCodec`, register in `CodecRegistry`; implement `IArtifactMaterializer`, register in registry.  |
| New OS / arch for syz IR            | Add `tools/syzgen` target binding; emit a sibling of `target_linux_amd64_*.gen.cpp`; add a `Target::<os>_<arch>()` accessor; rebuild constants and pseudo metadata. |
| New SpecialType callback (linux)    | Implement in `program/src/syz/linux/`; register in the `linux_amd64()` builder via `register_special_type`.    |
| New typed-view payload              | Define a new value type, mark it stable, and `ProgramArtifact::Build` it via `typeid(T)`. Consumers gate access through `As<T>()`. |
| Schema field readable from C view   | Add it to `PseudoMeta` / `SyzTargetTables`; emit from `tools/syzgen pseudo` / `target`; do **not** force the worker to take a typed dependency. |

## 8. Non-Goals

- No fuzzing decisions. Mutator policy, scheduler weighting, coverage
  feedback, repro orchestration are owned by other modules.
- No kernel knowledge inside the neutral API. The artifact / codec /
  format layer is target-agnostic; kernel-shaped semantics live below
  it under `syz/`.
- No hand-edited generated headers. `.gen.hpp` / `.gen.cpp` are the
  syzgen contract; edits go to the emitter (`tools/syzgen/`) and are
  re-emitted, then verified byte-equal.
- No format conversion (e.g. AFL bytes → syz IR). Each artifact is
  produced in one format and persisted in that format; cross-format
  translation, if ever needed, would be an opt-in mutator stage.
- No worker dependency on the typed IR. The worker speaks
  `SyzTargetTables` only. The current typed-Target inclusion in the
  worker driver is tracked debt, not a contract.

# Mutator Component Design

> **Scope**: this doc describes the **current** state of the `mutator/` module
> (post V1 retirement + AsyncAdmitWorker + 33/333 throttle landed) and how it
> provides syzkaller-parity mutation/generation capabilities under the reFuzz
> architecture.
> No history / migration paths / retired implementations / future plans.
> Source-of-truth is the code; references take the form `file:line`.

---

## 1. Module scope

`mutator/` is the **input mutation + program generation** component of reFuzz.
Its single responsibility is: turn a `Seed` (already selected) — or no input
at all — into a new `Prog` / payload.

**Out of scope**:
- Feedback evaluation, interesting-judgement -> `feedback/`
- Corpus admission, scheduler feedback -> `corpus/`
- Program IR + codecs -> `program/`
- Config resolution, component wiring -> `control/` + `assembler/`
- Worker execution, cross-VM transport -> `executor/` + `channel/`

The mutator **only consumes** the seed it is handed and emits a new payload.

---

## 2. Architecture overview

### 2.1 Three layers

```
catalog -> manager -> engine
```

| Layer | Role | Public contract |
|---|---|---|
| **`MutatorEngineCatalog`** | Build-time registry: id <-> construction lambda | `Register(Entry)` / `Build(name, ctx)` |
| **`MutatorManager`** | Owns engines, exposes the active one through `EngineHandle<IMutatorEngine>` | `AddEngine` / `SwitchEngineByName` / `Handle()` |
| **`IMutatorEngine`** | Hot-path contract; performs the actual mutation | `Mutate / MutateTyped / Generate / SwitchPolicyByName / OnSeedAdmitted` |

### 2.2 Build-time data flow

```
RegisterBuiltinMutatorEngines(catalog)         // mutator_catalog.cpp
        |  registers the single entry "syz"
        v
Assembler                                       // control/assembler/
        |  catalog.Build("syz", BuildContext{ corpus_store, mount_capable })
        v
SyzV2MutatorEngine (unique_ptr)                 // mutator/src/linux/syz_v2/engines/
        |
        v
manager.AddEngine(engine, activate=false)
manager.SwitchEngineByName("syz")               // explicit set-active; avoids
                                                // depending on registration order
```

### 2.3 Runtime data flow

```
FuzzerLoop / Stages                             // control/src/loop|stages/
   |  mutator_handle_.Get()        (acquire load, O(1))
   v
SyzV2MutatorEngine
   |- Mutate(seed)              v1 byte path           returns vector<uint8_t>
   |- MutateTyped(artifact)     v2 typed pipeline      returns MutationResult{ artifact }
   '- Generate()                empty-corpus bootstrap returns MutationResult
                                / forced generation
```

`MutatorManager` is only written at build time; runtime code never proxies
through the manager. `EngineHandle<T>` is a `std::atomic<T*>` (release/acquire),
hot path uses zero locks and zero branches.

---

## 3. Directory layout

```
mutator/
|-- design.md                                                   # this file
|-- include/refuzz/mutator/
|   |-- mutator.hpp / mutator_manager.hpp / mutator_catalog.hpp
|   |-- mutator_engine.hpp                                      # IMutatorEngine contract
|   '-- linux/syz_v2/                                           # syzkaller-parity impl
|       |-- engines/syz_v2_engine.hpp                           # SyzV2MutatorEngine
|       |-- ops/                                                # 5 mutator ops (Splice/Insert/MutateArg/Squash/Remove)
|       |-- policies/syz_v2_mutation_policies.hpp               # weighted + single-op policies
|       |-- choice_table.hpp / choice_table_handle.hpp          # syscall-pair preference table
|       |-- generator.hpp / gen_state.hpp / random.hpp          # type-aware generation stack
|       |-- components.hpp                                      # SyzV2MutationContext / ISyzV2MutatorOp / ISyzV2MutationPolicy
|       '-- special_gen.hpp
|-- src/
|   |-- mutator_catalog.cpp / mutator_manager.cpp
|   '-- linux/syz_v2/                                           # implementations of the headers above
'-- (no src/linux/syz/, no src/linux/compo/  -- V1/composable are retired)
```

---

## 4. `IMutatorEngine` contract

`mutator/include/refuzz/mutator/mutator_engine.hpp:33-67`

```cpp
class IMutatorEngine {
public:
    virtual std::string Name() const = 0;

    // v1 compatibility: bytes-in / bytes-out. Still called by v1 stages.
    virtual std::vector<uint8_t> Mutate(const Seed& seed) = 0;

    // v2 main path (sec.3.10 typed pipeline): typed-in / typed-out, no
    // text decode/encode on the hot path.
    virtual MutationResult MutateTyped(const ProgramArtifact& artifact);

    // Sec.015 sec.5/sec.6.1: corpus-independent generation, no seed input.
    // GenerateProducerStage uses this on empty-corpus bootstrap and on the
    // 5%-probability "forced generate" path.
    virtual MutationResult Generate();

    virtual bool SwitchPolicyByName(std::string_view name) = 0;
    virtual std::string ActivePolicyName() const = 0;

    // Notification from corpus admission. Only meaningful for engines whose
    // behaviour depends on corpus state. SyzV2MutatorEngine overrides and
    // (after throttling) calls RebuildChoiceTable.
    virtual void OnSeedAdmitted(const Seed& /*seed*/) {}
};
```

`MutationResult` is a `(status, changed, artifact)` triple
(`program/include/refuzz/program/mutation_result.hpp`). The default
implementations of `Generate` / `MutateTyped` return `kSkipped` so engines
that do not opt into the v2 path stay valid and silent.

---

## 5. `SyzV2MutatorEngine` -- the core syzkaller-parity implementation

`mutator/include/refuzz/mutator/linux/syz_v2/engines/syz_v2_engine.hpp`
`mutator/src/linux/syz_v2/engines/syz_v2_engine.cpp`

This is the only entry currently registered in the catalog (id `"syz"`).

### 5.1 The three API methods, mapped to upstream syzkaller

| API | Implementation outline | syzkaller upstream counterpart |
|---|---|---|
| `Generate()` | `GenerateFreshProg()` -> `length_dist_(master_)` draws ncalls (default `[2,8]`) -> `mut_v2::Generate(target, prog_seed, ncalls, ChoiceTable, PseudoSelectionPolicy, GenState)` -> `sanitize_fix` -> `MakeArtifactFromTypedProg` | `prog.Target.Generate(rnd, RecommendedCalls, ChoiceTable)` |
| `MutateTyped(artifact)` | clone typed prog -> read active policy -> policy picks op(s) -> `op.Apply(prog, ctx, rng)` per op -> `sanitize_fix` -> `MakeArtifactFromTypedProg` | `prog.Prog.Mutate(rnd, ncalls, ct, noMutate, corpus)` |
| `Mutate(seed)` | byte-level entry: `decoder_.decode(seed.payload)` -> single `MutateTyped` -> `encoder_.encode(prog)` back to bytes | v1-stage compatibility shim; new code paths use `MutateTyped` |

`Generate()` uses `ncalls = uniform_int_distribution<int>(ncalls_lo=2, ncalls_hi=8)`,
matching syzkaller's `RecommendedCalls = [2, 8]`.

### 5.2 Op registry -- all five syzkaller ops

`EnsureMutationComponents` registers 5 ops (`syz_v2_engine.cpp:586+`):

| reFuzz class | id (`Name()`) | weight | Upstream syzkaller counterpart |
|---|---|---|---|
| `SyzV2SpliceOp` | `splice` | 200 | `mutateProgArgsBalanced`'s splice path |
| `SyzV2InsertCallOp` | `insert_call` | 100 | `mutateInsertCall` |
| `SyzV2MutateArgOp` | `mutate_arg` | 100 | `mutateArg` |
| `SyzV2SquashAnyOp` | `squash_any` | 50 | `squashAny` |
| `SyzV2RemoveCallOp` | `remove_call` | 10 | `mutateRemoveCall` |

The weights **strictly match** syzkaller's `mutateArgsBalanced` distribution
in `prog/mutation.go` (200/100/100/50/10).

Each op implements
`ISyzV2MutatorOp::Apply(syz::Prog&, SyzV2MutationContext&, RandGen&)`
(`components.hpp:75-83`). On failure the op **must not** modify `prog`; the
policy then picks a different op next round and never retries the same op.

### 5.3 Policy registry (six entries + alias compatibility)

| Index | id (`Name()`) | Class | Behaviour |
|---|---|---|---|
| 0 (default) | `syz_v2_balanced` | `SyzV2WeightedMutationPolicy` | Picks 1 op, weighted-random by op weight |
| 1 | `syz_v2_splice_heavy` | `SyzV2SingleOpPolicy("splice")` | Forces splice |
| 2 | `syz_v2_insert_call` | `SyzV2SingleOpPolicy("insert_call")` | Forces insert |
| 3 | `syz_v2_mutate_arg` | `SyzV2SingleOpPolicy("mutate_arg")` | Forces arg-level mutation |
| 4 | `syz_v2_remove_call` | `SyzV2SingleOpPolicy("remove_call")` | Forces remove |
| 5 | `syz_v2_squash_any` | `SyzV2SingleOpPolicy("squash_any")` | Forces squash-any |

**Alias compatibility** (`FindPolicyIndex` line 471-481): config values
`uniform` / `balanced` / `splice_heavy` / `insert_call` / `mutate_arg` /
`remove_call` / `squash_any` map to the corresponding `syz_v2_*` policy
automatically.

**Switch semantics** (three-stage, lock-free):
1. Any thread calls `SwitchPolicyByName(name)` -> writes `next_policy_idx_`
   (atomic store).
2. The next `Mutate*()` entry runs `ApplyPendingSwitchIfAny()`, promoting
   pending into `active_policy_idx_`.
3. `ActivePolicyName()` returns `policies_[active_policy_idx_]->Name()`.

The control plane holds **no locks**; the engine applies the switch lazily.

### 5.4 ChoiceTable -- syscall preference matrix

`mutator/include/refuzz/mutator/linux/syz_v2/choice_table.hpp`
`mutator/src/linux/syz_v2/choice_table.cpp`

An N x N matrix `runs[i][j]` used to weighted-sample syscall j given
syscall i. Two layers add up:

| Layer | Source | Implementation |
|---|---|---|
| **Static prio** | SyscallMeta argument types (resource/ptr/buffer/...) -> producer/consumer relations | `compute_static_prio()`, deterministic, mirrors upstream `prog/prio.go:91-124` |
| **Dynamic prio** | Adjacent-syscall co-occurrence frequency in corpus | `compute_dynamic_prio(corpus_store, decoder)`, full corpus walk |

**COW publishing** (zero-lock readers):
```cpp
auto fresh = std::make_shared<ChoiceTable>();
fresh->build(target_, *corpus_store_, local_decoder, pseudo_policy_);
std::atomic_store(&choice_table_, std::move(fresh));        // release
target_.set_default_choice_table(...);                       // sync to generator
```

Reader side: `auto snap = std::atomic_load(&choice_table_);` (acquire).
The snapshot stays valid for one whole `Mutate*` call; the previous
ChoiceTable is destroyed when its last reader drops it.

**Two build trigger paths**:
1. **Lazy first build** -- `EnsureChoiceTableSnapshot()` on first call (works
   even with an empty corpus; only static prio is populated).
2. **OnSeedAdmitted** -- async notification path, see sec.5.6.

`rebuild_mu_` (`std::mutex`, `syz_v2_engine.hpp:186`) serialises the two
build paths. **`Mutate*` hot path never holds this mutex** -- it only does
an atomic_load of the snapshot.

`RebuildChoiceTable` constructs a **stack-local `TextDecoder`**
(`syz_v2_engine.cpp:517-518`) instead of using the engine's member
`decoder_`. This prevents the worker thread that runs rebuild from racing
with the hot-path Mutate's reuse of `decoder_` internal cache state.

### 5.5 Generator / GenState / RandGen -- type-aware generation stack

| Class | File | Role |
|---|---|---|
| `mut_v2::Generate(...)` | `generator.cpp` | Main entry: pick syscall by ChoiceTable preference, recursively materialise args by their type description |
| `GenState` | `gen_state.hpp` | Tracks resources already produced inside a Prog; supports walking resource parent chains; carries `pseudo_policy()` |
| `RandGen` | `random.hpp` | Generator-side RNG (`std::mt19937_64` + helpers); separate from the mutator-op RNG `mut_rand_` |
| `SyzV2MutationContext` | `components.hpp:43-68` | Per-op context bag: `target` / `splice_donor` / `gen_state` / `choice_table` / `prev_call_id` / `affected_call_index` |
| `SpecialGen` | `special_gen.hpp` | reFuzz counterpart of upstream `target.SpecialTypes` (filename / sockaddr / iovec / ...) |

`PseudoSelectionPolicy` (defined in `program/syz/...`) is derived from
`BuildContext.mount_capable` at catalog build time
(`mutator_catalog.cpp:39-49`). Non-mount-capable processes use
`kPseudoSelectionPolicyDefault` (native syscalls only); mount-capable
processes use the extended set with `kMountCapableCaps`.

### 5.6 OnSeedAdmitted -- asynchronous ChoiceTable update path

reFuzz decouples the corpus admit path so it never blocks the fuzz main
thread:

```
[feedback / fuzz main thread]
  feedback engine flags interesting
    -> corpus_inbox.TryPush(seed)            (non-blocking mutex try_lock)

[fuzz main thread RunOnce]
  warm_tick % 32 -> corpus_manager.Tick()
    -> store.AddSeed / scheduler.OnSeedAdded / metrics
    -> on_admit_(seed)                       (lambda installed by FuzzerLoop)
        -> admit_worker_->Enqueue(seed, mutator_engine_at_admit)

[control::AsyncAdmitWorker, dedicated thread]
  swap queue -> batch
    |- for each seed: CorpusDiskIO::SaveSeed (synchronous disk IO)
    '- at end of batch, call OnSeedAdmitted ONCE per admit-time engine
        -> SyzV2MutatorEngine::OnSeedAdmitted
            |- throttle decision (sec.5.7)
            '- if firing: RebuildChoiceTable()
```

**Key invariant**: the engine pointer received by `OnSeedAdmitted` is the
engine that was active **at the moment of enqueue** (captured via
`mutator_handle_.TryGet()` inside the on_admit_ lambda). Even if the
engine is switched later, the admit-time engine is the one notified --
matching upstream syzkaller's "the subscriber that was active when the
seed entered corpus is the one notified" semantics.

### 5.7 33/333 rebuild throttle (syzkaller-parity)

`SyzV2MutatorEngine::OnSeedAdmitted` (`syz_v2_engine.cpp:546-577`) follows
syzkaller `pkg/fuzzer/fuzzer.go:406-426` exactly:

```cpp
const size_t cur       = corpus_store_->Size();
const size_t threshold = (cur < 100) ? 33 : 333;
const size_t prev      = ct_built_at_corpus_size_.load(acquire);
if (prev + threshold >= cur) return;        // not enough new admits, skip
RebuildChoiceTable();
ct_built_at_corpus_size_.store(cur, release);
```

| Aspect | reFuzz | Upstream syzkaller |
|---|---|---|
| Threshold | `cur < 100 ? 33 : 333` | same |
| Trigger condition | `prev + threshold < cur` (strict) | `fuzzer.ctProgs + regenerateEveryProgs < len(progs)` |
| `prev` update timing | After rebuild completes; writes `cur` | `fuzzer.ctProgs = len(programs)` |

**Why throttle**: dynamic prio needs a minimum statistical sample
(>= 33 seeds) before it carries signal. Without throttling, noisy
single-seed prio gets adopted into the ChoiceTable immediately and
biases the mutator off-track during the first 1-32 admits, causing
corpus focus drift.

**First lazy build**: `EnsureChoiceTableSnapshot` writes
`ct_built_at_corpus_size_ = corpus_store_->Size()` after the first build
completes (line 540-543), so the throttle baseline starts correctly.

**Null `corpus_store_` fallback**: if the engine is wired without a
corpus store (testing / extreme wiring), `OnSeedAdmitted` calls
`RebuildChoiceTable()` directly, equivalent to v1 behaviour.

---

## 6. Threading model

### 6.1 Manager layer

| Operation | Calling thread |
|---|---|
| `Catalog.Build` / `Manager.AddEngine` | Build-time, single-threaded (Assembler) |
| `Manager.SwitchEngineByName` | Any thread (release-store on the handle) |
| `Manager.Handle().Get()` | Any thread (acquire-load); **called every fuzz tick on the hot path** |

`EngineHandle<T>` is `std::atomic<T*>`. All engines are owned permanently
by `MutatorManager::engines_`; switching only changes the handle pointer
and never destroys the previous engine. Readers therefore always see a
stable pointer during a switch.

### 6.2 Inside SyzV2MutatorEngine

| Resource | Synchronisation | Accessor |
|---|---|---|
| `choice_table_` (`shared_ptr`) | `std::atomic_store` / `std::atomic_load` (COW) | hot path reads, rebuild path stores |
| `rebuild_mu_` (`std::mutex`) | `lock_guard` | held only inside `RebuildChoiceTable`; serialises lazy-first-build vs admit-worker rebuild |
| `ct_built_at_corpus_size_` (`atomic<size_t>`) | release/acquire | `OnSeedAdmitted` (admit-worker thread) + `EnsureChoiceTableSnapshot` (main thread) |
| `decoder_` / `encoder_` members | **single-threaded**, hot path only | fuzz main thread |
| `master_` / `mut_rand_` / `length_dist_` | single-threaded | fuzz main thread |
| `next_policy_idx_` (`atomic<int>`) | release-store / acquire-load | switcher writes, Mutate-entry reads |
| `active_policy_idx_` (`int`) | single-threaded | written/read inside `ApplyPendingSwitchIfAny` |
| `ops_` / `policies_` registries | Written once at build time, read-only afterwards | all threads |

**Mutate hot path is lock-free and never blocks**. The only mutex,
`rebuild_mu_`, lives entirely inside `RebuildChoiceTable` and never
crosses readers.

### 6.3 admit worker (`control::AsyncAdmitWorker`)

Full details in `control/include/refuzz/control/async_admit_worker.hpp`.
From the mutator's perspective:
- The worker thread calls `engine.OnSeedAdmitted(seed)` once per
  admit-time engine that appears in a batch.
- The engine pointer is captured by the caller (FuzzerLoop) at enqueue
  time via `mutator_handle_.TryGet()`.
- Engine lifetime is guaranteed to outlive the FuzzerLoop by
  `MutatorManager::engines_`. FuzzerLoop's destructor runs
  `admit_worker_->StopAndDrain()` before the manager is destroyed, so
  the worker never observes a dangling engine.

---

## 7. Module boundaries

### 7.1 With `assembler/` and `control/`

`assembler` provides `BuildContext{ corpus_store, mount_capable }` ->
catalog constructs the engine -> manager receives it. The mutator does
not parse config and does not pick defaults.

`FuzzerLoop` interacts with the mutator via exactly two surfaces:
1. `mutator_handle_.Get().MutateTyped(artifact)` /
   `Mutate(seed)` / `Generate()` -- called inside stages.
2. `mutator_handle_.Get().SwitchPolicyByName(name)` -- forwarded from
   `IPolicyControl`.

### 7.2 With `corpus/`

The mutator only **reads** the corpus, via `ICorpusStore*`
(`BuildContext.corpus_store`, may be null):

- `SyzV2SpliceOp` calls `corpus_store->SampleSeedId(rng)` +
  `GetSeed(id)` to pick a splice donor.
- `ChoiceTable::compute_dynamic_prio` calls
  `corpus_store->ForEachSeed(visitor)` to count co-occurrence.

The mutator **never writes** the corpus. Admission, priority and scheduler
notifications are owned by `CorpusManager` + `CorpusInbox`.
`InMemoryCorpusStore` is itself thread-safe (`shared_mutex` + ForEachSeed
snapshot mode), permitting the admit-worker thread to call ForEachSeed
concurrently with the main thread's AddSeed.

### 7.3 With `program/`

All IR operations are delegated to `program/syz/`:
- `syz::Prog` / `syz::Call` / `syz::Type` -- the v2 IR
- `syz::TextDecoder` / `syz::TextEncoder` -- canonical text codec used
  for corpus persistence
- `syz::sanitize_fix` -- repair illegal prog states that mutator ops may
  produce
- `syz::MakeArtifactFromTypedProg` -- wrap a Prog into a `ProgramArtifact`
  (typed pipeline sec.3.10)

### 7.4 With `feedback/`

No direct dependency. The feedback engine triggers corpus_inbox.TryPush
through the `actions.admit_seed` lambda installed by
`MutationalConsumerStage`; the chain stays entirely inside the control
layer.

---

## 8. Capability checklist vs upstream syzkaller

| syzkaller capability | reFuzz implementation | File |
|---|---|---|
| `prog.Target.Generate` | `Generate()` -> `mut_v2::Generate` | `linux/syz_v2/generator.cpp` |
| `prog.Prog.Mutate` 5-op weighted | `MutateTyped()` + `SyzV2WeightedMutationPolicy` | `linux/syz_v2/policies/` + `engines/` |
| 5 mutator ops (splice / insertCall / mutateArg / squashAny / removeCall) | 5 `SyzV2*Op` classes, weights 200/100/100/50/10 | `linux/syz_v2/ops/` |
| `prog.Target.BuildChoiceTable` static + dynamic prio | `mut_v2::ChoiceTable::build` (same two layers) | `linux/syz_v2/choice_table.cpp` |
| `pkg/fuzzer.choiceTableUpdater` async rebuild | `AsyncAdmitWorker` + `OnSeedAdmitted` | `control/src/loop/async_admit_worker.cpp` |
| `pkg/fuzzer.ChoiceTable()` 33/333 throttle | `OnSeedAdmitted` entry-side throttle | `syz_v2_engine.cpp:546-577` |
| `prog.Target.SpecialTypes` (filename / sockaddr / iovec / ...) | `mut_v2::SpecialGen` | `linux/syz_v2/special_gen.cpp` |
| Resource producer->consumer chain in Generate | `GenState::create_resource_chain` | `linux/syz_v2/gen_state.cpp` |
| `pseudo` syscall selection policy | `PseudoSelectionPolicy` derived from `BuildContext.mount_capable` | `mutator_catalog.cpp:39-49` |
| `prog.Target.Sanitize` | `syz::sanitize_fix` (in `program/`, called from mutator) | implementation lives in `program/` |

---

## 9. Invariants cheat sheet

Read / change the mutator only after internalising these:

1. **Catalog id must equal engine `Name()`** -- `MutatorManager::SwitchEngineByName(name)` routes by `Name()`.
2. **Mutate hot path holds zero locks** -- only `atomic_load(choice_table_)` and read-only access to ops/policies registries.
3. **`RebuildChoiceTable` must hold `rebuild_mu_`** -- prevents lazy-first-build and the admit-worker rebuild from doing redundant builds against the same corpus, and from corrupting decoder cache state.
4. **`RebuildChoiceTable` uses a stack-local `TextDecoder`, never the member `decoder_`** -- the member decoder is owned by the hot-path Mutate; cross-thread sharing would corrupt its cache.
5. **The engine* received by `OnSeedAdmitted` is the admit-time active engine** -- captured by the enqueue side via `mutator_handle_.TryGet()`; the worker never reads the handle itself.
6. **Policy switch is a two-stage request/apply** -- `SwitchPolicyByName` writes `next_policy_idx_` from any thread; only the next `Mutate*` entry commits.
7. **The catalog has exactly one entry today: `"syz"`** -- V1 SyzMutatorEngine and ComposableMutatorEngine are retired; only SyzV2 remains.
8. **Op registration order is the tiebreaker for the weighted policy** -- the order Splice / Insert / MutateArg / SquashAny / Remove is fixed; new ops must consider the tie-break implication.
9. **Throttle writes `ct_built_at_corpus_size_` AFTER `RebuildChoiceTable`** -- on failure / exception, the next admit re-evaluates and never silently drops an update.

---

## 10. Key references

| Topic | File |
|---|---|
| Catalog registration | `mutator/src/mutator_catalog.cpp` |
| `IMutatorEngine` contract | `mutator/include/refuzz/mutator/mutator_engine.hpp` |
| SyzV2 engine implementation | `mutator/src/linux/syz_v2/engines/syz_v2_engine.cpp` |
| Five mutator ops | `mutator/src/linux/syz_v2/ops/{splice,insert_call,mutate_arg,squash_any,remove_call}.cpp` |
| Six policies + alias map | `mutator/src/linux/syz_v2/policies/syz_v2_mutation_policies.cpp` + `syz_v2_engine.cpp:471-481` |
| ChoiceTable build | `mutator/src/linux/syz_v2/choice_table.cpp` |
| 33/333 throttle | `mutator/src/linux/syz_v2/engines/syz_v2_engine.cpp:546-577` |
| RebuildChoiceTable serialisation + local decoder | `syz_v2_engine.cpp:512-527` |
| AsyncAdmitWorker | `control/src/loop/async_admit_worker.cpp` |
| Corpus store concurrency | `corpus/src/corpus/in_memory_corpus.cpp` |
| Generator entry point | `mutator/src/linux/syz_v2/generator.cpp` (`mut_v2::Generate`) |

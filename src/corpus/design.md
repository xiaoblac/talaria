# Corpus Component Design

## 1. Scope

`corpus/` owns the **persisted, scheduleable seed pool** of reFuzz. Its job is to
turn raw "candidate program" inputs from the feedback path into a long-lived
seed set that the fuzz loop can sample, mutate, and persist.

It is target-agnostic. The same code path serves syz-kernel, AFL-style CLI,
SQL-diff, etc. Target-specific behavior is injected via:

- **Profile** &mdash; declares decoder + load policy via `ProfileDefaults.corpus_prep`.
- **Stage chain** &mdash; declares whether/how the loop produces seeds without
  corpus input (e.g., `GenerateProducerStage`).

## 2. Component Map

```
                    feedback engine
                          |
                          v
                     CorpusInbox            (bounded, lock-free best-effort)
                          |
                  CorpusManager.Tick()      (admission orchestration)
            +--------------+--------------+
            |              |              |
            v              v              v
       FilterRegistry  PolicyRegistry  on_admit_(seed) ---> CorpusDiskIO::SaveSeed
                          |
                          v
                     ICorpusStore           (in_memory backend; catalog-registered)
                          |
                   ISchedulerEngine         (priority / round-robin policies)
                          |
                          v
                  FuzzerLoop -> mutator
```

| Component             | Role                                                   | File |
|-----------------------|--------------------------------------------------------|------|
| `ICorpusStore`        | Storage boundary: AddSeed / GetSeed / ForEach / Size   | `core/include/refuzz/fuzzer/interfaces.hpp` |
| `InMemoryCorpusStore` | Default backend (catalog id `"in_memory"`)             | `corpus/src/corpus/in_memory_corpus.cpp` |
| `CorpusInbox`         | Bounded mutex-protected MPSC queue, non-blocking push  | `corpus/include/refuzz/corpus/inbox.hpp` |
| `CorpusManager`       | Drains inbox, applies admission policy, calls store    | `corpus/src/corpus/corpus_manager.cpp` |
| `ICorpusFilter` / `ICorpusAdmissionPolicy` | Per-seed admission hooks         | `corpus/include/refuzz/corpus/corpus_manager.hpp` |
| `CorpusDiskIO`        | `SaveSeed` / `LoadAll` / `LoadCrashRepros`             | `corpus/src/corpus/corpus_disk_io.cpp` |
| `SeedIdAllocator`     | Boot-time seed id allocation                           | `corpus/include/refuzz/corpus/seed_id_allocator.hpp` |
| `CorpusLoadPolicy`    | enum: `StrictTyped` / `LenientBytes`                   | `corpus/include/refuzz/corpus/corpus_prep_policy.hpp` |
| `ISchedulerEngine` + `SchedulerManager` | Next-seed selection (handle-based) | `corpus/include/refuzz/scheduler/` |

## 3. Key Flows

### 3.1 Startup load

```
Orchestrator::Build()
  -> profile->corpus_prep.build_decoder(cfg)         // ArtifactMaterializerFn or null
  -> CorpusDiskIO::LoadAll(store, scheduler, dir,
                            id_alloc,
                            decoder,
                            profile->corpus_prep.load_policy)
  -> CorpusDiskIO::LoadCrashRepros(...)              // optional
  -> log "corpus_empty_start" if store.Size() == 0   // empty corpus is legal
```

There is **no bootstrap seed**. An empty corpus is a legal startup state; the
fuzz loop's `GenerateProducerStage` is responsible for producing fresh
programs from nothing.

### 3.2 Runtime admission

```
feedback_dispatcher
  -> actions.admit_seed(seed) ----> CorpusInbox.TryPush
  -> actions.notify_scheduler(...) -> ISchedulerEngine.OnFeedback

CorpusManager.Tick()                  (called once per FuzzerLoop tick)
  -> for up to max_drain:
       inbox.TryPop(seed)
       -> policy.SelectFilters() -> filter.Test() chain
       -> store.AddSeed()
       -> scheduler.OnSeedAdded(id)
       -> on_admit_(seed)             // disk persistence side effect
```

### 3.3 Seed selection

```
FuzzerLoop tick:
  scheduler_handle.Get().NextSeedId() -> seed_id
  corpus.GetSeed(seed_id)             -> Seed
  mutator.MutateTyped(seed.artifact)  // or Mutate(seed) bytes path
  -> push HostFuzzTask
```

## 4. Concurrency Model

The store and the scheduler engine are accessed from the FuzzerLoop main
thread only. Cross-thread input arrives through `CorpusInbox`, which uses
`std::try_to_lock` and drops on contention or full queue. Drop counts surface
as `fuzzer.inbox_drop{queue=result}`.

Engine swaps (e.g., scheduler policy switch) go through `EngineHandle<T>`,
read on every access by the loop and the consumer stages.

## 5. Adaptation to syzkaller

Three knobs make `corpus/` carry a syzkaller-class workload without bending
its core abstractions:

### 5.1 Decoder + load policy come from the profile

`kernel_profile.cpp` populates `ProfileDefaults.corpus_prep`:

```cpp
p.corpus_prep.build_decoder = [](const OrchestratorConfig&) {
    return MakeRegistryMaterializer(
        ProgFormat::kSyzProg,
        ProgramTargetKey{Target::linux_amd64().os(), arch, revision});
};
p.corpus_prep.load_policy = CorpusLoadPolicy::StrictTyped;
```

`StrictTyped` causes `LoadAll` to **drop** any payload the decoder cannot turn
into a `ProgramArtifact` (no seed_id allocated, no scheduler notification).
This prevents bytes-only zombie seeds from polluting a typed corpus and being
sent verbatim to the worker.

### 5.2 Stage chain produces from empty state

The kernel profile's producer chain is `[generate_producer, mutational_producer]`:

- `GenerateProducerStage`:
  - empty corpus &rarr; 100% generate (corpus-independent path).
  - non-empty corpus &rarr; ~5% generate, otherwise `kDone` so
    `mutational_producer` runs.
  - calls `IMutatorEngine::Generate()` which on `SyzV2MutatorEngine` wraps
    the existing `GenerateFreshProg` (ChoiceTable + pseudo policy + ncalls
    distribution) and returns a typed `ProgramArtifact`.
- `MutationalProducerStage` selects via scheduler and calls `MutateTyped`.

This mirrors syzkaller's `Fuzzer.genProgram()` 95% mutate / 5% generate
split, but expressed as two reFuzz stages composed via `producer_chain`
rather than an `if/else` inside one fuzzer object.

### 5.3 Artifact authority on the runtime path

A v2 syz seed carries `seed.artifact` (typed `Prog`). The mutational producer
takes the typed path (`MutateTyped`) without re-decoding payload text.
Bytes-only seeds (legacy / `LenientBytes` profiles) fall back to
`Mutate(seed)`. The store treats both shapes the same.

## 6. Extension Points

| Need                                | Where to extend |
|-------------------------------------|-----------------|
| New on-disk backend (mmap, sqlite)  | Implement `ICorpusStore`, register in `CorpusStoreCatalog`. |
| Per-seed admission rule             | Implement `ICorpusFilter`, register in `CorpusManager` ctor. |
| Different filter combinations       | Implement `ICorpusAdmissionPolicy`. Switch via `SwitchAdmissionPolicyByName`. |
| New scheduling algorithm            | Implement `ISchedulingPolicy` (lightweight) or `ISchedulerEngine` (full). |
| New target family corpus shape      | Set `ProfileDefaults.corpus_prep.{build_decoder, load_policy}` per profile; no corpus code change required. |

## 7. Non-Goals

- Cross-target seed conversion (e.g., AFL bytes &rarr; syz IR).
- Content-level dedup (only `seed_id` uniqueness today).
- Persisting full seed metadata (only `payload.bin` + sidecar JSON; runtime
  state like `interesting_hits`, scheduler boost/cool flags is rebuilt).
- Strict global capacity (`SizeBudgetFilter` is admission-time only).

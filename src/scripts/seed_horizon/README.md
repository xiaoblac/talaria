# seed_horizon — structural-horizon seed-value (S/P/R) toolchain

Static analysis that builds the **S/P/R unlock-hypothesis graph** feeding `future(seed)` (the
forward/structural seed-value signal). An edge is the hypothesis:

> **A** establishes precondition **P** on shared location **S** → unlocks gate-slice **R** owned by **B**.

The C++ side (`corpus/include/refuzz/scheduler/horizon/static_belief_graph.hpp`) loads the produced
`graph_M` as a recall-complete Beta prior and calibrates it in-loop (α/β) from the live frontier.
Design constitutions: `docs/plans/structural-horizon-seed-value.md`, `docs/plans/seed-future-value.md`.

## Current kernel Bitcode pointer-analysis track

The current `variant -> candidate handler` pointer-analysis work is tracked separately from the original
S/P/R dependency-graph pipeline. Start with:

- `handler-candidate-pointer-analysis-plan.md` for the complete method and staged plan.
- `step4-pointer-analysis-handoff-2026-07-16.md` for the current code/data checkpoint.
- `points-to-constraint-schema.md` and `recognizer-seed-schema.md` for solver inputs.
- `step4-gate-schema.md` for the closure and conservation acceptance contract.

Step 4 is still in progress; the existing recursive resolver is not yet consuming the new global fixpoint.

## Layout

```
seed_horizon/
  substrate/   shared lib: consts, membership, resource model, coupling join, Beta confidence,
               pc bridge, in-loop observe, region belief
  angles/      CHANNEL federation: resource, const_eq, pointer_null, container, value_dyn,
               fptr_install, global_state, relational — one detector per coupling channel
  extract/     bitcode -> linked facts
  model/       pure schema + syzkaller variant classification
  provenance/  structural resource -> REG/context recognizers
  resolve/     recursive dispatch resolver + candidate region construction
  probes/      ad-hoc analyses over the same facts (read-only)
```

## Pipeline (run everything from the repo root; data lives in `run/seed_horizon/`)

1. **Build/link kernel bitcode** from the `build-kasan-clang` tree:
   `extract/link_kernel_ir.py` produces linked `.bc` batches under `run/seed_horizon/kernel_linked/`.
2. **Extract facts** — `extract/ir_defuse.cpp` (build → `run/seed_horizon/ir_defuse`), swept over all
   `.ll` by `extract/sweep_gates.sh` → `all_gates.tsv` + `all_writes.tsv`. Linked `REG`/`CMD` facts live
   in `kernel_facts_linked/{reg,cmd}.tsv`; candidate inspection: `extract/compose.py` (diagnostic only);
   implicit def-use: `extract/implicit_defuse.py` over `kernel_linked/**/*.bc`.
3. **Classify variants** — `probes/variant_taxonomy.py` parses the syzkaller catalog into intent
   classes only. It does not bind variants to handlers.
4. **Build structural context** — `provenance/fd.py` and `provenance/socket.py` recover resource -> REG-row
   candidates and recursive context providers. They return candidate sets, never a point binding.
5. **Audit recursive candidates** — `probes/candidate_trace.py` and `probes/region_audit.py` run the
   recursive resolver/fixpoint:
   `variant -> context resources -> candidate REG rows -> entry handlers -> recursive leaves/region`.
   A non-empty candidate set is reported as coverage for the candidate graph; uniqueness is a separate
   confidence property, not the graph admission rule.

## Probes (read-only)

- `probes/candidate_trace.py` — recursive candidate-set funnel over the full syzkaller catalog.
- `probes/region_audit.py` — candidate region size/confidence/coverage audit.
- `probes/s4_decompose.py`, `probes/no_context_sweep.py` — rank missing provenance recognizers.
- `probes/hardness_proof.py`, `probes/pkind_taxonomy.py` — raw fact audits.

## Key artifacts (`run/seed_horizon/`)

`ir_defuse` (built binary) · `all_{gates,writes}.tsv` · `kernel_facts_linked/{reg,cmd,fields}.tsv`
· `kernel_linked/**/*.defuse.tsv` · `variant_taxonomy.tsv` · `candidate_trace.tsv` ·
`region_audit.tsv` · `devnode_anchors.tsv` · `horizon_model.json` · `function_block_map.tsv`.

## Conventions

- Entry scripts that import the packages put `scripts/seed_horizon/` on `sys.path` via
  `sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))`.

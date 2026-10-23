"""Additive corpus-class extensions.

This module *adds* new corpus enumeration paths on top of `enumerate.py`,
without modifying any existing function or descriptor entry.  The point is:
running the original `generate_seed_corpus.py` still produces byte-identical
seeds; running `extend_seed_corpus.py` produces *additional* seeds under a
separate output sub-tree.

First extension: **three-slot same-family lifecycle**.

Reason: existing two-slot interleave doesn't exercise any 3+ slot scenario;
L1.12 v0 audit (see `docs/agentic-fuzz/v0_experiments/L1_12_corpus_summary/`)
flagged this as a coverage gap.  We don't pretend to know which bug it'll
find — the point is to broaden the input surface so reFuzz can autonomously
discover anything that lives in 3-slot interaction paths.

Output source_rule: `<family>.lifecycle.valid_three_slots`.

Depth budget defaults to 4 (12^4 ≈ 20k DFS paths before dedup, comparable
to existing two-slot enumeration cost).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator

from worker_abi import ProgramCall

from corpus import Descriptor

from .enumerate import GeneratedProgram, _canonical_args
from .lifecycle import ObjectLifecycle, parse_lifecycle


@dataclass(frozen=True)
class ExtConfig:
    """Knobs for additive corpus classes. Stays separate from
    enumerate.GenConfig so the original generator is unaffected."""
    max_depth_three_slots: int = 4
    max_depth_cross_pair:  int = 4


# ---------------------------------------------------------------------------
# B1 — three-slot same-family lifecycle
# ---------------------------------------------------------------------------


def gen_valid_three_slot_interleave(
    descriptor: Descriptor,
    lifecycles: dict[str, ObjectLifecycle],
    object_name: str,
    ext: ExtConfig,
    base_config,
) -> Iterator[GeneratedProgram]:
    """DFS over slots 0, 1, 2 of the same family.

    A seed is yielded iff the program touches **all three** slots — otherwise
    it would be subsumed by the existing single-slot / two-slot rules.
    """
    lc = lifecycles[object_name]
    valid_transitions = [t for t in lc.transitions if not t.invalid]
    by_from: dict[str, list] = {state: [] for state in lc.states}
    for t in valid_transitions:
        by_from[t.from_state].append(t)

    rule = f"{object_name}.lifecycle.valid_three_slots"
    max_depth = ext.max_depth_three_slots
    initial = (lc.initial_state, lc.initial_state, lc.initial_state)

    def dfs(states: tuple[str, str, str],
            prefix: list[ProgramCall],
            depth: int) -> Iterator[tuple[ProgramCall, ...]]:
        if depth > 0:
            yield tuple(prefix)
        if depth >= max_depth:
            return
        for slot_idx in (0, 1, 2):
            cur = states[slot_idx]
            for t in by_from[cur]:
                spec = descriptor.apis[t.api]
                args = _canonical_args(t.api, descriptor, slot_idx, base_config)
                prefix.append(ProgramCall(spec.api_id, args))
                next_states = list(states)
                next_states[slot_idx] = t.to_state
                yield from dfs(
                    (next_states[0], next_states[1], next_states[2]),
                    prefix, depth + 1)
                prefix.pop()

    for calls in dfs(initial, [], 0):
        if len(calls) < 3:
            continue
        slots_used = {int(c.args[0]) for c in calls}
        # Require all three slots actually exercised.
        if slots_used != {0, 1, 2}:
            continue
        yield GeneratedProgram(rule, calls)


# ---------------------------------------------------------------------------
# B2 — cross-family two-way interleave
# ---------------------------------------------------------------------------


def gen_cross_family_pair_interleave(
    descriptor: Descriptor,
    lifecycles: dict[str, ObjectLifecycle],
    family_a: str,
    family_b: str,
    ext: ExtConfig,
    base_config,
) -> Iterator[GeneratedProgram]:
    """DFS over slot 0 of family_a + slot 0 of family_b (joint state).

    Only yield if both families are exercised.  Mirrors the existing
    `gen_cross_object_interleave` shape (which hardwired sem+mutex) but
    parameterized — generates any 2-family combo we haven't covered.

    Output rule: `cross.<family_a>_<family_b>.interleave`.
    """
    lc_a = lifecycles[family_a]
    lc_b = lifecycles[family_b]

    def by_from(lc: ObjectLifecycle) -> dict[str, list]:
        out: dict[str, list] = {state: [] for state in lc.states}
        for t in lc.transitions:
            if t.invalid:
                continue
            out[t.from_state].append(t)
        return out

    trans_a = by_from(lc_a)
    trans_b = by_from(lc_b)

    rule = f"cross.{family_a}_{family_b}.interleave"
    max_depth = ext.max_depth_cross_pair
    initial = (lc_a.initial_state, lc_b.initial_state)

    def dfs(states: tuple[str, str], prefix: list[ProgramCall],
            depth: int) -> Iterator[tuple[ProgramCall, ...]]:
        if depth > 0:
            yield tuple(prefix)
        if depth >= max_depth:
            return
        for choice, current, options in (
                (0, states[0], trans_a[states[0]]),
                (1, states[1], trans_b[states[1]])):
            for t in options:
                spec = descriptor.apis[t.api]
                args = _canonical_args(t.api, descriptor, 0, base_config)
                prefix.append(ProgramCall(spec.api_id, args))
                next_states = list(states)
                next_states[choice] = t.to_state
                yield from dfs(
                    (next_states[0], next_states[1]), prefix, depth + 1)
                prefix.pop()

    for calls in dfs(initial, [], 0):
        # require both families exercised
        ids_a = {descriptor.apis[t.api].api_id for ts in trans_a.values() for t in ts}
        ids_b = {descriptor.apis[t.api].api_id for ts in trans_b.values() for t in ts}
        seen_a = any(c.api_id in ids_a for c in calls)
        seen_b = any(c.api_id in ids_b for c in calls)
        if not (seen_a and seen_b):
            continue
        yield GeneratedProgram(rule, calls)


# Cross-family pairs we generate. `sem_mutex` already exists in the original
# generator (`gen_cross_object_interleave`); skip that pair to stay additive.
CROSS_PAIRS = (
    ("semaphore", "event"),
    ("semaphore", "timer"),
    ("mutex",     "msgq"),
    ("mutex",     "event"),
    ("event",     "timer"),
    ("event",     "msgq"),
    ("timer",     "msgq"),
)


# ---------------------------------------------------------------------------
# Top-level orchestrator
# ---------------------------------------------------------------------------


# Families whose lifecycle is rich enough to make 3-slot enumeration useful.
# (mutex's 3-state FSM also fine; just include all five.)
SUPPORTED_FAMILIES = ("semaphore", "mutex", "msgq", "event", "timer", "wq")


def enumerate_b1_three_slot(
    descriptor: Descriptor, base_config, ext: ExtConfig | None = None,
) -> list[GeneratedProgram]:
    """B1: three-slot same-family lifecycle."""
    if ext is None: ext = ExtConfig()
    lifecycles = parse_lifecycle(descriptor.lifecycle)
    out: list[GeneratedProgram] = []
    for family in SUPPORTED_FAMILIES:
        if family not in lifecycles:
            continue
        out.extend(gen_valid_three_slot_interleave(
            descriptor, lifecycles, family, ext, base_config))
    return out


def enumerate_b2_cross_pair(
    descriptor: Descriptor, base_config, ext: ExtConfig | None = None,
) -> list[GeneratedProgram]:
    """B2: cross-family two-way interleave (7 pairs, sem+mutex stays in
    original generator so we skip it here)."""
    if ext is None: ext = ExtConfig()
    lifecycles = parse_lifecycle(descriptor.lifecycle)
    out: list[GeneratedProgram] = []
    for fa, fb in CROSS_PAIRS:
        if fa not in lifecycles or fb not in lifecycles:
            continue
        out.extend(gen_cross_family_pair_interleave(
            descriptor, lifecycles, fa, fb, ext, base_config))
    return out


# ---------------------------------------------------------------------------
# B3 — multi-waiter scenarios
# ---------------------------------------------------------------------------


def _discover_spawn_targets(descriptor: Descriptor) -> dict[str, "ApiSpec"]:
    """Scan descriptor for TASK_SPAWN_BLOCK_* APIs that target a resource
    family (have a non-task `*_slot` arg). Returns family → spawn ApiSpec.
    Pure descriptor inspection — no hardcoded family list."""
    out: dict[str, "ApiSpec"] = {}
    for spec in descriptor.apis.values():
        if not spec.name.startswith("TASK_SPAWN_BLOCK_"):
            continue
        for at in spec.arg_types:
            if at.endswith("_slot") and at != "task_slot":
                out[at.removesuffix("_slot")] = spec
                break
    return out


def _discover_tickle_apis(
    descriptor: Descriptor, family: str,
) -> list["ApiSpec"]:
    """All APIs that declare wakes_pend_list == family. Descriptor-driven —
    `wakes_pend_list` is a per-API declarative spec field set in the
    descriptor JSON (one-time human investment per kernel API)."""
    return [
        s for s in descriptor.apis.values()
        if s.wakes_pend_list == family
    ]


def gen_multi_waiter_for_family(
    descriptor: Descriptor,
    family: str,
    spawn_spec: "ApiSpec",
    base_config,
) -> Iterator[GeneratedProgram]:
    """Pre-create target resource + spawn N victims blocking on it + exercise
    each declared wake/cleanup op (descriptor-driven, no hardcoded list).

    Convention: a family `X` has a CREATE API named `{X.upper()}_CREATE`.
    Tickle ops are discovered via `wakes_pend_list == family` on each ApiSpec.
    """
    create_api  = f"{family.upper()}_CREATE"
    create_spec = descriptor.apis.get(create_api)
    if create_spec is None:
        return
    tickle_specs = _discover_tickle_apis(descriptor, family)
    if not tickle_specs:
        return

    def make_create_call() -> ProgramCall:
        args = _canonical_args(create_api, descriptor, slot=0, config=base_config)
        return ProgramCall(create_spec.api_id, args)

    def make_spawn_call(task_slot: int) -> ProgramCall:
        # SPAWN args = (task_slot, target_slot=0). _canonical_args would put
        # task_slot in both positions; force target slot to 0 explicitly.
        return ProgramCall(spawn_spec.api_id, (task_slot, 0))

    def make_tickle_call(spec: "ApiSpec") -> ProgramCall:
        args = _canonical_args(spec.name, descriptor, slot=0, config=base_config)
        return ProgramCall(spec.api_id, args)

    rule = f"multi_waiter.{family}.tickle"
    for tickle_spec in tickle_specs:
        for n_waiters in (2, 3):
            calls = [make_create_call()]
            for i in range(n_waiters):
                calls.append(make_spawn_call(i))
            calls.append(make_tickle_call(tickle_spec))
            yield GeneratedProgram(
                f"{rule}.{tickle_spec.name.lower()}",
                tuple(calls))


def enumerate_b3_multi_waiter(
    descriptor: Descriptor, base_config, ext: ExtConfig | None = None,
) -> list[GeneratedProgram]:
    """B3: multi-waiter seeds, fully descriptor-derived.

    Algorithm:
      1. Scan descriptor for TASK_SPAWN_BLOCK_* APIs → infer (family, spawn_api)
         from the non-task `*_slot` arg type. No hardcoded family list.
      2. For each (family, spawn_api), find all APIs declaring
         `wakes_pend_list == family` → enumerate CREATE + N×SPAWN + tickle.
    """
    out: list[GeneratedProgram] = []
    for family, spawn_spec in _discover_spawn_targets(descriptor).items():
        out.extend(gen_multi_waiter_for_family(
            descriptor, family, spawn_spec, base_config))
    return out


# All registered extension classes (slug → enumerator).
# Each lands in its own output dir (`corpus/generated_<slug>/`).
EXTENSION_CLASSES = {
    "three_slots":   enumerate_b1_three_slot,
    "cross_pair":    enumerate_b2_cross_pair,
    "multi_waiter":  enumerate_b3_multi_waiter,
}

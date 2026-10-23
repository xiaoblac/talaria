"""Bounded enumeration of XiUOS reFuzz program candidates.

Strategy: split generation into rule classes, each with its own constraint.
This keeps the joint state space tractable and lets dry-run validation
attribute failures to a specific rule.

Single canonical parameter value is used inside lifecycle DFS. Parameter
variation (raw timeout, raw value, invalid slot) is injected by dedicated
rule classes on top of short valid prefixes, not by combinatorial expansion.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator

from corpus import Descriptor
from worker_abi import ApiId, ProgramCall

from .canonical import VALID_SLOT_MAX, canonical_key
from .lifecycle import ObjectLifecycle, parse_lifecycle


@dataclass(frozen=True)
class GenConfig:
    max_depth_valid_single: int = 6
    max_depth_interleave_two_slots: int = 4
    max_depth_cross_object: int = 4
    raw_timeout: int = 0xFFFFFFFF
    raw_value: int = 0xFFFFFFFF
    invalid_slots: tuple[int, ...] = (4, 255)
    canonical_timeout: int = 0
    canonical_value: int = 1


@dataclass(frozen=True)
class GeneratedProgram:
    source_rule: str
    calls: tuple[ProgramCall, ...]


def _canonical_args(api_name: str, descriptor: Descriptor, slot: int, config: GenConfig) -> tuple[int, ...]:
    """Build args using a single canonical value per non-slot dimension."""
    spec = descriptor.apis[api_name]
    args: list[int] = []
    for arg_type in spec.arg_types:
        if arg_type in ("sem_slot", "mutex_slot", "msgq_slot",
                        "event_slot", "timer_slot", "task_slot",
                        "wq_slot", "dq_slot", "waitq_slot", "malloc_slot",
                        "gb_slot", "ca_slot", "avl_slot", "cap_slot"):
            args.append(slot)
        elif arg_type == "timeout":
            args.append(config.canonical_timeout)
        elif arg_type == "small_value":
            args.append(config.canonical_value)
        elif arg_type in ("msg_size_idx", "max_msgs_idx", "byte_pattern_idx",
                          "event_options_idx", "events_pattern_idx",
                          "event_process_options_idx",
                          "timer_ticks_idx", "timer_mode_idx",
                          "delay_ms_idx",
                          "dq_node_count_idx", "dq_size_idx", "dq_timeout_idx",
                          "waitq_ticks_idx",
                          "malloc_size_idx", "calloc_count_idx",
                          "gb_block_slot", "gb_block_size_idx",
                          "gb_block_count_idx", "gb_timeout_idx",
                          "ca_length_idx", "ca_xfer_idx", "ca_force",
                          "avl_data_idx",
                          "cap_pid_idx", "cap_type_idx"):
            # All *_idx args fold through the worker's & 0x03 / lookup
            # tables; the canonical seed picks index 0. Parameter variation
            # along these axes happens via the host mutator, not the
            # corpus enumerator — keeping the seed corpus deterministic.
            args.append(0)
        else:
            args.append(0)
    return tuple(args)


# [cross-family setup] A victim-spawning op blocks on a FOREIGN resource (a
# waitq / sem / event / msgq at some slot) that must already be live. But these
# ops are transitions of the *task* lifecycle, so the single-lifecycle DFS that
# emits them never creates that resource — the spawn then dies at the worker's
# "resource not live" guard (e.g. WAITQ_SPAWN_WAIT returns -ERROR when its waitq
# slot was never WAITQ_INIT'd), so the victim never spawns and the whole
# victim/leak path is unreachable from the corpus. Inject the resource-creation
# call on the referenced slot before the spawn op.
#   spawn_api -> tuple of (setup_api, index of the foreign-resource slot arg),
#   applied in order. Most need one creator; the high-priority mutex victim must
#   block on a mutex the WORKER already HOLDS, so it needs MUTEX_CREATE *and*
#   MUTEX_OBTAIN — otherwise the victim acquires the free mutex and there is no
#   priority inversion.
_SPAWN_VICTIM_SETUP: dict[str, tuple[tuple[str, int], ...]] = {
    "WAITQ_SPAWN_WAIT":            (("WAITQ_INIT",   1),),
    "TASK_SPAWN_BLOCK_SEM":        (("SEM_CREATE",   1),),
    "TASK_SPAWN_BLOCK_EVENT":      (("EVENT_CREATE", 1),),
    "TASK_SPAWN_BLOCK_MSGQ_RECV":  (("MSGQ_CREATE",  1),),
    "TASK_SPAWN_BLOCK_MUTEX_HIGH": (("MUTEX_CREATE", 1), ("MUTEX_OBTAIN", 1)),
}


def _inject_cross_family_setup(
    calls: tuple[ProgramCall, ...],
    descriptor: Descriptor,
    config: GenConfig,
) -> tuple[ProgramCall, ...]:
    """Prepend the resource setup call(s) before any victim-spawning op that
    blocks on a foreign resource (see _SPAWN_VICTIM_SETUP). Idempotent per
    (setup_api, slot): a setup the program already performs is not repeated.
    A no-op for programs containing no such spawn op."""
    id_to_name = {spec.api_id: name for name, spec in descriptor.apis.items()}
    setup_ids = {
        descriptor.apis[setup].api_id
        for steps in _SPAWN_VICTIM_SETUP.values()
        for setup, _ in steps
        if setup in descriptor.apis
    }
    done: set[tuple[int, int]] = set()
    out: list[ProgramCall] = []
    for c in calls:
        # A setup the program already performs makes its (api, slot) satisfied.
        if c.api_id in setup_ids and c.args:
            done.add((c.api_id, int(c.args[0])))
        steps = _SPAWN_VICTIM_SETUP.get(id_to_name.get(c.api_id, ""))
        if steps is not None:
            for setup_name, slot_idx in steps:
                if setup_name in descriptor.apis and slot_idx < len(c.args):
                    setup = descriptor.apis[setup_name]
                    slot = int(c.args[slot_idx])
                    key = (setup.api_id, slot)
                    if key not in done:
                        setup_args = _canonical_args(setup_name, descriptor, slot, config)
                        out.append(ProgramCall(setup.api_id, setup_args))
                        done.add(key)
        out.append(c)
    return tuple(out)


def _dfs_single_slot(
    lc: ObjectLifecycle,
    descriptor: Descriptor,
    slot: int,
    max_depth: int,
    config: GenConfig,
) -> Iterator[tuple[ProgramCall, ...]]:
    valid_transitions = [t for t in lc.transitions if not t.invalid]

    def dfs(state: str, prefix: list[ProgramCall], depth: int) -> Iterator[tuple[ProgramCall, ...]]:
        if depth > 0:
            yield tuple(prefix)
        if depth >= max_depth:
            return
        for t in valid_transitions:
            if t.from_state != state:
                continue
            spec = descriptor.apis[t.api]
            args = _canonical_args(t.api, descriptor, slot, config)
            prefix.append(ProgramCall(spec.api_id, args))
            yield from dfs(t.to_state, prefix, depth + 1)
            prefix.pop()

    yield from dfs(lc.initial_state, [], 0)


def gen_valid_single_slot(
    descriptor: Descriptor,
    lifecycles: dict[str, ObjectLifecycle],
    object_name: str,
    config: GenConfig,
) -> Iterator[GeneratedProgram]:
    lc = lifecycles[object_name]
    rule = f"{object_name}.lifecycle.valid_single_slot"
    for calls in _dfs_single_slot(lc, descriptor, slot=0, max_depth=config.max_depth_valid_single, config=config):
        yield GeneratedProgram(rule, calls)


def gen_valid_two_slot_interleave(
    descriptor: Descriptor,
    lifecycles: dict[str, ObjectLifecycle],
    object_name: str,
    config: GenConfig,
) -> Iterator[GeneratedProgram]:
    """DFS over two slots of the same object type. Joint state tracks both slots."""
    lc = lifecycles[object_name]
    valid_transitions = [t for t in lc.transitions if not t.invalid]
    by_from: dict[str, list] = {state: [] for state in lc.states}
    for t in valid_transitions:
        by_from[t.from_state].append(t)

    rule = f"{object_name}.lifecycle.valid_interleave_two_slots"
    max_depth = config.max_depth_interleave_two_slots
    initial = (lc.initial_state, lc.initial_state)

    def dfs(states: tuple[str, str], prefix: list[ProgramCall], depth: int) -> Iterator[tuple[ProgramCall, ...]]:
        if depth > 0:
            yield tuple(prefix)
        if depth >= max_depth:
            return
        for slot_idx in (0, 1):
            cur = states[slot_idx]
            for t in by_from[cur]:
                spec = descriptor.apis[t.api]
                args = _canonical_args(t.api, descriptor, slot_idx, config)
                prefix.append(ProgramCall(spec.api_id, args))
                next_states = list(states)
                next_states[slot_idx] = t.to_state
                yield from dfs((next_states[0], next_states[1]), prefix, depth + 1)
                prefix.pop()

    for calls in dfs(initial, [], 0):
        if len(calls) < 2:
            continue
        slots_used = {int(c.args[0]) for c in calls}
        if 1 not in slots_used:
            continue
        yield GeneratedProgram(rule, calls)


def gen_cross_object_interleave(
    descriptor: Descriptor,
    lifecycles: dict[str, ObjectLifecycle],
    config: GenConfig,
) -> Iterator[GeneratedProgram]:
    """Sem slot 0 and mutex slot 0, jointly tracked."""
    sem_lc = lifecycles["semaphore"]
    mutex_lc = lifecycles["mutex"]

    def by_from(lc: ObjectLifecycle) -> dict[str, list]:
        out: dict[str, list] = {state: [] for state in lc.states}
        for t in lc.transitions:
            if t.invalid:
                continue
            out[t.from_state].append(t)
        return out

    sem_trans = by_from(sem_lc)
    mutex_trans = by_from(mutex_lc)

    rule = "sem_mutex.interleave"
    max_depth = config.max_depth_cross_object
    initial = (sem_lc.initial_state, mutex_lc.initial_state)

    def dfs(states: tuple[str, str], prefix: list[ProgramCall], depth: int) -> Iterator[tuple[ProgramCall, ...]]:
        if depth > 0:
            yield tuple(prefix)
        if depth >= max_depth:
            return
        for choice, current in (("sem", states[0]), ("mutex", states[1])):
            options = sem_trans[current] if choice == "sem" else mutex_trans[current]
            for t in options:
                spec = descriptor.apis[t.api]
                args = _canonical_args(t.api, descriptor, 0, config)
                prefix.append(ProgramCall(spec.api_id, args))
                next_states = list(states)
                if choice == "sem":
                    next_states[0] = t.to_state
                else:
                    next_states[1] = t.to_state
                yield from dfs((next_states[0], next_states[1]), prefix, depth + 1)
                prefix.pop()

    for calls in dfs(initial, [], 0):
        if len(calls) < 2:
            continue
        api_ids = {int(c.api_id) for c in calls}
        from .canonical import SEM_APIS, MUTEX_APIS
        if not (api_ids & SEM_APIS) or not (api_ids & MUTEX_APIS):
            continue
        yield GeneratedProgram(rule, calls)


def _valid_prefix_to_live(
    lc: ObjectLifecycle,
    descriptor: Descriptor,
    slot: int,
    target_state: str,
    config: GenConfig,
) -> tuple[ProgramCall, ...] | None:
    """Shortest valid sequence from initial_state to target_state on a single slot."""
    if lc.initial_state == target_state:
        return tuple()
    valid_transitions = [t for t in lc.transitions if not t.invalid]
    from collections import deque
    queue: deque[tuple[str, tuple[ProgramCall, ...]]] = deque()
    queue.append((lc.initial_state, tuple()))
    seen = {lc.initial_state}
    while queue:
        state, path = queue.popleft()
        for t in valid_transitions:
            if t.from_state != state:
                continue
            if t.to_state in seen:
                continue
            spec = descriptor.apis[t.api]
            args = _canonical_args(t.api, descriptor, slot, config)
            next_path = path + (ProgramCall(spec.api_id, args),)
            if t.to_state == target_state:
                return next_path
            seen.add(t.to_state)
            queue.append((t.to_state, next_path))
    return None


def gen_invalid_op_on_empty(
    descriptor: Descriptor,
    lifecycles: dict[str, ObjectLifecycle],
    config: GenConfig,
) -> Iterator[GeneratedProgram]:
    """Single call exercising an `invalid: true` transition from EMPTY on slot 0."""
    for obj_name, lc in lifecycles.items():
        rule = f"{obj_name}.invalid.op_on_empty"
        for t in lc.transitions:
            if not t.invalid or t.from_state != lc.initial_state:
                continue
            spec = descriptor.apis[t.api]
            args = _canonical_args(t.api, descriptor, 0, config)
            yield GeneratedProgram(rule, (ProgramCall(spec.api_id, args),))


def gen_invalid_slot_single_call(
    descriptor: Descriptor,
    config: GenConfig,
) -> Iterator[GeneratedProgram]:
    """Single call with an out-of-range slot, for each slot-arg api."""
    rule = "invalid.slot.single_call"
    for api_name, spec in descriptor.apis.items():
        if not spec.arg_types or spec.arg_types[0] not in (
                "sem_slot", "mutex_slot", "msgq_slot",
                "event_slot", "timer_slot"):
            continue
        for invalid_slot in config.invalid_slots:
            args = list(_canonical_args(api_name, descriptor, invalid_slot, config))
            yield GeneratedProgram(rule, (ProgramCall(spec.api_id, tuple(args)),))


def gen_raw_timeout_in_valid_path(
    descriptor: Descriptor,
    lifecycles: dict[str, ObjectLifecycle],
    config: GenConfig,
) -> Iterator[GeneratedProgram]:
    """For each api that takes a timeout, put it after a minimal valid prefix
    and pass `raw_timeout` (0xffffffff) to exercise worker normalization."""
    rule = "raw.timeout.in_valid_path"
    by_api: dict[str, ObjectLifecycle] = {
        transition.api: lc
        for lc in lifecycles.values()
        for transition in lc.transitions
        if not transition.invalid
    }
    for api_name, spec in descriptor.apis.items():
        if "timeout" not in spec.arg_types:
            continue
        lc = by_api.get(api_name)
        if lc is None or not spec.arg_types or spec.arg_types[0] != lc.slot_type:
            continue
        transition = next(
            t for t in lc.transitions
            if not t.invalid and t.api == api_name
        )
        prefix = _valid_prefix_to_live(
            lc,
            descriptor,
            slot=0,
            target_state=transition.from_state,
            config=config,
        )
        if prefix is None:
            continue
        args = []
        for arg_type in spec.arg_types:
            if arg_type == lc.slot_type:
                args.append(0)
            elif arg_type == "timeout":
                args.append(config.raw_timeout)
            else:
                args.append(0)
        target_call = ProgramCall(spec.api_id, tuple(args))
        yield GeneratedProgram(rule, prefix + (target_call,))


def gen_raw_value_in_valid_path(
    descriptor: Descriptor,
    lifecycles: dict[str, ObjectLifecycle],
    config: GenConfig,
) -> Iterator[GeneratedProgram]:
    """Sem create and set_value with `raw_value` to exercise small-value normalize."""
    rule = "raw.value.in_valid_path"
    # SEM_CREATE on EMPTY with raw value
    spec_create = descriptor.apis["SEM_CREATE"]
    args = list(_canonical_args("SEM_CREATE", descriptor, 0, config))
    args[1] = config.raw_value
    yield GeneratedProgram(rule, (ProgramCall(spec_create.api_id, tuple(args)),))

    # SEM_SET_VALUE on LIVE with raw value: prefix with SEM_CREATE then SEM_SET_VALUE
    spec_setv = descriptor.apis["SEM_SET_VALUE"]
    create_args = _canonical_args("SEM_CREATE", descriptor, 0, config)
    setv_args = list(_canonical_args("SEM_SET_VALUE", descriptor, 0, config))
    setv_args[1] = config.raw_value
    calls = (
        ProgramCall(spec_create.api_id, create_args),
        ProgramCall(spec_setv.api_id, tuple(setv_args)),
    )
    yield GeneratedProgram(rule, calls)


def enumerate_all(
    descriptor: Descriptor,
    config: GenConfig,
) -> list[GeneratedProgram]:
    """Run all rule classes, dedupe by canonical key, preserve first-seen rule."""
    lifecycles = parse_lifecycle(descriptor.lifecycle)
    seen: set[tuple] = set()
    out: list[GeneratedProgram] = []

    def consume(it: Iterator[GeneratedProgram]) -> None:
        for prog in it:
            if not prog.calls:
                continue
            # [cross-family setup] inject any resource-creation a victim-spawning
            # op needs, before deduping — so INIT→SPAWN_WAIT (etc.) reach the
            # corpus instead of guard-rejected SPAWN_WAIT-on-empty.
            calls = _inject_cross_family_setup(prog.calls, descriptor, config)
            key = canonical_key(calls)
            if key in seen:
                continue
            seen.add(key)
            out.append(GeneratedProgram(prog.source_rule, calls))

    consume(gen_valid_single_slot(descriptor, lifecycles, "semaphore", config))
    consume(gen_valid_single_slot(descriptor, lifecycles, "mutex", config))
    if "msgq" in lifecycles:
        consume(gen_valid_single_slot(descriptor, lifecycles, "msgq", config))
    if "event" in lifecycles:
        consume(gen_valid_single_slot(descriptor, lifecycles, "event", config))
    if "timer" in lifecycles:
        consume(gen_valid_single_slot(descriptor, lifecycles, "timer", config))
    if "task" in lifecycles:
        consume(gen_valid_single_slot(descriptor, lifecycles, "task", config))
    if "wq" in lifecycles:
        consume(gen_valid_single_slot(descriptor, lifecycles, "wq", config))
    if "dq" in lifecycles:
        consume(gen_valid_single_slot(descriptor, lifecycles, "dq", config))
    if "waitq" in lifecycles:
        consume(gen_valid_single_slot(descriptor, lifecycles, "waitq", config))
    if "malloc" in lifecycles:
        consume(gen_valid_single_slot(descriptor, lifecycles, "malloc", config))
    if "gb" in lifecycles:
        consume(gen_valid_single_slot(descriptor, lifecycles, "gb", config))
    if "ca" in lifecycles:
        consume(gen_valid_single_slot(descriptor, lifecycles, "ca", config))
    if "avl" in lifecycles:
        consume(gen_valid_single_slot(descriptor, lifecycles, "avl", config))
    if "cap" in lifecycles:
        consume(gen_valid_single_slot(descriptor, lifecycles, "cap", config))
    consume(gen_valid_two_slot_interleave(descriptor, lifecycles, "semaphore", config))
    consume(gen_valid_two_slot_interleave(descriptor, lifecycles, "mutex", config))
    if "msgq" in lifecycles:
        consume(gen_valid_two_slot_interleave(descriptor, lifecycles, "msgq", config))
    if "event" in lifecycles:
        consume(gen_valid_two_slot_interleave(descriptor, lifecycles, "event", config))
    if "timer" in lifecycles:
        consume(gen_valid_two_slot_interleave(descriptor, lifecycles, "timer", config))
    if "task" in lifecycles:
        consume(gen_valid_two_slot_interleave(descriptor, lifecycles, "task", config))
    if "wq" in lifecycles:
        consume(gen_valid_two_slot_interleave(descriptor, lifecycles, "wq", config))
    if "dq" in lifecycles:
        consume(gen_valid_two_slot_interleave(descriptor, lifecycles, "dq", config))
    if "waitq" in lifecycles:
        consume(gen_valid_two_slot_interleave(descriptor, lifecycles, "waitq", config))
    if "malloc" in lifecycles:
        consume(gen_valid_two_slot_interleave(descriptor, lifecycles, "malloc", config))
    if "gb" in lifecycles:
        consume(gen_valid_two_slot_interleave(descriptor, lifecycles, "gb", config))
    if "ca" in lifecycles:
        consume(gen_valid_two_slot_interleave(descriptor, lifecycles, "ca", config))
    if "avl" in lifecycles:
        consume(gen_valid_two_slot_interleave(descriptor, lifecycles, "avl", config))
    # cap is intentionally NOT in two-slot interleave: its pid-keyed ops are
    # slot-independent and CAP_ADD_ROOT_SELF has argc=0, which the two-slot
    # generator's args[0] slot-grouping cannot represent. Single-slot covers it.
    consume(gen_cross_object_interleave(descriptor, lifecycles, config))
    consume(gen_invalid_op_on_empty(descriptor, lifecycles, config))
    consume(gen_invalid_slot_single_call(descriptor, config))
    consume(gen_raw_timeout_in_valid_path(descriptor, lifecycles, config))
    consume(gen_raw_value_in_valid_path(descriptor, lifecycles, config))

    return out

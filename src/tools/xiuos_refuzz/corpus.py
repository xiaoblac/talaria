"""XiUOS seed corpus and descriptor helpers."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from worker_abi import ApiId, ProgramCall, ResultStatus, SuiteId, encode_program

TOOL_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOL_DIR.parent.parent  # tools/xiuos_refuzz -> tools -> repo root
DEFAULT_DESCRIPTOR = TOOL_DIR / "descriptors" / "common_kernel_sem_mutex.json"
DEFAULT_SEED_DIR = TOOL_DIR / "corpus" / "seed"
# [Stage 3 规范化] generated corpus 是可重生缓存 → 落 gitignored run/xiuos/corpus/,
# 不再 tracked 在 tools/。source (descriptors/ + seed/) 仍住 TOOL_DIR。
DEFAULT_GENERATED_DIR = REPO_ROOT / "run" / "xiuos" / "corpus" / "generated"


@dataclass(frozen=True)
class ParameterDomain:
    valid: tuple[int, ...]
    boundary: tuple[int, ...] = ()
    invalid: tuple[int, ...] = ()

    @property
    def allowed(self) -> tuple[int, ...]:
        return self.valid + self.boundary + self.invalid


@dataclass(frozen=True)
class ApiSpec:
    name: str
    api_id: ApiId
    argc: int
    arg_types: tuple[str, ...]
    # Optional declarative spec: which target family's pend_list this API wakes
    # (e.g. SEM_DELETE wakes "sem" waiters). Used by descriptor-driven
    # multi-waiter corpus generator to enumerate tickle ops without a
    # hand-written family→tickle list.
    wakes_pend_list: str | None = None


@dataclass(frozen=True)
class Descriptor:
    name: str
    suite: SuiteId
    max_calls: int
    sem_slots: int
    mutex_slots: int
    timeouts: tuple[int, ...]
    small_values: tuple[int, ...]
    # KMsgQueue family — Phase 2 §C #22 follow-up. The *_idx tuples mirror
    # the worker's lookup tables in kernel/refuzz/refuzz_worker.c; values
    # here are the canonical *_idx domain ({0,1,2,3}), not the actual
    # msg_size / max_msgs the worker resolves them to.
    msgq_slots: int = 0
    msg_size_indices: tuple[int, ...] = ()
    max_msgs_indices: tuple[int, ...] = ()
    byte_pattern_indices: tuple[int, ...] = ()
    # KEvent family — same descriptor-driven pattern as msgq. The *_indices
    # tuples store the {0..3} domain; the worker maps them through bounded
    # tables to real options / event-bit-patterns.
    event_slots: int = 0
    event_options_indices: tuple[int, ...] = ()
    events_pattern_indices: tuple[int, ...] = ()
    # KTimer family — 3-state lifecycle. The ticks/mode tuples carry the
    # canonical {0..3} index domain; the worker maps them through
    # bounded tables to real ticks (10/20/50/100) and trigger modes.
    timer_slots: int = 0
    timer_ticks_indices: tuple[int, ...] = ()
    timer_mode_indices: tuple[int, ...] = ()
    # KTask (victim) family — 2-state lifecycle (EMPTY/BLOCKED). The slot
    # cap mirrors the worker's g_task_slots[XIUOS_TASK_SLOTS]; args[1] of
    # SPAWN ops references a target resource slot (sem/event/msgq) — corpus
    # generator emits them as {0..3}.
    task_slots: int = 0
    # KWorkQueue family — 2-state lifecycle (EMPTY/LIVE). 跟 task slot 一样
    # 由 worker 持有指针(WorkqueueType*),非 id;corpus 只关心 slot 域。
    wq_slots: int = 0
    # Dataqueue family — 2-state lifecycle (EMPTY/LIVE). Worker owns the
    # caller struct + heap base + data buffers; corpus only references
    # slot indices.
    dq_slots: int = 0
    # Waitqueue family — 2-state lifecycle (EMPTY/LIVE). Worker owns the
    # caller WaitQueueType struct; corpus only references slot indices.
    # Victim spawns flow through task family slots.
    waitq_slots: int = 0
    # Direct allocator family — 2-state lifecycle (EMPTY/ALLOCATED). Worker
    # owns void* pointers; corpus only references slot indices + size/count
    # idx tables.
    malloc_slots: int = 0
    # Gatherblock family — 2-state lifecycle (EMPTY/LIVE). Worker owns pool
    # handles + per-pool block ptrs; corpus references pool slot + block slot
    # + size/count/timeout idx.
    gb_slots: int = 0
    # Circular-area family — 2-state lifecycle (EMPTY/LIVE). Worker owns the
    # ring handle; corpus references slot + length/xfer idx + force flag.
    ca_slots: int = 0
    # AVL tree family — 2-state lifecycle (EMPTY/LIVE). Worker owns the root
    # pointer; corpus references slot + data idx (folds to 16 keys).
    avl_slots: int = 0
    # Capability family — flag-buffer slots + a global pid->cap map. corpus
    # references flag slot + pid idx + type idx.
    cap_slots: int = 0
    domains: dict[str, ParameterDomain] = field(default_factory=dict)
    lifecycle: Mapping[str, Any] = field(default_factory=dict)
    apis: dict[str, ApiSpec] = field(default_factory=dict)


@dataclass(frozen=True)
class SeedProgram:
    name: str
    suite: SuiteId
    calls: tuple[ProgramCall, ...]
    source: str
    source_rule: str
    purpose: str
    expected_status: ResultStatus
    expected_min_calls: int


def _read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _suite_id(name: str) -> SuiteId:
    try:
        return SuiteId[name]
    except KeyError as exc:
        raise ValueError(f"unknown suite {name!r}") from exc


def _api_id(name: str) -> ApiId:
    try:
        return ApiId[name]
    except KeyError as exc:
        raise ValueError(f"unknown api {name!r}") from exc


def _result_status(value: str | int) -> ResultStatus:
    if isinstance(value, str):
        try:
            return ResultStatus[value]
        except KeyError as exc:
            raise ValueError(f"unknown result status {value!r}") from exc
    try:
        return ResultStatus(int(value))
    except ValueError as exc:
        raise ValueError(f"unknown result status {value!r}") from exc


def _int_tuple(values: Any) -> tuple[int, ...]:
    return tuple(int(value) for value in values)


def _load_domain(
    raw_domains: Mapping[str, Any],
    name: str,
    valid: tuple[int, ...],
) -> ParameterDomain:
    raw = raw_domains.get(name, {})
    return ParameterDomain(
        valid=_int_tuple(raw.get("valid", valid)),
        boundary=_int_tuple(raw.get("boundary", ())),
        invalid=_int_tuple(raw.get("invalid", ())),
    )


def load_descriptor(path: Path = DEFAULT_DESCRIPTOR) -> Descriptor:
    raw = _read_json(path)
    limits = raw["limits"]
    apis: dict[str, ApiSpec] = {}
    sem_slots = int(limits["sem_slots"])
    mutex_slots = int(limits["mutex_slots"])
    timeouts = _int_tuple(limits["timeouts"])
    small_values = _int_tuple(limits["small_values"])

    # MsgQueue family — present iff descriptor declares them. Defaulting
    # to 0 / empty tuples keeps the loader backward-compatible with
    # pre-MSGQ descriptor JSONs that some external tools may still ship.
    msgq_slots = int(limits.get("msgq_slots", 0))
    msg_size_indices = _int_tuple(limits.get("msg_size_indices", ()))
    max_msgs_indices = _int_tuple(limits.get("max_msgs_indices", ()))
    byte_pattern_indices = _int_tuple(limits.get("byte_pattern_indices", ()))

    event_slots = int(limits.get("event_slots", 0))
    event_options_indices = _int_tuple(limits.get("event_options_indices", ()))
    events_pattern_indices = _int_tuple(limits.get("events_pattern_indices", ()))

    timer_slots = int(limits.get("timer_slots", 0))
    timer_ticks_indices = _int_tuple(limits.get("timer_ticks_indices", ()))
    timer_mode_indices = _int_tuple(limits.get("timer_mode_indices", ()))

    task_slots = int(limits.get("task_slots", 0))
    wq_slots   = int(limits.get("wq_slots", 0))
    dq_slots   = int(limits.get("dq_slots", 0))
    waitq_slots = int(limits.get("waitq_slots", 0))
    malloc_slots = int(limits.get("malloc_slots", 0))
    gb_slots   = int(limits.get("gb_slots", 0))
    ca_slots   = int(limits.get("ca_slots", 0))
    avl_slots  = int(limits.get("avl_slots", 0))
    cap_slots  = int(limits.get("cap_slots", 0))

    raw_domains = raw.get("domains", {})

    for item in raw["apis"]:
        arg_types = tuple(arg["type"] for arg in item["args"])
        spec = ApiSpec(
            name=item["name"],
            api_id=_api_id(item["api_id"]),
            argc=int(item["argc"]),
            arg_types=arg_types,
            wakes_pend_list=item.get("wakes_pend_list"),
        )
        if spec.argc != len(spec.arg_types):
            raise ValueError(f"{spec.name}: argc does not match args")
        apis[spec.name] = spec

    domains = {
        "sem_slot": _load_domain(raw_domains, "sem_slot", tuple(range(sem_slots))),
        "mutex_slot": _load_domain(
            raw_domains, "mutex_slot", tuple(range(mutex_slots))
        ),
        "timeout": _load_domain(raw_domains, "timeout", timeouts),
        "small_value": _load_domain(raw_domains, "small_value", small_values),
    }
    if msgq_slots > 0:
        domains["msgq_slot"] = _load_domain(
            raw_domains, "msgq_slot", tuple(range(msgq_slots))
        )
        domains["msg_size_idx"] = _load_domain(
            raw_domains, "msg_size_idx", msg_size_indices
        )
        domains["max_msgs_idx"] = _load_domain(
            raw_domains, "max_msgs_idx", max_msgs_indices
        )
        domains["byte_pattern_idx"] = _load_domain(
            raw_domains, "byte_pattern_idx", byte_pattern_indices
        )
    if event_slots > 0:
        domains["event_slot"] = _load_domain(
            raw_domains, "event_slot", tuple(range(event_slots))
        )
        domains["event_options_idx"] = _load_domain(
            raw_domains, "event_options_idx", event_options_indices
        )
        domains["events_pattern_idx"] = _load_domain(
            raw_domains, "events_pattern_idx", events_pattern_indices
        )
        domains["event_process_options_idx"] = _load_domain(
            raw_domains, "event_process_options_idx", (0, 1, 2, 3)
        )
    if timer_slots > 0:
        domains["timer_slot"] = _load_domain(
            raw_domains, "timer_slot", tuple(range(timer_slots))
        )
        domains["timer_ticks_idx"] = _load_domain(
            raw_domains, "timer_ticks_idx", timer_ticks_indices
        )
        domains["timer_mode_idx"] = _load_domain(
            raw_domains, "timer_mode_idx", timer_mode_indices
        )
    if task_slots > 0:
        domains["task_slot"] = _load_domain(
            raw_domains, "task_slot", tuple(range(task_slots))
        )
    if wq_slots > 0:
        domains["wq_slot"] = _load_domain(
            raw_domains, "wq_slot", tuple(range(wq_slots))
        )
    if dq_slots > 0:
        domains["dq_slot"] = _load_domain(
            raw_domains, "dq_slot", tuple(range(dq_slots))
        )
        domains["dq_node_count_idx"] = _load_domain(
            raw_domains, "dq_node_count_idx", (0, 1, 2, 3)
        )
        domains["dq_size_idx"] = _load_domain(
            raw_domains, "dq_size_idx", (0, 1, 2, 3)
        )
        domains["dq_timeout_idx"] = _load_domain(
            raw_domains, "dq_timeout_idx", (0, 1, 2, 3)
        )
    if waitq_slots > 0:
        domains["waitq_slot"] = _load_domain(
            raw_domains, "waitq_slot", tuple(range(waitq_slots))
        )
        domains["waitq_ticks_idx"] = _load_domain(
            raw_domains, "waitq_ticks_idx", (0, 1, 2, 3)
        )
    if malloc_slots > 0:
        domains["malloc_slot"] = _load_domain(
            raw_domains, "malloc_slot", tuple(range(malloc_slots))
        )
        domains["malloc_size_idx"] = _load_domain(
            raw_domains, "malloc_size_idx", (0, 1, 2, 3)
        )
        domains["calloc_count_idx"] = _load_domain(
            raw_domains, "calloc_count_idx", (0, 1, 2, 3)
        )
    if gb_slots > 0:
        domains["gb_slot"] = _load_domain(
            raw_domains, "gb_slot", tuple(range(gb_slots))
        )
        domains["gb_block_slot"] = _load_domain(
            raw_domains, "gb_block_slot", (0, 1, 2, 3)
        )
        domains["gb_block_size_idx"] = _load_domain(
            raw_domains, "gb_block_size_idx", (0, 1, 2, 3)
        )
        domains["gb_block_count_idx"] = _load_domain(
            raw_domains, "gb_block_count_idx", (0, 1, 2, 3)
        )
        domains["gb_timeout_idx"] = _load_domain(
            raw_domains, "gb_timeout_idx", (0, 1, 2, 3)
        )
    if ca_slots > 0:
        domains["ca_slot"] = _load_domain(
            raw_domains, "ca_slot", tuple(range(ca_slots))
        )
        domains["ca_length_idx"] = _load_domain(
            raw_domains, "ca_length_idx", (0, 1, 2, 3)
        )
        domains["ca_xfer_idx"] = _load_domain(
            raw_domains, "ca_xfer_idx", (0, 1, 2, 3)
        )
        domains["ca_force"] = _load_domain(
            raw_domains, "ca_force", (0, 1)
        )
    if avl_slots > 0:
        domains["avl_slot"] = _load_domain(
            raw_domains, "avl_slot", tuple(range(avl_slots))
        )
        domains["avl_data_idx"] = _load_domain(
            raw_domains, "avl_data_idx", tuple(range(16))
        )
    if cap_slots > 0:
        domains["cap_slot"] = _load_domain(
            raw_domains, "cap_slot", tuple(range(cap_slots))
        )
        domains["cap_pid_idx"] = _load_domain(
            raw_domains, "cap_pid_idx", (0, 1, 2, 3)
        )
        domains["cap_type_idx"] = _load_domain(
            raw_domains, "cap_type_idx", (0, 1, 2, 3)
        )

    return Descriptor(
        name=raw["name"],
        suite=_suite_id(raw["suite"]),
        max_calls=int(limits["max_calls"]),
        sem_slots=sem_slots,
        mutex_slots=mutex_slots,
        timeouts=timeouts,
        small_values=small_values,
        msgq_slots=msgq_slots,
        msg_size_indices=msg_size_indices,
        max_msgs_indices=max_msgs_indices,
        byte_pattern_indices=byte_pattern_indices,
        event_slots=event_slots,
        event_options_indices=event_options_indices,
        events_pattern_indices=events_pattern_indices,
        timer_slots=timer_slots,
        timer_ticks_indices=timer_ticks_indices,
        timer_mode_indices=timer_mode_indices,
        task_slots=task_slots,
        wq_slots=wq_slots,
        dq_slots=dq_slots,
        waitq_slots=waitq_slots,
        malloc_slots=malloc_slots,
        gb_slots=gb_slots,
        ca_slots=ca_slots,
        avl_slots=avl_slots,
        cap_slots=cap_slots,
        domains=domains,
        lifecycle=raw.get("lifecycle", {}),
        apis=apis,
    )


def _validate_arg(descriptor: Descriptor, arg_type: str, value: int, api_name: str) -> None:
    if value < 0:
        raise ValueError(f"{api_name}: negative argument {value}")
    domain = descriptor.domains.get(arg_type)
    if domain is None:
        raise ValueError(f"{api_name}: unknown argument type {arg_type!r}")
    if value not in domain.allowed:
        raise ValueError(f"{api_name}: {arg_type} value outside descriptor domain: {value}")


def load_seed_data(
    raw: Mapping[str, Any],
    descriptor: Descriptor,
    *,
    source_name: str = "<memory>",
) -> SeedProgram:
    suite = _suite_id(raw["suite"])
    if suite != descriptor.suite:
        raise ValueError(f"{source_name}: suite {suite.name} does not match descriptor")

    calls: list[ProgramCall] = []
    for index, item in enumerate(raw["calls"]):
        api_name = item["api"]
        if api_name not in descriptor.apis:
            raise ValueError(f"{source_name}: unknown api {api_name!r} at call {index}")

        spec = descriptor.apis[api_name]
        args = tuple(int(value) for value in item.get("args", []))
        if len(args) != spec.argc:
            raise ValueError(
                f"{source_name}: {api_name} expects {spec.argc} args, got {len(args)}"
            )

        for arg_type, value in zip(spec.arg_types, args):
            _validate_arg(descriptor, arg_type, value, api_name)

        calls.append(ProgramCall(spec.api_id, args))

    if len(calls) > descriptor.max_calls:
        raise ValueError(f"{source_name}: too many calls: {len(calls)}")

    expected_status = _result_status(raw.get("expected_status", "OK"))
    expected_min_calls = int(raw.get("expected_min_calls", len(calls)))
    if expected_min_calls < 0 or expected_min_calls > len(calls):
        raise ValueError(
            f"{source_name}: expected_min_calls {expected_min_calls} outside call range"
        )

    return SeedProgram(
        name=raw["name"],
        suite=suite,
        calls=tuple(calls),
        source=raw.get("source", "manual_bootstrap"),
        source_rule=raw.get("source_rule", raw.get("source", "manual_bootstrap")),
        purpose=raw.get("purpose", "smoke"),
        expected_status=expected_status,
        expected_min_calls=expected_min_calls,
    )


def load_seed(path: Path, descriptor: Descriptor) -> SeedProgram:
    return load_seed_data(_read_json(path), descriptor, source_name=str(path))


def iter_seed_paths(seed_dir: Path = DEFAULT_SEED_DIR) -> list[Path]:
    return sorted(seed_dir.glob("*.json"))


def load_seeds(
    descriptor: Descriptor,
    seed_dir: Path = DEFAULT_SEED_DIR,
) -> list[SeedProgram]:
    return [load_seed(path, descriptor) for path in iter_seed_paths(seed_dir)]


def encode_seed(seed: SeedProgram) -> bytes:
    return encode_program(seed.calls, suite_id=seed.suite)

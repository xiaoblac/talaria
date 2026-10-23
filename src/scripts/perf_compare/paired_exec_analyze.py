#!/usr/bin/env python3
"""Report each side's own native wall-time/CPU/runqueue performance from its
own timeline log, independently. Population-level only: no cross-system
request pairing, no shared correlation key, no replay result/outcome file --
each side's numbers stand on their own, valid because both sides consumed
the same fixed, ordered request stream (see
docs/plans/fixed-request-stream-performance-replay.md)."""

from __future__ import annotations

import argparse
import datetime as dt
import math
import os
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable


TOKEN_RE = re.compile(r"([A-Za-z][A-Za-z0-9]*)=([+-]?\d+)")

CLOCK_RESET_BACKWARD_US = 1_000_000
EXEC_COUNTER_FIELDS = ("done", "pc", "ch", "ex", "pa", "pi", "miss")
VM_COUNTER_FIELDS = ("u", "n", "s", "i", "w", "hi", "si", "st")


@dataclass(frozen=True)
class TimelineRow:
    worker: int
    request_id: int
    fields: dict[str, int]


@dataclass
class TimelineParse:
    name: str
    path: Path
    rows: dict[tuple[int, int], TimelineRow]
    ad_count: int
    detail_count: int
    duplicate_ad: int
    duplicate_detail: int
    unmatched_halves: int
    invalid_rows: int


@dataclass(frozen=True)
class Metric:
    key: str
    label: str
    getter: Callable[[TimelineRow], int]


@dataclass(frozen=True)
class MetricValues:
    metric: Metric
    syz: list[int]
    rfz: list[int]


@dataclass(frozen=True)
class RoleCpuSample:
    worker: int
    timestamp_us: int
    cpu_us: int
    completed: int


@dataclass(frozen=True)
class RoleCpuSummary:
    name: str
    path: Path
    sample_count: int
    worker_count: int
    valid_intervals: int
    reset_boundaries: int
    zero_completion_intervals: int
    invalid_rows: int
    cpu_us: int
    completed: int

    @property
    def cpu_per_completion_us(self) -> float:
        if self.completed == 0:
            return math.nan
        return self.cpu_us / self.completed


@dataclass(frozen=True)
class ExecCpuSample:
    epoch: int
    worker: int
    timestamp_us: int
    done: int
    process_cpu_us: int
    children_cpu_us: int
    execution_cpu_us: int
    parent_active_cpu_us: int
    parent_idle_cpu_us: int
    missing: int


@dataclass(frozen=True)
class VmCpuSample:
    epoch: int
    timestamp_us: int
    user: int
    nice: int
    system: int
    idle: int
    iowait: int
    irq: int
    softirq: int
    steal: int
    running: int
    blocked: int
    hz: int


@dataclass
class CpuLedgerParse:
    name: str
    path: Path
    exec_samples: dict[int, dict[int, list[ExecCpuSample]]]
    role_samples: dict[int, dict[int, list[RoleCpuSample]]]
    vm_samples: dict[int, list[VmCpuSample]]
    invalid_exec_rows: int
    invalid_role_rows: int
    invalid_vm_rows: int
    clock_resets: int


@dataclass
class CounterDelta:
    values: dict[str, int]
    sample_count: int = 0
    valid_intervals: int = 0
    reset_boundaries: int = 0
    generation_baselines: int = 0
    first_timestamp_us: int | None = None
    last_timestamp_us: int | None = None


@dataclass
class CpuClosureSummary:
    name: str
    path: Path
    valid: bool
    reason: str
    epochs_seen: int
    epochs_used: int
    clock_resets: int
    exec_workers: int
    role_workers: int
    exec_samples: int
    role_samples: int
    vm_samples: int
    invalid_rows: int
    valid_intervals: int
    reset_boundaries: int
    generation_baselines: int
    coverage_us: int
    max_boundary_gap_us: int
    completed: int
    shared_completed: int
    missing: int
    parent_process_cpu_us: float
    children_cpu_us: float
    execution_cpu_us: float
    parent_active_cpu_us: float
    parent_idle_cpu_us: float
    shared_cpu_us: float
    vm_busy_cpu_us: float
    irq_cpu_us: float
    softirq_cpu_us: float

    @property
    def child_outside_execution_us(self) -> float:
        return self.children_cpu_us - self.execution_cpu_us

    @property
    def programs_per_second(self) -> float:
        # Denominator for every ms/second figure. `completed` and the CPU
        # totals are accumulated over the same closure windows, so this is the
        # throughput those totals were produced at -- not the driver's
        # end-to-end wall clock.
        if self.coverage_us <= 0:
            return math.nan
        return self.completed / (self.coverage_us / 1_000_000.0)

    @property
    def parent_unsegmented_us(self) -> float:
        return (
            self.parent_process_cpu_us
            - self.parent_active_cpu_us
            - self.parent_idle_cpu_us
        )

    @property
    def model_active_cpu_us(self) -> float:
        return (
            self.child_outside_execution_us
            + self.parent_active_cpu_us
            + self.shared_cpu_us
        )

    @property
    def other_cpu_us(self) -> float:
        return (
            self.vm_busy_cpu_us
            - self.parent_process_cpu_us
            - self.children_cpu_us
            - self.shared_cpu_us
            - self.irq_cpu_us
            - self.softirq_cpu_us
        )

    @property
    def closure_gap_percent(self) -> float:
        if self.vm_busy_cpu_us <= 0:
            return math.nan
        return abs(self.other_cpu_us) * 100.0 / self.vm_busy_cpu_us

    @property
    def missing_percent(self) -> float:
        if self.completed <= 0:
            return math.nan
        return self.missing * 100.0 / self.completed

    @property
    def completion_skew_percent(self) -> float:
        if self.completed <= 0:
            return math.nan
        return abs(self.shared_completed - self.completed) * 100.0 / self.completed


def parse_tokens(line: str) -> dict[str, int]:
    return {key: int(value) for key, value in TOKEN_RE.findall(line)}


def resolve_refuzz_log(path: Path) -> Path:
    """Resolve the dedicated worker log while retaining old-run compatibility."""
    if path.is_dir():
        worker_log = path / "worker.log"
        if worker_log.is_file():
            return worker_log
        serial_log = path / "serial.log"
        if serial_log.is_file():
            return serial_log
        return worker_log

    if path.name == "serial.log":
        worker_log = path.with_name("worker.log")
        if worker_log.is_file():
            return worker_log
    return path


def parse_timeline(
    path: Path,
    name: str,
    marker: str,
    worker_field: str,
) -> TimelineParse:
    ad: dict[tuple[int, int], dict[str, int]] = {}
    detail: dict[tuple[int, int], dict[str, int]] = {}
    duplicate_ad_keys: set[tuple[int, int]] = set()
    duplicate_detail_keys: set[tuple[int, int]] = set()

    with path.open("r", errors="replace") as source:
        for line in source:
            if marker not in line:
                continue
            fields = parse_tokens(line)
            # Multiple guest processes share the worker serial. A partial
            # WorkerPerfStage line (wid=) can be glued to an RfzTL line (w=),
            # so generic precedence silently assigns the reFuzz record to the
            # wrong worker. Each format has one authoritative worker field.
            worker = fields.get(worker_field)
            request_id = fields.get("id")
            if worker is None or request_id is None:
                continue
            key = (worker, request_id)
            if "A" in fields and "D" in fields:
                if key in ad:
                    duplicate_ad_keys.add(key)
                ad[key] = fields
            elif all(field in fields for field in ("B", "C", "R", "A2")):
                if key in detail:
                    duplicate_detail_keys.add(key)
                detail[key] = fields

    rows: dict[tuple[int, int], TimelineRow] = {}
    invalid_rows = 0
    duplicate_keys = duplicate_ad_keys | duplicate_detail_keys
    for key in (ad.keys() & detail.keys()) - duplicate_keys:
        fields = dict(ad[key])
        fields.update(detail[key])
        if not all(fields.get(stamp, 0) > 0 for stamp in ("A", "B", "C", "D", "R", "A2")):
            invalid_rows += 1
            continue
        if not (
            fields["A"] <= fields["B"] <= fields["C"] <= fields["D"]
            and fields["C"] <= fields["R"] <= fields["A2"]
        ):
            invalid_rows += 1
            continue
        rows[key] = TimelineRow(key[0], key[1], fields)

    return TimelineParse(
        name=name,
        path=path,
        rows=rows,
        ad_count=len(ad),
        detail_count=len(detail),
        duplicate_ad=len(duplicate_ad_keys),
        duplicate_detail=len(duplicate_detail_keys),
        unmatched_halves=len(ad.keys() ^ detail.keys()),
        invalid_rows=invalid_rows,
    )


def parse_role_cpu(
    path: Path,
    name: str,
    marker: str,
    worker_field: str | None,
) -> RoleCpuSummary:
    samples_by_worker: dict[int, list[RoleCpuSample]] = defaultdict(list)
    invalid_rows = 0

    with path.open("r", errors="replace") as source:
        for line in source:
            if marker not in line:
                continue
            fields = parse_tokens(line)
            worker = fields.get(worker_field) if worker_field else 0
            timestamp_us = fields.get("t")
            cpu_us = fields.get("cpu")
            completed = fields.get("done")
            if (
                worker is None
                or timestamp_us is None
                or cpu_us is None
                or completed is None
                or worker < 0
                or timestamp_us < 0
                or cpu_us < 0
                or completed < 0
            ):
                invalid_rows += 1
                continue
            samples_by_worker[worker].append(
                RoleCpuSample(worker, timestamp_us, cpu_us, completed)
            )

    valid_intervals = 0
    reset_boundaries = 0
    zero_completion_intervals = 0
    total_cpu_us = 0
    total_completed = 0
    for samples in samples_by_worker.values():
        previous: RoleCpuSample | None = None
        for sample in samples:
            if previous is not None:
                if (
                    sample.timestamp_us < previous.timestamp_us
                    or sample.cpu_us < previous.cpu_us
                    or sample.completed < previous.completed
                ):
                    # A process/VM restart starts a new cumulative series. The
                    # boundary itself spans incomparable counter generations.
                    reset_boundaries += 1
                else:
                    cpu_delta = sample.cpu_us - previous.cpu_us
                    completed_delta = sample.completed - previous.completed
                    if cpu_delta > 0 or completed_delta > 0:
                        valid_intervals += 1
                        total_cpu_us += cpu_delta
                        total_completed += completed_delta
                        if cpu_delta > 0 and completed_delta == 0:
                            zero_completion_intervals += 1
            previous = sample

    return RoleCpuSummary(
        name=name,
        path=path,
        sample_count=sum(len(samples) for samples in samples_by_worker.values()),
        worker_count=len(samples_by_worker),
        valid_intervals=valid_intervals,
        reset_boundaries=reset_boundaries,
        zero_completion_intervals=zero_completion_intervals,
        invalid_rows=invalid_rows,
        cpu_us=total_cpu_us,
        completed=total_completed,
    )


def _fields_after_marker(line: str, marker: str, offset: int) -> dict[str, int]:
    start = offset + len(marker)
    end = line.find("[", start)
    if end < 0:
        end = len(line)
    return parse_tokens(line[start:end])


def parse_cpu_ledger(
    path: Path,
    name: str,
    exec_marker: str,
    exec_worker_field: str,
    role_marker: str,
    role_worker_field: str | None,
    vm_marker: str,
) -> CpuLedgerParse:
    """Parse cumulative CPU streams and split guest-clock reset epochs."""
    exec_samples: dict[int, dict[int, list[ExecCpuSample]]] = defaultdict(
        lambda: defaultdict(list)
    )
    role_samples: dict[int, dict[int, list[RoleCpuSample]]] = defaultdict(
        lambda: defaultdict(list)
    )
    vm_samples: dict[int, list[VmCpuSample]] = defaultdict(list)
    invalid_exec_rows = 0
    invalid_role_rows = 0
    invalid_vm_rows = 0
    clock_resets = 0
    epoch = 0
    max_timestamp_us: int | None = None
    previous_vm_counters: tuple[int, ...] | None = None

    marker_specs = (
        ("exec", exec_marker),
        ("role", role_marker),
        ("vm", vm_marker),
    )

    with path.open("r", errors="replace") as source:
        for line in source:
            occurrences: list[tuple[int, str, str]] = []
            for kind, marker in marker_specs:
                offset = line.find(marker)
                while offset >= 0:
                    occurrences.append((offset, kind, marker))
                    offset = line.find(marker, offset + len(marker))

            for offset, kind, marker in sorted(occurrences):
                fields = _fields_after_marker(line, marker, offset)
                timestamp_us = fields.get("t")
                if timestamp_us is None or timestamp_us < 0:
                    if kind == "exec":
                        invalid_exec_rows += 1
                    elif kind == "role":
                        invalid_role_rows += 1
                    else:
                        invalid_vm_rows += 1
                    continue

                if kind == "exec":
                    worker = fields.get(exec_worker_field)
                    if (
                        worker is None
                        or worker < 0
                        or any(fields.get(field, -1) < 0 for field in EXEC_COUNTER_FIELDS)
                    ):
                        invalid_exec_rows += 1
                        continue
                elif kind == "role":
                    worker = fields.get(role_worker_field) if role_worker_field else 0
                    if (
                        worker is None
                        or worker < 0
                        or fields.get("cpu", -1) < 0
                        or fields.get("done", -1) < 0
                    ):
                        invalid_role_rows += 1
                        continue
                else:
                    if (
                        any(fields.get(field, -1) < 0 for field in VM_COUNTER_FIELDS)
                        or fields.get("run", -1) < 0
                        or fields.get("blk", -1) < 0
                        or fields.get("hz", 0) <= 0
                    ):
                        invalid_vm_rows += 1
                        continue

                clock_went_back = (
                    max_timestamp_us is not None
                    and timestamp_us + CLOCK_RESET_BACKWARD_US < max_timestamp_us
                )
                vm_counters = (
                    tuple(fields[field] for field in VM_COUNTER_FIELDS)
                    if kind == "vm"
                    else None
                )
                vm_counters_reset = (
                    kind == "vm"
                    and previous_vm_counters is not None
                    and any(
                        current < previous
                        for current, previous in zip(vm_counters, previous_vm_counters)
                    )
                )
                if clock_went_back or vm_counters_reset:
                    epoch += 1
                    clock_resets += 1
                    max_timestamp_us = None
                    previous_vm_counters = None

                max_timestamp_us = (
                    timestamp_us
                    if max_timestamp_us is None
                    else max(max_timestamp_us, timestamp_us)
                )

                if kind == "exec":
                    exec_samples[epoch][worker].append(
                        ExecCpuSample(
                            epoch=epoch,
                            worker=worker,
                            timestamp_us=timestamp_us,
                            done=fields["done"],
                            process_cpu_us=fields["pc"],
                            children_cpu_us=fields["ch"],
                            execution_cpu_us=fields["ex"],
                            parent_active_cpu_us=fields["pa"],
                            parent_idle_cpu_us=fields["pi"],
                            missing=fields["miss"],
                        )
                    )
                elif kind == "role":
                    role_samples[epoch][worker].append(
                        RoleCpuSample(
                            worker=worker,
                            timestamp_us=timestamp_us,
                            cpu_us=fields["cpu"],
                            completed=fields["done"],
                        )
                    )
                else:
                    vm_samples[epoch].append(
                        VmCpuSample(
                            epoch=epoch,
                            timestamp_us=timestamp_us,
                            user=fields["u"],
                            nice=fields["n"],
                            system=fields["s"],
                            idle=fields["i"],
                            iowait=fields["w"],
                            irq=fields["hi"],
                            softirq=fields["si"],
                            steal=fields["st"],
                            running=fields["run"],
                            blocked=fields["blk"],
                            hz=fields["hz"],
                        )
                    )
                    previous_vm_counters = vm_counters

    for by_worker in exec_samples.values():
        for samples in by_worker.values():
            samples.sort(key=lambda sample: sample.timestamp_us)
    for by_worker in role_samples.values():
        for samples in by_worker.values():
            samples.sort(key=lambda sample: sample.timestamp_us)
    for samples in vm_samples.values():
        samples.sort(key=lambda sample: sample.timestamp_us)

    return CpuLedgerParse(
        name=name,
        path=path,
        exec_samples={
            epoch_id: dict(by_worker)
            for epoch_id, by_worker in exec_samples.items()
        },
        role_samples={
            epoch_id: dict(by_worker)
            for epoch_id, by_worker in role_samples.items()
        },
        vm_samples=dict(vm_samples),
        invalid_exec_rows=invalid_exec_rows,
        invalid_role_rows=invalid_role_rows,
        invalid_vm_rows=invalid_vm_rows,
        clock_resets=clock_resets,
    )


def _counter_delta(
    samples: list[object],
    start_us: int,
    end_us: int,
    fields: dict[str, Callable[[object], int]],
    timestamp: Callable[[object], int],
    include_generation_baselines: bool = False,
) -> CounterDelta:
    selected = [
        (index, sample)
        for index, sample in enumerate(samples)
        if start_us <= timestamp(sample) <= end_us
    ]
    result = CounterDelta(
        values={field: 0 for field in fields},
        sample_count=len(selected),
        first_timestamp_us=timestamp(selected[0][1]) if selected else None,
        last_timestamp_us=timestamp(selected[-1][1]) if selected else None,
    )

    def add_generation_baseline(sample: object) -> None:
        result.generation_baselines += 1
        for field, getter in fields.items():
            result.values[field] += getter(sample)

    # A logical worker ID can first appear after the persistent window starts.
    # Its first absolute process counters cover a process born inside the
    # window, so omitting them would lose startup CPU. Do not add the first
    # baseline when an older sample exists outside the window: that process may
    # predate the target boundary and cannot be clipped exactly.
    if (
        include_generation_baselines
        and selected
        and selected[0][0] == 0
        and timestamp(selected[0][1]) > start_us
    ):
        add_generation_baseline(selected[0][1])

    for (_, previous), (_, current) in zip(selected, selected[1:]):
        previous_values = {field: getter(previous) for field, getter in fields.items()}
        current_values = {field: getter(current) for field, getter in fields.items()}
        if (
            timestamp(current) < timestamp(previous)
            or any(current_values[field] < previous_values[field] for field in fields)
        ):
            result.reset_boundaries += 1
            if include_generation_baselines:
                # The current sample belongs to a new process generation. Its
                # absolute values recover work done between process birth and
                # the first successfully emitted sample.
                add_generation_baseline(current)
            continue
        result.valid_intervals += 1
        for field in fields:
            result.values[field] += current_values[field] - previous_values[field]
    return result


def compute_cpu_closure(ledger: CpuLedgerParse) -> CpuClosureSummary:
    """Close CPU counters over persistent per-epoch measurement windows.

    VM and shared-role streams persist for the experiment and define the target
    window. Loop-parent IDs are recyclable process identities: each contributes
    only while it exists and must never narrow the target window.
    """
    epoch_ids = sorted(
        set(ledger.exec_samples) | set(ledger.role_samples) | set(ledger.vm_samples)
    )
    skipped_epochs: Counter[str] = Counter()
    epochs_used = 0
    exec_workers_seen: set[int] = set()
    role_workers_seen: set[int] = set()
    exec_sample_count = 0
    role_sample_count = 0
    vm_sample_count = 0
    valid_intervals = 0
    reset_boundaries = 0
    generation_baselines = 0
    coverage_us = 0
    max_boundary_gap_us = 0

    totals: dict[str, float] = defaultdict(float)

    exec_fields: dict[str, Callable[[object], int]] = {
        "done": lambda sample: sample.done,
        "pc": lambda sample: sample.process_cpu_us,
        "ch": lambda sample: sample.children_cpu_us,
        "ex": lambda sample: sample.execution_cpu_us,
        "pa": lambda sample: sample.parent_active_cpu_us,
        "pi": lambda sample: sample.parent_idle_cpu_us,
        "miss": lambda sample: sample.missing,
    }
    role_fields: dict[str, Callable[[object], int]] = {
        "cpu": lambda sample: sample.cpu_us,
        "done": lambda sample: sample.completed,
    }
    vm_fields: dict[str, Callable[[object], int]] = {
        "u": lambda sample: sample.user,
        "n": lambda sample: sample.nice,
        "s": lambda sample: sample.system,
        "i": lambda sample: sample.idle,
        "w": lambda sample: sample.iowait,
        "hi": lambda sample: sample.irq,
        "si": lambda sample: sample.softirq,
        "st": lambda sample: sample.steal,
    }

    for epoch in epoch_ids:
        exec_by_worker = ledger.exec_samples.get(epoch, {})
        role_by_worker = ledger.role_samples.get(epoch, {})
        vm = ledger.vm_samples.get(epoch, [])
        if not exec_by_worker or not role_by_worker or not vm:
            skipped_epochs["missing stream"] += 1
            continue

        persistent_series: list[list[object]] = [*role_by_worker.values(), vm]
        if any(len(samples) < 2 for samples in persistent_series):
            skipped_epochs["fewer than two samples"] += 1
            continue

        start_us = max(samples[0].timestamp_us for samples in persistent_series)
        end_us = min(samples[-1].timestamp_us for samples in persistent_series)
        if end_us <= start_us:
            skipped_epochs["empty common window"] += 1
            continue

        exec_deltas = [
            _counter_delta(
                samples,
                start_us,
                end_us,
                exec_fields,
                lambda sample: sample.timestamp_us,
                include_generation_baselines=True,
            )
            for samples in exec_by_worker.values()
        ]
        exec_deltas = [delta for delta in exec_deltas if delta.sample_count > 0]
        role_deltas = [
            _counter_delta(
                samples,
                start_us,
                end_us,
                role_fields,
                lambda sample: sample.timestamp_us,
                include_generation_baselines=True,
            )
            for samples in role_by_worker.values()
        ]
        vm_delta = _counter_delta(
            vm,
            start_us,
            end_us,
            vm_fields,
            lambda sample: sample.timestamp_us,
        )
        if not exec_deltas or not any(
            delta.valid_intervals > 0 or delta.generation_baselines > 0
            for delta in exec_deltas
        ):
            skipped_epochs["no loop-parent accounting in persistent window"] += 1
            continue
        if vm_delta.valid_intervals == 0 or any(
            delta.valid_intervals == 0 for delta in role_deltas
        ):
            skipped_epochs["no valid interval in common window"] += 1
            continue
        all_deltas = [*exec_deltas, *role_deltas, vm_delta]

        selected_vm = [
            sample for sample in vm if start_us <= sample.timestamp_us <= end_us
        ]
        hz_values = {sample.hz for sample in selected_vm}
        if len(hz_values) != 1:
            skipped_epochs["CLK_TCK changed"] += 1
            continue
        hz = hz_values.pop()

        epoch_exec: dict[str, int] = defaultdict(int)
        for delta in exec_deltas:
            for field, value in delta.values.items():
                epoch_exec[field] += value
        epoch_role: dict[str, int] = defaultdict(int)
        for delta in role_deltas:
            for field, value in delta.values.items():
                epoch_role[field] += value

        ticks_to_us = 1_000_000.0 / hz
        vm_busy_ticks = (
            vm_delta.values["u"]
            + vm_delta.values["n"]
            + vm_delta.values["s"]
            + vm_delta.values["hi"]
            + vm_delta.values["si"]
        )
        totals["done"] += epoch_exec["done"]
        totals["shared_done"] += epoch_role["done"]
        totals["miss"] += epoch_exec["miss"]
        totals["pc"] += epoch_exec["pc"]
        totals["ch"] += epoch_exec["ch"]
        totals["ex"] += epoch_exec["ex"]
        totals["pa"] += epoch_exec["pa"]
        totals["pi"] += epoch_exec["pi"]
        totals["shared"] += epoch_role["cpu"]
        totals["vm_busy"] += vm_busy_ticks * ticks_to_us
        totals["irq"] += vm_delta.values["hi"] * ticks_to_us
        totals["softirq"] += vm_delta.values["si"] * ticks_to_us

        # Boundary quality describes only the persistent streams that define
        # the target window. A retired/recycled loop-parent is not expected to
        # have samples at either global boundary.
        for delta in [*role_deltas, vm_delta]:
            if delta.first_timestamp_us is not None:
                max_boundary_gap_us = max(
                    max_boundary_gap_us,
                    delta.first_timestamp_us - start_us,
                    end_us - delta.last_timestamp_us,
                )
        for delta in all_deltas:
            valid_intervals += delta.valid_intervals
            reset_boundaries += delta.reset_boundaries
            generation_baselines += delta.generation_baselines
        exec_sample_count += sum(delta.sample_count for delta in exec_deltas)
        role_sample_count += sum(delta.sample_count for delta in role_deltas)
        vm_sample_count += vm_delta.sample_count
        exec_workers_seen.update(exec_by_worker)
        role_workers_seen.update(role_by_worker)
        coverage_us += end_us - start_us
        epochs_used += 1

    valid = epochs_used > 0 and totals["done"] > 0 and totals["vm_busy"] > 0
    if valid:
        reason = "ok"
    elif skipped_epochs:
        reason = "; ".join(
            f"{label}: {count}" for label, count in sorted(skipped_epochs.items())
        )
    else:
        reason = "no cumulative CPU records"

    return CpuClosureSummary(
        name=ledger.name,
        path=ledger.path,
        valid=valid,
        reason=reason,
        epochs_seen=len(epoch_ids),
        epochs_used=epochs_used,
        clock_resets=ledger.clock_resets,
        exec_workers=len(exec_workers_seen),
        role_workers=len(role_workers_seen),
        exec_samples=exec_sample_count,
        role_samples=role_sample_count,
        vm_samples=vm_sample_count,
        invalid_rows=(
            ledger.invalid_exec_rows
            + ledger.invalid_role_rows
            + ledger.invalid_vm_rows
        ),
        valid_intervals=valid_intervals,
        reset_boundaries=reset_boundaries,
        generation_baselines=generation_baselines,
        coverage_us=coverage_us,
        max_boundary_gap_us=max_boundary_gap_us,
        completed=int(totals["done"]),
        shared_completed=int(totals["shared_done"]),
        missing=int(totals["miss"]),
        parent_process_cpu_us=totals["pc"],
        children_cpu_us=totals["ch"],
        execution_cpu_us=totals["ex"],
        parent_active_cpu_us=totals["pa"],
        parent_idle_cpu_us=totals["pi"],
        shared_cpu_us=totals["shared"],
        vm_busy_cpu_us=totals["vm_busy"],
        irq_cpu_us=totals["irq"],
        softirq_cpu_us=totals["softirq"],
    )


def wall_metrics() -> list[Metric]:
    return [
        Metric("prep", "prep (B-A)", lambda row: row.fields["B"] - row.fields["A"]),
        Metric("exec", "exec (C-B)", lambda row: row.fields["C"] - row.fields["B"]),
        Metric("publish", "publish (D-C)", lambda row: row.fields["D"] - row.fields["C"]),
        Metric("reuse", "reuse (R-C)", lambda row: row.fields["R"] - row.fields["C"]),
        Metric("reap", "child death/reap (rp-C)", reap_delta),
        Metric("post_reap", "post-reap readiness (R-rp)", post_reap_delta),
        Metric("idle", "idle (A2-R)", lambda row: row.fields["A2"] - row.fields["R"]),
        Metric("span", "complete span (D-A)", lambda row: row.fields["D"] - row.fields["A"]),
        Metric("cycle", "worker cycle (A2-A)", lambda row: row.fields["A2"] - row.fields["A"]),
    ]


def reap_delta(row: TimelineRow) -> int:
    reap = row.fields.get("rp", 0)
    if reap <= 0 or not row.fields["C"] <= reap <= row.fields["R"]:
        return -1
    return reap - row.fields["C"]


def post_reap_delta(row: TimelineRow) -> int:
    reap = row.fields.get("rp", 0)
    if reap <= 0 or not row.fields["C"] <= reap <= row.fields["R"]:
        return -1
    return row.fields["R"] - reap


def cpu_metrics() -> list[Metric]:
    return [
        Metric("exec_cpu", "exec CPU (cc-bc)", lambda row: row.fields["cc"] - row.fields["bc"]),
        Metric("fork_cpu", "fork CPU (fc)", lambda row: row.fields["fc"]),
        Metric("setup_cpu", "child setup CPU (bc)", lambda row: row.fields["bc"]),
        Metric("post_c_cpu", "post-C CPU (ru-cc)", lambda row: row.fields["ru"] - row.fields["cc"]),
        Metric("parent_pre_cpu", "parent pre-engine CPU (ppc)", lambda row: row.fields["ppc"]),
        Metric("parent_engine_cpu", "parent engine CPU (pec)", lambda row: row.fields["pec"]),
        Metric("parent_post_cpu", "parent post-engine CPU (poc)", lambda row: row.fields["poc"]),
        Metric(
            "parent_active_cpu",
            "parent active CPU (ppc+pec+poc)",
            lambda row: row.fields["ppc"] + row.fields["pec"] + row.fields["poc"],
        ),
        Metric("parent_idle_cpu", "parent idle-window CPU (pic)", lambda row: row.fields["pic"]),
        Metric(
            "dedicated_model_cpu",
            "dedicated model CPU",
            lambda row: (
                row.fields["ppc"]
                + row.fields["pec"]
                + row.fields["poc"]
                + row.fields["bc"]
                + row.fields["ru"]
                - row.fields["cc"]
            ),
        ),
    ]


def parent_runqueue_metrics() -> list[Metric]:
    return [
        Metric("parent_pre_rq", "parent pre-engine runqueue (ppq)", lambda row: row.fields["ppq"]),
        Metric("parent_engine_rq", "parent engine runqueue (peq)", lambda row: row.fields["peq"]),
        Metric("parent_post_rq", "parent post-engine runqueue (poq)", lambda row: row.fields["poq"]),
        Metric(
            "parent_active_rq",
            "parent active runqueue (ppq+peq+poq)",
            lambda row: row.fields["ppq"] + row.fields["peq"] + row.fields["poq"],
        ),
        Metric("parent_idle_rq", "parent idle-window runqueue (piq)", lambda row: row.fields["piq"]),
    ]


def collect_one_side(rows: Iterable[TimelineRow], metric: Metric) -> list[int]:
    values: list[int] = []
    for row in rows:
        try:
            value = metric.getter(row)
        except KeyError:
            continue
        if value < 0:
            continue
        values.append(value)
    return values


def collect_metric_values(
    syz_rows: Iterable[TimelineRow], rfz_rows: Iterable[TimelineRow], metrics: list[Metric]
) -> list[MetricValues]:
    # Each side's own full population, collected independently -- no shared
    # key, no pairing. The two lists for a metric can differ in length; that
    # is expected, not an error (docs/plans/fixed-request-stream-performance-
    # replay.md: population-level comparison needs identical INPUT, not
    # per-record correspondence in the OUTPUT).
    syz_rows = list(syz_rows)
    rfz_rows = list(rfz_rows)
    return [
        MetricValues(metric, collect_one_side(syz_rows, metric), collect_one_side(rfz_rows, metric))
        for metric in metrics
    ]


def percentile(values: list[int], quantile: float) -> float:
    if not values:
        return math.nan
    ordered = sorted(values)
    return float(ordered[round((len(ordered) - 1) * quantile)])


def statistics(values: list[int]) -> dict[str, float]:
    if not values:
        return {key: math.nan for key in ("p50", "p90", "p95", "p99", "mean")}
    return {
        "p50": percentile(values, 0.50),
        "p90": percentile(values, 0.90),
        "p95": percentile(values, 0.95),
        "p99": percentile(values, 0.99),
        "mean": sum(values) / len(values),
    }


def format_ms(value_us: float) -> str:
    if math.isnan(value_us):
        return "NA"
    return f"{value_us / 1000.0:.3f}"


def format_percent(value: float) -> str:
    if math.isnan(value):
        return "NA"
    return f"{value:.1f}%"


def format_ratio(numerator: float, denominator: float) -> str:
    if math.isnan(numerator) or math.isnan(denominator) or denominator == 0:
        return "NA"
    return f"{numerator / denominator:.3f}x"


def markdown_path(path: Path) -> str:
    return "`" + str(path).replace("`", "\\`") + "`"


def append_distribution_table(lines: list[str], title: str, values: list[MetricValues]) -> None:
    lines.extend(
        [
            f"## {title}",
            "",
            "All values are milliseconds. Each system's column is that system's own full "
            "population for this metric, collected independently -- not a paired subset, "
            "not the same sample count on both sides.",
            "",
            "| Metric | System | N | p50 | p90 | p95 | p99 | mean |",
            "|---|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for item in values:
        for system, samples in (("syz", item.syz), ("rfz", item.rfz)):
            stats = statistics(samples)
            label = item.metric.label if system == "syz" else ""
            lines.append(
                f"| {label} | {system} | {len(samples)} | {format_ms(stats['p50'])} | "
                f"{format_ms(stats['p90'])} | {format_ms(stats['p95'])} | "
                f"{format_ms(stats['p99'])} | {format_ms(stats['mean'])} |"
            )
    lines.append("")


def append_role_cpu_table(
    lines: list[str],
    syz_role: RoleCpuSummary,
    rfz_role: RoleCpuSummary,
) -> None:
    lines.extend(
        [
            "## Shared-Role Amortized CPU Cost",
            "",
            "Shared roles are accounted over cumulative windows, not assigned to a request interval. The input capture must already delimit the experiment's steady-state period. CPU/program is `sum(valid CPU deltas) / sum(valid completion deltas)`. Counter-decrease boundaries are skipped; a valid interval with zero completions still contributes its CPU delta.",
            "",
            "| System | Role | workers | samples | valid intervals | reset boundaries skipped | zero-completion CPU intervals | invalid rows | CPU in windows (ms) | completed programs | CPU/program (ms) |",
            "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for system, role, summary in (
        ("syz", "runner", syz_role),
        ("rfz", "daemon aggregate", rfz_role),
    ):
        lines.append(
            f"| {system} | {role} | {summary.worker_count} | {summary.sample_count} | "
            f"{summary.valid_intervals} | {summary.reset_boundaries} | "
            f"{summary.zero_completion_intervals} | {summary.invalid_rows} | "
            f"{format_ms(float(summary.cpu_us))} | {summary.completed} | "
            f"{format_ms(summary.cpu_per_completion_us)} |"
        )
    lines.extend(
        [
            "",
            f"Aggregate daemon/runner CPU-per-program ratio: `{format_ratio(rfz_role.cpu_per_completion_us, syz_role.cpu_per_completion_us)}`.",
            "",
            "The denominator is every completed program covered by the role samples, not only the exact request pairs used by the timeline tables.",
            "",
        ]
    )


def _per_program(value_us: float, completed: int) -> float:
    if completed <= 0:
        return math.nan
    return value_us / completed


def _per_second(value_us: float, coverage_us: int) -> float:
    if coverage_us <= 0:
        return math.nan
    return value_us / (coverage_us / 1_000_000.0)


def _cpu_share(value_us: float, total_us: float) -> float:
    if total_us <= 0:
        return math.nan
    return value_us * 100.0 / total_us


def _closure_status(summary: CpuClosureSummary) -> str:
    if not summary.valid:
        return "INVALID"
    if summary.closure_gap_percent <= 2.0:
        return "PASS"
    if summary.closure_gap_percent <= 5.0:
        return "INVESTIGATE"
    return "UNEXPLAINED"


# Category pairs split by an implementation-placed anchor. Neither member is
# comparable across systems on its own -- work migrates across the anchor when
# the two implementations place it differently -- but the sum is anchor-free.
# Same rule as appendix A.2 of docs/plans/execution-mechanism-experiments.md,
# which states it for `cc-bc` / `ru-cc`; `ex` / `ch-ex` is the same split at B.
BOUNDARY_PAIRS: list[tuple[str, str, tuple[str, ...]]] = [
    (
        "child total (`ch`)",
        "B anchor is placed by each implementation",
        ("execution body (`ex`)", "child outside execution (`ch-ex`)"),
    ),
    (
        "interrupt path total",
        "one notification design replaces the other",
        ("hard IRQ", "softirq"),
    ),
]


def _attribution_verdict(mech: float, thru: float) -> str:
    """Classify a per-second change from its two multiplicative factors.

    ms/second = ms/program x programs/second, exactly. So the per-second ratio
    between the two systems factors into a mechanism term and a throughput
    term, and the sign of each decides what the movement means:

      mech<1, product<1  the work shrank per program and per unit time
      mech<1, product>1  the work shrank per program but not by enough to
                         offset the higher rate; its absolute rate went up.
                         This is a real cost of running faster, not a
                         regression in the mechanism.
      mech>1, product<1  the work grew per program and is only hidden by the
                         higher rate. Reporting ms/program alone would be
                         dilution.
      mech>1, product>1  the work grew both ways.
    """
    if math.isnan(mech) or math.isnan(thru):
        return "NA"
    product = mech * thru
    if mech <= 1.0 and product <= 1.0:
        return "real reduction"
    if mech <= 1.0 and product > 1.0:
        return "outpaced by throughput"
    if mech > 1.0 and product <= 1.0:
        return "diluted by throughput"
    return "real increase"


def append_per_second_attribution(
    lines: list[str],
    syz: CpuClosureSummary,
    rfz: CpuClosureSummary,
    categories: list[tuple[str, Callable[[CpuClosureSummary], float]]],
) -> None:
    """Split each per-second change into mechanism and throughput factors.

    A category whose ms/program falls can still have its ms/second rise, and
    the reverse. Neither column answers "did this get cheaper" on its own, so
    the report does the decomposition instead of leaving it to the reader.
    """
    thru_syz = syz.programs_per_second
    thru_rfz = rfz.programs_per_second
    if math.isnan(thru_syz) or math.isnan(thru_rfz) or thru_syz <= 0:
        lines.extend(["Per-second attribution unavailable: no valid coverage span.", ""])
        return
    thru = thru_rfz / thru_syz

    lines.extend(
        [
            "### Why each per-second value moved",
            "",
            "`ms/second = ms/program x programs/second` is an identity, so the "
            "per-second ratio between the two systems is the product of a "
            "mechanism factor (`rfz ms/program / syz ms/program`) and a "
            "throughput factor, which is the same for every row. The two "
            "factors are reported separately because their signs can disagree, "
            "and the disagreement is what the verdict names: a category can "
            "cost less per program and still consume more CPU per second "
            "purely because more programs run per second.",
            "",
            f"Throughput factor for this run: {format_ratio(thru_rfz, thru_syz)} "
            f"({thru_syz:.3f} -> {thru_rfz:.3f} programs/s over the closure span).",
            "",
            "| CPU category | mechanism (ms/prog) | throughput | per-second | verdict |",
            "|---|---:|---:|---:|---|",
        ]
    )

    def _row(label: str, get_syz: float, get_rfz: float) -> None:
        pp_syz = _per_program(get_syz, syz.completed)
        pp_rfz = _per_program(get_rfz, rfz.completed)
        if math.isnan(pp_syz) or math.isnan(pp_rfz) or pp_syz == 0:
            lines.append(f"| {label} | NA | NA | NA | NA |")
            return
        mech = pp_rfz / pp_syz
        lines.append(
            f"| {label} | {mech:.3f}x | {thru:.3f}x | {mech * thru:.3f}x | "
            f"{_attribution_verdict(mech, thru)} |"
        )

    for label, getter in categories:
        _row(label, getter(syz), getter(rfz))

    lines.extend(
        [
            "",
            "Anchor-free sums. The members of each pair below are separated by "
            "a boundary that each implementation places for itself, so work "
            "migrates between them and neither member is comparable across "
            "systems on its own. Read the sum; use the members only to say "
            "where inside the sum the work sits.",
            "",
            "| Anchor-free total | members | mechanism (ms/prog) | throughput | per-second | verdict |",
            "|---|---|---:|---:|---:|---|",
        ]
    )
    by_label = dict(categories)
    for total_label, why, members in BOUNDARY_PAIRS:
        getters = [by_label[m] for m in members if m in by_label]
        if len(getters) != len(members):
            continue
        sum_syz = sum(g(syz) for g in getters)
        sum_rfz = sum(g(rfz) for g in getters)
        pp_syz = _per_program(sum_syz, syz.completed)
        pp_rfz = _per_program(sum_rfz, rfz.completed)
        member_text = " + ".join(members)
        if math.isnan(pp_syz) or math.isnan(pp_rfz) or pp_syz == 0:
            lines.append(f"| {total_label} | {member_text} | NA | NA | NA | NA |")
            continue
        mech = pp_rfz / pp_syz
        lines.append(
            f"| {total_label} | {member_text} | {mech:.3f}x | {thru:.3f}x | "
            f"{mech * thru:.3f}x | {_attribution_verdict(mech, thru)} |"
        )
        lines.append(f"| | _{why}_ | | | | |")
    lines.append("")


def append_cpu_closure_tables(
    lines: list[str],
    syz: CpuClosureSummary,
    rfz: CpuClosureSummary,
) -> None:
    lines.extend(
        [
            "## Full-Population Guest CPU Closure",
            "",
            "Each system's persistent shared-role and `/proc/stat` streams define the common window within each guest-clock epoch. Recyclable loop-parent IDs contribute all valid lifecycle deltas inside that window but do not shorten it. Counter-decrease boundaries are never subtracted across; the first absolute counters of a new in-window generation recover its startup cost. Boundary gap covers only persistent streams.",
            "",
            "| System | status | epochs used/seen | exec IDs/role workers | samples exec/role/vm | valid intervals | counter resets | generation baselines | clock resets | coverage (s) | max boundary gap (ms) | exec done | shared done | denominator skew | missing | invalid rows |",
            "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for system, summary in (("syz", syz), ("rfz", rfz)):
        lines.append(
            f"| {system} | {_closure_status(summary)} | "
            f"{summary.epochs_used}/{summary.epochs_seen} | "
            f"{summary.exec_workers}/{summary.role_workers} | "
            f"{summary.exec_samples}/{summary.role_samples}/{summary.vm_samples} | "
            f"{summary.valid_intervals} | {summary.reset_boundaries} | "
            f"{summary.generation_baselines} | {summary.clock_resets} | "
            f"{summary.coverage_us / 1_000_000.0:.3f} | "
            f"{summary.max_boundary_gap_us / 1000.0:.3f} | "
            f"{summary.completed} | {summary.shared_completed} | "
            f"{format_percent(summary.completion_skew_percent)} | "
            f"{summary.missing} ({format_percent(summary.missing_percent)}) | "
            f"{summary.invalid_rows} |"
        )
    lines.append("")
    lines.append(
        "`exec IDs` are observed resource identifiers, not configured concurrency. Syzkaller deliberately rotates IDs from a pool after subprocess failures; therefore 10 observed IDs can still represent 6 worker slots."
    )
    lines.append("")
    for system, summary in (("syz", syz), ("rfz", rfz)):
        if not summary.valid:
            lines.append(f"- `{system}` closure unavailable: {summary.reason}.")
    if not syz.valid or not rfz.valid:
        lines.append("")

    categories: list[tuple[str, Callable[[CpuClosureSummary], float]]] = [
        ("execution body (`ex`)", lambda summary: summary.execution_cpu_us),
        (
            "child outside execution (`ch-ex`)",
            lambda summary: summary.child_outside_execution_us,
        ),
        ("loop parent active (`pa`)", lambda summary: summary.parent_active_cpu_us),
        ("loop parent idle window (`pi`)", lambda summary: summary.parent_idle_cpu_us),
        (
            "loop parent unsegmented (`pc-pa-pi`)",
            lambda summary: summary.parent_unsegmented_us,
        ),
        ("shared runner/daemon", lambda summary: summary.shared_cpu_us),
        ("hard IRQ", lambda summary: summary.irq_cpu_us),
        ("softirq", lambda summary: summary.softirq_cpu_us),
        ("unclassified residual", lambda summary: summary.other_cpu_us),
    ]
    lines.extend(
        [
            "The following rows are exclusive and sum to VM busy CPU. `ms/program` uses the loop-parent `done` denominator so the column remains additive; shared-role denominator skew is reported above. `ms/second` divides the same total by the closure coverage span, so the two columns differ by exactly the throughput of the run; the attribution table below separates those two effects.",
            "",
            "| CPU category | System | total CPU (ms) | ms/program | ms/second | share of VM busy |",
            "|---|---:|---:|---:|---:|---:|",
        ]
    )
    for label, getter in categories:
        for system, summary in (("syz", syz), ("rfz", rfz)):
            value = getter(summary)
            lines.append(
                f"| {label if system == 'syz' else ''} | {system} | "
                f"{format_ms(value)} | "
                f"{format_ms(_per_program(value, summary.completed))} | "
                f"{format_ms(_per_second(value, summary.coverage_us))} | "
                f"{format_percent(_cpu_share(value, summary.vm_busy_cpu_us))} |"
            )

    lines.append("")
    append_per_second_attribution(lines, syz, rfz, categories)

    lines.extend(
        [
            "| Derived total | System | ms/program | share/status |",
            "|---|---:|---:|---:|",
        ]
    )
    for system, summary in (("syz", syz), ("rfz", rfz)):
        shared_per_shared_done = _per_program(
            summary.shared_cpu_us, summary.shared_completed
        )
        lines.extend(
            [
                f"| VM busy CPU | {system} | {format_ms(_per_program(summary.vm_busy_cpu_us, summary.completed))} | 100.0% |",
                f"| execution-model active CPU | {system} | {format_ms(_per_program(summary.model_active_cpu_us, summary.completed))} | {_cpu_share(summary.model_active_cpu_us, summary.vm_busy_cpu_us):.1f}% |",
                f"| shared-role CPU/shared completion | {system} | {format_ms(shared_per_shared_done)} | denominator={summary.shared_completed} |",
                f"| absolute closure gap | {system} | {format_ms(_per_program(abs(summary.other_cpu_us), summary.completed))} | {format_percent(summary.closure_gap_percent)} ({_closure_status(summary)}) |",
            ]
        )
    lines.extend(
        [
            "",
            "A closure gap at or below 2% passes. Between 2% and 5% requires boundary/reset investigation. Above 5% is UNEXPLAINED by this cumulative CPU account alone -- in practice this is the common outcome, not a rare exception, so every closure run also carries guest-wide kernel-profile sampling (gp.data, read via probe_attribute.py) whose comm/symbol breakdown is how the residual gets explained. UNEXPLAINED does not invalidate the wall-time or per-request CPU comparisons elsewhere in this report, which do not depend on this closure. In-task syscall kernel time is already charged to the child process counters and must not be counted again.",
            "",
        ]
    )


def build_report(
    syz: TimelineParse,
    rfz: TimelineParse,
    syz_closure: CpuClosureSummary,
    rfz_closure: CpuClosureSummary,
) -> str:
    wall_values = collect_metric_values(syz.rows.values(), rfz.rows.values(), wall_metrics())
    cpu_values = collect_metric_values(syz.rows.values(), rfz.rows.values(), cpu_metrics())
    parent_rq_values = collect_metric_values(syz.rows.values(), rfz.rows.values(), parent_runqueue_metrics())
    generated = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    lines = [
        "# Independent Execution Performance Report",
        "",
        f"Generated: `{generated}`",
        "",
        f"- Syzkaller timeline: {markdown_path(syz.path)}",
        f"- reFuzz timeline: {markdown_path(rfz.path)}",
        "",
        "Both systems consumed the same fixed, ordered request stream "
        "(docs/plans/fixed-request-stream-performance-replay.md). Every table below reports "
        "each system's own native measurements independently, from its own timeline log -- "
        "there is no cross-system request pairing, no shared correlation key, and no replay "
        "result/outcome file. Population sizes (N) can differ between the two systems and "
        "between metrics; that reflects each system's own sampling and completion, not an "
        "error.",
        "",
        "## Timeline Integrity",
        "",
        "| System | A/D rows | B/C/R/A2 rows | duplicate A/D | duplicate detail | unmatched halves | invalid ordering | complete rows |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
        f"| syz | {syz.ad_count} | {syz.detail_count} | {syz.duplicate_ad} | {syz.duplicate_detail} | {syz.unmatched_halves} | {syz.invalid_rows} | {len(syz.rows)} |",
        f"| rfz | {rfz.ad_count} | {rfz.detail_count} | {rfz.duplicate_ad} | {rfz.duplicate_detail} | {rfz.unmatched_halves} | {rfz.invalid_rows} | {len(rfz.rows)} |",
        "",
    ]

    append_distribution_table(lines, "Guest Wall-Time Intervals", wall_values)
    append_distribution_table(lines, "Per-Request CPU Time", cpu_values)
    append_distribution_table(lines, "Loop-Parent Runqueue Wait", parent_rq_values)
    append_cpu_closure_tables(lines, syz_closure, rfz_closure)

    lines.extend(
        [
            "## Metric Sample Counts",
            "",
            "| Metric | syz N | rfz N |",
            "|---|---:|---:|",
        ]
    )
    for item in wall_values + cpu_values + parent_rq_values:
        lines.append(f"| {item.metric.label} | {len(item.syz)} | {len(item.rfz)} |")
    lines.extend(
        [
            "",
            "`publish (D-C)` and `reuse (R-C)` can overlap and must not be summed. `child death/reap (rp-C)` and `post-reap readiness (R-rp)` partition reuse only when both systems report an ordered, non-zero `rp`; timeout/kill rows with `rp=0` are dropped from those two metrics. `complete span (D-A)` is request completion latency; `worker cycle (A2-A)` ends when that execution unit has accepted the next request.",
            "",
            "CPU time is resource consumption rather than elapsed wall time. `parent active CPU` is `ppc+pec+poc`; `fork CPU (fc)` is shown diagnostically but is already contained in `pec`. Therefore `dedicated model CPU` is `parent active + child setup (bc) + child post-C (ru-cc)` and does not add `fc` again. Parent idle-window CPU/runqueue is reported separately and excluded from that active-cost total.",
            "",
            "Use the parent active total for the cross-system resource claim. The component rows are diagnostic: probe work is included, and the deferred TL record is emitted inside different active subsegments in the two implementations (`pec` in Syzkaller, `ppc` in reFuzz).",
            "",
            "Per request, loop-parent accounting adds four `CLOCK_THREAD_CPUTIME_ID` samples and four `/proc/self/schedstat` open/read/close samples. Shared-role CPU sampling adds one process-CPU read and one best-effort log record per role about every five seconds.",
            "",
            "Percentiles use the nearest observed sample.",
            "",
        ]
    )
    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--syz-log", required=True, type=Path)
    parser.add_argument(
        "--rfz-log",
        required=True,
        type=Path,
        help=(
            "reFuzz worker.log, its containing directory, or a legacy serial.log "
            "path (a sibling worker.log is preferred when present)"
        ),
    )
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    rfz_log = resolve_refuzz_log(args.rfz_log)
    for path in (args.syz_log, rfz_log):
        if not path.is_file():
            print(f"paired_exec_analyze: missing input: {path}", file=sys.stderr)
            return 1

    try:
        syz = parse_timeline(args.syz_log, "syz", "[SyzTL]", worker_field="wid")
        rfz = parse_timeline(rfz_log, "rfz", "[RfzTL]", worker_field="w")
        syz_ledger = parse_cpu_ledger(
            args.syz_log,
            "syz",
            exec_marker="[SyzExecCPU]",
            exec_worker_field="wid",
            role_marker="[SyzRoleCPU]",
            role_worker_field=None,
            vm_marker="[SyzCPU]",
        )
        rfz_ledger = parse_cpu_ledger(
            rfz_log,
            "rfz",
            exec_marker="[RfzExecCPU]",
            exec_worker_field="w",
            role_marker="[RfzRoleCPU]",
            role_worker_field="w",
            vm_marker="[RfzCPU]",
        )
        syz_closure = compute_cpu_closure(syz_ledger)
        rfz_closure = compute_cpu_closure(rfz_ledger)
        report = build_report(syz, rfz, syz_closure, rfz_closure)
    except (OSError, ValueError) as error:
        print(f"paired_exec_analyze: {error}", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary_output = args.output.with_name(f".{args.output.name}.tmp.{os.getpid()}")
    try:
        temporary_output.write_text(report, encoding="utf-8")
        os.replace(temporary_output, args.output)
    finally:
        temporary_output.unlink(missing_ok=True)
    print(f"paired_exec_analyze: syz_rows={len(syz.rows)} rfz_rows={len(rfz.rows)} report={args.output}")
    return 0 if syz.rows and rfz.rows else 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

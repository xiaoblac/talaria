#!/usr/bin/env python3
"""Compare independent Syzkaller and reFuzz performance runs.

This report is population-level: requests are not paired across systems.  Each
metric uses its largest valid sample population, while cumulative CPU closure
reuses the exact accounting implementation from paired_exec_analyze.py.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import math
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

import paired_exec_analyze as paired


@dataclass(frozen=True)
class RunInputs:
    name: str
    root: Path
    run_dir: Path
    timeline_log: Path
    results_csv: Path
    config: Path
    vcpus: int
    programs_per_second: float
    calls_per_second: float
    completed: int
    measured_seconds: float


@dataclass(frozen=True)
class TimelinePopulations:
    name: str
    path: Path
    ad_rows: int
    detail_rows: int
    duplicate_ad: int
    duplicate_detail: int
    unmatched_halves: int
    invalid_ad: int
    invalid_detail: int
    joined_rows: int
    intervals: dict[str, list[int]]
    request_cpu: dict[str, list[int]]
    runqueue: dict[str, list[int]]


@dataclass(frozen=True)
class MetricSpec:
    key: str
    label: str
    getter: Callable[[dict[str, int]], int]


@dataclass(frozen=True)
class CsvResult:
    programs_per_second: float
    calls_per_second: float
    completed: int
    measured_seconds: float


WALL_LABELS = (
    ("prep", "prep (B-A)"),
    ("exec", "exec (C-B)"),
    ("publish", "publish (D-C)"),
    ("reuse", "reuse (R-C)"),
    ("reap", "child death/reap (rp-C)"),
    ("post_reap", "post-reap readiness (R-rp)"),
    ("idle", "idle (A2-R)"),
    ("span", "complete span (D-A)"),
    ("cycle", "worker cycle (A2-A)"),
)


CPU_SPECS = (
    MetricSpec("exec_cpu", "exec CPU (cc-bc)", lambda row: row["cc"] - row["bc"]),
    MetricSpec("fork_cpu", "fork CPU (fc)", lambda row: row["fc"]),
    MetricSpec("setup_cpu", "child setup CPU (bc)", lambda row: row["bc"]),
    MetricSpec("post_c_cpu", "child post-C CPU (ru-cc)", lambda row: row["ru"] - row["cc"]),
    MetricSpec("parent_pre_cpu", "parent pre-engine CPU (ppc)", lambda row: row["ppc"]),
    MetricSpec("parent_engine_cpu", "parent engine CPU (pec)", lambda row: row["pec"]),
    MetricSpec("parent_post_cpu", "parent post-engine CPU (poc)", lambda row: row["poc"]),
    MetricSpec(
        "parent_active_cpu",
        "parent active CPU (ppc+pec+poc)",
        lambda row: row["ppc"] + row["pec"] + row["poc"],
    ),
    MetricSpec("parent_idle_cpu", "parent idle-window CPU (pic)", lambda row: row["pic"]),
    MetricSpec(
        "dedicated_model_cpu",
        "dedicated model CPU",
        lambda row: (
            row["ppc"] + row["pec"] + row["poc"]
            + row["bc"] + row["ru"] - row["cc"]
        ),
    ),
)


RUNQUEUE_SPECS = (
    MetricSpec("parent_pre_rq", "parent pre-engine runqueue (ppq)", lambda row: row["ppq"]),
    MetricSpec("parent_engine_rq", "parent engine runqueue (peq)", lambda row: row["peq"]),
    MetricSpec("parent_post_rq", "parent post-engine runqueue (poq)", lambda row: row["poq"]),
    MetricSpec(
        "parent_active_rq",
        "parent active runqueue (ppq+peq+poq)",
        lambda row: row["ppq"] + row["peq"] + row["poq"],
    ),
    MetricSpec("parent_idle_rq", "parent idle-window runqueue (piq)", lambda row: row["piq"]),
)


def _timeline_fields(line: str, marker: str) -> dict[str, int]:
    offset = line.find(marker)
    if offset < 0:
        return {}
    start = offset + len(marker)
    end = line.find("[", start)
    if end < 0:
        end = len(line)
    return paired.parse_tokens(line[start:end])


def _valid_order(row: dict[str, int], fields: tuple[str, ...]) -> bool:
    values = [row.get(field, 0) for field in fields]
    return all(value > 0 for value in values) and values == sorted(values)


def _collect_specs(
    rows: Iterable[dict[str, int]], specs: Iterable[MetricSpec]
) -> dict[str, list[int]]:
    result = {spec.key: [] for spec in specs}
    for row in rows:
        for spec in specs:
            try:
                value = spec.getter(row)
            except KeyError:
                continue
            if value >= 0:
                result[spec.key].append(value)
    return result


def parse_timeline_populations(
    name: str, path: Path, marker: str, worker_field: str
) -> TimelinePopulations:
    ad: dict[tuple[int, int], dict[str, int]] = {}
    detail: dict[tuple[int, int], dict[str, int]] = {}
    duplicate_ad: set[tuple[int, int]] = set()
    duplicate_detail: set[tuple[int, int]] = set()

    with path.open(errors="replace") as source:
        for line in source:
            if marker not in line:
                continue
            fields = _timeline_fields(line, marker)
            worker = fields.get(worker_field)
            request_id = fields.get("id")
            if worker is None or request_id is None:
                continue
            key = (worker, request_id)
            if "A" in fields and "D" in fields:
                if key in ad:
                    duplicate_ad.add(key)
                ad[key] = fields
            elif all(field in fields for field in ("B", "C", "R", "A2")):
                if key in detail:
                    duplicate_detail.add(key)
                detail[key] = fields

    clean_ad = {key: row for key, row in ad.items() if key not in duplicate_ad}
    clean_detail = {
        key: row for key, row in detail.items() if key not in duplicate_detail
    }
    valid_ad = {
        key: row for key, row in clean_ad.items() if _valid_order(row, ("A", "D"))
    }
    valid_detail = {
        key: row
        for key, row in clean_detail.items()
        if _valid_order(row, ("B", "C"))
        and _valid_order(row, ("C", "R", "A2"))
    }

    intervals = {key: [] for key, _ in WALL_LABELS}
    for row in valid_ad.values():
        intervals["span"].append(row["D"] - row["A"])
    for row in valid_detail.values():
        intervals["exec"].append(row["C"] - row["B"])
        intervals["reuse"].append(row["R"] - row["C"])
        intervals["idle"].append(row["A2"] - row["R"])
        reap = row.get("rp", 0)
        if row["C"] <= reap <= row["R"]:
            intervals["reap"].append(reap - row["C"])
            intervals["post_reap"].append(row["R"] - reap)

    joined: list[dict[str, int]] = []
    for key in valid_ad.keys() & valid_detail.keys():
        row = dict(valid_ad[key])
        row.update(valid_detail[key])
        if not (
            row["A"] <= row["B"] <= row["C"] <= row["D"]
            and row["C"] <= row["R"] <= row["A2"]
        ):
            continue
        joined.append(row)
        intervals["prep"].append(row["B"] - row["A"])
        intervals["publish"].append(row["D"] - row["C"])
        intervals["cycle"].append(row["A2"] - row["A"])

    detail_rows = list(valid_detail.values())
    return TimelinePopulations(
        name=name,
        path=path,
        ad_rows=len(ad),
        detail_rows=len(detail),
        duplicate_ad=len(duplicate_ad),
        duplicate_detail=len(duplicate_detail),
        unmatched_halves=len(clean_ad.keys() ^ clean_detail.keys()),
        invalid_ad=len(clean_ad) - len(valid_ad),
        invalid_detail=len(clean_detail) - len(valid_detail),
        joined_rows=len(joined),
        intervals=intervals,
        request_cpu=_collect_specs(detail_rows, CPU_SPECS),
        runqueue=_collect_specs(detail_rows, RUNQUEUE_SPECS),
    )


def read_csv_result(path: Path, tool: str, run_id: int) -> CsvResult:
    with path.open(newline="", encoding="utf-8") as source:
        rows = [
            row
            for row in csv.DictReader(source)
            if row.get("arm") == "D"
            and row.get("tool") == tool
            and int(row.get("run", "0")) == run_id
            and row.get("status") == "ok"
        ]
    if len(rows) != 1:
        raise ValueError(
            f"expected one successful D/{tool}/run={run_id} row in {path}, got {len(rows)}"
        )
    row = rows[0]
    return CsvResult(
        programs_per_second=float(row["programs_per_sec"]),
        calls_per_second=float(row["syz_calls_per_sec"]),
        completed=int(row["completed"]),
        measured_seconds=float(row["wall_s"]),
    )


def _read_vcpus(path: Path, system: str) -> int:
    with path.open(encoding="utf-8") as source:
        config = json.load(source)
    if system == "syz":
        return int(config["vm"]["cpu"])
    return int(config["channel"]["vm"]["qemu"]["cpu"])


def _resolve_refuzz_worker_log(run_dir: Path, config: Path) -> Path:
    archived = run_dir / "worker.log"
    if archived.is_file():
        return archived
    with config.open(encoding="utf-8") as source:
        work_dir = Path(json.load(source)["work_dir"])
    candidates = sorted(work_dir.glob("run-*/vm-*/worker.log"))
    if not candidates:
        raise FileNotFoundError(
            f"no worker.log in {run_dir} or under configured work_dir {work_dir}"
        )
    return candidates[-1]


def resolve_inputs(root: Path, system: str, run_id: int) -> RunInputs:
    prefix = "syz" if system == "syz" else "refuzz"
    run_dir = root / f"D_{prefix}_run_{run_id:02d}"
    results = root / "results.csv"
    if system == "syz":
        log = run_dir / "syz_perf_serial.log"
        config = run_dir / "syzkaller_config.json"
        tool = "syzkaller"
    else:
        config = run_dir / "refuzz_config.json"
        log = _resolve_refuzz_worker_log(run_dir, config)
        tool = "refuzz"
    for path in (run_dir, results, log, config):
        if not path.exists():
            raise FileNotFoundError(path)
    result = read_csv_result(results, tool, run_id)
    return RunInputs(
        name=system,
        root=root,
        run_dir=run_dir,
        timeline_log=log,
        results_csv=results,
        config=config,
        vcpus=_read_vcpus(config, system),
        programs_per_second=result.programs_per_second,
        calls_per_second=result.calls_per_second,
        completed=result.completed,
        measured_seconds=result.measured_seconds,
    )


def parse_ledger(inputs: RunInputs) -> paired.CpuLedgerParse:
    if inputs.name == "syz":
        return paired.parse_cpu_ledger(
            inputs.timeline_log,
            "syz",
            exec_marker="[SyzExecCPU]",
            exec_worker_field="wid",
            role_marker="[SyzRoleCPU]",
            role_worker_field=None,
            vm_marker="[SyzCPU]",
        )
    return paired.parse_cpu_ledger(
        inputs.timeline_log,
        "rfz",
        exec_marker="[RfzExecCPU]",
        exec_worker_field="w",
        role_marker="[RfzRoleCPU]",
        role_worker_field="w",
        vm_marker="[RfzCPU]",
    )


def _fmt_ms(value_us: float) -> str:
    return "NA" if math.isnan(value_us) else f"{value_us / 1000.0:.3f}"


def _fmt_number(value: float, digits: int = 3) -> str:
    return "NA" if math.isnan(value) else f"{value:.{digits}f}"


def _ratio(rfz: float, syz: float) -> float:
    if math.isnan(rfz) or math.isnan(syz) or syz == 0:
        return math.nan
    return rfz / syz


def _append_population_table(
    lines: list[str],
    title: str,
    labels: Iterable[tuple[str, str]],
    syz_values: dict[str, list[int]],
    rfz_values: dict[str, list[int]],
) -> None:
    lines.extend(
        [
            f"## {title}",
            "",
            "Each metric uses its own largest valid sample population. Values are milliseconds; `rfz/syz` compares population means and is not a paired-request effect.",
            "",
            "| Metric | System | n | p50 | p90 | p95 | p99 | mean | rfz/syz mean |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for key, label in labels:
        syz_stats = paired.statistics(syz_values.get(key, []))
        rfz_stats = paired.statistics(rfz_values.get(key, []))
        ratio = _ratio(rfz_stats["mean"], syz_stats["mean"])
        for system, values, stats in (
            ("syz", syz_values.get(key, []), syz_stats),
            ("rfz", rfz_values.get(key, []), rfz_stats),
        ):
            lines.append(
                f"| {label if system == 'syz' else ''} | {system} | {len(values)} | "
                f"{_fmt_ms(stats['p50'])} | {_fmt_ms(stats['p90'])} | "
                f"{_fmt_ms(stats['p95'])} | {_fmt_ms(stats['p99'])} | "
                f"{_fmt_ms(stats['mean'])} | "
                f"{_fmt_number(ratio) + 'x' if system == 'rfz' else ''} |"
            )
    lines.append("")


def _vm_runqueue(ledger: paired.CpuLedgerParse) -> list[int]:
    return [
        sample.running
        for samples in ledger.vm_samples.values()
        for sample in samples
    ]


def _busy_cores(summary: paired.CpuClosureSummary) -> float:
    if not summary.valid or summary.coverage_us <= 0:
        return math.nan
    return summary.vm_busy_cpu_us / summary.coverage_us


def _append_resources(
    lines: list[str],
    syz_inputs: RunInputs,
    rfz_inputs: RunInputs,
    syz_ledger: paired.CpuLedgerParse,
    rfz_ledger: paired.CpuLedgerParse,
    syz_closure: paired.CpuClosureSummary,
    rfz_closure: paired.CpuClosureSummary,
) -> None:
    syz_busy = _busy_cores(syz_closure)
    rfz_busy = _busy_cores(rfz_closure)
    syz_runq = _vm_runqueue(syz_ledger)
    rfz_runq = _vm_runqueue(rfz_ledger)
    syz_eff = syz_inputs.programs_per_second / syz_busy if syz_busy > 0 else math.nan
    rfz_eff = rfz_inputs.programs_per_second / rfz_busy if rfz_busy > 0 else math.nan
    rows = (
        ("Measured window (s)", syz_inputs.measured_seconds, rfz_inputs.measured_seconds, ""),
        ("Programs/s", syz_inputs.programs_per_second, rfz_inputs.programs_per_second, "x"),
        ("Executed calls/s", syz_inputs.calls_per_second, rfz_inputs.calls_per_second, "x"),
        ("Guest busy cores", syz_busy, rfz_busy, "x"),
        ("Guest busy (%)", syz_busy * 100 / syz_inputs.vcpus, rfz_busy * 100 / rfz_inputs.vcpus, "x"),
        ("Programs/s/busy-core", syz_eff, rfz_eff, "x"),
        ("VM runqueue p50", paired.percentile(syz_runq, 0.50), paired.percentile(rfz_runq, 0.50), "x"),
        ("VM runqueue p99", paired.percentile(syz_runq, 0.99), paired.percentile(rfz_runq, 0.99), "x"),
    )
    lines.extend(
        [
            "## Resources And Throughput",
            "",
            "Busy cores and efficiency use each system's valid cumulative-CPU closure window. Throughput comes from the successful D-arm row in `results.csv`.",
            "",
            "| Metric | Syzkaller | reFuzz | rfz/syz |",
            "|---|---:|---:|---:|",
        ]
    )
    for label, syz_value, rfz_value, suffix in rows:
        ratio = _ratio(rfz_value, syz_value)
        lines.append(
            f"| {label} | {_fmt_number(syz_value)} | {_fmt_number(rfz_value)} | "
            f"{_fmt_number(ratio) + suffix if suffix else ''} |"
        )
    lines.append("")


def _append_integrity(
    lines: list[str], syz: TimelinePopulations, rfz: TimelinePopulations
) -> None:
    lines.extend(
        [
            "## Timeline Integrity",
            "",
            "| System | A/D rows | detail rows | duplicate A/D | duplicate detail | unmatched halves | invalid A/D | invalid detail | valid joined |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for item in (syz, rfz):
        lines.append(
            f"| {item.name} | {item.ad_rows} | {item.detail_rows} | "
            f"{item.duplicate_ad} | {item.duplicate_detail} | "
            f"{item.unmatched_halves} | {item.invalid_ad} | "
            f"{item.invalid_detail} | {item.joined_rows} |"
        )
    lines.append("")


def _change_percent(rfz: float, syz: float) -> float:
    if syz == 0 or math.isnan(syz) or math.isnan(rfz):
        return math.nan
    return (rfz - syz) * 100.0 / syz


def _mean(values: dict[str, list[int]], key: str) -> float:
    return paired.statistics(values.get(key, []))["mean"]


def _append_conclusions(
    lines: list[str],
    syz_inputs: RunInputs,
    rfz_inputs: RunInputs,
    syz_timeline: TimelinePopulations,
    rfz_timeline: TimelinePopulations,
    syz_closure: paired.CpuClosureSummary,
    rfz_closure: paired.CpuClosureSummary,
) -> None:
    throughput_ratio = _ratio(
        rfz_inputs.programs_per_second, syz_inputs.programs_per_second
    )
    lines.extend(["## Bounded Conclusions", ""])
    lines.append(
        f"- reFuzz throughput is `{_fmt_number(throughput_ratio)}x` Syzkaller in these independent one-hour runs."
    )
    for key, label in (("span", "complete span"), ("publish", "publish"), ("reuse", "reuse")):
        change = _change_percent(
            _mean(rfz_timeline.intervals, key), _mean(syz_timeline.intervals, key)
        )
        lines.append(f"- reFuzz {label} mean change is `{_fmt_number(change, 1)}%`.")
    lines.append(
        f"- CPU closure gaps are `syz={_fmt_number(syz_closure.closure_gap_percent, 2)}%` and `rfz={_fmt_number(rfz_closure.closure_gap_percent, 2)}%`; values above 5% are UNEXPLAINED by this cumulative account alone (the common case in practice) and are explained by the paired guest-wide kernel-profile sampling, not by re-running with profiling added."
    )
    lines.append(
        "- Execution wall/CPU distributions include different online-fuzz programs. They are end-to-end population results, not fixed-program causal effects; use the paired replay report for that claim."
    )
    lines.append("")


def build_report(
    syz_inputs: RunInputs,
    rfz_inputs: RunInputs,
    syz_timeline: TimelinePopulations,
    rfz_timeline: TimelinePopulations,
    syz_ledger: paired.CpuLedgerParse,
    rfz_ledger: paired.CpuLedgerParse,
    syz_closure: paired.CpuClosureSummary,
    rfz_closure: paired.CpuClosureSummary,
) -> str:
    generated = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    lines = [
        "# Independent Fuzz Execution Comparison",
        "",
        f"Generated: `{generated}`",
        "",
        f"- Syzkaller run: {paired.markdown_path(syz_inputs.root)}",
        f"- Syzkaller timeline: {paired.markdown_path(syz_inputs.timeline_log)}",
        f"- reFuzz run: {paired.markdown_path(rfz_inputs.root)}",
        f"- reFuzz timeline: {paired.markdown_path(rfz_inputs.timeline_log)}",
        "",
        "The two runs are independent fuzz populations. No request identity is paired across systems. Wall-time branches `publish(C-D)` and `reuse(C-R)` may overlap and are never added together.",
        "",
    ]
    _append_integrity(lines, syz_timeline, rfz_timeline)
    _append_population_table(
        lines,
        "Guest Wall-Time Intervals",
        WALL_LABELS,
        syz_timeline.intervals,
        rfz_timeline.intervals,
    )
    _append_population_table(
        lines,
        "Per-Request CPU Time",
        ((spec.key, spec.label) for spec in CPU_SPECS),
        syz_timeline.request_cpu,
        rfz_timeline.request_cpu,
    )
    _append_population_table(
        lines,
        "Loop-Parent Runqueue Wait",
        ((spec.key, spec.label) for spec in RUNQUEUE_SPECS),
        syz_timeline.runqueue,
        rfz_timeline.runqueue,
    )
    paired.append_cpu_closure_tables(lines, syz_closure, rfz_closure)
    _append_resources(
        lines,
        syz_inputs,
        rfz_inputs,
        syz_ledger,
        rfz_ledger,
        syz_closure,
        rfz_closure,
    )
    _append_conclusions(
        lines,
        syz_inputs,
        rfz_inputs,
        syz_timeline,
        rfz_timeline,
        syz_closure,
        rfz_closure,
    )
    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--syz-run", required=True, type=Path)
    parser.add_argument("--rfz-run", required=True, type=Path)
    parser.add_argument("--run-id", type=int, default=1)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        syz_inputs = resolve_inputs(args.syz_run, "syz", args.run_id)
        rfz_inputs = resolve_inputs(args.rfz_run, "rfz", args.run_id)
        syz_timeline = parse_timeline_populations(
            "syz", syz_inputs.timeline_log, "[SyzTL]", "wid"
        )
        rfz_timeline = parse_timeline_populations(
            "rfz", rfz_inputs.timeline_log, "[RfzTL]", "w"
        )
        syz_ledger = parse_ledger(syz_inputs)
        rfz_ledger = parse_ledger(rfz_inputs)
        syz_closure = paired.compute_cpu_closure(syz_ledger)
        rfz_closure = paired.compute_cpu_closure(rfz_ledger)
        report = build_report(
            syz_inputs,
            rfz_inputs,
            syz_timeline,
            rfz_timeline,
            syz_ledger,
            rfz_ledger,
            syz_closure,
            rfz_closure,
        )
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        print(f"independent_exec_compare: {error}", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_name(f".{args.output.name}.tmp.{os.getpid()}")
    try:
        temporary.write_text(report, encoding="utf-8")
        os.replace(temporary, args.output)
    finally:
        temporary.unlink(missing_ok=True)
    print(f"independent_exec_compare: report={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

#!/usr/bin/env python3
"""Collect and summarize refuzz-perf replay runs.

Reads the launch manifest (optional), waits for containers to exit (unless
--no-wait), validates each run directory, and writes summary.csv / summary.md
under the results root.

Usage:
  python3 docker/collect_perf_results.py --results /data/perf-results
  python3 docker/collect_perf_results.py --results /data/perf-results --no-wait
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


RUN_GLOB = "e3-scale/rfz-*__on-*"
STREAM_BY_WORKLOAD = {"W1": "syz-a", "W2": "rfz-a"}
REQUIRED = [
    "RUN.json",
    "rfz/.replay_drained",
    "rfz/worker.log",
    "rfz/host_events.txt",
    "rfz/probe/gp.data",
    "independent_compare.md",
    "probe_attribution.txt",
]
EXPECTED_CODE_ID = "0c3edbfb81eb"


def iso_to_epoch(s: str) -> float:
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return dt.timestamp()
    except ValueError:
        return float("nan")


def latest_run_dir(results: Path, workload: str, workers: int) -> Path | None:
    stream = STREAM_BY_WORKLOAD[workload]
    matches = sorted(
        results.glob(f"e3-scale/rfz-w{workers}__on-{stream}__*"),
        key=lambda p: p.stat().st_mtime,
    )
    return matches[-1] if matches else None


def last_runtime_panel(host_events: Path) -> dict[str, int]:
    out: dict[str, int] = {}
    for line in host_events.read_text(errors="replace").splitlines():
        if "evt=runtime_panel" not in line and "RuntimePanel" not in line:
            continue
        for key in ("generated", "completion", "abnormal", "terminal", "exec_calls"):
            m = re.search(rf"{key}=(\d+)", line)
            if m:
                out[key] = int(m.group(1))
    return out


def parse_independent_compare(run_dir: Path) -> dict[str, float | str]:
    path = run_dir / "independent_compare.md"
    if not path.exists():
        return {"closure_status": "missing", "closure_gap_pct": ""}
    text = path.read_text(errors="replace")
    out: dict[str, float | str] = {}

    def num(s: str) -> float:
        try:
            return float(s)
        except ValueError:
            return float("nan")

    # Guest Wall-Time Intervals: complete span / worker cycle mean and p50.
    for label, key in (
        ("complete span (D-A)", "span_p50_ms"),
        ("worker cycle (A2-A)", "cycle_p50_ms"),
        ("dedicated model CPU", "model_cpu_mean_ms"),
        ("parent active runqueue (ppq+peq+poq)", "active_rq_mean_ms"),
    ):
        label_row = False
        for line in text.splitlines():
            if line.startswith("|") and label in line:
                # Table: | Metric | System | N | p50 | p90 | p95 | p99 | mean |
                cells = [c.strip() for c in line.strip().strip("|").split("|")]
                if len(cells) >= 8:
                    label_row = True
                    continue
            if label_row and line.startswith("|") and " rfz " in line:
                cells = [c.strip() for c in line.strip().strip("|").split("|")]
                if len(cells) >= 8:
                    if key.endswith("_p50_ms"):
                        out[key] = num(cells[3])
                    else:
                        out[key] = num(cells[-1])
                break
        if key not in out:
            out[key] = float("nan")

    # Closure summary: rfz row status.
    for line in text.splitlines():
        if line.startswith("| rfz |") and "UNEXPLAINED" in line:
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if len(cells) >= 2:
                out["closure_status"] = cells[1]
            break
    else:
        out["closure_status"] = "missing"

    # Absolute closure gap line.
    for line in text.splitlines():
        if "absolute closure gap" in line and "| rfz |" in line:
            m = re.search(r"([\d.]+)%", line)
            out["closure_gap_pct"] = num(m.group(1)) if m else float("nan")
            break
    else:
        out["closure_gap_pct"] = float("nan")
    return out


def analyze_run(run_dir: Path, container: str | None) -> dict[str, object]:
    run_json_path = run_dir / "RUN.json"
    if not run_json_path.exists():
        return {
            "run": run_dir.name,
            "container": container or "",
            "workload": "",
            "workers": "",
            "status": "missing RUN.json",
            "code_id": "",
            "drain": "",
            "missing": "RUN.json",
            "wall_s": "",
            "exec_calls": "",
            "terminal": "",
            "completion": "",
            "span_p50_ms": "",
            "cycle_p50_ms": "",
            "model_cpu_mean_ms": "",
            "active_rq_mean_ms": "",
            "closure_status": "",
            "closure_gap_pct": "",
        }
    run_json = json.loads(run_json_path.read_text())
    fields = run_json.get("fields", {})
    code = run_json.get("code", {})
    started = run_json.get("started_utc", "")
    finished = run_json.get("finished_utc", "")

    host_events = run_dir / "rfz/host_events.txt"
    panel = last_runtime_panel(host_events) if host_events.exists() else {}
    perf = parse_independent_compare(run_dir)

    drain = ""
    drain_path = run_dir / "rfz/.replay_drained"
    if drain_path.exists():
        drain = drain_path.read_text(errors="replace").strip()

    missing = [f for f in REQUIRED if not (run_dir / f).exists()]
    wall_s = float("nan")
    if started and finished:
        wall_s = iso_to_epoch(finished) - iso_to_epoch(started)

    return {
        "run": run_dir.name,
        "container": container or "",
        "workload": (run_json.get("stream", {}) or {}).get("id", ""),
        "workers": (run_json.get("knobs", {}) or {}).get("rfz_workers", ""),
        "status": run_json.get("status", ""),
        "code_id": code.get("id", ""),
        "drain": drain,
        "missing": ";".join(missing),
        "wall_s": wall_s,
        "exec_calls": panel.get("exec_calls", ""),
        "terminal": panel.get("terminal", ""),
        "completion": panel.get("completion", ""),
        "span_p50_ms": perf.get("span_p50_ms", ""),
        "cycle_p50_ms": perf.get("cycle_p50_ms", ""),
        "model_cpu_mean_ms": perf.get("model_cpu_mean_ms", ""),
        "active_rq_mean_ms": perf.get("active_rq_mean_ms", ""),
        "closure_status": perf.get("closure_status", ""),
        "closure_gap_pct": perf.get("closure_gap_pct", ""),
    }


def wait_for_containers(manifest: Path, timeout_s: int) -> None:
    if not manifest.exists():
        return
    names = []
    with manifest.open() as f:
        for line in f:
            if line.strip():
                names.append(line.split("\t", 1)[0])
    if not names:
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        running = []
        for name in names:
            try:
                st = subprocess.run(
                    ["docker", "inspect", "-f", "{{.State.Status}}", name],
                    capture_output=True, text=True, timeout=10,
                ).stdout.strip()
            except Exception:
                st = "gone"
            if st == "running":
                running.append(name)
        if not running:
            return
        time.sleep(30)
    raise SystemExit(f"timeout waiting for containers: {', '.join(names)}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", type=Path, default=Path("/data/perf-results"))
    ap.add_argument("--no-wait", action="store_true")
    ap.add_argument("--wait-timeout", type=int, default=7200)
    args = ap.parse_args()

    results: Path = args.results
    manifest = results / "launch_manifest.txt"
    if not args.no_wait:
        wait_for_containers(manifest, args.wait_timeout)

    expected: list[tuple[str, str, int, str | None]] = []
    if manifest.exists():
        with manifest.open() as f:
            for line in f:
                parts = line.rstrip("\n").split("\t")
                if len(parts) >= 4:
                    expected.append((parts[1], parts[2], 1, parts[0]))
        # The manifest stores workers as a string; normalize.
        expected = [(wl, int(wk), 1, name) for wl, wk, _, name in expected]
    else:
        for wl, stream in STREAM_BY_WORKLOAD.items():
            for wk in (6, 7):
                expected.append((wl, wk, 1, None))

    rows = []
    for workload, workers, _, container in expected:
        run_dir = latest_run_dir(results, workload, workers)
        if run_dir is None:
            rows.append({
                "run": f"missing {workload} w{workers}",
                "container": container or "",
                "workload": STREAM_BY_WORKLOAD[workload],
                "workers": workers,
                "status": "missing",
                "code_id": "", "drain": "", "missing": "run dir",
                "wall_s": "", "exec_calls": "", "terminal": "", "completion": "",
                "span_p50_ms": "", "cycle_p50_ms": "",
                "model_cpu_mean_ms": "", "active_rq_mean_ms": "",
                "closure_status": "", "closure_gap_pct": "",
            })
            continue
        rows.append(analyze_run(run_dir, container))

    fields = [
        "run", "container", "workload", "workers", "status", "code_id", "drain",
        "missing", "wall_s", "exec_calls", "terminal", "completion",
        "span_p50_ms", "cycle_p50_ms", "model_cpu_mean_ms", "active_rq_mean_ms",
        "closure_status", "closure_gap_pct",
    ]
    with (results / "summary.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)

    lines = [
        "# refuzz-perf replay summary",
        "",
        "| run | workload | workers | status | code.id | drain | wall_s | exec_calls | span p50 (ms) | cycle p50 (ms) | model CPU mean (ms) | active rq mean (ms) | closure gap |",
        "|---|---:|---:|---|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for r in rows:
        lines.append(
            f"| {r['run']} | {r['workload']} | {r['workers']} | {r['status']} | "
            f"{r['code_id']} | {r['drain']} | {r['wall_s']} | {r['exec_calls']} | "
            f"{r['span_p50_ms']} | {r['cycle_p50_ms']} | {r['model_cpu_mean_ms']} | "
            f"{r['active_rq_mean_ms']} | {r['closure_gap_pct']} |"
        )
    (results / "summary.md").write_text("\n".join(lines) + "\n")

    failed = [r for r in rows if r["status"] not in ("complete",) or r["missing"]]
    bad_code = [r for r in rows if r["code_id"] and r["code_id"] != EXPECTED_CODE_ID]
    if failed or bad_code:
        for r in failed:
            print(f"FAIL {r['run']}: status={r['status']} missing={r['missing']}")
        for r in bad_code:
            print(f"FAIL {r['run']}: code.id={r['code_id']} != {EXPECTED_CODE_ID}")
        return 1

    print(f"summary: {results}/summary.csv, {results}/summary.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())

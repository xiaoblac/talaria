#!/usr/bin/env python3
# Copyright 2026 reFuzz project author -------youngkk.
#
# MAB fuzz-tool comparison metrics, extracted from one reFuzz run's host_events.txt.
#
# The three "对比的数据" we solidified for the MAB fuzz tool (see speed_compare.py):
#
#   1. task execution share   — per-stage produce counts {gen, mut, triage, enrich}.
#        The producer loop (control/src/loop/fuzzer_loop.cpp) attributes every
#        producing iteration to exactly one stage: pass-1 triage (++triage_drains),
#        pass-1.5 enrich/smash/hints/fault (++enrich_drains), pass-2 MAB gen/mut
#        (PickCount → pick_gen/pick_mut). These four counters partition `iter`
#        (verified: pick_gen+pick_mut+triage_drains+enrich_drains == iter), so the
#        proportions are an exact accounting of how the scheduler spent its tasks.
#        Source: the final `evt=mab_arm_state` line.
#
#   2. PC-per-syscall coverage — cumulative corpus-PC (and edge / kcov-PC) as a
#        function of EXECUTED SYSCALLS, bucketed at 0, 0.5M, 1M, ... exec_calls.
#        This is the project headline (PC-per-syscall efficiency vs syzkaller),
#        re-based from coverage-vs-time onto coverage-vs-syscalls. Every
#        `[RuntimePanel]`/`[ShutdownPanel]` snapshot carries `exec_calls`,
#        `Corpus PC total`, `Corpus Edge total`, `KCOV PC total` in one line, so
#        the (syscalls -> coverage) series comes straight from runtime_panel.
#        Source: all `evt=runtime_panel` lines.
#
#   3. execution speed — programs/s and executed-syscalls/s. Handled directly by
#        speed_compare.py (real fuzzer.calls.executed counter); not recomputed here.
#
# Usage (standalone, re-runnable on any already-finished run):
#   python3 mab_metrics.py <host_events.txt> <out_dir> [--syscall-bucket 500000]
#
# Writes into <out_dir>:
#   mab_metrics.json          — machine-readable rollup (both metrics)
#   task_share.tsv            — metric 1: final per-stage counts + share %
#   task_share_series.tsv     — metric 1 over time (cumulative + per-snapshot delta share)
#   pc_vs_syscalls.tsv        — metric 2: raw (exec_calls -> coverage) series, one row/snapshot
#   pc_per_syscall_buckets.tsv— metric 2: coverage at exec_calls milestones (0, bucket, 2*bucket, ...)
import argparse
import json
import re
from pathlib import Path
from typing import Any

DEFAULT_SYSCALL_BUCKET = 500_000  # 0.5M executed syscalls per milestone

# runtime_panel sub-fields. The panel is one log line with embedded literal "\n",
# so each regex just searches the whole line.
_RP_TS = re.compile(r"snapshot ts_us=(\d+)")
_RP_CALLS = re.compile(r"\bexec_calls=(\d+)")
_RP_KCOV = re.compile(r"KCOV PC total=(\d+)")
_RP_CPC = re.compile(r"Corpus PC total=(\d+)")
_RP_CEDGE = re.compile(r"Corpus Edge total=(\d+)")
_RP_GEN = re.compile(r"\bgenerated=(\d+)")
_RP_COMPL = re.compile(r"\bcompletion=(\d+)")
_RP_CORP = re.compile(r"\bcorpus=(\d+)\b")
_RP_INTR = re.compile(r"\binteresting=(\d+)")
_RP_GROWTH = re.compile(r"\bcorpus_growth=(\d+)")

# the four stage-produce counters that partition every producing iteration.
TASK_STAGES = ("gen", "mut", "triage", "enrich")
_MAB_FIELD = {
    "gen": "pick_gen",
    "mut": "pick_mut",
    "triage": "triage_drains",
    "enrich": "enrich_drains",
}


def _read_lines(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def parse_runtime_panels(path: Path) -> list[dict[str, int]]:
    """Every runtime_panel/shutdown_panel snapshot as a dict (cumulative counters)."""
    out: list[dict[str, int]] = []
    for line in _read_lines(path):
        if "evt=runtime_panel" not in line:
            continue
        ts = _RP_TS.search(line)
        calls = _RP_CALLS.search(line)
        if ts is None or calls is None:
            continue

        def g(rx: re.Pattern[str]) -> int:
            m = rx.search(line)
            return int(m.group(1)) if m else 0

        out.append({
            "ts_us": int(ts.group(1)),
            "exec_calls": int(calls.group(1)),
            "kcov_pc": g(_RP_KCOV),
            "corpus_pc": g(_RP_CPC),
            "corpus_edge": g(_RP_CEDGE),
            "generated": g(_RP_GEN),
            "completion": g(_RP_COMPL),
            "corpus": g(_RP_CORP),
            "interesting": g(_RP_INTR),
            "corpus_growth": g(_RP_GROWTH),
        })
    out.sort(key=lambda r: (r["exec_calls"], r["ts_us"]))
    return out


def parse_mab_states(path: Path) -> list[dict[str, str]]:
    """Every `evt=mab_arm_state` line as a generic key=value dict (tab-separated)."""
    out: list[dict[str, str]] = []
    for line in _read_lines(path):
        if "evt=mab_arm_state" not in line:
            continue
        rec: dict[str, str] = {}
        for tok in line.split("\t"):
            k, _, v = tok.partition("=")
            if _:
                rec[k.strip()] = v.strip()
        if rec.get("evt") == "mab_arm_state":
            out.append(rec)
    return out


def _as_int(rec: dict[str, str], key: str) -> int:
    try:
        return int(float(rec.get(key, "0")))
    except (TypeError, ValueError):
        return 0


def compute_task_share(mab_final: dict[str, str] | None) -> dict[str, Any]:
    """Metric 1: final per-stage counts + share% of {gen,mut,triage,enrich}."""
    if not mab_final:
        return {"available": False}
    counts = {s: _as_int(mab_final, _MAB_FIELD[s]) for s in TASK_STAGES}
    total = sum(counts.values())
    shares = {s: (100.0 * counts[s] / total if total else 0.0) for s in TASK_STAGES}
    iters = _as_int(mab_final, "iter")
    return {
        "available": True,
        "counts": counts,
        "share_pct": shares,
        "total_tasks": total,
        "iter": iters,
        # partition self-check: the four stage counters should equal `iter`.
        "partition_ok": (total == iters) if iters else None,
        # carry the per-arm reward/cov context for the MAB write-up.
        "g_gen": mab_final.get("g_gen"),
        "g_mut": mab_final.get("g_mut"),
        "cov_gen": mab_final.get("cov_gen"),
        "cov_mut": mab_final.get("cov_mut"),
        "mut_share": mab_final.get("mut_share"),
        "epoch": mab_final.get("epoch"),
    }


def compute_task_share_series(mab_states: list[dict[str, str]]) -> list[dict[str, Any]]:
    """Metric 1 over time: each snapshot's cumulative counts + per-snapshot delta share."""
    series: list[dict[str, Any]] = []
    prev = {s: 0 for s in TASK_STAGES}
    for rec in mab_states:
        cum = {s: _as_int(rec, _MAB_FIELD[s]) for s in TASK_STAGES}
        delta = {s: max(0, cum[s] - prev[s]) for s in TASK_STAGES}
        dtot = sum(delta.values())
        ctot = sum(cum.values())
        series.append({
            "iter": _as_int(rec, "iter"),
            "ts_us": _as_int(rec, "wall_us") or _as_int(rec, "mono_us"),
            "cum": cum,
            "cum_share_pct": {s: (100.0 * cum[s] / ctot if ctot else 0.0) for s in TASK_STAGES},
            "delta": delta,
            "inst_share_pct": {s: (100.0 * delta[s] / dtot if dtot else 0.0) for s in TASK_STAGES},
        })
        prev = cum
    return series


def compute_pc_per_syscall(panels: list[dict[str, int]],
                           bucket: int = DEFAULT_SYSCALL_BUCKET) -> dict[str, Any]:
    """Metric 2: cumulative coverage at executed-syscall milestones 0, bucket, 2*bucket, ...

    For each milestone we report the FIRST snapshot whose exec_calls >= milestone
    (its actual exec_calls + coverage). The final snapshot is always appended as the
    end-of-run point, plus the headline PC-per-syscall / edge-per-syscall efficiency.
    """
    if not panels:
        return {"available": False}
    last = panels[-1]
    max_calls = last["exec_calls"]
    rows: list[dict[str, Any]] = []
    milestone = 0
    pi = 0
    while milestone <= max_calls:
        while pi < len(panels) and panels[pi]["exec_calls"] < milestone:
            pi += 1
        if pi >= len(panels):
            break
        p = panels[pi]
        rows.append({
            "milestone_calls": milestone,
            "exec_calls": p["exec_calls"],
            "kcov_pc": p["kcov_pc"],
            "corpus_pc": p["corpus_pc"],
            "corpus_edge": p["corpus_edge"],
            "ts_us": p["ts_us"],
        })
        milestone += bucket
    # always include the true end point (it may sit between two milestones).
    if not rows or rows[-1]["exec_calls"] != last["exec_calls"]:
        rows.append({
            "milestone_calls": "final",
            "exec_calls": last["exec_calls"],
            "kcov_pc": last["kcov_pc"],
            "corpus_pc": last["corpus_pc"],
            "corpus_edge": last["corpus_edge"],
            "ts_us": last["ts_us"],
        })
    eff = {
        "corpus_pc_per_syscall": (last["corpus_pc"] / max_calls) if max_calls else 0.0,
        "corpus_edge_per_syscall": (last["corpus_edge"] / max_calls) if max_calls else 0.0,
        "kcov_pc_per_syscall": (last["kcov_pc"] / max_calls) if max_calls else 0.0,
        # per 1k syscalls — more legible than the raw per-1 ratios.
        "corpus_pc_per_1k": (1000.0 * last["corpus_pc"] / max_calls) if max_calls else 0.0,
        "corpus_edge_per_1k": (1000.0 * last["corpus_edge"] / max_calls) if max_calls else 0.0,
    }
    return {
        "available": True,
        "bucket": bucket,
        "final_exec_calls": max_calls,
        "final_corpus_pc": last["corpus_pc"],
        "final_corpus_edge": last["corpus_edge"],
        "final_kcov_pc": last["kcov_pc"],
        "milestones": rows,
        "efficiency": eff,
    }


def _write_tsv(path: Path, header: list[str], rows: list[list[Any]]) -> None:
    lines = ["\t".join(header)]
    for r in rows:
        lines.append("\t".join(str(c) for c in r))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def emit(host_events: Path, out_dir: Path,
         bucket: int = DEFAULT_SYSCALL_BUCKET) -> dict[str, Any]:
    """Parse host_events.txt and write all metric-1/2 artifacts into out_dir."""
    out_dir.mkdir(parents=True, exist_ok=True)
    panels = parse_runtime_panels(host_events)
    mab_states = parse_mab_states(host_events)
    mab_final = mab_states[-1] if mab_states else None

    task = compute_task_share(mab_final)
    task_series = compute_task_share_series(mab_states)
    pc = compute_pc_per_syscall(panels, bucket)

    rollup = {
        "source": str(host_events),
        "syscall_bucket": bucket,
        "task_share": task,
        "pc_per_syscall": pc,
    }
    (out_dir / "mab_metrics.json").write_text(json.dumps(rollup, indent=2), encoding="utf-8")

    # metric 1 — final task share
    if task.get("available"):
        _write_tsv(out_dir / "task_share.tsv",
                   ["stage", "count", "share_pct"],
                   [[s, task["counts"][s], f"{task['share_pct'][s]:.3f}"] for s in TASK_STAGES]
                   + [["total", task["total_tasks"], "100.000"]])
    # metric 1 — task share over time
    if task_series:
        _write_tsv(out_dir / "task_share_series.tsv",
                   ["iter", "ts_us",
                    "cum_gen", "cum_mut", "cum_triage", "cum_enrich",
                    "inst_gen_pct", "inst_mut_pct", "inst_triage_pct", "inst_enrich_pct"],
                   [[r["iter"], r["ts_us"],
                     r["cum"]["gen"], r["cum"]["mut"], r["cum"]["triage"], r["cum"]["enrich"],
                     f"{r['inst_share_pct']['gen']:.2f}", f"{r['inst_share_pct']['mut']:.2f}",
                     f"{r['inst_share_pct']['triage']:.2f}", f"{r['inst_share_pct']['enrich']:.2f}"]
                    for r in task_series])
    # metric 2 — raw (syscalls -> coverage) series
    if panels:
        _write_tsv(out_dir / "pc_vs_syscalls.tsv",
                   ["ts_us", "exec_calls", "kcov_pc", "corpus_pc", "corpus_edge",
                    "corpus", "interesting"],
                   [[p["ts_us"], p["exec_calls"], p["kcov_pc"], p["corpus_pc"],
                     p["corpus_edge"], p["corpus"], p["interesting"]] for p in panels])
    # metric 2 — milestone buckets
    if pc.get("available"):
        _write_tsv(out_dir / "pc_per_syscall_buckets.tsv",
                   ["milestone_calls", "exec_calls", "kcov_pc", "corpus_pc", "corpus_edge"],
                   [[r["milestone_calls"], r["exec_calls"], r["kcov_pc"],
                     r["corpus_pc"], r["corpus_edge"]] for r in pc["milestones"]])
    return rollup


def _fmt_share(task: dict[str, Any]) -> str:
    if not task.get("available"):
        return "(no mab_arm_state)"
    sp = task["share_pct"]
    return (f"gen {sp['gen']:.1f}% / mut {sp['mut']:.1f}% / "
            f"triage {sp['triage']:.1f}% / enrich {sp['enrich']:.1f}%")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("host_events", type=Path, help="path to a run's host_events.txt")
    ap.add_argument("out_dir", type=Path, help="directory to write the metric artifacts")
    ap.add_argument("--syscall-bucket", type=int, default=DEFAULT_SYSCALL_BUCKET,
                    help="executed-syscall milestone step for metric 2 (default 500000 = 0.5M)")
    args = ap.parse_args()
    rollup = emit(args.host_events, args.out_dir, args.syscall_bucket)

    task = rollup["task_share"]
    pc = rollup["pc_per_syscall"]
    print(f"# task execution share : {_fmt_share(task)}")
    if task.get("available") and task.get("partition_ok") is False:
        print(f"#   WARNING: stage counters ({task['total_tasks']}) != iter ({task['iter']}) "
              "— partition assumption violated")
    if pc.get("available"):
        eff = pc["efficiency"]
        print(f"# PC-per-syscall        : {pc['final_corpus_pc']} corpus-PC over "
              f"{pc['final_exec_calls']} syscalls "
              f"= {eff['corpus_pc_per_1k']:.2f} PC / 1k syscalls "
              f"({eff['corpus_edge_per_1k']:.2f} edge / 1k)")
        print(f"# milestones (exec_calls -> corpus_pc):")
        for r in pc["milestones"]:
            print(f"#   {str(r['milestone_calls']):>9} | exec_calls={r['exec_calls']:>9} | "
                  f"corpus_pc={r['corpus_pc']:>7} | corpus_edge={r['corpus_edge']:>7} | "
                  f"kcov_pc={r['kcov_pc']:>7}")
    print(f"# artifacts -> {args.out_dir}")


if __name__ == "__main__":
    main()

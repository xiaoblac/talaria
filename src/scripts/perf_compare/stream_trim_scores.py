#!/usr/bin/env python3
"""Pick the long-tail records of a fixed request stream, symmetrically.

Emits a file of 0-based stream indices for tools/syz-stream-filter to drop. This
script knows nothing about the stream's binary format on purpose -- see that
tool's header for why format knowledge stays in pkg/requeststream.

HOW A RECORD IS LOCATED IN THE STREAM
The stream carries inputs only: no timings, no identities, no sequence key in
either side's task trace. What both sides do have is a per-request timestamp
taken at the moment the request was minted from the stream, under the lock that
also advances the stream cursor:

  * Syzkaller: `created_us`, stamped in streamReplayer.Next() (syz-manager/
    manager.go) inside sr.mu, which is the same critical section that does
    sr.pos++.
  * reFuzz: `task_queue_push_ts_us` on evt=task_trace, the push into the
    in-memory task queue that the fixed-input producer feeds in stream order.

So sorting a run's trace rows by that timestamp reconstructs emission order,
which IS stream order. Verified on the 34424-record stream: both sides produce
34424 rows with 34424 DISTINCT such timestamps, so the mapping row i -> record i
is total and unambiguous. It only holds when the run replayed the whole stream
with zero undecodable records; --require-full enforces that.

WHY THE CRITERION AVERAGES SEVERAL RUNS AND BOTH SYSTEMS
Measured on the same 34424 records (Spearman rank correlation / top-10% tail-set
overlap):

  rfz@6 run1 vs run2  (same config)  0.835 / 87.8%   <- the noise floor
  syz@6      vs rfz@6 (cross-system) 0.753 / 62.0%

The cross-system figure is clearly worse than the noise floor, so the two
systems genuinely disagree about which records are expensive -- it is not just
measurement scatter. Trimming by one system's timings would therefore delete
that system's own worst cases and flatter it. Averaging normalised ranks over
runs from BOTH systems removes that asymmetry, and averaging over repeats of the
same config suppresses the scatter.

Ranks, not raw durations: the two systems measure different quantities (syz's
executor-reported elapsed vs reFuzz's guest worker_done-worker_start) with
different scales, and their medians differ by ~30%. Ranks are scale-free, so no
per-system normalisation constant has to be invented.

WHY 1% IS NOT AN OFFERED TRIM LEVEL
The same-config repeat overlap in the top 1% band is only 62.9%, i.e. more than
a third of the extreme tail is scatter rather than a program property. A 1% trim
would mostly be selecting noise. The top 10% band repeats at 87.8% and is what
this script is meant for.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path


def syz_durations(path: Path) -> list[int]:
    """(stream index -> duration_us) from a syz-manager task trace."""
    rows = []
    with path.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            # elapsed_us is the executor's own measurement of running THIS
            # program. Preferred over completion_observed-executing, which also
            # contains guest-side scheduling delay and so tracks how loaded the
            # guest was rather than how expensive the program is.
            rows.append((int(r["created_us"]), int(r["elapsed_us"])))
    rows.sort()
    return [d for _, d in rows]


def rfz_durations(path: Path) -> list[int]:
    """(stream index -> duration_us) from a reFuzz host_events.txt."""
    rows = []
    with path.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            if "evt=task_trace" not in line:
                continue
            d = dict(kv.split("=", 1) for kv in line.strip().split("\t") if "=" in kv)
            # Guest-clock pair, so it measures execution inside the worker and
            # excludes host queueing entirely.
            rows.append((int(d["task_queue_push_ts_us"]),
                         int(d["worker_done_ts_us"]) - int(d["worker_start_ts_us"])))
    rows.sort()
    return [d for _, d in rows]


def ranks(values: list[int]) -> list[float]:
    """Fractional ranks in [0,1]; ties broken by input order (immaterial here,
    all timestamps are distinct and durations are microsecond-resolution)."""
    order = sorted(range(len(values)), key=lambda i: values[i])
    out = [0.0] * len(values)
    n = max(len(values) - 1, 1)
    for position, i in enumerate(order):
        out[i] = position / n
    return out


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--syz-trace", type=Path, action="append", default=[],
                   help="syz_task_trace.jsonl from a stream-replay run (repeatable)")
    p.add_argument("--rfz-trace", type=Path, action="append", default=[],
                   help="host_events.txt from a run_mode=replay run (repeatable)")
    p.add_argument("--records", type=int, required=True,
                   help="record count of the stream these traces replayed")
    p.add_argument("--trim-percent", type=float, required=True,
                   help="drop this percent of records, the most expensive first")
    p.add_argument("--out", type=Path, required=True, help="indices file to write")
    p.add_argument("--prefix", type=int, default=0,
                   help="rank and trim only within the first N records. Needed when the "
                        "replayed stream is a PREFIX of the one the traces came from: taking "
                        "the globally-slowest records that happen to fall inside a prefix "
                        "gives a different trim strength than the requested percentage, "
                        "because the long tail is not uniformly distributed along the stream "
                        "(the first 10000 of this 34424-record stream hold only 780 of the "
                        "global top 3442, i.e. 7.8% rather than 10%). Ranking within the "
                        "prefix keeps the criterion identical to the full-stream case.")
    p.add_argument("--require-full", action="store_true", default=True,
                   help="fail unless every trace has exactly --records rows (default)")
    p.add_argument("--allow-partial", dest="require_full", action="store_false",
                   help="permit traces shorter than --records (index mapping becomes "
                        "unreliable; only for diagnostics)")
    args = p.parse_args()

    sources: list[tuple[str, list[int]]] = []
    for path in args.syz_trace:
        sources.append((f"syz:{path.parent.parent.name}", syz_durations(path)))
    for path in args.rfz_trace:
        sources.append((f"rfz:{path.parent.parent.name}", rfz_durations(path)))
    if not sources:
        sys.exit("need at least one --syz-trace or --rfz-trace")
    if not any(name.startswith("syz:") for name, _ in sources) or \
       not any(name.startswith("rfz:") for name, _ in sources):
        # Refused rather than warned: a one-sided trim is exactly the biased
        # selection this script exists to avoid, and its output is
        # indistinguishable from a symmetric one downstream.
        sys.exit("refusing a one-sided trim: pass at least one trace from EACH system "
                 "(see the module docstring -- cross-system tail agreement is only 62%)")

    print("source traces:")
    for name, d in sources:
        if len(d) != args.records:
            msg = (f"  {name}: {len(d)} rows but stream has {args.records} records")
            if args.require_full:
                sys.exit(msg + "  -- index mapping would be wrong; refusing")
            print(msg + "  (--allow-partial)")
        s = sorted(d)
        print(f"  {name}: n={len(d)} median={s[len(s)//2]/1e3:.1f}ms "
              f"p90={s[int(.9*len(s))]/1e3:.1f}ms max={s[-1]/1e3:.1f}ms")

    n = min(len(d) for _, d in sources)
    if args.prefix:
        if args.prefix > n:
            sys.exit(f"--prefix {args.prefix} exceeds the {n} available rows")
        n = args.prefix
        print(f"\nranking within the first {n} records only (--prefix)")
    # Average WITHIN each system first, then across systems with equal weight.
    # Averaging over the flat list of traces instead would weight a system by how
    # many runs happened to be available: the first attempt here passed one syz
    # trace and two reFuzz traces, making the score 2/3 reFuzz-determined, and the
    # resulting trim removed 44% of reFuzz's execution time against 37.5% of
    # syzkaller's -- i.e. it re-introduced exactly the asymmetry this criterion
    # exists to remove. Per-system means make the trim independent of run counts.
    per_system: dict[str, list[list[float]]] = {}
    for name, d in sources:
        per_system.setdefault(name.split(":", 1)[0], []).append(ranks(d[:n]))
    system_scores = [[statistics.fmean(r[i] for r in rs) for i in range(n)]
                     for rs in per_system.values()]
    score = [statistics.fmean(s[i] for s in system_scores) for i in range(n)]
    print(f"\ncriterion: equal weight per system over "
          + ", ".join(f"{k}({len(v)} run{'s' if len(v) > 1 else ''})"
                      for k, v in per_system.items()))

    drop_count = round(n * args.trim_percent / 100.0)
    if drop_count <= 0:
        sys.exit(f"--trim-percent {args.trim_percent} drops no records out of {n}")
    if drop_count >= n:
        sys.exit(f"--trim-percent {args.trim_percent} would drop every record")
    dropped = sorted(sorted(range(n), key=lambda i: -score[i])[:drop_count])

    # Report how much execution time leaves with those records, per source. This
    # is the number that says whether the trim is worth running: dropping 10% of
    # records that carry 2% of the time would change nothing measurable.
    print(f"\ndropping {drop_count}/{n} records ({100*drop_count/n:.2f}%)")
    dropset = set(dropped)
    for name, d in sources:
        total = sum(d[:n])
        gone = sum(d[i] for i in dropped)
        print(f"  {name}: removes {100*gone/total:.1f}% of total execution time")

    header = [
        "# stream indices to drop -- generated by stream_trim_scores.py",
        f"# trim_percent={args.trim_percent} dropped={drop_count} of {n}",
        f"# criterion=equal-weight-per-system mean normalised rank over: "
        + ", ".join(name for name, _ in sources),
    ]
    args.out.write_text("\n".join(header + [str(i) for i in dropped]) + "\n",
                        encoding="utf-8")
    print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

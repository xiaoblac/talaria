#!/usr/bin/env python3
"""Aggregate exec-oracle per-call JSONL into per-pseudo evidence.

Input  : <path>.jsonl produced by `refuzz_exec_oracle -per-call-jsonl <path>`
         (one JSON object per kernel call from a paired-oracle compare session,
         with syscall name + per-call sorted+deduped PC hex strings for both
         sides + err/flag mismatch booleans + cover-availability flag).

         Replaces the retired layer3 per-call jsonl pipeline (the per-call
         schema is a strict superset, so old aggregation logic ports straight
         over — we just gained cover_available / actionable_err_mismatch /
         kcov_buffer_overflow gating).

Output : CSV with one row per pseudo syscall (syz_* name), columns:

  name                       upstream syz_* name (= syz.SyscallName)
  hits                       per-call records seen (any cover state)
  cover_available_hits       records with cover_available=true (the only ones
                             contributing to PC / jaccard math)
  kcov_overflow_hits         records flagged kcov_buffer_overflow=true. These
                             are excluded from union_jaccard / per_call_jaccard
                             because raw refCov hit kcov ring cap — worker
                             measurement artifact per plan §13.5 finding #3,
                             not real path divergence.
  syz_pc_count               |union(syz_pcs across cover-available, non-overflow hits)|
  ref_pc_count               |union(ref_pcs across cover-available, non-overflow hits)|
  union_jaccard              |syz_pc_union ∩ ref_pc_union| / |union|
                             — "do both sides reach the same kernel depth"
                             across the call's lifetime. Stable across kcov
                             noise: per-call sets jitter, but union over N
                             hits converges to the handler's reachable set.
  exact_set_match_rate       fraction of cover-available, non-overflow hits
                             where syz_pc_set == ref_pc_set exactly. Strict —
                             one PC flip zeroes it.
  per_call_jaccard_mean      arithmetic mean of per-call jaccards over the
                             same denominator as union_jaccard
  per_call_jaccard_median    median of same
  real_err_mis_rate          fraction of records with real_err_mismatch=true
                             (denominator = hits). Real = both sides Executed
                             AND syz_err != ref_err.
  actionable_err_mis_rate    fraction with actionable_err_mismatch=true.
                             actionable = real_err_mismatch AFTER filtering
                             the syz_mount_image$* {0, EBUSY} structural-
                             tension family (plan §13.5). Use this for
                             allowlist decisions; raw real_err_mis_rate is
                             observation-only.
  depth_proxy                max(syz_pc_count, ref_pc_count) — quick sort key
                             when triaging pseudos by "deepest path reached".

The output is the L1 evidence layer the manifest workflow describes:
downstream `scripts/pc_compare/import_oracle_to_proof_status.py` writes these numbers
into `configs/pseudo_proof_status.csv` for the corresponding pseudo rows.

Usage:
  python3 scripts/pc_compare/exec_oracle_per_pseudo_aggregate.py \\
    --jsonl run/exec-oracle-<ts>/per-call.jsonl \\
    --out-csv configs/pseudo_oracle_evidence.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


def parse_pcs_hex(hex_str: str) -> set[int]:
    """Decode the continuous 16-hex-char/uint64 stream into a set of PCs.

    Both harnesses sort+dedupe before emission, so the set semantics
    we need is loss-free. Invalid lengths or non-hex bytes return an
    empty set (we treat parse failures as "no coverage info" rather
    than aborting the whole aggregate).
    """
    if not hex_str or len(hex_str) % 16 != 0:
        return set()
    n = len(hex_str) // 16
    out: set[int] = set()
    for i in range(n):
        try:
            out.add(int(hex_str[i * 16:(i + 1) * 16], 16))
        except ValueError:
            return set()
    return out


def jaccard(a: set[int], b: set[int]) -> float:
    if not a and not b:
        return 1.0
    union = len(a | b)
    if union == 0:
        return 1.0
    return len(a & b) / union


@dataclass
class PseudoAccumulator:
    name: str
    hits: int = 0
    cover_hits: int = 0
    overflow_hits: int = 0
    syz_pc_union: set[int] = field(default_factory=set)
    ref_pc_union: set[int] = field(default_factory=set)
    per_call_jaccards: list[float] = field(default_factory=list)
    exact_set_matches: int = 0
    real_err_mis: int = 0
    actionable_err_mis: int = 0

    def add(self, rec: dict) -> None:
        self.hits += 1
        if rec.get("real_err_mismatch"):
            self.real_err_mis += 1
        if rec.get("actionable_err_mismatch"):
            self.actionable_err_mis += 1
        # Cover availability gates everything PC-related. Without it the
        # parse_pcs_hex of empty strings returns set() which would (a) record
        # a trivial jaccard=1.0, (b) trivially match exact_set, both
        # polluting equivalence evidence — keep these calls in the `hits`
        # denominator for err rates only.
        if not rec.get("cover_available"):
            return
        # kcov ring buffer overflow is a worker measurement artifact (plan
        # §13.5 finding #3). Drop from PC / jaccard pools so union_jaccard
        # isn't dragged down by saturated cov sets; still count in
        # overflow_hits so an operator can see the worker-side health metric.
        if rec.get("kcov_buffer_overflow"):
            self.overflow_hits += 1
            return
        self.cover_hits += 1
        syz_pcs = parse_pcs_hex(rec.get("syz_pcs_hex", ""))
        ref_pcs = parse_pcs_hex(rec.get("ref_pcs_hex", ""))
        self.syz_pc_union |= syz_pcs
        self.ref_pc_union |= ref_pcs
        self.per_call_jaccards.append(jaccard(syz_pcs, ref_pcs))
        if syz_pcs == ref_pcs:
            # Both-empty falls here too. After cover_available gating both
            # empty is genuinely "both sides observed no PCs while running
            # under cover capture", which is still legitimate equivalence
            # evidence (handler returned early identically). Counted.
            self.exact_set_matches += 1

    def row(self) -> dict[str, str]:
        union_jac = jaccard(self.syz_pc_union, self.ref_pc_union)
        denom = max(self.cover_hits, 1)  # avoid div-by-zero in rate output
        per_call_mean = (
            statistics.fmean(self.per_call_jaccards) if self.per_call_jaccards else 0.0
        )
        per_call_median = (
            statistics.median(self.per_call_jaccards) if self.per_call_jaccards else 0.0
        )
        depth_proxy = max(len(self.syz_pc_union), len(self.ref_pc_union))
        return {
            "name": self.name,
            "hits": str(self.hits),
            "cover_available_hits": str(self.cover_hits),
            "kcov_overflow_hits": str(self.overflow_hits),
            "syz_pc_count": str(len(self.syz_pc_union)),
            "ref_pc_count": str(len(self.ref_pc_union)),
            "union_jaccard": f"{union_jac:.6f}",
            "exact_set_match_rate": (
                f"{self.exact_set_matches / denom:.6f}" if self.cover_hits else "0.000000"
            ),
            "per_call_jaccard_mean": f"{per_call_mean:.6f}",
            "per_call_jaccard_median": f"{per_call_median:.6f}",
            "real_err_mis_rate": (
                f"{self.real_err_mis / self.hits:.6f}" if self.hits else "0.000000"
            ),
            "actionable_err_mis_rate": (
                f"{self.actionable_err_mis / self.hits:.6f}" if self.hits else "0.000000"
            ),
            "depth_proxy": str(depth_proxy),
        }


CSV_FIELDS = [
    "name",
    "hits",
    "cover_available_hits",
    "kcov_overflow_hits",
    "syz_pc_count",
    "ref_pc_count",
    "union_jaccard",
    "exact_set_match_rate",
    "per_call_jaccard_mean",
    "per_call_jaccard_median",
    "real_err_mis_rate",
    "actionable_err_mis_rate",
    "depth_proxy",
]


def iter_records(path: Path) -> Iterable[dict]:
    with path.open("r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as e:
                print(f"warning: skip malformed JSONL at line {lineno}: {e}", file=sys.stderr)


def aggregate(records: Iterable[dict], pseudo_only: bool) -> dict[str, PseudoAccumulator]:
    accumulators: dict[str, PseudoAccumulator] = {}
    for rec in records:
        name = rec.get("syscall", "")
        if not name:
            continue
        if pseudo_only and not name.startswith("syz_"):
            continue
        acc = accumulators.get(name)
        if acc is None:
            acc = PseudoAccumulator(name=name)
            accumulators[name] = acc
        acc.add(rec)
    return accumulators


def write_csv(path: Path, accumulators: dict[str, PseudoAccumulator]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = [accumulators[name].row() for name in sorted(accumulators)]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--jsonl", type=Path, required=True,
                        help="per-call JSONL emitted by refuzz_exec_oracle -per-call-jsonl")
    parser.add_argument("--out-csv", type=Path, required=True,
                        help="output CSV with one row per pseudo")
    parser.add_argument("--include-non-pseudo", action="store_true",
                        help="aggregate every syscall, not just syz_* "
                             "(default: pseudo-only).")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.jsonl.exists():
        print(f"error: missing input JSONL: {args.jsonl}", file=sys.stderr)
        return 2
    accumulators = aggregate(iter_records(args.jsonl), pseudo_only=not args.include_non_pseudo)
    write_csv(args.out_csv, accumulators)

    total_hits = sum(a.hits for a in accumulators.values())
    total_cover = sum(a.cover_hits for a in accumulators.values())
    total_overflow = sum(a.overflow_hits for a in accumulators.values())
    print(f"pseudo_count={len(accumulators)}")
    print(f"total_call_hits={total_hits}")
    print(f"total_cover_hits={total_cover}")
    print(f"total_overflow_hits={total_overflow}")
    print(f"out_csv={args.out_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

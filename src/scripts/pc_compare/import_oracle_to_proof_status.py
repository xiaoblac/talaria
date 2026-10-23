#!/usr/bin/env python3
"""Merge exec-oracle per-pseudo evidence into configs/pseudo_proof_status.csv.

Reads the evidence CSV produced by
`scripts/pc_compare/exec_oracle_per_pseudo_aggregate.py` and writes its numeric
columns into the matching `name` rows of `configs/pseudo_proof_status.csv`:

  proof_status.csv field           ← evidence field
  ------------------------         -----------------
  oracle_kcov_jaccard              union_jaccard
  oracle_kcov_digest_match         exact_set_match_rate
  oracle_err_mismatch              real_err_mis_rate
  oracle_actionable_err_mismatch   actionable_err_mis_rate

Evidence-driven candidate growth (default ON):
When the importer sees evidence for a pseudo NOT yet in proof_status, it
auto-promotes that pseudo by inserting a new proof_status row with:
  - status columns (signature/layout/trace/result/review_verdict) = "pending"
  - evidence columns filled in from the evidence row
  - oracle_first_seen = today's ISO date (provenance)

Rationale: corpus-triage runs surface real reFuzz worker behaviour on
syscalls reFuzz may not have curated into candidate yet (e.g. syz_kvm_*,
syz_io_uring_*, syz_fuse_*). Discarding that evidence as "non_candidate
warning" wastes paired-oracle measurements — the right model is "we
observed it run, so it's in scope; the L2 verdict decision is still
human".

proof_status.csv is the single source of truth for candidates.
generate_pseudo_manifest reads proof_status to derive
configs/pseudo_candidate_allowlist.txt — this script does NOT touch that
file. To disable auto-promote (e.g. to keep candidate set fixed), pass
`--no-auto-promote`. Evidence for off-candidate pseudos is then dropped
and reported as warnings (the pre-2026-05-20 behaviour).

The L2 columns — `signature_status / layout_status / trace_status /
result_status / analysis / review_verdict / notes` — are human-curated
and left untouched by this script for existing rows; for auto-promoted
rows they're initialized to `pending` / empty.

Usage:
  python3 scripts/pc_compare/import_oracle_to_proof_status.py \\
    --evidence configs/pseudo_oracle_evidence.csv

  # dry-run: print what would change without writing
  python3 scripts/pc_compare/import_oracle_to_proof_status.py \\
    --evidence configs/pseudo_oracle_evidence.csv --dry-run

  # keep candidate set frozen — useful for benchmark reproducibility
  python3 scripts/pc_compare/import_oracle_to_proof_status.py \\
    --evidence configs/pseudo_oracle_evidence.csv --no-auto-promote
"""

from __future__ import annotations

import argparse
import csv
import datetime
import sys
from pathlib import Path


# Evidence column → proof_status column. Pinned here so the schema
# contract between the two files is explicit and auditable; changes
# here must be made in tandem with the aggregator's CSV_FIELDS and the
# generator's PROOF_FIELDS.
FIELD_MAP = {
    "union_jaccard": "oracle_kcov_jaccard",
    "exact_set_match_rate": "oracle_kcov_digest_match",
    "real_err_mis_rate": "oracle_err_mismatch",
    "actionable_err_mis_rate": "oracle_actionable_err_mismatch",
}

# Default values for newly auto-promoted proof_status rows. Each L2-curated
# status column starts at "pending"; evidence (L1) columns are filled by
# merge() from the evidence CSV; analysis/notes stay empty.
NEW_ROW_DEFAULTS = {
    "signature_status": "pending",
    "layout_status":    "pending",
    "trace_status":     "pending",
    "result_status":    "pending",
    "review_verdict":   "pending",
}


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def read_proof_status(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            raise SystemExit(f"proof_status.csv missing header: {path}")
        fieldnames = list(reader.fieldnames)
        rows = list(reader)
    for col in FIELD_MAP.values():
        if col not in fieldnames:
            raise SystemExit(
                f"proof_status.csv missing required column: {col} "
                f"(present={fieldnames})"
            )
    return fieldnames, rows


def read_evidence(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            raise SystemExit(f"evidence.csv missing header: {path}")
        for col in FIELD_MAP:
            if col not in reader.fieldnames:
                raise SystemExit(
                    f"evidence.csv missing required column: {col} "
                    f"(present={list(reader.fieldnames)})"
                )
        return list(reader)


def make_new_row(name: str, ev: dict[str, str], fieldnames: list[str]) -> dict[str, str]:
    """Build a fresh proof_status row for an auto-promoted pseudo.

    Status columns default to 'pending'; evidence columns come from the
    evidence row; oracle_first_seen records today's date so audit logs
    can trace when a pseudo entered scope. Field order matches the
    proof_status.csv header so writer.writerows preserves layout.
    """
    row = {col: "" for col in fieldnames}
    row["name"] = name
    for col, default_val in NEW_ROW_DEFAULTS.items():
        if col in row:
            row[col] = default_val
    for ev_col, ps_col in FIELD_MAP.items():
        if ps_col in row:
            row[ps_col] = (ev.get(ev_col) or "").strip()
    # Provenance: when did this pseudo first show up in evidence?
    if "oracle_first_seen" in row:
        row["oracle_first_seen"] = datetime.date.today().isoformat()
    return row


def merge(
    proof_rows: list[dict[str, str]],
    evidence_rows: list[dict[str, str]],
    fieldnames: list[str],
    auto_promote: bool,
) -> tuple[int, list[str], list[str], list[tuple[str, dict[str, tuple[str, str]]]]]:
    """Merge evidence into proof_status rows in place.

    Returns (updated_count, auto_promoted_names, skipped_non_candidate, change_log).
    Either auto_promoted_names or skipped_non_candidate is populated, never both.
    """
    by_name = {r.get("name", ""): r for r in proof_rows}
    updated = 0
    auto_promoted: list[str] = []
    skipped: list[str] = []
    changes: list[tuple[str, dict[str, tuple[str, str]]]] = []
    for ev in evidence_rows:
        name = ev.get("name", "").strip()
        if not name:
            continue
        target = by_name.get(name)
        if target is None:
            if auto_promote:
                new_row = make_new_row(name, ev, fieldnames)
                proof_rows.append(new_row)
                by_name[name] = new_row
                auto_promoted.append(name)
            else:
                skipped.append(name)
            continue
        row_changes: dict[str, tuple[str, str]] = {}
        for ev_col, ps_col in FIELD_MAP.items():
            new_val = (ev.get(ev_col) or "").strip()
            old_val = (target.get(ps_col) or "").strip()
            if new_val != old_val:
                row_changes[ps_col] = (old_val, new_val)
            target[ps_col] = new_val
        if row_changes:
            changes.append((name, row_changes))
            updated += 1
    return updated, auto_promoted, skipped, changes


def write_proof_status(path: Path, fieldnames: list[str], rows: list[dict[str, str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def parse_args() -> argparse.Namespace:
    root = repo_root()
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--evidence", type=Path, required=True,
                        help="per-pseudo evidence CSV from "
                             "scripts/pc_compare/exec_oracle_per_pseudo_aggregate.py")
    parser.add_argument("--proof-status", type=Path,
                        default=root / "configs/pseudo_proof_status.csv",
                        help="proof_status CSV to update in place")
    parser.add_argument("--no-auto-promote", action="store_true",
                        help="disable evidence-driven candidate growth — "
                             "evidence for off-candidate pseudos is dropped "
                             "and reported as warnings instead. Use this to "
                             "keep the candidate set frozen across runs.")
    parser.add_argument("--dry-run", action="store_true",
                        help="print changes but do not write")
    parser.add_argument("--show-changes", type=int, default=20,
                        help="print up to N updated rows (default 20)")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.evidence.exists():
        print(f"error: missing evidence csv: {args.evidence}", file=sys.stderr)
        return 2
    if not args.proof_status.exists():
        print(f"error: missing proof_status csv: {args.proof_status}", file=sys.stderr)
        return 2

    fieldnames, rows = read_proof_status(args.proof_status)
    evidence_rows = read_evidence(args.evidence)

    auto_promote = not args.no_auto_promote
    updated, auto_promoted, skipped, changes = merge(
        rows, evidence_rows, fieldnames, auto_promote=auto_promote)

    if not args.dry_run:
        write_proof_status(args.proof_status, fieldnames, rows)
    print(f"evidence_rows={len(evidence_rows)}")
    print(f"proof_status_rows={len(rows)}")
    print(f"updated={updated}")
    print(f"auto_promoted={len(auto_promoted)}")
    print(f"skipped_non_candidate={len(skipped)}")
    if auto_promoted:
        print(f"\nauto-promoted (first {min(len(auto_promoted), args.show_changes)}):")
        for n in auto_promoted[: args.show_changes]:
            print(f"  {n}")
        if len(auto_promoted) > args.show_changes:
            print(f"  ... and {len(auto_promoted) - args.show_changes} more")
    if skipped:
        print(f"\nwarn: --no-auto-promote dropped {len(skipped)} evidence rows "
              f"(not in proof_status):")
        for n in skipped[: args.show_changes]:
            print(f"  {n}")
        if len(skipped) > args.show_changes:
            print(f"  ... and {len(skipped) - args.show_changes} more")
    if changes:
        print(f"\nfirst {min(len(changes), args.show_changes)} value updates:")
        for name, row_changes in changes[: args.show_changes]:
            parts = [f"{col}: {old!r}→{new!r}" for col, (old, new) in row_changes.items()]
            print(f"  {name}  " + "  ".join(parts))
    if args.dry_run:
        print("\n(dry-run: proof_status.csv was NOT modified; "
              "candidate_allowlist is a manifest-generated view and unaffected by this script)")
    else:
        print(f"\nwrote: {args.proof_status}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

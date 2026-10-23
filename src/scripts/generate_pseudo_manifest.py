#!/usr/bin/env python3
"""Generate the syz_* pseudo manifest and evidence-gated allowlist.

The manifest is the audit surface for aligning upstream syzkaller and reFuzz:
each upstream sys/linux/*.txt syz_* definition gets one CSV row, joined with
the generated reFuzz pseudo metadata table. The candidate list records pseudo
calls worth analyzing; the allowlist is populated only after a reviewed verdict
accepts the observed evidence.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


PSEUDO_NAME_RE = re.compile(r"^(syz_[A-Za-z0-9_$]+)\(")
REFUZZ_META_RE = re.compile(
    r'\{\s*0x[0-9a-fA-F]+ULL,\s*"(?P<name>[^"]+)",\s*'
    r"(?P<argc>\d+)u,\s*PseudoDomain::(?P<domain>\w+),\s*"
    r"PseudoImplKind::(?P<impl>\w+),\s*(?P<cap>.*?),\s*"
    r"\{[^}]*\},\s*PseudoConcurrency::(?P<concurrency>\w+)\s*\}"
)

DEFAULT_META = (
    "program/include/refuzz/program/syz/pseudo/generated/pseudo_meta.gen.hpp"
)
DEFAULT_MANIFEST = "configs/pseudo_manifest.csv"
DEFAULT_ALLOWLIST = "configs/pseudo_allowlist.txt"
DEFAULT_CANDIDATE_ALLOWLIST = "configs/pseudo_candidate_allowlist.txt"
DEFAULT_DISABLELIST = "configs/pseudo_disablelist.txt"
DEFAULT_PROOF_STATUS = "configs/pseudo_proof_status.csv"

FIRST_BATCH_PREFIXES = (
    "syz_open_dev",
    "syz_open_procfs",
    "syz_init_net_socket",
    "syz_genetlink_get_family_id",
)
FIRST_BATCH_EXACT = {
    "syz_clone",
    "syz_clone3",
    "syz_pidfd_open",
}

MANIFEST_FIELDS = [
    "name",
    "upstream_file",
    "upstream_signature",
    "upstream_attrs",
    "upstream_arg_count",
    "refuzz_present",
    "refuzz_arg_count",
    "refuzz_domain",
    "refuzz_impl_kind",
    "cap_mask",
    "concurrency",
    "candidate",
    "signature_status",
    "layout_status",
    "trace_status",
    "result_status",
    "oracle_err_mismatch",
    "oracle_actionable_err_mismatch",
    "oracle_kcov_jaccard",
    "oracle_kcov_digest_match",
    "oracle_first_seen",
    "analysis",
    "review_verdict",
    "proof_status",
    "decision",
    "status",
]

PROOF_FIELDS = [
    "name",
    "signature_status",
    "layout_status",
    "trace_status",
    "result_status",
    "oracle_err_mismatch",
    "oracle_actionable_err_mismatch",
    "oracle_kcov_jaccard",
    "oracle_kcov_digest_match",
    "oracle_first_seen",
    "analysis",
    "review_verdict",
    "notes",
]

REVIEW_VERDICTS = {"pending", "allow", "disable", "port"}


@dataclass(frozen=True)
class UpstreamPseudo:
    name: str
    file: str
    signature: str
    attrs: str
    arg_count: int


@dataclass(frozen=True)
class RefuzzPseudo:
    name: str
    arg_count: int
    domain: str
    impl: str
    cap_mask: str
    concurrency: str


@dataclass(frozen=True)
class ProofRecord:
    name: str
    signature_status: str = "pending"
    layout_status: str = "pending"
    trace_status: str = "pending"
    result_status: str = "pending"
    oracle_err_mismatch: str = ""
    oracle_actionable_err_mismatch: str = ""
    oracle_kcov_jaccard: str = ""
    oracle_kcov_digest_match: str = ""
    oracle_first_seen: str = ""
    analysis: str = ""
    review_verdict: str = "pending"
    notes: str = ""


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def strip_namespace(value: str) -> str:
    return value.removeprefix("k")


def is_first_batch_helper(name: str) -> bool:
    return name in FIRST_BATCH_EXACT or name.startswith(FIRST_BATCH_PREFIXES)


def matching_open(text: str, close_idx: int) -> int | None:
    depth = 0
    in_string = False
    escaped = False
    for idx in range(close_idx, -1, -1):
        ch = text[idx]
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == ")":
            depth += 1
        elif ch == "(":
            depth -= 1
            if depth == 0:
                return idx
    return None


def find_matching_close(text: str, open_idx: int) -> int | None:
    depth = 0
    bracket_depth = 0
    in_string = False
    escaped = False
    for idx in range(open_idx, len(text)):
        ch = text[idx]
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "[":
            bracket_depth += 1
        elif ch == "]" and bracket_depth:
            bracket_depth -= 1
        elif bracket_depth == 0 and ch == "(":
            depth += 1
        elif bracket_depth == 0 and ch == ")":
            depth -= 1
            if depth == 0:
                return idx
    return None


def split_top_level_args(args: str) -> list[str]:
    parts: list[str] = []
    start = 0
    bracket_depth = 0
    paren_depth = 0
    in_string = False
    escaped = False
    for idx, ch in enumerate(args):
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "[":
            bracket_depth += 1
        elif ch == "]" and bracket_depth:
            bracket_depth -= 1
        elif ch == "(":
            paren_depth += 1
        elif ch == ")" and paren_depth:
            paren_depth -= 1
        elif ch == "," and bracket_depth == 0 and paren_depth == 0:
            parts.append(args[start:idx].strip())
            start = idx + 1
    tail = args[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def parse_signature(line: str) -> tuple[str, str, int] | None:
    match = PSEUDO_NAME_RE.match(line)
    if match is None:
        return None
    args_open = line.find("(", len(match.group(1)))
    if args_open < 0:
        return None
    args_close = find_matching_close(line, args_open)
    if args_close is None:
        raise ValueError(f"unterminated argument list: {line}")

    args_text = line[args_open + 1 : args_close].strip()
    arg_count = 0 if not args_text else len(split_top_level_args(args_text))

    signature = line.strip()
    attrs = ""
    stripped = signature.rstrip()
    if stripped.endswith(")"):
        attr_open = matching_open(stripped, len(stripped) - 1)
        if attr_open is not None and attr_open > args_close:
            has_attr_separator = attr_open > 0 and stripped[attr_open - 1].isspace()
            before_attr = stripped[:attr_open].rstrip()
            if has_attr_separator and before_attr:
                attrs = stripped[attr_open + 1 : -1].strip()
                signature = before_attr
    return signature, attrs, arg_count


def scan_upstream(sys_linux_dir: Path, syzkaller_root: Path) -> dict[str, UpstreamPseudo]:
    pseudos: dict[str, UpstreamPseudo] = {}
    for path in sorted(sys_linux_dir.glob("*.txt")):
        rel = path.relative_to(syzkaller_root)
        with path.open("r", encoding="utf-8") as f:
            for lineno, raw in enumerate(f, start=1):
                line = raw.strip()
                match = PSEUDO_NAME_RE.match(line)
                if match is None:
                    continue
                parsed = parse_signature(line)
                if parsed is None:
                    continue
                signature, attrs, argc = parsed
                name = match.group(1)
                location = f"{rel}:{lineno}"
                if name in pseudos:
                    prev = pseudos[name]
                    raise ValueError(
                        f"duplicate upstream pseudo {name}: {prev.file} and {location}"
                    )
                pseudos[name] = UpstreamPseudo(
                    name=name,
                    file=location,
                    signature=signature,
                    attrs=attrs,
                    arg_count=argc,
                )
    return pseudos


def scan_refuzz_meta(meta_path: Path) -> dict[str, RefuzzPseudo]:
    pseudos: dict[str, RefuzzPseudo] = {}
    with meta_path.open("r", encoding="utf-8") as f:
        for raw in f:
            match = REFUZZ_META_RE.search(raw)
            if match is None:
                continue
            name = match.group("name")
            if name in pseudos:
                raise ValueError(f"duplicate reFuzz pseudo metadata: {name}")
            pseudos[name] = RefuzzPseudo(
                name=name,
                arg_count=int(match.group("argc")),
                domain=strip_namespace(match.group("domain")),
                impl=strip_namespace(match.group("impl")),
                cap_mask=" ".join(match.group("cap").split()),
                concurrency=strip_namespace(match.group("concurrency")),
            )
    return pseudos


def read_name_file(path: Path) -> set[str]:
    if not path.exists():
        return set()
    names: set[str] = set()
    with path.open("r", encoding="utf-8") as f:
        for raw in f:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            names.add(line)
    return names


def first_batch_candidates(
    upstream: dict[str, UpstreamPseudo],
    refuzz: dict[str, RefuzzPseudo],
) -> set[str]:
    return {
        name
        for name in upstream
        if is_first_batch_helper(name)
        and (meta := refuzz.get(name)) is not None
        and meta.impl == "Native"
    }


def seed_candidates(
    policy: str,
    candidate_path: Path,
    legacy_allowlist_path: Path,
    proof_status_path: Path,
    upstream: dict[str, UpstreamPseudo],
    refuzz: dict[str, RefuzzPseudo],
) -> tuple[set[str], list[str], str]:
    """Resolve the candidate set per policy.

    Evidence-driven model (2026-05-20+): proof_status.csv is the single
    source of truth for which pseudos are candidates. Every pseudo with
    a proof_status row is a candidate; manifest writes the allowlist file
    purely as a derived view. The fallback chain tolerates older repos
    missing proof_status.csv.
    """
    warnings: list[str] = []
    source = policy
    if policy == "proof-status-or-existing-candidate-or-allowlist-or-first-batch":
        if proof_status_path.exists():
            policy = "proof-status"
            source = "proof-status"
        elif candidate_path.exists():
            policy = "existing-candidate"
            source = "existing-candidate"
        elif legacy_allowlist_path.exists():
            policy = "existing-allowlist"
            source = "existing-allowlist"
        else:
            policy = "first-batch-helpers"
            source = "first-batch-helpers"
    elif policy == "existing-candidate-or-allowlist-or-first-batch":
        # Legacy fallback chain (pre-evidence-driven). Kept for explicit
        # benchmark-reproducibility callers that need to skip proof_status.
        if candidate_path.exists():
            policy = "existing-candidate"
            source = "existing-candidate"
        elif legacy_allowlist_path.exists():
            policy = "existing-allowlist"
            source = "existing-allowlist"
        else:
            policy = "first-batch-helpers"
            source = "first-batch-helpers"

    if policy == "proof-status":
        candidates = set(read_proof_status(proof_status_path).keys())
    elif policy == "existing-candidate":
        candidates = read_name_file(candidate_path)
    elif policy == "existing-allowlist":
        candidates = read_name_file(legacy_allowlist_path)
    elif policy == "first-batch-helpers":
        candidates = first_batch_candidates(upstream, refuzz)
    elif policy == "empty":
        candidates = set()
    else:
        raise ValueError(f"unknown candidate seed policy: {policy}")

    unknown = sorted(name for name in candidates if name not in upstream)
    if unknown:
        warnings.append(
            "candidate entries not present in upstream sys/linux/*.txt: "
            + ", ".join(unknown)
        )
    candidates = {name for name in candidates if name in upstream}
    return candidates, warnings, source


def normalize_status_value(value: str | None) -> str:
    status = (value or "").strip().lower()
    if status == "":
        return "pending"
    return status


def normalize_verdict(value: str | None) -> str:
    verdict = (value or "").strip().lower()
    if verdict == "":
        return "pending"
    return verdict


def read_proof_status(path: Path) -> dict[str, ProofRecord]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            return {}
        if "name" not in reader.fieldnames:
            raise ValueError(f"{path} is missing proof status column: name")
        records: dict[str, ProofRecord] = {}
        for row in reader:
            name = (row.get("name") or "").strip()
            if not name:
                continue
            if name in records:
                raise ValueError(f"duplicate proof status row: {name}")
            records[name] = ProofRecord(
                name=name,
                signature_status=normalize_status_value(row.get("signature_status")),
                layout_status=normalize_status_value(row.get("layout_status")),
                trace_status=normalize_status_value(row.get("trace_status")),
                result_status=normalize_status_value(row.get("result_status")),
                oracle_err_mismatch=(row.get("oracle_err_mismatch") or "").strip(),
                oracle_actionable_err_mismatch=(
                    row.get("oracle_actionable_err_mismatch") or ""
                ).strip(),
                oracle_kcov_jaccard=(row.get("oracle_kcov_jaccard") or "").strip(),
                oracle_kcov_digest_match=(
                    row.get("oracle_kcov_digest_match") or ""
                ).strip(),
                oracle_first_seen=(row.get("oracle_first_seen") or "").strip(),
                analysis=(row.get("analysis") or "").strip(),
                review_verdict=normalize_verdict(row.get("review_verdict")),
                notes=(row.get("notes") or "").strip(),
            )
    return records


def proof_record_for(name: str, records: dict[str, ProofRecord]) -> ProofRecord:
    return records.get(name, ProofRecord(name=name))


def summarize_proof(candidate: bool, record: ProofRecord | None) -> str:
    if not candidate:
        return "n/a"
    record = record or ProofRecord(name="")
    verdict = record.review_verdict
    if verdict not in REVIEW_VERDICTS:
        return "invalid"
    if verdict == "allow":
        return "accepted"
    if verdict == "disable":
        return "rejected"
    if verdict == "port":
        return "port"
    return "pending"


def decide(
    name: str,
    upstream: UpstreamPseudo,
    refuzz: RefuzzPseudo | None,
    candidates: set[str],
    proof: ProofRecord | None,
) -> tuple[str, str]:
    candidate = name in candidates
    if refuzz is None:
        if candidate:
            return "port", "invalid_candidate_missing_refuzz"
        return "port", "port_missing_refuzz"
    if refuzz.impl != "Native":
        if candidate:
            return "port", f"invalid_candidate_refuzz_{refuzz.impl.lower()}"
        return "port", f"port_refuzz_{refuzz.impl.lower()}"
    if upstream.arg_count != refuzz.arg_count:
        if candidate:
            return "disable", "invalid_candidate_arg_count_mismatch"
        return "disable", "arg_count_mismatch"

    if not candidate:
        return "disable", "disabled"

    proof_status = summarize_proof(candidate, proof)
    if proof_status == "accepted":
        return "allow", "allowed"
    if proof_status == "rejected":
        return "disable", "review_rejected"
    if proof_status == "port":
        return "port", "review_port"
    if proof_status == "invalid":
        return "disable", "review_invalid"
    return "disable", "review_pending"


def build_rows(
    upstream: dict[str, UpstreamPseudo],
    refuzz: dict[str, RefuzzPseudo],
    candidates: set[str],
    proof_records: dict[str, ProofRecord],
) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for name in sorted(upstream):
        up = upstream[name]
        rz = refuzz.get(name)
        candidate = name in candidates
        proof = proof_record_for(name, proof_records) if candidate else None
        proof_status = summarize_proof(candidate, proof)
        decision, status = decide(name, up, rz, candidates, proof)
        rows.append(
            {
                "name": name,
                "upstream_file": up.file,
                "upstream_signature": up.signature,
                "upstream_attrs": up.attrs,
                "upstream_arg_count": str(up.arg_count),
                "refuzz_present": "true" if rz is not None else "false",
                "refuzz_arg_count": "" if rz is None else str(rz.arg_count),
                "refuzz_domain": "" if rz is None else rz.domain,
                "refuzz_impl_kind": "" if rz is None else rz.impl,
                "cap_mask": "" if rz is None else rz.cap_mask,
                "concurrency": "" if rz is None else rz.concurrency,
                "candidate": "true" if candidate else "false",
                "signature_status": "" if proof is None else proof.signature_status,
                "layout_status": "" if proof is None else proof.layout_status,
                "trace_status": "" if proof is None else proof.trace_status,
                "result_status": "" if proof is None else proof.result_status,
                "oracle_err_mismatch": "" if proof is None else proof.oracle_err_mismatch,
                "oracle_actionable_err_mismatch": (
                    "" if proof is None else proof.oracle_actionable_err_mismatch
                ),
                "oracle_kcov_jaccard": "" if proof is None else proof.oracle_kcov_jaccard,
                "oracle_kcov_digest_match": (
                    "" if proof is None else proof.oracle_kcov_digest_match
                ),
                "oracle_first_seen": "" if proof is None else proof.oracle_first_seen,
                "analysis": "" if proof is None else proof.analysis,
                "review_verdict": "" if proof is None else proof.review_verdict,
                "proof_status": proof_status,
                "decision": decision,
                "status": status,
            }
        )
    return rows


def write_manifest(path: Path, rows: Iterable[dict[str, str]]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=MANIFEST_FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_name_file(path: Path, names: Iterable[str], header: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    sorted_names = sorted(names)
    with path.open("w", encoding="utf-8") as f:
        for line in header:
            f.write("# ")
            f.write(line)
            f.write("\n")
        for name in sorted_names:
            f.write(name)
            f.write("\n")


def write_candidate_allowlist(path: Path, names: Iterable[str], source: str) -> None:
    names = set(names)
    write_name_file(
        path,
        names,
        [
            "Candidate pseudo syscall allowlist for proof work.",
            "These entries are NOT automatically enabled for fair benchmark runs.",
            "One exact upstream syz_* name per line; comments are allowed.",
            "Regenerate manifest with scripts/generate_pseudo_manifest.py.",
            f"seed_policy={source}",
            f"candidate_count={len(names)}",
        ],
    )


def write_allowlist(path: Path, names: Iterable[str]) -> None:
    names = set(names)
    write_name_file(
        path,
        names,
        [
            "Reviewed reFuzz/syzkaller pseudo syscall allowlist.",
            "Only entries with review_verdict=allow are enabled for fair benchmark runs.",
            "One exact upstream syz_* name per line; comments are allowed.",
            "Regenerate manifest with scripts/generate_pseudo_manifest.py.",
            f"allowed_count={len(names)}",
        ],
    )


def write_disablelist(path: Path, names: Iterable[str]) -> None:
    names = set(names)
    write_name_file(
        path,
        names,
        [
            "Exact upstream syz_* names disabled for syzkaller fairness runs.",
            "Generated as all upstream syz_* entries minus pseudo_allowlist.txt.",
            "One exact upstream syz_* name per line.",
            f"disabled_count={len(names)}",
        ],
    )


def write_proof_status(path: Path,
                       candidates: set[str],
                       records: dict[str, ProofRecord]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=PROOF_FIELDS, lineterminator="\n")
        writer.writeheader()
        for name in sorted(candidates):
            record = proof_record_for(name, records)
            writer.writerow(
                {
                    "name": name,
                    "signature_status": record.signature_status,
                    "layout_status": record.layout_status,
                    "trace_status": record.trace_status,
                    "result_status": record.result_status,
                    "oracle_err_mismatch": record.oracle_err_mismatch,
                    "oracle_actionable_err_mismatch": record.oracle_actionable_err_mismatch,
                    "oracle_kcov_jaccard": record.oracle_kcov_jaccard,
                    "oracle_kcov_digest_match": record.oracle_kcov_digest_match,
                    "oracle_first_seen": record.oracle_first_seen,
                    "analysis": record.analysis,
                    "review_verdict": record.review_verdict,
                    "notes": record.notes,
                }
            )


def parse_args() -> argparse.Namespace:
    root = repo_root()
    parser = argparse.ArgumentParser(
        description="Generate pseudo manifest, proof status, allowlist, and disablelist"
    )
    parser.add_argument(
        "--syzkaller-root",
        type=Path,
        default=root.parent,
        help="upstream syzkaller root (default: parent of reFuzz repo)",
    )
    parser.add_argument(
        "--sys-linux-dir",
        type=Path,
        default=None,
        help="override upstream sys/linux directory",
    )
    parser.add_argument(
        "--refuzz-meta",
        type=Path,
        default=root / DEFAULT_META,
        help="reFuzz generated pseudo_meta.gen.hpp",
    )
    parser.add_argument(
        "--manifest-out",
        type=Path,
        default=root / DEFAULT_MANIFEST,
        help="output pseudo manifest CSV",
    )
    parser.add_argument(
        "--allowlist-out",
        type=Path,
        default=root / DEFAULT_ALLOWLIST,
        help="output proof-backed pseudo allowlist",
    )
    parser.add_argument(
        "--candidate-allowlist-out",
        type=Path,
        default=root / DEFAULT_CANDIDATE_ALLOWLIST,
        help="output candidate pseudo allowlist",
    )
    parser.add_argument(
        "--disablelist-out",
        type=Path,
        default=root / DEFAULT_DISABLELIST,
        help="output exact syzkaller disable_syscalls list",
    )
    parser.add_argument(
        "--proof-status",
        type=Path,
        default=root / DEFAULT_PROOF_STATUS,
        help="input/output proof status CSV",
    )
    parser.add_argument(
        "--candidate-seed-policy",
        choices=(
            "proof-status-or-existing-candidate-or-allowlist-or-first-batch",
            "proof-status",
            "existing-candidate-or-allowlist-or-first-batch",
            "existing-candidate",
            "existing-allowlist",
            "first-batch-helpers",
            "empty",
        ),
        default="proof-status-or-existing-candidate-or-allowlist-or-first-batch",
        help=(
            "candidate seed policy: preserve an existing candidate list when present, "
            "otherwise convert an existing allowlist into candidates, otherwise seed "
            "from first-batch helper pseudos"
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    syzkaller_root = args.syzkaller_root.resolve()
    sys_linux_dir = (
        args.sys_linux_dir.resolve()
        if args.sys_linux_dir is not None
        else syzkaller_root / "sys/linux"
    )
    meta_path = args.refuzz_meta.resolve()

    if not sys_linux_dir.is_dir():
        print(f"error: missing sys/linux dir: {sys_linux_dir}", file=sys.stderr)
        return 2
    if not meta_path.is_file():
        print(f"error: missing reFuzz pseudo metadata: {meta_path}", file=sys.stderr)
        return 2

    upstream = scan_upstream(sys_linux_dir, syzkaller_root)
    refuzz = scan_refuzz_meta(meta_path)
    candidates, warnings, source = seed_candidates(
        args.candidate_seed_policy,
        args.candidate_allowlist_out,
        args.allowlist_out,
        args.proof_status,
        upstream,
        refuzz,
    )
    proof_records = read_proof_status(args.proof_status)
    rows = build_rows(upstream, refuzz, candidates, proof_records)

    for warning in warnings:
        print(f"warning: {warning}", file=sys.stderr)

    allowed = {row["name"] for row in rows if row["decision"] == "allow"}
    disabled_for_syzkaller = sorted(set(upstream) - allowed)
    write_candidate_allowlist(args.candidate_allowlist_out, candidates, source)
    write_proof_status(args.proof_status, candidates, proof_records)
    write_allowlist(args.allowlist_out, allowed)
    write_disablelist(args.disablelist_out, disabled_for_syzkaller)
    manifest_hash = write_manifest(args.manifest_out, rows)

    allowed_count = len(allowed)
    disabled_count = sum(1 for row in rows if row["decision"] == "disable")
    port_count = sum(1 for row in rows if row["decision"] == "port")
    review_pending_count = sum(1 for row in rows if row["proof_status"] == "pending")
    review_accepted_count = sum(1 for row in rows if row["proof_status"] == "accepted")
    invalid_count = sum(
        1
        for row in rows
        if row["status"].startswith("invalid_") or row["proof_status"] == "invalid"
    )

    print(f"upstream_pseudo_count={len(upstream)}")
    print(f"refuzz_pseudo_count={len(refuzz)}")
    print(f"candidate_count={len(candidates)}")
    print(f"allowed_count={allowed_count}")
    print(f"disabled_count={disabled_count}")
    print(f"syzkaller_disable_count={len(disabled_for_syzkaller)}")
    print(f"port_count={port_count}")
    print(f"review_pending_count={review_pending_count}")
    print(f"review_accepted_count={review_accepted_count}")
    print(f"invalid_count={invalid_count}")
    print(f"manifest={args.manifest_out}")
    print(f"candidate_allowlist={args.candidate_allowlist_out}")
    print(f"allowlist={args.allowlist_out}")
    print(f"disablelist={args.disablelist_out}")
    print(f"proof_status={args.proof_status}")
    print(f"manifest_sha256={manifest_hash}")
    return 1 if invalid_count else 0


if __name__ == "__main__":
    raise SystemExit(main())

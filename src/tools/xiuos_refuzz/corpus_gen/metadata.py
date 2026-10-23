"""Build seed JSON files with full metadata."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Iterable

from worker_abi import ApiId, ProgramCall

from .canonical import canonical_key
from .enumerate import GeneratedProgram


GENERATOR_VERSION = "bounded_lifecycle_v1"


def _api_name(api_id: int, api_id_to_name: dict[int, str]) -> str:
    return api_id_to_name[int(api_id)]


def _stable_hash(calls: tuple[ProgramCall, ...]) -> str:
    key = canonical_key(calls)
    payload = json.dumps(key, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:8]


def build_api_id_to_name() -> dict[int, str]:
    return {int(member): member.name for member in ApiId}


def seed_to_dict(
    program: GeneratedProgram,
    *,
    suite_name: str,
    seq: int,
    api_id_to_name: dict[int, str],
    descriptor_argc: dict[str, int],
) -> tuple[str, dict]:
    digest = _stable_hash(program.calls)
    rule_slug = program.source_rule.replace(".", "_")
    name = f"gen_{rule_slug}_{seq:03d}_{digest}"

    calls_payload = []
    for call in program.calls:
        api_name = _api_name(int(call.api_id), api_id_to_name)
        expected_argc = descriptor_argc[api_name]
        args = list(int(a) for a in call.args[:expected_argc])
        calls_payload.append({"api": api_name, "args": args})

    return name, {
        "name": name,
        "suite": suite_name,
        "source": f"generated_{GENERATOR_VERSION}",
        "source_rule": program.source_rule,
        "purpose": "corpus_seed",
        "expected_status": "OK",
        "expected_min_calls": len(program.calls),
        "calls": calls_payload,
    }


def write_seed_files(
    programs: Iterable[GeneratedProgram],
    out_root: Path,
    *,
    suite_name: str,
    descriptor_argc: dict[str, int],
) -> list[tuple[Path, dict]]:
    api_id_to_name = build_api_id_to_name()
    out_root.mkdir(parents=True, exist_ok=True)
    per_rule_seq: dict[str, int] = {}
    written: list[tuple[Path, dict]] = []
    for program in programs:
        per_rule_seq[program.source_rule] = per_rule_seq.get(program.source_rule, 0) + 1
        seq = per_rule_seq[program.source_rule]
        name, payload = seed_to_dict(
            program,
            suite_name=suite_name,
            seq=seq,
            api_id_to_name=api_id_to_name,
            descriptor_argc=descriptor_argc,
        )
        rule_dir = out_root / program.source_rule.replace(".", "/")
        rule_dir.mkdir(parents=True, exist_ok=True)
        path = rule_dir / f"{seq:03d}_{name.split('_')[-1]}.json"
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        written.append((path, payload))
    return written


def write_manifest(
    out_root: Path,
    *,
    descriptor_path: Path,
    descriptor_digest: str,
    config_dict: dict,
    written: list[tuple[Path, dict]],
) -> None:
    counts: dict[str, int] = {}
    for _, payload in written:
        counts[payload["source_rule"]] = counts.get(payload["source_rule"], 0) + 1

    manifest = {
        "generator_version": GENERATOR_VERSION,
        "descriptor": str(descriptor_path.name),
        "descriptor_sha256": descriptor_digest,
        "config": config_dict,
        "total_seeds": len(written),
        "per_rule_counts": counts,
    }
    (out_root / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def descriptor_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

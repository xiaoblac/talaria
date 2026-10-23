#!/usr/bin/env python3
# Copyright 2026 reFuzz project author -------youngkk.
#
# Reproducible snapshot of the current variant -> candidate-handler analysis.
import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from resolve.candidates import build_candidate_run
from resolve.dispatch import ENABLED_RESOLVER_PASSES, RESOLVER_PASSES, _FOLLOW_BRIDGES
from resolve.fixpoint import DEFAULT_MAX_ROUNDS, _TYPE_UNION_PROVIDER_STRUCTS


SCHEMA_VERSION = 1
DEFAULT_SH = "run/seed_horizon"


def csv(values):
    values = sorted(str(value) for value in values if value not in (None, "", "-"))
    return ",".join(values) if values else "-"


def json_cell(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def file_digest(path, count_lines=True):
    digest = hashlib.sha256()
    size = 0
    lines = 0
    last = b""
    with path.open("rb") as source:
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
            if count_lines:
                lines += chunk.count(b"\n")
                last = chunk[-1:]
    if count_lines and size and last != b"\n":
        lines += 1
    return digest.hexdigest(), size, lines if count_lines else "-"


def git_head(root):
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
    return proc.stdout.strip() if proc.returncode == 0 else "unknown"


def anchor_ops(run, rows):
    return {
        run.reg_rows[row][2]
        for row in rows
        if 0 <= row < len(run.reg_rows) and run.reg_rows[row][2] not in (None, "", "-")
    }


def write_candidates(path, run):
    candidate_pairs = 0
    with path.open("w") as out:
        out.write("#variant\tbase\tintent\thandler\tcandidate_count\tresolver_pass\t"
                  "fail_stage\tfail_class\tconfidence\n")
        for name in sorted(run.records):
            record = run.records[name]
            handlers = sorted(record.leaves) or ["-"]
            candidate_pairs += len(record.leaves)
            for handler in handlers:
                out.write("\t".join([
                    name,
                    record.spec.base,
                    record.spec.intent,
                    handler,
                    str(len(record.leaves)),
                    record.resolver_pass,
                    record.fail_stage,
                    record.fail_class,
                    record.confidence,
                ]) + "\n")
    return candidate_pairs


def write_provenance(path, run):
    with path.open("w") as out:
        out.write("#variant\thandler\tresolver_pass\tresources\tproduced_resources\t"
                  "specific_resources\tdiscriminant\tanchor_rows\tanchor_ops\tentry_handlers\t"
                  "trace\tdemands\n")
        for name in sorted(run.records):
            record = run.records[name]
            for handler in sorted(record.leaves):
                trace = [list(edge) if isinstance(edge, tuple) else edge for edge in record.trace]
                trace.sort(key=json_cell)
                demands = [list(demand) for demand in sorted(record.demands)]
                out.write("\t".join([
                    name,
                    handler,
                    record.resolver_pass,
                    csv(record.spec.resources),
                    csv(record.spec.produced_resources),
                    csv(record.spec.specific_resources),
                    str(record.spec.discriminant) if record.spec.discriminant is not None else "-",
                    csv(record.anchor_rows),
                    csv(anchor_ops(run, record.anchor_rows)),
                    csv(record.entry_handlers),
                    json_cell(trace),
                    json_cell(demands),
                ]) + "\n")


def write_pass_config(path, run, candidate_pairs, root):
    pass_counts = collections.Counter(record.resolver_pass for record in run.records.values())
    config = {
        "schema_version": SCHEMA_VERSION,
        "git_head": git_head(root),
        "resolver": {
            "passes": [
                {
                    "name": name,
                    "resource_rule": resource_rule,
                    "inline_leaf": inline_leaf,
                    "field_bridge": field_bridge,
                    "enabled": name in ENABLED_RESOLVER_PASSES,
                }
                for name, resource_rule, inline_leaf, field_bridge in RESOLVER_PASSES
            ],
            "follow_bridges": _FOLLOW_BRIDGES,
            "environment": {
                "REFUZZ_NO_BRIDGE": os.environ.get("REFUZZ_NO_BRIDGE"),
                "REFUZZ_RESOLVER_PASSES": os.environ.get("REFUZZ_RESOLVER_PASSES"),
            },
        },
        "fixpoint": {
            "default_max_rounds": DEFAULT_MAX_ROUNDS,
            "observed_rounds": run.rounds,
            "type_union_provider_structs": list(_TYPE_UNION_PROVIDER_STRUCTS),
            "negative_cache": sorted(run.neg_cache),
            "per_round": [
                [
                    {"struct": struct, "result": result, "field_count": field_count}
                    for struct, result, field_count in round_results
                ]
                for round_results in run.per_round
            ],
        },
        "population": {
            "variants": len(run.records),
            "candidate_nonempty": sum(bool(record.leaves) for record in run.records.values()),
            "candidate_pairs": candidate_pairs,
            "resolver_pass_counts": dict(sorted(pass_counts.items())),
        },
        "provenance_scope": (
            "resolver_pass is exact for the winning current pass; trace is the pass-wide union and is not "
            "yet a per-leaf predecessor chain"
        ),
    }
    with path.open("w") as out:
        json.dump(config, out, indent=2, sort_keys=True)
        out.write("\n")


def write_manifest(path, root, sh, outputs):
    artifacts = [
        ("input", Path(sh) / "horizon_model.json", True),
        ("input", Path(sh) / "variant_grammar.jsonl", True),
        ("input", Path(sh) / "kernel_linked" / "batches.tsv", True),
        ("input", Path(sh) / "kernel_facts_linked" / "reg.tsv", True),
        ("input", Path(sh) / "kernel_facts_linked" / "fields.tsv", True),
        ("input", Path(sh) / "kernel_facts_linked" / "cmd.tsv", True),
        ("input", Path(sh) / "function_block_map.tsv", True),
        ("binary", Path(sh) / "ir_defuse", False),
        ("source", Path("scripts/seed_horizon/extract/ir_defuse.cpp"), True),
        ("source", Path("scripts/seed_horizon/model/schema.py"), True),
        ("source", Path("scripts/seed_horizon/model/generated.py"), True),
        ("source", Path("scripts/seed_horizon/model/variant.py"), True),
        ("source", Path("scripts/seed_horizon/provenance/cgroup.py"), True),
        ("source", Path("scripts/seed_horizon/provenance/context.py"), True),
        ("source", Path("scripts/seed_horizon/provenance/devnode.py"), True),
        ("source", Path("scripts/seed_horizon/provenance/fd.py"), True),
        ("source", Path("scripts/seed_horizon/provenance/socket.py"), True),
        ("source", Path("scripts/seed_horizon/resolve/candidates.py"), True),
        ("source", Path("scripts/seed_horizon/resolve/dispatch.py"), True),
        ("source", Path("scripts/seed_horizon/resolve/fixpoint.py"), True),
        ("source", Path("scripts/seed_horizon/probes/baseline_snapshot.py"), True),
    ]
    artifacts.extend(("output", output.relative_to(root), True) for output in outputs)
    with path.open("w") as out:
        out.write("#role\tpath\tsha256\tbytes\tlines\n")
        for role, relative, count_lines in artifacts:
            artifact = relative if relative.is_absolute() else root / relative
            if not artifact.exists():
                raise FileNotFoundError(f"missing baseline artifact: {artifact}")
            digest, size, lines = file_digest(artifact, count_lines)
            try:
                shown = artifact.relative_to(root)
            except ValueError:
                shown = artifact
            out.write(f"{role}\t{shown}\t{digest}\t{size}\t{lines}\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--sh", default=DEFAULT_SH)
    args = parser.parse_args()

    root = Path(args.root).resolve()
    sh = Path(args.sh)
    if not sh.is_absolute():
        sh = root / sh
    run = build_candidate_run(str(sh), str(root))

    candidates = sh / "baseline_candidates.tsv"
    provenance = sh / "baseline_candidate_provenance.tsv"
    pass_config = sh / "baseline_pass_config.json"
    manifest = sh / "baseline_manifest.tsv"

    candidate_pairs = write_candidates(candidates, run)
    write_provenance(provenance, run)
    write_pass_config(pass_config, run, candidate_pairs, root)
    write_manifest(manifest, root, sh, [candidates, provenance, pass_config])

    print(f"baseline variants={len(run.records)} candidate_pairs={candidate_pairs}")
    print(f"wrote {candidates}")
    print(f"wrote {provenance}")
    print(f"wrote {pass_config}")
    print(f"wrote {manifest}")


if __name__ == "__main__":
    main()

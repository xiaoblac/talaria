#!/usr/bin/env python3
"""Generate XiUOS reFuzz seed corpus from a descriptor.

Strategy: 9 source-rule classes drive bounded lifecycle DFS + canonical
dedupe + targeted parameter perturbation. Output is fully deterministic for
a given descriptor + depth knobs (the --seed flag is reserved for future
stochastic sampling and currently has no effect).

See docs/xiuos-refuzz/050_corpus_generation_method.md for the method.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

TOOL_DIR = Path(__file__).resolve().parent
if str(TOOL_DIR) not in sys.path:
    sys.path.insert(0, str(TOOL_DIR))

from corpus import DEFAULT_DESCRIPTOR, DEFAULT_GENERATED_DIR, load_descriptor

from corpus_gen.enumerate import GenConfig, enumerate_all
from corpus_gen.metadata import (
    descriptor_sha256,
    write_manifest,
    write_seed_files,
)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--descriptor", type=Path, default=DEFAULT_DESCRIPTOR,
                   help="descriptor JSON path")
    p.add_argument("--out", type=Path, default=DEFAULT_GENERATED_DIR,
                   help="output root for generated seeds")
    p.add_argument("--max-depth-single", type=int, default=6,
                   help="DFS depth for single-slot valid lifecycle (default 6)")
    p.add_argument("--max-depth-interleave", type=int, default=4,
                   help="DFS depth for two-slot same-object interleave (default 4)")
    p.add_argument("--max-depth-cross-object", type=int, default=4,
                   help="DFS depth for sem-mutex cross-object interleave (default 4)")
    p.add_argument("--seed", type=int, default=42,
                   help="reserved for future stochastic sampling; current enumeration "
                        "is fully deterministic")
    p.add_argument("--dry-list", action="store_true",
                   help="print rule-by-rule counts only; do not write files")
    p.add_argument("--clean", action="store_true",
                   help="remove --out before writing")
    return p.parse_args()


def main() -> int:
    args = parse_args()

    descriptor = load_descriptor(args.descriptor)
    config = GenConfig(
        max_depth_valid_single=args.max_depth_single,
        max_depth_interleave_two_slots=args.max_depth_interleave,
        max_depth_cross_object=args.max_depth_cross_object,
    )

    programs = enumerate_all(descriptor, config)

    counts: dict[str, int] = {}
    for prog in programs:
        counts[prog.source_rule] = counts.get(prog.source_rule, 0) + 1

    print(f"GENERATED {len(programs)} seeds across {len(counts)} rules")
    for rule, count in sorted(counts.items()):
        print(f"  {count:5d}  {rule}")

    if args.dry_list:
        return 0

    if args.clean and args.out.exists():
        shutil.rmtree(args.out)

    descriptor_argc = {name: spec.argc for name, spec in descriptor.apis.items()}
    written = write_seed_files(
        programs,
        args.out,
        suite_name=descriptor.suite.name,
        descriptor_argc=descriptor_argc,
    )

    write_manifest(
        args.out,
        descriptor_path=args.descriptor,
        descriptor_digest=descriptor_sha256(args.descriptor),
        config_dict={
            "max_depth_valid_single": config.max_depth_valid_single,
            "max_depth_interleave_two_slots": config.max_depth_interleave_two_slots,
            "max_depth_cross_object": config.max_depth_cross_object,
            "raw_timeout": config.raw_timeout,
            "raw_value": config.raw_value,
            "invalid_slots": list(config.invalid_slots),
            "canonical_timeout": config.canonical_timeout,
            "canonical_value": config.canonical_value,
            "rng_seed": args.seed,
        },
        written=written,
    )

    print(f"WROTE {len(written)} seed files under {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

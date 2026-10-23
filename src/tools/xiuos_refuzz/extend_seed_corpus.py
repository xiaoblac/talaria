#!/usr/bin/env python3
"""Generate **additive** XiUOS seed corpus extensions.

`generate_seed_corpus.py` produces the canonical corpus under
`corpus/generated/`. This script runs **in parallel** and writes ONLY new
corpus classes registered in `corpus_gen/extensions.EXTENSION_CLASSES`.

每个 corpus 类一个独立输出目录 (`corpus/generated_<slug>/`),原 generator 和
其它扩展类互不干扰 — 重新跑 `generate_seed_corpus.py` 仍产出 byte-identical
原 corpus;单独跑 `--class three_slots` 只重生 B1 目录。

XiuosFuzzSession::Bootstrap 用 recursive_directory_iterator + shuffle,自动
覆盖所有 sibling 目录,操作侧零改动。

详见 memory `feedback-expand-bug-coverage-via-corpus` 和
`docs/agentic-fuzz/bug_hunting/02_corpus_plan.md`.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

TOOL_DIR = Path(__file__).resolve().parent
if str(TOOL_DIR) not in sys.path:
    sys.path.insert(0, str(TOOL_DIR))

from corpus import DEFAULT_DESCRIPTOR, load_descriptor

from corpus_gen.enumerate import GenConfig
from corpus_gen.extensions import EXTENSION_CLASSES, ExtConfig
from corpus_gen.metadata import (
    descriptor_sha256,
    write_manifest,
    write_seed_files,
)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--descriptor", type=Path, default=DEFAULT_DESCRIPTOR)
    p.add_argument(
        "--classes", nargs="+",
        choices=list(EXTENSION_CLASSES) + ["all"],
        default=["all"],
        help="which extension class(es) to generate (default: all)")
    p.add_argument(
        # [Stage 3 规范化] generated_<slug>/ 是可重生缓存 → 落 gitignored run/xiuos/corpus/
        "--corpus-root", type=Path,
        default=TOOL_DIR.parent.parent / "run" / "xiuos" / "corpus",
        help="parent of generated_<slug>/ output dirs")
    p.add_argument("--max-depth-three-slots", type=int, default=4)
    p.add_argument("--max-depth-cross-pair",  type=int, default=4)
    p.add_argument("--clean", action="store_true",
                   help="rm -rf the per-class output dir before writing")
    p.add_argument("--dry-list", action="store_true",
                   help="print per-rule counts; don't write files")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    descriptor = load_descriptor(args.descriptor)
    base_config = GenConfig()
    ext_config  = ExtConfig(
        max_depth_three_slots=args.max_depth_three_slots,
        max_depth_cross_pair=args.max_depth_cross_pair,
    )

    classes = list(EXTENSION_CLASSES) if "all" in args.classes else args.classes
    total = 0
    for slug in classes:
        enumerator = EXTENSION_CLASSES[slug]
        programs = enumerator(descriptor, base_config, ext_config)
        counts: dict[str, int] = {}
        for prog in programs:
            counts[prog.source_rule] = counts.get(prog.source_rule, 0) + 1
        print(f"[{slug}] {len(programs)} seeds across {len(counts)} rules")
        for rule, count in sorted(counts.items()):
            print(f"  {count:5d}  {rule}")

        if args.dry_list:
            total += len(programs)
            continue

        out_dir = args.corpus_root / f"generated_{slug}"
        if args.clean and out_dir.exists():
            shutil.rmtree(out_dir)

        descriptor_argc = {name: spec.argc
                           for name, spec in descriptor.apis.items()}
        written = write_seed_files(
            programs, out_dir,
            suite_name=descriptor.suite.name,
            descriptor_argc=descriptor_argc,
        )
        write_manifest(
            out_dir,
            descriptor_path=args.descriptor,
            descriptor_digest=descriptor_sha256(args.descriptor),
            config_dict={
                "generator": "extend_seed_corpus.py",
                "class": slug,
                "max_depth_three_slots": ext_config.max_depth_three_slots,
                "max_depth_cross_pair":  ext_config.max_depth_cross_pair,
            },
            written=written,
        )
        print(f"[{slug}] wrote {len(written)} files under {out_dir}")
        total += len(written)

    print(f"\nTOTAL {total} seeds across {len(classes)} class(es)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

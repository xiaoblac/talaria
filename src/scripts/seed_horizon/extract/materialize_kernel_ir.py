#!/usr/bin/env python3
# Copyright 2026 reFuzz project author -------youngkk.
#
# Materialize LLVM IR from kbuild .o.cmd commands recorded in the current
# build-kasan-clang tree. Outputs are written under run/seed_horizon/kernel_ir
# by default, so the kernel build directory remains read-only for this step.

import argparse
import csv
import concurrent.futures
from pathlib import Path
import re
import shlex
import subprocess
import sys


DEFAULT_BUILD = "/workspace/syzkaller/kernel/build-kasan-clang"
DEFAULT_MANIFEST = "run/seed_horizon/kernel_tu_manifest.tsv"
DEFAULT_OUT_DIR = "run/seed_horizon/kernel_ir"
DEFAULT_LOG = "run/seed_horizon/kernel_ir_materialize.tsv"


def hidden_cmd_for_object(build, object_rel):
    obj = build / object_rel
    return obj.with_name("." + obj.name[:-2] + ".o.cmd")


def read_savedcmd(cmd_path, object_rel):
    prefix = f"savedcmd_{object_rel} :="
    with cmd_path.open(errors="replace") as f:
        for line in f:
            if line.startswith(prefix):
                return line.split(":=", 1)[1].strip()
    return ""


def transform_to_ir_cmd(savedcmd, out_path, fmt):
    args = shlex.split(savedcmd)
    out = []
    skip_next = False
    replaced_output = False
    for i, arg in enumerate(args):
        if skip_next:
            skip_next = False
            continue
        if arg.startswith("-Wp,-MMD,"):
            continue
        if arg == "-c":
            continue
        if arg == "-o":
            out.extend(["-o", str(out_path)])
            skip_next = True
            replaced_output = True
            continue
        out.append(arg)

    if not replaced_output:
        out.extend(["-o", str(out_path)])

    if fmt == "ll":
        out.extend(["-emit-llvm", "-S", "-fno-discard-value-names"])
    else:
        out.extend(["-emit-llvm", "-c"])
    return out


def load_manifest(path):
    with Path(path).open() as f:
        yield from csv.DictReader(f, delimiter="\t")


def select_rows(rows, only, regex, all_missing):
    only = set(only or [])
    pattern = re.compile(regex) if regex else None
    for row in rows:
        obj = row["object_rel"]
        if only and obj not in only:
            continue
        if pattern and not pattern.search(obj):
            continue
        if all_missing and row["ir_status"] != "ll_missing_reproducible_from_o_cmd":
            continue
        if not only and not pattern and not all_missing:
            continue
        yield row


def materialize_one(row, build, out_dir, fmt, force, dry_run):
    obj = row["object_rel"]
    if row["ir_status"] != "ll_missing_reproducible_from_o_cmd":
        return {
            "status": "SKIP",
            "object_rel": obj,
            "out": "",
            "reason": row["ir_status"],
            "cmd": "",
        }
    cmd_path = hidden_cmd_for_object(build, obj)
    savedcmd = read_savedcmd(cmd_path, obj) if cmd_path.exists() else ""
    if not savedcmd:
        return {
            "status": "FAIL",
            "object_rel": obj,
            "out": "",
            "reason": "missing_savedcmd",
            "cmd": "",
        }

    suffix = "." + fmt
    out_path = out_dir / obj[:-2]
    out_path = out_path.with_suffix(suffix)
    cmd = transform_to_ir_cmd(savedcmd, out_path.resolve(), fmt)
    if out_path.exists() and not force:
        return {
            "status": "SKIP",
            "object_rel": obj,
            "out": str(out_path),
            "reason": "exists",
            "cmd": shlex.join(cmd) if dry_run else "",
        }
    if dry_run:
        return {
            "status": "DRYRUN",
            "object_rel": obj,
            "out": str(out_path),
            "reason": "dry_run",
            "cmd": shlex.join(cmd),
        }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        cmd,
        cwd=build,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if proc.returncode == 0 and out_path.exists():
        return {
            "status": "OK",
            "object_rel": obj,
            "out": str(out_path),
            "reason": "",
            "cmd": "",
        }
    err = proc.stderr.strip().splitlines()
    msg = err[-1] if err else f"exit={proc.returncode}"
    return {
        "status": "FAIL",
        "object_rel": obj,
        "out": str(out_path),
        "reason": msg,
        "cmd": "",
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--build", default=DEFAULT_BUILD)
    ap.add_argument("--manifest", default=DEFAULT_MANIFEST)
    ap.add_argument("--out-dir", default=DEFAULT_OUT_DIR)
    ap.add_argument("--only", action="append", default=[])
    ap.add_argument("--regex")
    ap.add_argument("--all-missing", action="store_true")
    ap.add_argument("--format", choices=("ll", "bc"), default="ll")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--jobs", type=int, default=1)
    ap.add_argument("--limit", type=int)
    ap.add_argument("--log", default=DEFAULT_LOG)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    build = Path(args.build).resolve()
    out_dir = Path(args.out_dir)
    rows = list(select_rows(load_manifest(args.manifest), args.only, args.regex, args.all_missing))
    if args.limit is not None:
        rows = rows[: args.limit]
    if not rows:
        raise SystemExit("no manifest rows selected")

    jobs = max(1, args.jobs)
    results = []
    if jobs == 1:
        for row in rows:
            results.append(materialize_one(row, build, out_dir, args.format, args.force, args.dry_run))
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as ex:
            futs = [
                ex.submit(materialize_one, row, build, out_dir, args.format, args.force, args.dry_run)
                for row in rows
            ]
            for fut in concurrent.futures.as_completed(futs):
                results.append(fut.result())

    counts = {"OK": 0, "FAIL": 0, "SKIP": 0, "DRYRUN": 0}
    log_path = Path(args.log)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w") as f:
        fields = ["status", "object_rel", "out", "reason", "cmd"]
        f.write("\t".join(fields) + "\n")
        for r in sorted(results, key=lambda x: x["object_rel"]):
            counts[r["status"]] = counts.get(r["status"], 0) + 1
            f.write("\t".join(r[k].replace("\t", " ") for k in fields) + "\n")
            if not args.quiet:
                if r["status"] in {"OK", "SKIP"}:
                    print(f"{r['status']}\t{r['object_rel']}\t{r['out'] or r['reason']}")
                elif r["status"] == "DRYRUN":
                    print(f"DRYRUN\t{r['object_rel']}\t{r['cmd']}")
                else:
                    print(f"FAIL\t{r['object_rel']}\t{r['reason']}")

    print(
        f"summary\tok={counts.get('OK', 0)}\tfail={counts.get('FAIL', 0)}"
        f"\tskipped={counts.get('SKIP', 0)}\tdryrun={counts.get('DRYRUN', 0)}"
        f"\tselected={len(rows)}\tlog={log_path}"
    )
    fail = counts.get("FAIL", 0)
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())

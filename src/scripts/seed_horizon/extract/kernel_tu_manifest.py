#!/usr/bin/env python3
# Copyright 2026 reFuzz project author -------youngkk.
#
# Build a per-TU manifest for the current kernel build. This is intentionally
# read-only: it records the universe of compiled kernel C objects and whether
# each object already has LLVM IR available from the same build.

import argparse
import collections
import json
import os
import re
import subprocess
from pathlib import Path


DEFAULT_BUILD = "/workspace/syzkaller/kernel/build-kasan-clang"
DEFAULT_SRC = "/workspace/syzkaller/kernel/linux-6.19.13"
DEFAULT_OUT = "run/seed_horizon/kernel_tu_manifest.tsv"
DEFAULT_SUMMARY = "run/seed_horizon/kernel_tu_manifest_summary.json"

KERNEL_PREFIXES = (
    "arch/",
    "block/",
    "certs/",
    "crypto/",
    "drivers/",
    "fs/",
    "init/",
    "io_uring/",
    "ipc/",
    "kernel/",
    "lib/",
    "mm/",
    "net/",
    "security/",
    "sound/",
    "usr/",
    "virt/",
)

EXCLUDE_PREFIXES = (
    "scripts/",
    "tools/",
)


def relpath(path, root):
    return path.relative_to(root).as_posix()


def hidden_cmd_for(path, suffix):
    return path.with_name("." + path.name[: -len(suffix)] + suffix + ".cmd")


def read_cmd_info(cmd_path, rel):
    info = {
        "cmd_present": cmd_path.exists(),
        "source_abs": "",
        "compiler": "",
        "kbuild_basename": "",
        "kbuild_modname": "",
    }
    if not cmd_path.exists():
        return info

    saved_prefix = f"savedcmd_{rel} :="
    source_prefix = f"source_{rel} :="
    try:
        with cmd_path.open(errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if line.startswith(saved_prefix):
                    cmd = line.split(":=", 1)[1].strip()
                    parts = cmd.split()
                    if parts:
                        info["compiler"] = Path(parts[0]).name
                    m = re.search(r'-DKBUILD_BASENAME=\'"([^"]+)"\'', cmd)
                    if m:
                        info["kbuild_basename"] = m.group(1)
                    m = re.search(r'-DKBUILD_MODNAME=\'"([^"]+)"\'', cmd)
                    if m:
                        info["kbuild_modname"] = m.group(1)
                elif line.startswith(source_prefix):
                    info["source_abs"] = line.split(":=", 1)[1].strip()
    except OSError:
        pass
    return info


def source_rel(source_abs, src):
    if not source_abs:
        return ""
    p = Path(source_abs)
    try:
        return p.relative_to(src).as_posix()
    except ValueError:
        return source_abs


def is_kernel_rel(rel):
    return rel.startswith(KERNEL_PREFIXES) and not rel.startswith(EXCLUDE_PREFIXES)


def should_skip_object(rel):
    base = rel.rsplit("/", 1)[-1]
    if rel.startswith(".tmp_") or "/.tmp_" in rel:
        return True
    if base in {"vmlinux.o"}:
        return True
    if base.endswith(".mod.o"):
        return True
    return False


def linked_objects(build):
    archive = build / "vmlinux.a"
    if not archive.exists():
        return set()
    proc = subprocess.run(
        ["llvm-ar-20", "t", str(archive)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if proc.returncode != 0:
        return set()
    out = set()
    build_s = str(build) + os.sep
    for line in proc.stdout.splitlines():
        p = line.strip()
        if not p:
            continue
        if p.startswith(build_s):
            p = p[len(build_s):]
        out.add(p)
    return out


def row_for_object(obj, build, src, linked):
    obj_rel = relpath(obj, build)
    o_cmd = hidden_cmd_for(obj, ".o")
    ll = obj.with_suffix(".ll")
    ll_rel = relpath(ll, build)
    ll_cmd = hidden_cmd_for(ll, ".ll")
    bc = obj.with_suffix(".bc")

    o_info = read_cmd_info(o_cmd, obj_rel)
    ll_info = read_cmd_info(ll_cmd, ll_rel)
    source_abs = o_info["source_abs"] or ll_info["source_abs"]
    src_rel = source_rel(source_abs, src)
    source_ext = Path(source_abs).suffix if source_abs else ""
    kernel_rel = is_kernel_rel(obj_rel)
    linked_scope = obj_rel in linked if linked else kernel_rel
    analysis_scope = linked_scope and kernel_rel and source_ext == ".c"
    clang_object = "clang" in o_info["compiler"]

    if ll.exists():
        ir_status = "ll_present"
    elif analysis_scope and o_info["cmd_present"] and clang_object:
        ir_status = "ll_missing_reproducible_from_o_cmd"
    elif analysis_scope and not o_info["cmd_present"]:
        ir_status = "ll_missing_no_o_cmd"
    elif analysis_scope:
        ir_status = "ll_missing_nonclang_o_cmd"
    else:
        ir_status = "out_of_scope"

    return {
        "object_rel": obj_rel,
        "source_rel": src_rel,
        "source_abs": source_abs,
        "area": obj_rel.split("/", 1)[0] if "/" in obj_rel else ".",
        "linked_scope": int(linked_scope),
        "analysis_scope": int(analysis_scope),
        "source_ext": source_ext,
        "object_cmd": int(o_info["cmd_present"]),
        "object_compiler": o_info["compiler"],
        "ll_rel": ll_rel,
        "ll_present": int(ll.exists()),
        "ll_cmd": int(ll_cmd.exists()),
        "bc_rel": relpath(bc, build),
        "bc_present": int(bc.exists()),
        "ir_status": ir_status,
        "kbuild_basename": o_info["kbuild_basename"] or ll_info["kbuild_basename"],
        "kbuild_modname": o_info["kbuild_modname"] or ll_info["kbuild_modname"],
    }


def summarize(rows, build, src):
    scoped = [r for r in rows if r["analysis_scope"]]
    linked = [r for r in rows if r["linked_scope"]]
    by_status = collections.Counter(r["ir_status"] for r in rows)
    scoped_by_status = collections.Counter(r["ir_status"] for r in scoped)
    by_area = collections.defaultdict(collections.Counter)
    for r in scoped:
        by_area[r["area"]][r["ir_status"]] += 1

    return {
        "build": str(build),
        "src": str(src),
        "objects_total": len(rows),
        "linked_objects": len(linked),
        "analysis_scope_c_tus": len(scoped),
        "ir_status": dict(sorted(by_status.items())),
        "analysis_scope_ir_status": dict(sorted(scoped_by_status.items())),
        "analysis_scope_by_area": {
            area: dict(sorted(counter.items()))
            for area, counter in sorted(by_area.items())
        },
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--build", default=DEFAULT_BUILD)
    ap.add_argument("--src", default=DEFAULT_SRC)
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--summary", default=DEFAULT_SUMMARY)
    args = ap.parse_args()

    build = Path(args.build).resolve()
    src = Path(args.src).resolve()
    if not build.is_dir():
        raise SystemExit(f"build dir not found: {build}")

    rows = []
    linked = linked_objects(build)
    for obj in sorted(build.rglob("*.o")):
        obj_rel = relpath(obj, build)
        if should_skip_object(obj_rel):
            continue
        rows.append(row_for_object(obj, build, src, linked))

    fields = [
        "object_rel",
        "source_rel",
        "source_abs",
        "area",
        "linked_scope",
        "analysis_scope",
        "source_ext",
        "object_cmd",
        "object_compiler",
        "ll_rel",
        "ll_present",
        "ll_cmd",
        "bc_rel",
        "bc_present",
        "ir_status",
        "kbuild_basename",
        "kbuild_modname",
    ]

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w") as f:
        f.write("\t".join(fields) + "\n")
        for r in rows:
            f.write("\t".join(str(r[k]) for k in fields) + "\n")

    summary = summarize(rows, build, src)
    summary_path = Path(args.summary)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    with summary_path.open("w") as f:
        json.dump(summary, f, indent=2, sort_keys=True)
        f.write("\n")

    scoped = summary["analysis_scope_c_tus"]
    scoped_status = summary["analysis_scope_ir_status"]
    print(f"manifest: {out}")
    print(f"summary: {summary_path}")
    print(
        f"objects_total={summary['objects_total']} linked_objects={summary['linked_objects']}"
        f" analysis_scope_c_tus={scoped}"
    )
    print(
        "analysis_scope_ir_status="
        + ",".join(f"{k}:{v}" for k, v in sorted(scoped_status.items()))
    )


if __name__ == "__main__":
    main()

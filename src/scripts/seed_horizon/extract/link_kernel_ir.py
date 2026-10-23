#!/usr/bin/env python3
# Copyright 2026 reFuzz project author -------youngkk.
#
# Link manifest-driven kernel IR using the current build's vmlinux.a object
# order. This turns "full IR coverage" into linked facts, avoiding the
# per-TU-only loss of cross-TU registrations/tables.

import argparse
import csv
from pathlib import Path
import re
import subprocess
import sys


DEFAULT_BUILD = "/workspace/syzkaller/kernel/build-kasan-clang"
DEFAULT_IR_LIST = "run/seed_horizon/kernel_facts_linked/ir_list.tsv"
DEFAULT_OUT = "run/seed_horizon/kernel_linked/vmlinux.full.bc"
DEFAULT_BATCH_DIR = "run/seed_horizon/kernel_linked/batches"
DEFAULT_BATCH_MANIFEST = "run/seed_horizon/kernel_linked/batches.tsv"
DEFAULT_BATCH_OBJECTS = "run/seed_horizon/kernel_linked/batch_objects.tsv"


def load_ir_list(path):
    out = {}
    with Path(path).open() as f:
        for row in csv.DictReader(f, delimiter="\t"):
            out[row["object_rel"]] = row["ir_path"]
    return out


def normalize_obj(build, obj):
    obj = obj.strip()
    build_s = str(build) + "/"
    if obj.startswith(build_s):
        obj = obj[len(build_s):]
    return obj


def ar_members(llvm_ar, build, archive):
    proc = subprocess.run(
        [llvm_ar, "t", str(archive)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"{llvm_ar} failed: {archive}")
    for line in proc.stdout.splitlines():
        obj = normalize_obj(build, line)
        if not obj:
            continue
        yield obj


def vmlinux_order(build, llvm_ar):
    return list(ar_members(llvm_ar, build, build / "vmlinux.a"))


def write_rsp(paths, out_path, rsp_path):
    rsp_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with rsp_path.open("w") as f:
        for p in paths:
            f.write(str(Path(p).resolve()) + "\n")
        f.write("-o\n")
        f.write(str(out_path.resolve()) + "\n")


def link(paths, out_path, rsp_path, llvm_link):
    write_rsp(paths, out_path, rsp_path)
    proc = subprocess.run(
        [llvm_link, "@" + str(rsp_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return proc


def area_of(obj):
    return obj.split("/", 1)[0] if "/" in obj else "."


def archive_rel(build, archive):
    return str(archive.relative_to(build))


def archive_depth(rel):
    return len(Path(rel).parts)


def safe_batch_name(archive, chunk):
    stem = archive[:-2] if archive.endswith(".a") else archive
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "__", stem)
    return f"{safe}.{chunk:03d}.bc"


def chunked(items, size):
    if size <= 0 or len(items) <= size:
        yield 0, items
        return
    for idx, off in enumerate(range(0, len(items), size)):
        yield idx, items[off:off + size]


def build_archive_batches(build, llvm_ar, ir_by_obj, max_objs, archive_regex=None):
    ordered = [obj for obj in vmlinux_order(build, llvm_ar) if obj in ir_by_obj]
    order_index = {obj: idx for idx, obj in enumerate(ordered)}
    runtime_objs = set(order_index)

    archives = sorted(build.rglob("built-in.a"))
    owners = {}
    owner_depth = {}
    archive_member_count = {}
    for archive in archives:
        rel = archive_rel(build, archive)
        try:
            members = [obj for obj in ar_members(llvm_ar, build, archive) if obj in runtime_objs]
        except RuntimeError as exc:
            print(f"WARN\tarchive_read_failed\t{rel}\t{exc}", file=sys.stderr)
            continue
        if not members:
            continue
        archive_member_count[rel] = len(members)
        depth = archive_depth(rel)
        for obj in members:
            old_depth = owner_depth.get(obj, -1)
            if depth > old_depth or (depth == old_depth and rel < owners.get(obj, "\xff")):
                owners[obj] = rel
                owner_depth[obj] = depth

    grouped = {}
    for obj in ordered:
        grouped.setdefault(owners.get(obj, "__vmlinux_orphan__"), []).append(obj)

    rx = re.compile(archive_regex) if archive_regex else None
    batches = []
    for rel in sorted(grouped, key=lambda r: (r == "__vmlinux_orphan__", r)):
        if rx and not rx.search(rel):
            continue
        objs = sorted(grouped[rel], key=lambda obj: order_index[obj])
        for chunk, chunk_objs in chunked(objs, max_objs):
            batch_id = safe_batch_name(rel, chunk)[:-3]
            batches.append({
                "batch_id": batch_id,
                "archive_rel": rel,
                "chunk": str(chunk),
                "archive_member_count": str(archive_member_count.get(rel, len(objs))),
                "object_count": str(len(chunk_objs)),
                "objects": chunk_objs,
            })
    return batches, {
        "runtime_ir_objects": len(ordered),
        "assigned_objects": sum(len(batch["objects"]) for batch in batches),
        "archives_with_ir": len(archive_member_count),
        "unmatched_objects": len([obj for obj in ordered if obj not in owners]),
    }


def write_batch_outputs(batches, batch_dir, manifest_path, objects_path, statuses):
    batch_dir.mkdir(parents=True, exist_ok=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "batch_id",
        "archive_rel",
        "chunk",
        "archive_member_count",
        "object_count",
        "bc_path",
        "rsp_path",
        "status",
        "reason",
    ]
    with manifest_path.open("w") as mf, objects_path.open("w") as of:
        mf.write("\t".join(fields) + "\n")
        of.write("batch_id\tobject_rel\tir_path\n")
        for batch in batches:
            st = statuses[batch["batch_id"]]
            row = {
                "batch_id": batch["batch_id"],
                "archive_rel": batch["archive_rel"],
                "chunk": batch["chunk"],
                "archive_member_count": batch["archive_member_count"],
                "object_count": batch["object_count"],
                "bc_path": str(st["bc_path"]),
                "rsp_path": str(st["rsp_path"]),
                "status": st["status"],
                "reason": st["reason"],
            }
            mf.write("\t".join(row[k] for k in fields) + "\n")
            for obj, ir_path in st["objects"]:
                of.write(f"{batch['batch_id']}\t{obj}\t{ir_path}\n")


def run_batch_link(args, build, ir_by_obj):
    batch_dir = Path(args.batch_dir)
    manifest_path = Path(args.batch_manifest)
    objects_path = Path(args.batch_objects)
    batches, stats = build_archive_batches(
        build,
        args.llvm_ar,
        ir_by_obj,
        args.max_objs,
        archive_regex=args.archive_regex,
    )
    statuses = {}
    ok = fail = planned = skipped = 0
    for batch in batches:
        bc_path = batch_dir / safe_batch_name(batch["archive_rel"], int(batch["chunk"]))
        rsp_path = bc_path.with_suffix(bc_path.suffix + ".rsp")
        paths = [ir_by_obj[obj] for obj in batch["objects"]]
        object_rows = list(zip(batch["objects"], paths))
        if args.list_only:
            statuses[batch["batch_id"]] = {
                "bc_path": bc_path,
                "rsp_path": rsp_path,
                "status": "planned",
                "reason": "",
                "objects": object_rows,
            }
            planned += 1
            continue
        if args.skip_existing and bc_path.exists():
            statuses[batch["batch_id"]] = {
                "bc_path": bc_path,
                "rsp_path": rsp_path,
                "status": "SKIP",
                "reason": "existing",
                "objects": object_rows,
            }
            skipped += 1
            continue
        proc = link(paths, bc_path, rsp_path, args.llvm_link)
        if proc.returncode == 0 and bc_path.exists():
            statuses[batch["batch_id"]] = {
                "bc_path": bc_path,
                "rsp_path": rsp_path,
                "status": "OK",
                "reason": "",
                "objects": object_rows,
            }
            ok += 1
            print(f"OK\t{batch['batch_id']}\t{batch['object_count']}\t{bc_path}")
        else:
            err = proc.stderr.strip().splitlines()
            reason = err[-1] if err else f"exit={proc.returncode}"
            statuses[batch["batch_id"]] = {
                "bc_path": bc_path,
                "rsp_path": rsp_path,
                "status": "FAIL",
                "reason": reason,
                "objects": object_rows,
            }
            fail += 1
            print(f"FAIL\t{batch['batch_id']}\t{batch['object_count']}\t{reason}")

    write_batch_outputs(batches, batch_dir, manifest_path, objects_path, statuses)
    print(
        "summary"
        f"\tbatches={len(batches)}"
        f"\tplanned={planned}"
        f"\tok={ok}"
        f"\tskipped={skipped}"
        f"\tfail={fail}"
        f"\truntime_ir_objects={stats['runtime_ir_objects']}"
        f"\tassigned_objects={stats['assigned_objects']}"
        f"\tunmatched_objects={stats['unmatched_objects']}"
        f"\tarchives_with_ir={stats['archives_with_ir']}"
        f"\tmanifest={manifest_path}"
        f"\tobjects={objects_path}"
    )
    return 1 if fail else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--build", default=DEFAULT_BUILD)
    ap.add_argument("--ir-list", default=DEFAULT_IR_LIST)
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--mode", choices=("full", "area", "batch"), default="full")
    ap.add_argument("--area")
    ap.add_argument("--llvm-ar", default="llvm-ar-20")
    ap.add_argument("--llvm-link", default="llvm-link-20")
    ap.add_argument("--batch-dir", default=DEFAULT_BATCH_DIR)
    ap.add_argument("--batch-manifest", default=DEFAULT_BATCH_MANIFEST)
    ap.add_argument("--batch-objects", default=DEFAULT_BATCH_OBJECTS)
    ap.add_argument("--max-objs", type=int, default=256)
    ap.add_argument("--archive-regex")
    ap.add_argument("--list-only", action="store_true")
    ap.add_argument("--skip-existing", action="store_true")
    args = ap.parse_args()

    build = Path(args.build).resolve()
    ir_by_obj = load_ir_list(args.ir_list)
    if args.mode == "batch":
        return run_batch_link(args, build, ir_by_obj)

    ordered = []
    missing = []
    for obj in vmlinux_order(build, args.llvm_ar):
        if obj in ir_by_obj:
            if args.area and area_of(obj) != args.area:
                continue
            ordered.append((obj, ir_by_obj[obj]))
        elif obj.endswith(".o"):
            missing.append(obj)

    if args.mode == "area":
        grouped = {}
        for obj, path in ordered:
            grouped.setdefault(area_of(obj), []).append(path)
        base = Path(args.out)
        ok = fail = 0
        for area, paths in sorted(grouped.items()):
            out_path = base.with_name(f"{base.stem}.{area}{base.suffix}")
            rsp_path = out_path.with_suffix(out_path.suffix + ".rsp")
            proc = link(paths, out_path, rsp_path, args.llvm_link)
            if proc.returncode == 0 and out_path.exists():
                print(f"OK\t{area}\t{len(paths)}\t{out_path}")
                ok += 1
            else:
                err = proc.stderr.strip().splitlines()
                print(f"FAIL\t{area}\t{len(paths)}\t{err[-1] if err else proc.returncode}")
                fail += 1
        print(f"summary\tok={ok}\tfail={fail}\tmissing_objects={len(missing)}")
        return 1 if fail else 0

    paths = [path for _obj, path in ordered]
    out_path = Path(args.out)
    rsp_path = out_path.with_suffix(out_path.suffix + ".rsp")
    proc = link(paths, out_path, rsp_path, args.llvm_link)
    if proc.returncode != 0 or not out_path.exists():
        err = proc.stderr.strip().splitlines()
        print(f"FAIL\tfull\t{len(paths)}\t{err[-1] if err else proc.returncode}")
        print(f"rsp={rsp_path}")
        return 1
    print(f"OK\tfull\t{len(paths)}\t{out_path}\tmissing_objects={len(missing)}\trsp={rsp_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

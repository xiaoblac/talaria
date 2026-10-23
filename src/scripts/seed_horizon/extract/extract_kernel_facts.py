#!/usr/bin/env python3
# Copyright 2026 reFuzz project author -------youngkk.
#
# Extract full-kernel static facts from the manifest-defined runtime IR set.
# The input universe is the current build's linked C TUs. Existing build .ll
# files and materialized .o.cmd-derived .ll files are merged into one IR list.

import argparse
import collections
import concurrent.futures
import csv
from pathlib import Path
import re
import subprocess
import sys


DEFAULT_BUILD = "/workspace/syzkaller/kernel/build-kasan-clang"
DEFAULT_MANIFEST = "run/seed_horizon/kernel_tu_manifest.tsv"
DEFAULT_IR_ROOT = "run/seed_horizon/kernel_ir"
DEFAULT_IR_DEFUSE = "run/seed_horizon/ir_defuse"
DEFAULT_OUT_DIR = "run/seed_horizon/kernel_facts_linked"
DEFAULT_LINKED_BATCHES = "run/seed_horizon/kernel_linked/batches.tsv"
DEFAULT_MERGED_BC = "run/seed_horizon/vmlinux.bc"


HANDLER_RE = re.compile(r"\b(ioctl|setsockopt|getsockopt)=([A-Za-z0-9_.$]+)")
CMD_ARG_INDEX = {"ioctl": 1, "setsockopt": 2, "getsockopt": 2}


def load_manifest(path):
    with Path(path).open() as f:
        yield from csv.DictReader(f, delimiter="\t")


def materialized_ir_path(ir_root, object_rel):
    return (ir_root / object_rel[:-2]).with_suffix(".ll")


def build_ir_path(build, ll_rel):
    return build / ll_rel


def build_ir_list(manifest, build, ir_root):
    rows = []
    missing = []
    for row in load_manifest(manifest):
        if row.get("analysis_scope") != "1":
            continue
        mat = materialized_ir_path(ir_root, row["object_rel"])
        bll = build_ir_path(build, row["ll_rel"])
        if mat.exists():
            src = "materialized"
            ir = mat
        elif row.get("ll_present") == "1" and bll.exists():
            src = "build"
            ir = bll
        else:
            missing.append(row["object_rel"])
            continue
        rows.append({
            "object_rel": row["object_rel"],
            "source_rel": row["source_rel"],
            "ir_source": src,
            "ir_path": str(ir),
        })
    return rows, missing


def build_linked_batch_list(manifest):
    rows = []
    missing = []
    with Path(manifest).open() as f:
        for row in csv.DictReader(f, delimiter="\t"):
            if row.get("status") != "OK":
                missing.append(row.get("batch_id", ""))
                continue
            ir = Path(row["bc_path"])
            if not ir.exists():
                missing.append(row["batch_id"])
                continue
            rows.append({
                "object_rel": row["batch_id"],
                "source_rel": row["archive_rel"],
                "ir_source": "linked_batch",
                "ir_path": str(ir),
            })
    return rows, missing


def build_merged_list(merged_bc):
    """The single fully-linked vmlinux.bc as the sole IR row -- the whole-kernel cross-TU view, so a fact
    that depends on a cross-translation-unit reference (an installed fops, an anon-fd lift) is no longer
    invisible across batch boundaries.  One ir_defuse invocation per stage instead of 627."""
    p = Path(merged_bc)
    row = {"object_rel": "vmlinux", "source_rel": "vmlinux", "ir_source": "merged", "ir_path": str(p)}
    return ([row], []) if p.exists() else ([], ["vmlinux"])


def run_ir_defuse(ir_defuse, mode, ir_path, handlers=None):
    cmd = [ir_defuse, mode, ir_path]
    if handlers:
        cmd.extend(handlers)
    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return proc.returncode, proc.stdout.splitlines(), proc.stderr.strip().splitlines()


def extract_reg_one(ir_defuse, row):
    code, lines, err = run_ir_defuse(ir_defuse, "--reg", row["ir_path"])
    reason = "" if code == 0 else (err[-1] if err else f"exit={code}")
    return row, code, [ln for ln in lines if ln], reason


def parse_text_handler_defs(ir_path):
    names = set()
    try:
        with Path(ir_path).open(errors="replace") as f:
            for line in f:
                if not line.startswith("define "):
                    continue
                at = line.find("@")
                if at < 0:
                    continue
                rest = line[at + 1:].lstrip()
                if rest.startswith('"'):
                    end = rest.find('"', 1)
                    if end > 1:
                        names.add(rest[1:end])
                else:
                    end = rest.find("(")
                    if end > 0:
                        names.add(rest[:end].strip())
    except OSError:
        pass
    return names


def parse_nm_handler_defs(ir_path, llvm_nm):
    proc = subprocess.run(
        [llvm_nm, "--defined-only", "--format=posix", ir_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if proc.returncode != 0:
        return set()
    names = set()
    for line in proc.stdout.splitlines():
        fields = line.split()
        if len(fields) < 2:
            continue
        sym, typ = fields[0], fields[1]
        if typ and typ[0] in {"t", "T", "w", "W"}:
            names.add(sym)
    return names


def parse_handler_defs(ir_path, llvm_nm):
    if Path(ir_path).suffix == ".bc":
        return parse_nm_handler_defs(ir_path, llvm_nm)
    return parse_text_handler_defs(ir_path)


def extract_cmd_one(ir_defuse, row, handlers):
    code, lines, err = run_ir_defuse(ir_defuse, "--cmd", row["ir_path"], handlers)
    reason = "" if code == 0 else (err[-1] if err else f"exit={code}")
    return row, code, [ln for ln in lines if ln], reason


def extract_fields_one(ir_defuse, row):
    code, lines, err = run_ir_defuse(ir_defuse, "--fields", row["ir_path"])
    reason = "" if code == 0 else (err[-1] if err else f"exit={code}")
    return row, code, [ln for ln in lines if ln], reason


def write_ir_list(rows, missing, out_dir):
    out_dir.mkdir(parents=True, exist_ok=True)
    with (out_dir / "ir_list.tsv").open("w") as f:
        fields = ["object_rel", "source_rel", "ir_source", "ir_path"]
        f.write("\t".join(fields) + "\n")
        for row in rows:
            f.write("\t".join(row[k] for k in fields) + "\n")
    with (out_dir / "ir_missing.tsv").open("w") as f:
        f.write("object_rel\n")
        for obj in missing:
            f.write(obj + "\n")


def write_fact_outputs(results, raw_path, by_tu_path, log_path):
    ok = fail = 0
    with raw_path.open("w") as raw, by_tu_path.open("w") as by_tu, log_path.open("w") as log:
        log.write("status\tobject_rel\tir_path\treason\trows\n")
        for row, code, lines, reason in sorted(results, key=lambda x: x[0]["object_rel"]):
            status = "OK" if code == 0 else "FAIL"
            if code == 0:
                ok += 1
            else:
                fail += 1
            log.write(f"{status}\t{row['object_rel']}\t{row['ir_path']}\t{reason}\t{len(lines)}\n")
            for ln in lines:
                raw.write(ln + "\n")
                by_tu.write(row["object_rel"] + "\t" + ln + "\n")
    return ok, fail


def run_parallel(fn, rows, jobs):
    if jobs <= 1:
        return [fn(row) for row in rows]
    out = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as ex:
        futs = [ex.submit(fn, row) for row in rows]
        for fut in concurrent.futures.as_completed(futs):
            out.append(fut.result())
    return out


def collect_dispatch_specs(reg_path):
    specs = collections.defaultdict(set)
    with reg_path.open() as f:
        for ln in f:
            for m in HANDLER_RE.finditer(ln):
                if m.group(2) != "-":
                    specs[m.group(2)].add(m.group(1))
    return specs


def collect_structural_dispatch_specs(root="."):
    specs = collections.defaultdict(set)
    seed_horizon_root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(seed_horizon_root))
    from resolve.fixpoint import read_block_dops_ioctls

    for handler in read_block_dops_ioctls(root):
        specs[handler].add("ioctl")
    return specs


def load_field_target_rows(field_by_tu_path):
    out = collections.defaultdict(set)
    if not field_by_tu_path.exists():
        return out
    with field_by_tu_path.open() as f:
        for ln in f:
            c = ln.rstrip("\n").split("\t")
            if len(c) < 5 or c[1] != "FIELD":
                continue
            object_rel, field = c[0], c[2]
            for target in c[4].split(","):
                if target and target not in {"-", "..."}:
                    out[field].add((target, object_rel))
    return out


def parse_cmdicall_bridges(cmd_results, field_target_rows, dispatch_specs):
    bridges = set()
    for row, code, lines, _reason in cmd_results:
        if code != 0:
            continue
        source_object_rel = row["object_rel"]
        for ln in lines:
            c = ln.rstrip("\n").split("\t")
            if len(c) < 6 or c[0] != "CMDICALL":
                continue
            origin, caller, field = c[1], c[2], c[3]
            try:
                arg_idx = int(c[4])
            except ValueError:
                continue
            for op in dispatch_specs.get(origin, ()):
                if CMD_ARG_INDEX.get(op) != arg_idx:
                    continue
                for target, target_object_rel in field_target_rows.get(field, ()):
                    if target_object_rel == source_object_rel:
                        continue
                    if target != origin and target != caller:
                        bridges.add((origin, caller, field, op, target, target_object_rel, arg_idx))
    return bridges


def parse_direct_cmd_bridges(cmd_results, target_definition_rows):
    bridges = set()
    for row, code, lines, _reason in cmd_results:
        if code != 0:
            continue
        source_object_rel = row["object_rel"]
        for ln in lines:
            c = ln.rstrip("\n").split("\t")
            if len(c) < 6 or c[0] != "CMDBRIDGE":
                continue
            origin, caller, target = c[1], c[2], c[3]
            try:
                arg_idx = int(c[4])
            except ValueError:
                continue
            for target_object_rel in target_definition_rows.get(target, ()):
                if target_object_rel != source_object_rel:
                    bridges.add((origin, caller, "direct", f"arg{arg_idx}", target,
                                 target_object_rel, arg_idx))
    return bridges


def _cmd_origin(c):
    for extra in c[8:]:
        if extra.startswith("origin="):
            return extra.split("=", 1)[1]
    return None


def _with_origin(c, origin):
    base = c[:8]
    # A direct `cmd & mask` proof belongs to the function containing that switch. Cross-batch bridges
    # currently prove cmd taint/call reachability, but field-indirect bridges do not preserve the concrete
    # object identity needed to transplant the transformed selector (ecryptfs must not inherit nd_ioctl's
    # low-byte switch). Keep the copied row for exact-value compatibility, but do not lift mask semantics.
    extras = [x for x in c[8:]
              if not x.startswith("origin=") and not x.startswith("key_kind=mask:")]
    extras.append(f"origin={origin}")
    return "\t".join(base + extras)


def rewrite_cross_batch_cmd_lines(lines, target_to_origins):
    out = []
    kept = set()
    for ln in lines:
        c = ln.rstrip("\n").split("\t")
        if len(c) < 8 or c[0] != "CMD":
            continue
        origins = set()
        if c[1] in target_to_origins:
            origins.update(target_to_origins[c[1]])
        existing_origin = _cmd_origin(c)
        if existing_origin in target_to_origins:
            origins.update(target_to_origins[existing_origin])
        for origin in sorted(origins):
            out.append(_with_origin(c, origin))
            kept.add((c[1], c[2]))
    for ln in lines:
        c = ln.rstrip("\n").split("\t")
        if len(c) >= 5 and c[0] in {"CMDWRITE", "CMDUSE"} and (c[1], c[2]) in kept:
            out.append(ln)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--build", default=DEFAULT_BUILD)
    ap.add_argument("--manifest", default=DEFAULT_MANIFEST)
    ap.add_argument("--ir-root", default=DEFAULT_IR_ROOT)
    ap.add_argument("--ir-defuse", default=DEFAULT_IR_DEFUSE)
    ap.add_argument("--out-dir", default=DEFAULT_OUT_DIR)
    ap.add_argument("--linked-batches", default=DEFAULT_LINKED_BATCHES)
    ap.add_argument("--merged-bc", default=DEFAULT_MERGED_BC)
    ap.add_argument("--input", choices=("manifest", "batches", "merged"), default="manifest")
    ap.add_argument("--llvm-nm", default="llvm-nm-20")
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument("--stage", choices=("list", "reg", "fields", "cmd", "all"), default="all")
    args = ap.parse_args()

    build = Path(args.build).resolve()
    ir_root = Path(args.ir_root)
    out_dir = Path(args.out_dir)
    ir_defuse = str(Path(args.ir_defuse))
    if args.input == "merged":
        rows, missing = build_merged_list(args.merged_bc)
    elif args.input == "batches":
        rows, missing = build_linked_batch_list(args.linked_batches)
    else:
        rows, missing = build_ir_list(args.manifest, build, ir_root)
    write_ir_list(rows, missing, out_dir)
    print(f"ir_list={len(rows)} missing={len(missing)} out={out_dir / 'ir_list.tsv'}")
    if missing:
        print(f"missing list: {out_dir / 'ir_missing.tsv'}")
    if args.stage == "list":
        return 0 if not missing else 1

    if args.stage in {"reg", "all"}:
        reg_results = run_parallel(
            lambda row: extract_reg_one(ir_defuse, row),
            rows,
            max(1, args.jobs),
        )
        ok, fail = write_fact_outputs(
            reg_results,
            out_dir / "reg.tsv",
            out_dir / "reg.by_tu.tsv",
            out_dir / "reg.log.tsv",
        )
        print(f"reg ok={ok} fail={fail} rows={sum(len(r[2]) for r in reg_results)}")
        if fail:
            return 1

    if args.stage in {"fields", "all"}:
        field_results = run_parallel(
            lambda row: extract_fields_one(ir_defuse, row),
            rows,
            max(1, args.jobs),
        )
        ok, fail = write_fact_outputs(
            field_results,
            out_dir / "fields.tsv",
            out_dir / "fields.by_tu.tsv",
            out_dir / "fields.log.tsv",
        )
        print(f"fields ok={ok} fail={fail} rows={sum(len(r[2]) for r in field_results)}")
        if fail:
            return 1
        if args.stage == "fields":
            return 0

    if args.stage in {"cmd", "all"}:
        reg_path = out_dir / "reg.tsv"
        if not reg_path.exists():
            raise SystemExit(f"missing reg facts: {reg_path}")
        field_path = out_dir / "fields.tsv"
        if not field_path.exists():
            field_results = run_parallel(
                lambda row: extract_fields_one(ir_defuse, row),
                rows,
                max(1, args.jobs),
            )
            ok, fail = write_fact_outputs(
                field_results,
                field_path,
                out_dir / "fields.by_tu.tsv",
                out_dir / "fields.log.tsv",
            )
            print(f"fields ok={ok} fail={fail} rows={sum(len(r[2]) for r in field_results)}")
            if fail:
                return 1
        dispatch_specs = collect_dispatch_specs(reg_path)
        for handler, ops in collect_structural_dispatch_specs().items():
            dispatch_specs[handler].update(ops)
        dispatch_handlers = set(dispatch_specs)
        defs = collections.defaultdict(set)
        target_definition_rows = collections.defaultdict(set)
        for row in rows:
            names = parse_handler_defs(row["ir_path"], args.llvm_nm)
            for name in names:
                target_definition_rows[name].add(row["object_rel"])
                if name in dispatch_handlers:
                    for op in dispatch_specs[name]:
                        defs[row["object_rel"]].add(f"{op}={name}")
        print(f"dispatch_handlers={len(dispatch_handlers)} definition_tus={len(defs)}")
        cmd_results = run_parallel(
            lambda row: extract_cmd_one(ir_defuse, row, sorted(defs.get(row["object_rel"], ()))),
            rows,
            max(1, args.jobs),
        )
        field_target_rows = load_field_target_rows(out_dir / "fields.by_tu.tsv")
        bridges = parse_cmdicall_bridges(cmd_results, field_target_rows, dispatch_specs)
        direct_bridges = parse_direct_cmd_bridges(cmd_results, target_definition_rows)
        bridges |= direct_bridges
        bridge_specs_by_row = collections.defaultdict(lambda: collections.defaultdict(set))
        for origin, caller, field, op, target, target_object_rel, arg_idx in bridges:
            bridge_specs_by_row[target_object_rel][f"{op}={target}"].add(
                (origin, caller, field, arg_idx))
        extra_results = []
        if bridge_specs_by_row:
            row_by_obj = {row["object_rel"]: row for row in rows}
            # a bridge target may live in a batch whose .bc is absent from THIS build (stale fields.by_tu.tsv
            # vs current rows) -- we can't re-extract from a missing batch, so drop those targets.
            extra_objs = [obj for obj in sorted(bridge_specs_by_row) if obj in row_by_obj]
            dropped = len(bridge_specs_by_row) - len(extra_objs)
            if dropped:
                print(f"cmd bridge extra: dropped {dropped} target batches absent from rows")
            raw_extra = run_parallel(
                lambda row: extract_cmd_one(ir_defuse, row,
                                            sorted(bridge_specs_by_row[row["object_rel"]].keys())),
                [row_by_obj[obj] for obj in extra_objs],
                max(1, args.jobs),
            )
            for row, code, lines, reason in raw_extra:
                object_rel = row["object_rel"]
                target_to_origins = collections.defaultdict(set)
                bridge_lines = []
                for spec, proofs in bridge_specs_by_row[object_rel].items():
                    _op, target = spec.split("=", 1)
                    for origin, caller, field, arg_idx in proofs:
                        target_to_origins[target].add(origin)
                        tag = "CMDDBRIDGE" if field == "direct" else "CMDXBRIDGE"
                        bridge_lines.append(f"{tag}\t{origin}\t{caller}\t{field}\t{target}\t{arg_idx}")
                rewritten_cmd = rewrite_cross_batch_cmd_lines(lines, target_to_origins)
                rewritten = (bridge_lines + rewritten_cmd) if rewritten_cmd else []
                extra_results.append((row, code, rewritten, reason))
        if bridges:
            resolved = sum(len(v) for v in bridge_specs_by_row.values())
            print(f"cross_batch_fptr_bridges={len(bridges)} resolved_specs={resolved} "
                  f"direct_bridges={len(direct_bridges)} "
                  f"target_definition_tus={len(bridge_specs_by_row)}")
        cmd_results = cmd_results + extra_results
        ok, fail = write_fact_outputs(
            cmd_results,
            out_dir / "cmd.tsv",
            out_dir / "cmd.by_tu.tsv",
            out_dir / "cmd.log.tsv",
        )
        print(f"cmd ok={ok} fail={fail} rows={sum(len(r[2]) for r in cmd_results)}")
        if fail:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

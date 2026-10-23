#!/usr/bin/env python3
import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from model.variant import build_reg_rows
from provenance.context import build_provenance_context


DEFAULT_SH = "run/seed_horizon"
SCHEMA_VERSION = 1


def json_cell(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def stable_id(prefix, cells):
    payload = "\t".join(str(cell) for cell in cells).encode()
    return f"{prefix}:{hashlib.sha256(payload).hexdigest()[:20]}"


def load_reg_units(sh):
    linked_path = sh / "kernel_facts_linked" / "reg.tsv"
    by_tu_path = sh / "kernel_facts_linked" / "reg.by_tu.tsv"
    linked = [line.rstrip("\n") for line in linked_path.open() if line.startswith("REG\t")]
    by_tu = []
    for line in by_tu_path.open():
        columns = line.rstrip("\n").split("\t")
        if len(columns) >= 2 and columns[1] == "REG":
            by_tu.append((columns[0], "\t".join(columns[1:])))
    if len(linked) != len(by_tu):
        raise RuntimeError(f"REG/per-TU row mismatch: {len(linked)} != {len(by_tu)}")
    for index, (linked_row, (_unit, by_tu_row)) in enumerate(zip(linked, by_tu)):
        if linked_row != by_tu_row:
            raise RuntimeError(f"REG/per-TU order mismatch at row {index}")
    return [unit for unit, _row in by_tu]


def load_global_object_ids(path, symbols):
    by_unit_symbol = collections.defaultdict(set)
    with path.open(errors="replace") as source:
        source.readline()
        for line in source:
            columns = line.rstrip("\n").split("\t")
            if len(columns) != 13 or columns[1] != "global" or columns[3] not in symbols:
                continue
            by_unit_symbol[(columns[8], columns[3])].add(columns[0])
    return by_unit_symbol


def dispatch_object_ids(reg_row, dispatch_symbol, reg_units, object_ids):
    if dispatch_symbol == "-" or reg_row >= len(reg_units):
        return [(f"seed:reg-row:{reg_row}", "synthetic", "-")]
    unit = reg_units[reg_row]
    matches = sorted(object_ids.get((unit, dispatch_symbol), ()))
    if not matches:
        return [(f"unresolved:reg-row:{reg_row}:{dispatch_symbol}", "unresolved", unit)]
    status = "exact" if len(matches) == 1 else "fanout"
    return [(object_id, status, unit) for object_id in matches]


def registration_rows(context, reg_units, object_ids):
    rows = []
    for seed in context.install_seeds:
        if not 0 <= seed.reg_row < len(context.reg_rows):
            raise IndexError(f"invalid REG row {seed.reg_row} for {seed}")
        dispatch_kind, _device, dispatch_symbol, fields, subsystem = context.reg_rows[seed.reg_row]
        for dispatch_object_id, object_status, batch in dispatch_object_ids(
                seed.reg_row, dispatch_symbol, reg_units, object_ids):
            cells = (
                seed.relation,
                seed.root_kind,
                seed.root,
                seed.method,
                dispatch_kind,
                dispatch_object_id,
                dispatch_symbol,
                object_status,
                batch,
                seed.reg_row,
                json_cell(fields),
                subsystem,
                seed.source,
                seed.parent_root,
            )
            rows.append((stable_id("seed", cells),) + cells)

    for resource, field_sets in sorted(context.block_dops_ctx.items()):
        dispatch_object = f"seed:resource:{resource}:block_device_operations"
        for fields in field_sets:
            cells = (
                "context_install",
                "resource",
                resource,
                "block-command-context",
                "block_device_operations",
                dispatch_object,
                "-",
                "synthetic",
                "-",
                "-",
                json_cell(fields),
                "block",
                "build_block_dops_context",
                "-",
            )
            rows.append((stable_id("seed", cells),) + cells)
    return sorted(set(rows))


def reg_field_summaries(reg_rows, reg_units, object_ids):
    rows = []
    for reg_row, (dispatch_kind, _device, dispatch_symbol, fields, subsystem) in enumerate(reg_rows):
        for dispatch_object_id, object_status, batch in dispatch_object_ids(
                reg_row, dispatch_symbol, reg_units, object_ids):
            for field, handler in sorted(fields.items()):
                context = {
                    "batch": batch,
                    "dispatch_kind": dispatch_kind,
                    "dispatch_symbol": dispatch_symbol,
                    "object_status": object_status,
                    "reg_row": reg_row,
                    "subsystem": subsystem,
                }
                cells = (
                    "dispatch_field",
                    "dispatch_object",
                    dispatch_object_id,
                    field,
                    "function",
                    handler,
                    "-",
                    json_cell(context),
                    "REG",
                    f"reg_rows:{reg_row}",
                )
                rows.append((stable_id("summary", cells),) + cells)
    return rows


def block_context_summaries(context):
    rows = []
    for resource, field_sets in sorted(context.block_dops_ctx.items()):
        subject = f"seed:resource:{resource}:block_device_operations"
        for fields in field_sets:
            for field, handler in sorted(fields.items()):
                detail = {"method": "block-command-context", "resource": resource}
                cells = (
                    "context_field",
                    "seed_object",
                    subject,
                    field,
                    "function",
                    handler,
                    "-",
                    json_cell(detail),
                    "BLOCK_CONTEXT",
                    "build_block_dops_context",
                )
                rows.append((stable_id("summary", cells),) + cells)
    return rows


def extra_values(columns):
    values = {}
    positional = []
    for value in columns:
        if "=" in value:
            key, item = value.split("=", 1)
            values[key] = item
        else:
            positional.append(value)
    if positional:
        values["positional"] = positional
    return values


def cmd_summary(columns, line_number):
    kind = columns[0]
    relation = subject_kind = subject = key = target_kind = target = arg_index = "-"
    context = {}

    if kind == "CMD" and len(columns) >= 8:
        extras = extra_values(columns[8:])
        relation = "cmd_selector"
        subject_kind = "dispatcher"
        subject = extras.get("origin", columns[1])
        key = columns[2]
        target_kind = "function"
        target = columns[1]
        context = {
            "depth": columns[6],
            "exclusivity": columns[5],
            "key_kind": extras.get("key_kind", "exact"),
            "region_size": columns[4],
            "roots": columns[7],
            "slot": columns[3],
        }
    elif kind == "GENLCMD" and len(columns) >= 4:
        relation = "genl_selector"
        subject_kind = "genl_family"
        subject, key = columns[1], columns[2]
        target_kind, target = "function", columns[3]
        context = {"roots": columns[4] if len(columns) >= 5 else "-"}
    elif kind == "GENLMUX" and len(columns) >= 2:
        relation = "genl_multiplexer"
        subject_kind, subject = "function", columns[1]
    elif kind == "FSMOUNT" and len(columns) >= 3:
        relation = "fs_selector"
        subject_kind, subject = "filesystem", columns[1]
        key = "mount"
        target_kind, target = "function", columns[2]
        context = {"secondary": columns[3:]}
    elif kind == "FIELD_ICALL" and len(columns) >= 4:
        relation = "field_forward"
        subject_kind, subject = "function", columns[1]
        key = columns[3] or "-"
        target_kind, target = "field_slot", columns[2]
    elif kind == "FIELD_ICALL_SITE" and len(columns) >= 5:
        relation = "field_forward_site"
        subject_kind, subject = "function", columns[1]
        key = columns[4] or "-"
        target_kind, target = "field_slot", columns[3]
        context = {"instruction": columns[2]}
    elif kind == "CMD_REACH" and len(columns) >= 4:
        relation = "cmd_reach"
        subject_kind, subject = "function", columns[1]
        key = columns[2]
        target_kind, target = "instruction", columns[3]
    elif kind == "CMD_REACH_NOT" and len(columns) >= 4:
        relation = "cmd_reach_not"
        subject_kind, subject = "function", columns[1]
        key = columns[3]
        target_kind, target = "instruction", columns[2]
    elif kind == "CMDBRIDGE" and len(columns) >= 6:
        relation = "cmd_call_bridge"
        subject_kind, subject = "function", columns[2]
        key = columns[1]
        target_kind, target = "function", columns[3]
        arg_index = columns[4]
        context = {"depth": columns[5]}
    elif kind == "CMDDBRIDGE" and len(columns) >= 6:
        relation = "cmd_data_bridge"
        subject_kind, subject = "function", columns[1]
        key = columns[3]
        target_kind, target = "function", columns[2]
        arg_index = columns[5]
        context = {"operation": columns[4]}
    elif kind == "CMDXBRIDGE" and len(columns) >= 6:
        relation = "cmd_cross_bridge"
        subject_kind, subject = "function", columns[2]
        key = columns[3]
        target_kind, target = "function", columns[4]
        context = {"origin": columns[1], "depth": columns[5]}
    elif kind == "CMDICALL" and len(columns) >= 6:
        relation = "cmd_field_forward"
        subject_kind, subject = "function", columns[2]
        key = columns[3]
        target_kind, target = "field_slot", columns[3]
        arg_index = columns[4]
        context = {"origin": columns[1], "depth": columns[5]}
    elif kind == "CALLBACK_BRIDGE" and len(columns) >= 7:
        relation = "callback_bridge"
        subject_kind, subject = "function", columns[1]
        key = columns[6]
        target_kind, target = "function", columns[3]
        arg_index = columns[4]
        context = {
            "callback_cmd_arg": columns[5],
            "helper": columns[2],
        }
    else:
        return None

    cells = (
        relation,
        subject_kind,
        subject,
        key,
        target_kind,
        target,
        arg_index,
        json_cell(context),
        kind,
        f"cmd.tsv:{line_number}",
    )
    return (stable_id("summary", cells),) + cells


def cmd_summaries(path):
    rows = []
    with path.open() as source:
        for line_number, line in enumerate(source, 1):
            columns = line.rstrip("\n").split("\t")
            row = cmd_summary(columns, line_number)
            if row is not None:
                rows.append(row)
    return rows


def write_tsv(path, header, rows):
    with path.open("w") as out:
        out.write("\t".join(header) + "\n")
        for row in rows:
            out.write("\t".join(str(cell) for cell in row) + "\n")


def validate(context, registrations, summaries):
    actual = {
        (row[1], row[2], row[3], int(row[10]))
        for row in registrations if row[10] != "-"
    }
    expected = {
        ("entry_install", "resource", resource, row)
        for resource, rows in context.res2rows.items() for row in rows
    }
    expected.update({
        ("entry_install", "variant", variant, row)
        for variant, rows in context.variant2rows.items() for row in rows
    })
    expected.update({
        ("context_install", "resource", resource, row)
        for resource, rows in context.sock_proto_ctx.items() for row in rows
    })
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    registration_ids = [row[0] for row in registrations]
    summary_ids = [row[0] for row in summaries]
    block_expected = sum(len(field_sets) for field_sets in context.block_dops_ctx.values())
    block_actual = sum(
        row[4] == "block-command-context" and row[10] == "-"
        for row in registrations
    )
    object_status = collections.Counter(row[8] for row in registrations)
    audit = {
        "expected_install_relations": len(expected),
        "actual_install_relations": len(actual),
        "missing_install_relations": len(missing),
        "extra_install_relations": len(extra),
        "registration_id_collisions": len(registration_ids) - len(set(registration_ids)),
        "summary_id_collisions": len(summary_ids) - len(set(summary_ids)),
        "block_context_expected": block_expected,
        "block_context_actual": block_actual,
        "dispatch_object_status": dict(sorted(object_status.items())),
    }
    if missing or extra:
        raise RuntimeError(
            f"install seed conservation failed: missing={missing[:5]} extra={extra[:5]}")
    if audit["registration_id_collisions"] or audit["summary_id_collisions"]:
        raise RuntimeError(f"stable ID collision: {audit}")
    if block_expected != block_actual:
        raise RuntimeError(
            f"block context conservation failed: {block_actual} != {block_expected}")
    return audit


def write_manifest(path, registrations, summaries, audit):
    registration_methods = collections.Counter(row[4] for row in registrations)
    registration_relations = collections.Counter(row[1] for row in registrations)
    summary_relations = collections.Counter(row[1] for row in summaries)
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "registration_seed_count": len(registrations),
        "registration_methods": dict(sorted(registration_methods.items())),
        "registration_relations": dict(sorted(registration_relations.items())),
        "api_summary_count": len(summaries),
        "api_summary_relations": dict(sorted(summary_relations.items())),
        "audit": audit,
    }
    with path.open("w") as out:
        json.dump(manifest, out, indent=2, sort_keys=True)
        out.write("\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--sh", default=DEFAULT_SH)
    args = parser.parse_args()

    root = Path(args.root).resolve()
    sh = Path(args.sh)
    if not sh.is_absolute():
        sh = root / sh
    with (sh / "horizon_model.json").open() as source:
        hm = json.load(source)

    reg_rows = build_reg_rows(str(sh))
    context = build_provenance_context(hm, reg_rows, str(root))
    reg_units = load_reg_units(sh)
    dispatch_symbols = {row[2] for row in reg_rows if row[2] != "-"}
    object_ids = load_global_object_ids(sh / "objects.tsv", dispatch_symbols)
    registrations = registration_rows(context, reg_units, object_ids)
    summaries = reg_field_summaries(reg_rows, reg_units, object_ids)
    summaries.extend(block_context_summaries(context))
    summaries.extend(cmd_summaries(sh / "kernel_facts_linked" / "cmd.tsv"))
    summaries = sorted(set(summaries))
    audit = validate(context, registrations, summaries)

    registration_path = sh / "registration_seeds.tsv"
    summary_path = sh / "api_summaries.tsv"
    manifest_path = sh / "recognizer_seed_manifest.json"
    write_tsv(registration_path, [
        "#seed_id", "relation", "root_kind", "root", "method", "dispatch_kind",
        "dispatch_object_id", "dispatch_symbol", "object_status", "batch", "reg_row",
        "fields", "subsystem", "source", "parent_root",
    ], registrations)
    write_tsv(summary_path, [
        "#summary_id", "relation", "subject_kind", "subject", "key", "target_kind",
        "target", "arg_index", "context", "source_fact", "source",
    ], summaries)
    write_manifest(manifest_path, registrations, summaries, audit)

    print(f"registration seeds={len(registrations)}")
    print(f"api summaries={len(summaries)}")
    print(f"install conservation={audit['actual_install_relations']} missing=0 extra=0")
    print(f"wrote {registration_path}")
    print(f"wrote {summary_path}")
    print(f"wrote {manifest_path}")


if __name__ == "__main__":
    main()

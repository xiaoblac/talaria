#!/usr/bin/env python3
import argparse
import collections
import json
from pathlib import Path


DEFAULT_SH = "run/seed_horizon"
SCHEMA_VERSION = 3

TABLES = {
    "objects.tsv": {
        "header": [
            "#object_id", "kind", "scope", "symbol", "parent_object", "byte_offset",
            "type", "contained_structs", "size", "batch", "function", "instruction",
            "debug", "detail",
        ],
        "kinds": {"global", "function", "stack", "unknown", "block", "null"},
    },
    "points_to_constraints.tsv": {
        "header": [
            "#constraint_id", "kind", "dst_value", "src_value", "object_id",
            "byte_offset", "offset_kind", "struct_type", "field_name", "batch",
            "function", "instruction", "opcode", "debug", "detail", "dynamic_base",
            "dynamic_stride", "dynamic_count", "source_type",
        ],
        "kinds": {
            "ADDR_OF", "COPY", "FIELD_ADDR", "FIELD_ADDR_DYNAMIC",
            "FIELD_ADDR_STRIDED", "UNKNOWN_ADDR",
        },
    },
    "memory_constraints.tsv": {
        "header": [
            "#constraint_id", "kind", "dst_value", "pointer_value", "src_value",
            "object_id", "byte_offset", "size", "batch", "function", "instruction",
            "opcode", "debug", "detail",
        ],
        "kinds": {"LOAD", "STORE", "STORE_OBJECT", "MEMCPY", "MEMMOVE"},
    },
    "call_constraints.tsv": {
        "header": [
            "#constraint_id", "kind", "callsite", "caller", "callee", "target_object",
            "index", "value", "result_value", "batch", "function", "instruction",
            "opcode", "attributes", "debug", "detail",
        ],
        "kinds": {
            "FUNCTION_FORMAL", "CALL_TARGET", "CALL_CALLEE_VALUE", "CALL_ACTUAL",
            "CALL_RESULT", "RETURN_VALUE",
        },
    },
}

OFFSET_KIND = {
    "ADDR_OF": "exact",
    "UNKNOWN_ADDR": "exact",
    "COPY": "-",
    "FIELD_ADDR": "constant",
    "FIELD_ADDR_DYNAMIC": "dynamic",
    "FIELD_ADDR_STRIDED": "strided",
}


def new_table_report(path):
    return {
        "path": str(path),
        "rows": 0,
        "columns": 0,
        "bad_column_rows": 0,
        "bad_column_samples": [],
        "kind_counts": collections.Counter(),
        "unexpected_kind_counts": collections.Counter(),
    }


def read_rows(path, expected_header, report):
    with path.open(errors="replace") as source:
        header = source.readline().rstrip("\n").split("\t")
        report["columns"] = len(header)
        report["header_matches"] = header == expected_header
        for line_number, line in enumerate(source, 2):
            row = line.rstrip("\n").split("\t")
            report["rows"] += 1
            if len(row) != len(expected_header):
                report["bad_column_rows"] += 1
                if len(report["bad_column_samples"]) < 5:
                    report["bad_column_samples"].append({
                        "line": line_number,
                        "columns": len(row),
                    })
                continue
            yield line_number, row


def count_kind(row, table_spec, report):
    kind = row[1]
    report["kind_counts"][kind] += 1
    if kind not in table_spec["kinds"]:
        report["unexpected_kind_counts"][kind] += 1


def audit_objects(path, table_spec, witness):
    report = new_table_report(path)
    report["scope_counts"] = collections.Counter()
    report["invariants"] = collections.Counter()
    report["type_evidence"] = collections.Counter()
    report["same_type_different_global_examples"] = []
    report["same_type_different_stack_examples"] = []
    first_global_type = {}
    first_stack_type = {}

    for _, row in read_rows(path, table_spec["header"], report):
        count_kind(row, table_spec, report)
        object_id, kind, scope, symbol = row[:4]
        object_type = row[6]
        contained = row[7]
        incomplete = contained.startswith("?")
        contained_value = contained[1:] if incomplete else contained
        report["scope_counts"][scope] += 1
        is_aggregate = object_type.startswith(("struct.", "anon_struct:", "array[", "vector["))
        report["type_evidence"]["aggregate_rows"] += is_aggregate
        report["type_evidence"]["incomplete_rows"] += incomplete
        report["type_evidence"]["contained_rows"] += contained_value not in {"", "-"}
        if contained_value not in {"", "-"}:
            tokens = contained_value.split(",")
            report["type_evidence"]["contained_tokens"] += len(tokens)
            report["invariants"]["contained_on_nonaggregate"] += not is_aggregate
            report["invariants"]["empty_contained_token"] += any(not token for token in tokens)
        if object_type.startswith("struct.") and not incomplete:
            expected = object_type[len("struct."):]
            report["invariants"]["named_struct_missing_self"] += (
                contained_value == "-" or expected not in contained_value.split(","))
        if kind == "unknown" and ":site:object:unknown:" not in object_id:
            report["invariants"]["unknown_id_mismatch"] += 1
        if kind == "stack" and ":site:object:stack:" not in object_id:
            report["invariants"]["stack_id_mismatch"] += 1
        if kind == "block" and ":site:object:block:" not in object_id:
            report["invariants"]["block_id_mismatch"] += 1

        if kind == "global" and object_type != "-":
            previous = first_global_type.setdefault(object_type, object_id)
            if previous != object_id and len(report["same_type_different_global_examples"]) < 6:
                report["same_type_different_global_examples"].append({
                    "type": object_type,
                    "first": previous,
                    "second": object_id,
                })
        if kind == "stack" and object_type != "-":
            previous = first_stack_type.setdefault(object_type, object_id)
            if previous != object_id and len(report["same_type_different_stack_examples"]) < 6:
                report["same_type_different_stack_examples"].append({
                    "type": object_type,
                    "first": previous,
                    "second": object_id,
                })

        if kind == "global" and symbol == witness["global"]:
            witness["global_object_ids"].add(object_id)
        if kind == "function" and symbol == witness["function"]:
            witness["function_object_ids"].add(object_id)
    return report


def audit_points(path, table_spec, witness):
    report = new_table_report(path)
    report["offset_kind_counts"] = collections.Counter()
    report["offset_kind_mismatches"] = collections.Counter()
    report["unknown"] = {
        "opcode_counts": collections.Counter(),
        "detail_counts": collections.Counter(),
        "global_initializer_rows": 0,
        "no_debug_rows": 0,
        "object_id_mismatches": 0,
    }
    report["dynamic"] = {
        "opcode_counts": collections.Counter(),
        "typed_rows": 0,
        "named_field_rows": 0,
        "no_debug_rows": 0,
        "missing_source_rows": 0,
    }
    report["strided"] = {
        "rows": 0,
        "invalid_rows": 0,
        "maximum_count": 0,
        "total_expansion": 0,
    }
    report["negative_offsets"] = {
        "rows": 0,
        "minimum": None,
        "maximum": None,
        "typed_rows": 0,
        "named_field_rows": 0,
        "at_most_negative_1_mib": 0,
        "samples": [],
    }
    report["block_address_seeds"] = 0
    report["block_address_non_addr_of"] = 0
    report["field_source_types"] = collections.Counter()

    for _, row in read_rows(path, table_spec["header"], report):
        count_kind(row, table_spec, report)
        kind = row[1]
        report["offset_kind_counts"][row[6]] += 1
        expected_offset_kind = OFFSET_KIND.get(kind)
        if expected_offset_kind is not None and row[6] != expected_offset_kind:
            report["offset_kind_mismatches"][kind] += 1
        if kind.startswith("FIELD_ADDR"):
            report["field_source_types"][row[18]] += 1

        if kind == "UNKNOWN_ADDR":
            report["unknown"]["opcode_counts"][row[12]] += 1
            report["unknown"]["detail_counts"][row[14]] += 1
            report["unknown"]["global_initializer_rows"] += row[10] == "-"
            report["unknown"]["no_debug_rows"] += row[13] == "-"
            report["unknown"]["object_id_mismatches"] += ":site:object:unknown:" not in row[4]
        elif kind == "FIELD_ADDR_DYNAMIC":
            report["dynamic"]["opcode_counts"][row[12]] += 1
            report["dynamic"]["typed_rows"] += row[7] != "-"
            report["dynamic"]["named_field_rows"] += row[8] != "-"
            report["dynamic"]["no_debug_rows"] += row[13] == "-"
            report["dynamic"]["missing_source_rows"] += row[3] == "-"
        elif kind == "FIELD_ADDR_STRIDED":
            strided = report["strided"]
            strided["rows"] += 1
            try:
                int(row[15])
                stride = int(row[16])
                count = int(row[17])
                if stride == 0 or count <= 0:
                    raise ValueError
                strided["maximum_count"] = max(strided["maximum_count"], count)
                strided["total_expansion"] += count
            except ValueError:
                strided["invalid_rows"] += 1
        elif kind == "FIELD_ADDR" and row[5].startswith("-"):
            try:
                offset = int(row[5])
            except ValueError:
                continue
            if offset < 0:
                negative = report["negative_offsets"]
                negative["rows"] += 1
                negative["minimum"] = offset if negative["minimum"] is None else min(
                    negative["minimum"], offset)
                negative["maximum"] = offset if negative["maximum"] is None else max(
                    negative["maximum"], offset)
                negative["typed_rows"] += row[7] != "-"
                negative["named_field_rows"] += row[8] != "-"
                negative["at_most_negative_1_mib"] += offset <= -(1024 * 1024)
                if len(negative["samples"]) < 8:
                    negative["samples"].append({
                        "offset": offset,
                        "struct_type": row[7],
                        "field_name": row[8],
                        "batch": row[9],
                        "function": row[10],
                        "instruction": row[11],
                        "debug": row[13],
                    })

        if row[12] == "blockaddress":
            report["block_address_seeds"] += 1
            report["block_address_non_addr_of"] += kind != "ADDR_OF"
        if kind == "ADDR_OF" and row[4] in (
                witness["global_object_ids"] | witness["function_object_ids"]):
            witness["address_seeds"].append({
                "constraint_id": row[0],
                "value": row[2],
                "object": row[4],
            })
    return report


def audit_memory(path, table_spec, witness):
    report = new_table_report(path)
    report["invariants"] = collections.Counter()
    report["negative_offset_rows"] = 0

    for _, row in read_rows(path, table_spec["header"], report):
        count_kind(row, table_spec, report)
        kind = row[1]
        if kind == "STORE_OBJECT":
            report["invariants"]["store_object_missing_source"] += row[4] == "-"
            report["invariants"]["store_object_missing_object"] += row[5] == "-"
        if kind in {"LOAD", "STORE"}:
            report["invariants"]["load_store_missing_pointer"] += row[3] == "-"
        if kind in {"MEMCPY", "MEMMOVE"}:
            report["invariants"]["memory_transfer_missing_pointer"] += (
                row[2] == "-" or row[3] == "-")
        try:
            report["negative_offset_rows"] += int(row[6]) < 0
        except ValueError:
            pass

        if (kind == "STORE_OBJECT" and row[5] in witness["global_object_ids"]
                and row[4].endswith(":function:" + witness["function"])
                and row[6] == str(witness["offset"])):
            witness["stores"].append({
                "constraint_id": row[0],
                "source_value": row[4],
                "object": row[5],
                "offset": int(row[6]),
                "size": int(row[7]),
                "detail": row[13],
            })
    return report


def audit_calls(path, table_spec):
    report = new_table_report(path)
    report["invariants"] = collections.Counter()

    for _, row in read_rows(path, table_spec["header"], report):
        count_kind(row, table_spec, report)
        kind = row[1]
        if kind == "CALL_TARGET":
            report["invariants"]["target_missing_callsite"] += row[2] == "-"
            report["invariants"]["target_object_mismatch"] += ":object:function:" not in row[5]
        elif kind == "CALL_CALLEE_VALUE":
            report["invariants"]["callee_value_missing"] += row[2] == "-" or row[7] == "-"
        elif kind == "CALL_ACTUAL":
            report["invariants"]["actual_missing"] += (
                row[2] == "-" or row[6] == "-" or row[7] == "-")
        elif kind == "FUNCTION_FORMAL":
            report["invariants"]["formal_missing"] += (
                row[4] == "-" or row[6] == "-" or row[7] == "-")
        elif kind == "CALL_RESULT":
            report["invariants"]["result_missing"] += row[2] == "-" or row[8] == "-"
        elif kind == "RETURN_VALUE":
            report["invariants"]["return_missing"] += row[4] == "-" or row[7] == "-"
    return report


def plain(value):
    if isinstance(value, collections.Counter):
        return dict(sorted(value.items()))
    if isinstance(value, dict):
        return {key: plain(item) for key, item in sorted(value.items())}
    if isinstance(value, list):
        return [plain(item) for item in value]
    if isinstance(value, set):
        return sorted(value)
    return value


def collect_errors(report, manifest):
    errors = []
    manifest_counts = manifest.get("counts", {})
    for name, table in report["tables"].items():
        if not table["header_matches"]:
            errors.append(f"{name}: header mismatch")
        if table["bad_column_rows"]:
            errors.append(f"{name}: {table['bad_column_rows']} bad-column rows")
        if table["unexpected_kind_counts"]:
            errors.append(f"{name}: unexpected kinds {dict(table['unexpected_kind_counts'])}")
        if name in manifest_counts and table["rows"] != manifest_counts[name]:
            errors.append(
                f"{name}: row count {table['rows']} != manifest {manifest_counts[name]}")

    points = report["tables"]["points_to_constraints.tsv"]
    if points["offset_kind_mismatches"]:
        errors.append(f"points_to_constraints.tsv: offset kind mismatches")
    if points["unknown"]["object_id_mismatches"]:
        errors.append("points_to_constraints.tsv: unknown object ID mismatch")
    if points["dynamic"]["missing_source_rows"]:
        errors.append("points_to_constraints.tsv: dynamic GEP missing source")
    if points["strided"]["invalid_rows"]:
        errors.append("points_to_constraints.tsv: invalid strided GEP metadata")
    if points["block_address_non_addr_of"]:
        errors.append("points_to_constraints.tsv: non-ADDR_OF BlockAddress seed")

    for name in ("objects.tsv", "memory_constraints.tsv", "call_constraints.tsv"):
        invariants = report["tables"][name].get("invariants", {})
        if any(invariants.values()):
            errors.append(f"{name}: invariant failures {dict(invariants)}")

    witness = report["witness"]
    for key in ("global_object_ids", "function_object_ids", "address_seeds", "stores"):
        if not witness[key]:
            errors.append(f"witness: missing {key}")
    return errors


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--sh", default=DEFAULT_SH)
    parser.add_argument("--out", default="constraint_audit.json")
    parser.add_argument("--witness-global", default="tun_fops")
    parser.add_argument("--witness-function", default="tun_chr_ioctl")
    parser.add_argument("--witness-offset", type=int, default=80)
    args = parser.parse_args()

    root = Path(args.root).resolve()
    sh = Path(args.sh)
    if not sh.is_absolute():
        sh = root / sh
    output = Path(args.out)
    if not output.is_absolute():
        output = sh / output

    witness = {
        "global": args.witness_global,
        "function": args.witness_function,
        "offset": args.witness_offset,
        "global_object_ids": set(),
        "function_object_ids": set(),
        "address_seeds": [],
        "stores": [],
    }
    with (sh / "constraint_manifest.json").open() as source:
        manifest = json.load(source)

    reports = {}
    reports["objects.tsv"] = audit_objects(sh / "objects.tsv", TABLES["objects.tsv"], witness)
    reports["points_to_constraints.tsv"] = audit_points(
        sh / "points_to_constraints.tsv", TABLES["points_to_constraints.tsv"], witness)
    reports["memory_constraints.tsv"] = audit_memory(
        sh / "memory_constraints.tsv", TABLES["memory_constraints.tsv"], witness)
    reports["call_constraints.tsv"] = audit_calls(
        sh / "call_constraints.tsv", TABLES["call_constraints.tsv"])

    report = {
        "schema_version": SCHEMA_VERSION,
        "manifest_batch_count": manifest.get("batch_count"),
        "total_rows": sum(table["rows"] for table in reports.values()),
        "tables": reports,
        "witness": witness,
    }
    report["errors"] = collect_errors(report, manifest)
    serializable = plain(report)
    with output.open("w") as out:
        json.dump(serializable, out, indent=2, sort_keys=True)
        out.write("\n")

    print(f"audited rows={report['total_rows']} errors={len(report['errors'])}")
    for name, table in reports.items():
        print(f"{name} rows={table['rows']} bad_columns={table['bad_column_rows']}")
    print(f"wrote {output}")
    if report["errors"]:
        for error in report["errors"]:
            print(f"ERROR {error}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()

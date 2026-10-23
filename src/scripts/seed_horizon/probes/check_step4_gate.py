#!/usr/bin/env python3
import argparse
import collections
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile


REPORT_SCHEMA_VERSION = 1

PASS = "PASS"
FAIL = "FAIL"
NOT_RUN = "NOT_RUN"

CORE_ARTIFACTS = {
    "points_to.tsv": ["#value", "object"],
    "memory_points_to.tsv": ["#object", "target"],
    "indirect_call_targets.tsv": ["#callsite", "function_object", "function"],
    "fixpoint_derivations.tsv": [
        "#node", "object", "rule", "predecessor_node", "predecessor_object", "source",
    ],
}

CALL_TRANSFER_HEADER = [
    "#transfer_id", "kind", "callsite", "caller", "caller_context", "callee",
    "callee_context", "mode", "status", "expected_arg_flows", "emitted_arg_flows",
    "expected_return_flows", "emitted_return_flows", "reason", "source",
]

CALL_ARG_HEADER = [
    "#transfer_id", "callsite", "caller_context", "actual", "callee", "callee_context",
    "formal", "index", "source",
]

CALL_RETURN_HEADER = [
    "#transfer_id", "callsite", "caller_context", "callee", "callee_context",
    "return_value", "result_value", "source",
]

SUMMARY_RELATION_HEADER = [
    "#relation_id", "kind", "subject", "key", "target", "source",
]

SUMMARY_CENSUS_HEADER = [
    "#kind", "input_rows", "emitted_relations", "duplicate_rows", "unresolved_rows",
]

ACTIVATION_HEADER = [
    "#table", "kind", "loaded", "never_source_reached", "reached_not_executed",
    "executed_produced_new", "executed_no_new", "executions", "new_tuple_events",
    "duplicate_events", "policy_drop_events", "unresolved_events",
]

OBLIGATION_HEADER = [
    "#rule", "obligations", "satisfied", "policy_dispositions", "unresolved",
    "violations",
]

VIOLATION_HEADER = [
    "#obligation_id", "rule", "constraint_id", "premise", "detail",
]

DISPOSITION_HEADER = [
    "#obligation_id", "rule", "constraint_id", "reason", "source",
]

REQUIRED_OBLIGATION_RULES = {
    "ADDR_OF",
    "UNKNOWN_ADDR",
    "COPY",
    "FIELD_ADDR",
    "FIELD_ADDR_STRIDED",
    "FIELD_ADDR_DYNAMIC",
    "LOAD",
    "STORE",
    "STORE_OBJECT",
    "MEMCPY",
    "MEMMOVE",
    "CALL_TARGET",
    "CALL_ARGUMENT",
    "CALL_RETURN",
    "DISPATCH_SUMMARY",
    "SELECTOR_SUMMARY",
}

DETERMINISTIC_FILES = [
    "points_to.tsv",
    "memory_points_to.tsv",
    "indirect_call_targets.tsv",
    "call_transfer_map.tsv",
    "call_arg_flows.tsv",
    "call_return_flows.tsv",
    "dispatch_summary_relations.tsv",
    "selector_summary_relations.tsv",
    "summary_relation_census.tsv",
    "constraint_activation_census.tsv",
    "fixpoint_obligation_census.tsv",
    "fixpoint_violations.tsv",
    "policy_dispositions.tsv",
    "unresolved_relation_frontier.tsv",
]


class GateDataError(RuntimeError):
    pass


def check(name, status, summary, details=None):
    return {
        "name": name,
        "status": status,
        "summary": summary,
        "details": details or {},
    }


def parse_nonnegative(value, path, line_number, column):
    try:
        parsed = int(value)
    except ValueError as error:
        raise GateDataError(
            f"{path}:{line_number}: {column} is not an integer: {value!r}"
        ) from error
    if parsed < 0:
        raise GateDataError(
            f"{path}:{line_number}: {column} is negative: {parsed}"
        )
    return parsed


def iter_tsv(path, expected_header):
    if not path.is_file():
        raise GateDataError(f"missing artifact: {path}")
    with path.open(errors="replace") as source:
        header = source.readline().rstrip("\n").split("\t")
        if header != expected_header:
            raise GateDataError(
                f"{path}: header mismatch: expected {expected_header}, got {header}"
            )
        for line_number, line in enumerate(source, 2):
            row = line.rstrip("\n").split("\t")
            if len(row) != len(expected_header):
                raise GateDataError(
                    f"{path}:{line_number}: expected {len(expected_header)} columns, "
                    f"got {len(row)}"
                )
            yield line_number, row


def read_json(path):
    if not path.is_file():
        raise GateDataError(f"missing artifact: {path}")
    try:
        with path.open() as source:
            return json.load(source)
    except (json.JSONDecodeError, OSError) as error:
        raise GateDataError(f"cannot read JSON {path}: {error}") from error


def count_tsv_rows(path, expected_header):
    return sum(1 for _ in iter_tsv(path, expected_header))


def check_stats_contract(result_dir):
    path = result_dir / "fixpoint_stats.json"
    try:
        stats = read_json(path)
        policy = stats["policy"]
        inputs = stats["input"]
        solver = stats["solver"]
    except (GateDataError, KeyError, TypeError) as error:
        return check("global_stats_contract", FAIL, str(error)), None

    failures = []
    if stats.get("batch") != "all":
        failures.append(f"batch={stats.get('batch')!r}, expected 'all'")
    if policy.get("value_slice") != "all":
        failures.append(
            f"policy.value_slice={policy.get('value_slice')!r}, expected 'all'"
        )
    if inputs.get("object_schema_version") != 3:
        failures.append(
            "input.object_schema_version="
            f"{inputs.get('object_schema_version')!r}, expected 3"
        )
    pending = solver.get("pending_tuples")
    if pending != 0:
        failures.append(f"solver.pending_tuples={pending!r}, expected 0")
    if solver.get("truncated") is not False:
        failures.append(
            f"solver.truncated={solver.get('truncated')!r}, expected false"
        )
    value_tuples = solver.get("value_tuples")
    memory_tuples = solver.get("memory_tuples")
    tuples = solver.get("tuples")
    if not all(isinstance(value, int) and value >= 0
               for value in (value_tuples, memory_tuples, tuples)):
        failures.append("solver tuple counts must be non-negative integers")
    elif value_tuples + memory_tuples != tuples:
        failures.append(
            f"value_tuples + memory_tuples != tuples: "
            f"{value_tuples} + {memory_tuples} != {tuples}"
        )

    details = {
        "batch": stats.get("batch"),
        "value_slice": policy.get("value_slice"),
        "object_schema_version": inputs.get("object_schema_version"),
        "pending_tuples": pending,
        "truncated": solver.get("truncated"),
        "tuples": tuples,
    }
    if failures:
        details["failures"] = failures
        return check(
            "global_stats_contract", FAIL, "; ".join(failures), details
        ), stats
    return check(
        "global_stats_contract",
        PASS,
        "global schema-v3 value-slice=all run terminated without truncation",
        details,
    ), stats


def check_core_artifacts(result_dir):
    failures = []
    sizes = {}
    for name, header in CORE_ARTIFACTS.items():
        path = result_dir / name
        try:
            iterator = iter_tsv(path, header)
            first = next(iterator, None)
            if first is None:
                failures.append(f"{name} has no data rows")
            sizes[name] = path.stat().st_size
        except (GateDataError, OSError) as error:
            failures.append(str(error))
    if failures:
        return check(
            "core_relation_artifacts", FAIL, "; ".join(failures),
            {"failures": failures, "sizes": sizes},
        )
    return check(
        "core_relation_artifacts", PASS,
        "core points-to, memory, call-target, and derivation artifacts exist",
        {"sizes": sizes},
    )


def check_call_transfers(result_dir):
    map_path = result_dir / "call_transfer_map.tsv"
    arg_path = result_dir / "call_arg_flows.tsv"
    return_path = result_dir / "call_return_flows.tsv"
    try:
        arg_counts = collections.Counter()
        return_counts = collections.Counter()
        arg_rows = 0
        return_rows = 0
        for _, row in iter_tsv(arg_path, CALL_ARG_HEADER):
            arg_counts[row[0]] += 1
            arg_rows += 1
        for _, row in iter_tsv(return_path, CALL_RETURN_HEADER):
            return_counts[row[0]] += 1
            return_rows += 1

        transfers = {}
        status_counts = collections.Counter()
        mode_counts = collections.Counter()
        failures = []
        for line_number, row in iter_tsv(map_path, CALL_TRANSFER_HEADER):
            transfer_id = row[0]
            if transfer_id in transfers:
                failures.append(
                    f"{map_path}:{line_number}: duplicate transfer_id {transfer_id}"
                )
                continue
            kind, mode, status, reason = row[1], row[7], row[8], row[13]
            if kind not in {"direct", "indirect"}:
                failures.append(
                    f"{map_path}:{line_number}: invalid kind {kind!r}"
                )
            expected_args = parse_nonnegative(
                row[9], map_path, line_number, "expected_arg_flows"
            )
            emitted_args = parse_nonnegative(
                row[10], map_path, line_number, "emitted_arg_flows"
            )
            expected_returns = parse_nonnegative(
                row[11], map_path, line_number, "expected_return_flows"
            )
            emitted_returns = parse_nonnegative(
                row[12], map_path, line_number, "emitted_return_flows"
            )
            if emitted_args > expected_args:
                failures.append(
                    f"{transfer_id}: emitted {emitted_args} arg flows exceeds "
                    f"expected {expected_args}"
                )
            if emitted_returns > expected_returns:
                failures.append(
                    f"{transfer_id}: emitted {emitted_returns} return flows exceeds "
                    f"expected {expected_returns}"
                )
            if status == "active":
                if mode not in {"contextual", "context_insensitive"}:
                    failures.append(
                        f"{map_path}:{line_number}: active transfer has mode {mode!r}"
                    )
                if reason != "-":
                    failures.append(
                        f"{map_path}:{line_number}: active transfer has reason {reason!r}"
                    )
                if expected_args != emitted_args:
                    failures.append(
                        f"{transfer_id}: expected {expected_args} arg flows, "
                        f"reported {emitted_args}"
                    )
                if expected_returns != emitted_returns:
                    failures.append(
                        f"{transfer_id}: expected {expected_returns} return flows, "
                        f"reported {emitted_returns}"
                    )
            elif status == "no_pointer_interface":
                if any((expected_args, emitted_args, expected_returns, emitted_returns)):
                    failures.append(
                        f"{transfer_id}: no_pointer_interface transfer has flow counts"
                    )
                if reason == "-":
                    failures.append(f"{transfer_id}: no_pointer_interface has no reason")
            elif status == "unresolved":
                if reason == "-":
                    failures.append(f"{transfer_id}: unresolved transfer has no reason")
            else:
                failures.append(
                    f"{map_path}:{line_number}: invalid status {status!r}"
                )
            transfers[transfer_id] = {
                "status": status,
                "emitted_args": emitted_args,
                "emitted_returns": emitted_returns,
            }
            status_counts[status] += 1
            mode_counts[mode] += 1

        for transfer_id in arg_counts:
            if transfer_id not in transfers:
                failures.append(f"arg flow references unknown transfer {transfer_id}")
            elif transfers[transfer_id]["status"] == "no_pointer_interface":
                failures.append(
                    f"arg flow references no_pointer_interface transfer {transfer_id}"
                )
        for transfer_id in return_counts:
            if transfer_id not in transfers:
                failures.append(f"return flow references unknown transfer {transfer_id}")
            elif transfers[transfer_id]["status"] == "no_pointer_interface":
                failures.append(
                    f"return flow references no_pointer_interface transfer {transfer_id}"
                )
        for transfer_id, transfer in transfers.items():
            if arg_counts[transfer_id] != transfer["emitted_args"]:
                failures.append(
                    f"{transfer_id}: call_arg_flows has {arg_counts[transfer_id]} rows, "
                    f"map reports {transfer['emitted_args']}"
                )
            if return_counts[transfer_id] != transfer["emitted_returns"]:
                failures.append(
                    f"{transfer_id}: call_return_flows has "
                    f"{return_counts[transfer_id]} rows, "
                    f"map reports {transfer['emitted_returns']}"
                )
        if not transfers:
            failures.append("call_transfer_map.tsv has no transfer rows")
    except GateDataError as error:
        return check("call_transfer_conservation", FAIL, str(error))

    details = {
        "transfers": len(transfers),
        "arg_flows": arg_rows,
        "return_flows": return_rows,
        "status_counts": dict(sorted(status_counts.items())),
        "mode_counts": dict(sorted(mode_counts.items())),
    }
    if failures:
        details["failures"] = failures[:100]
        details["failure_count"] = len(failures)
        return check(
            "call_transfer_conservation", FAIL,
            f"{len(failures)} call-transfer conservation violation(s)", details,
        )
    return check(
        "call_transfer_conservation", PASS,
        "all call transfers and emitted argument/return flows are conserved", details,
    )


def check_summary_relations(result_dir):
    dispatch_path = result_dir / "dispatch_summary_relations.tsv"
    selector_path = result_dir / "selector_summary_relations.tsv"
    census_path = result_dir / "summary_relation_census.tsv"
    try:
        relation_counts = collections.Counter()
        relation_ids = set()
        failures = []
        for path in (dispatch_path, selector_path):
            for line_number, row in iter_tsv(path, SUMMARY_RELATION_HEADER):
                relation_id, kind = row[0], row[1]
                if relation_id in relation_ids:
                    failures.append(
                        f"{path}:{line_number}: duplicate relation_id {relation_id}"
                    )
                relation_ids.add(relation_id)
                relation_counts[kind] += 1

        census = {}
        for line_number, row in iter_tsv(census_path, SUMMARY_CENSUS_HEADER):
            kind = row[0]
            if kind in census:
                failures.append(
                    f"{census_path}:{line_number}: duplicate kind {kind}"
                )
                continue
            values = [
                parse_nonnegative(value, census_path, line_number, column)
                for value, column in zip(row[1:], SUMMARY_CENSUS_HEADER[1:])
            ]
            input_rows, emitted, duplicates, unresolved = values
            if input_rows != emitted + duplicates + unresolved:
                failures.append(
                    f"{kind}: input_rows {input_rows} != emitted {emitted} + "
                    f"duplicates {duplicates} + unresolved {unresolved}"
                )
            if relation_counts[kind] != emitted:
                failures.append(
                    f"{kind}: relation files contain {relation_counts[kind]} rows, "
                    f"census reports {emitted}"
                )
            census[kind] = {
                "input_rows": input_rows,
                "emitted_relations": emitted,
                "duplicate_rows": duplicates,
                "unresolved_rows": unresolved,
            }
        missing_kinds = {"dispatch_field", "context_field", "cmd_selector"} - census.keys()
        if missing_kinds:
            failures.append(
                "summary census missing kinds: " + ", ".join(sorted(missing_kinds))
            )
        extra_relation_kinds = relation_counts.keys() - census.keys()
        if extra_relation_kinds:
            failures.append(
                "relation rows missing from census: "
                + ", ".join(sorted(extra_relation_kinds))
            )
    except GateDataError as error:
        return check("summary_relation_conservation", FAIL, str(error))

    details = {
        "relations": len(relation_ids),
        "relation_counts": dict(sorted(relation_counts.items())),
        "census": census,
    }
    if failures:
        details["failures"] = failures
        return check(
            "summary_relation_conservation", FAIL,
            f"{len(failures)} summary conservation violation(s)", details,
        )
    return check(
        "summary_relation_conservation", PASS,
        "dispatch/context/cmd summaries are fully accounted", details,
    )


def check_constraint_activation(result_dir, stats):
    path = result_dir / "constraint_activation_census.tsv"
    try:
        failures = []
        keys = set()
        table_totals = collections.Counter()
        rows = 0
        for line_number, row in iter_tsv(path, ACTIVATION_HEADER):
            table, kind = row[0], row[1]
            key = (table, kind)
            if key in keys:
                failures.append(f"{path}:{line_number}: duplicate row {table}/{kind}")
                continue
            keys.add(key)
            values = [
                parse_nonnegative(value, path, line_number, column)
                for value, column in zip(row[2:], ACTIVATION_HEADER[2:])
            ]
            loaded, never_reached, reached_not_executed, produced, no_new = values[:5]
            if loaded != never_reached + reached_not_executed + produced + no_new:
                failures.append(
                    f"{table}/{kind}: loaded {loaded} != row-level states "
                    f"{never_reached + reached_not_executed + produced + no_new}"
                )
            table_totals[table] += loaded
            rows += 1

        expected = {
            "points_to_constraints": stats["input"]["point_rows"],
            "memory_constraints": stats["input"]["memory_rows"],
            "call_constraints": stats["input"]["call_rows"],
        }
        for table, expected_rows in expected.items():
            if table_totals[table] != expected_rows:
                failures.append(
                    f"{table}: census loaded {table_totals[table]}, "
                    f"fixpoint_stats input has {expected_rows}"
                )
        extra_tables = set(table_totals) - set(expected)
        if extra_tables:
            failures.append(
                "unexpected activation tables: " + ", ".join(sorted(extra_tables))
            )
        if not rows:
            failures.append("constraint activation census has no rows")
    except (GateDataError, KeyError, TypeError) as error:
        return check("constraint_activation_accounting", FAIL, str(error))

    details = {
        "rows": rows,
        "loaded_by_table": dict(sorted(table_totals.items())),
    }
    if failures:
        details["failures"] = failures
        return check(
            "constraint_activation_accounting", FAIL,
            f"{len(failures)} activation accounting violation(s)", details,
        )
    return check(
        "constraint_activation_accounting", PASS,
        "all input constraint rows are conserved in row-level activation states",
        details,
    )


def check_closure_certificate(result_dir):
    census_path = result_dir / "fixpoint_obligation_census.tsv"
    violations_path = result_dir / "fixpoint_violations.tsv"
    dispositions_path = result_dir / "policy_dispositions.tsv"
    unresolved_path = result_dir / "unresolved_relation_frontier.tsv"
    checker_stats_path = result_dir / "fixpoint_checker_stats.json"
    try:
        failures = []
        rules = set()
        totals = collections.Counter()
        for line_number, row in iter_tsv(census_path, OBLIGATION_HEADER):
            rule = row[0]
            if rule in rules:
                failures.append(f"{census_path}:{line_number}: duplicate rule {rule}")
                continue
            rules.add(rule)
            values = [
                parse_nonnegative(value, census_path, line_number, column)
                for value, column in zip(row[1:], OBLIGATION_HEADER[1:])
            ]
            obligations, satisfied, dispositions, unresolved, violations = values
            if obligations != satisfied + dispositions + unresolved + violations:
                failures.append(
                    f"{rule}: obligations {obligations} != terminal states "
                    f"{satisfied + dispositions + unresolved + violations}"
                )
            totals["obligations"] += obligations
            totals["satisfied"] += satisfied
            totals["policy_dispositions"] += dispositions
            totals["unresolved"] += unresolved
            totals["violations"] += violations

        missing_rules = REQUIRED_OBLIGATION_RULES - rules
        if missing_rules:
            failures.append(
                "obligation census missing rules: " + ", ".join(sorted(missing_rules))
            )
        violation_rows = count_tsv_rows(violations_path, VIOLATION_HEADER)
        disposition_rows = count_tsv_rows(dispositions_path, DISPOSITION_HEADER)
        unresolved_rows = count_tsv_rows(unresolved_path, DISPOSITION_HEADER)
        if violation_rows != totals["violations"]:
            failures.append(
                f"violation file has {violation_rows} rows, census reports "
                f"{totals['violations']}"
            )
        if disposition_rows != totals["policy_dispositions"]:
            failures.append(
                f"policy disposition file has {disposition_rows} rows, census reports "
                f"{totals['policy_dispositions']}"
            )
        if unresolved_rows != totals["unresolved"]:
            failures.append(
                f"unresolved frontier has {unresolved_rows} rows, census reports "
                f"{totals['unresolved']}"
            )

        checker_stats = read_json(checker_stats_path)
        if checker_stats.get("schema_version") != 1:
            failures.append(
                "fixpoint_checker_stats.schema_version must be 1"
            )
        if checker_stats.get("truncated") is not False:
            failures.append(
                f"fixpoint checker truncated={checker_stats.get('truncated')!r}"
            )
        for key in (
            "obligations", "satisfied", "policy_dispositions", "unresolved", "violations"
        ):
            if checker_stats.get(key) != totals[key]:
                failures.append(
                    f"checker stats {key}={checker_stats.get(key)!r}, "
                    f"census has {totals[key]}"
                )
        if totals["violations"]:
            failures.append(f"closure checker reports {totals['violations']} violation(s)")
    except (GateDataError, TypeError) as error:
        return check("independent_closure_certificate", FAIL, str(error))

    details = dict(totals)
    details["rules"] = len(rules)
    if failures:
        details["failures"] = failures
        return check(
            "independent_closure_certificate", FAIL,
            f"{len(failures)} closure certificate violation(s)", details,
        )
    return check(
        "independent_closure_certificate", PASS,
        "independent checker reports a complete zero-violation closure certificate",
        details,
    )


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while True:
            chunk = source.read(8 * 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def normalized_stats(path):
    stats = read_json(path)
    solver = dict(stats.get("solver", {}))
    solver.pop("load_seconds", None)
    solver.pop("solve_seconds", None)
    return {
        "batch": stats.get("batch"),
        "policy": stats.get("policy"),
        "input": stats.get("input"),
        "solver": solver,
    }


def check_determinism(result_dir, compare_dir):
    if compare_dir is None:
        return check(
            "deterministic_rerun", NOT_RUN,
            "no independent comparison directory supplied; use --compare for final gate",
        )
    try:
        if result_dir.resolve() == compare_dir.resolve():
            raise GateDataError("--compare must name an independent result directory")
        failures = []
        hashes = {}
        for name in DETERMINISTIC_FILES:
            first = result_dir / name
            second = compare_dir / name
            if not first.is_file() or not second.is_file():
                missing = [str(path) for path in (first, second) if not path.is_file()]
                failures.append("missing deterministic artifact(s): " + ", ".join(missing))
                continue
            first_hash = sha256_file(first)
            second_hash = sha256_file(second)
            hashes[name] = {"result": first_hash, "compare": second_hash}
            if first_hash != second_hash:
                failures.append(f"{name}: SHA-256 differs")
        if normalized_stats(result_dir / "fixpoint_stats.json") != normalized_stats(
            compare_dir / "fixpoint_stats.json"
        ):
            failures.append("normalized fixpoint_stats.json differs")
        first_checker = read_json(result_dir / "fixpoint_checker_stats.json")
        second_checker = read_json(compare_dir / "fixpoint_checker_stats.json")
        if first_checker != second_checker:
            failures.append("fixpoint_checker_stats.json differs")
    except (GateDataError, OSError) as error:
        return check("deterministic_rerun", FAIL, str(error))

    if failures:
        return check(
            "deterministic_rerun", FAIL,
            f"{len(failures)} deterministic comparison failure(s)",
            {"failures": failures, "hashes": hashes},
        )
    return check(
        "deterministic_rerun", PASS,
        "independent result directories have identical relation and census hashes",
        {"hashes": hashes},
    )


def evaluate_gate(result_dir, compare_dir=None):
    result_dir = Path(result_dir)
    compare_dir = Path(compare_dir) if compare_dir is not None else None
    checks = []

    stats_check, stats = check_stats_contract(result_dir)
    checks.append(stats_check)
    checks.append(check_core_artifacts(result_dir))
    checks.append(check_call_transfers(result_dir))
    checks.append(check_summary_relations(result_dir))
    if stats is None:
        checks.append(check(
            "constraint_activation_accounting", FAIL,
            "fixpoint_stats.json is unavailable, so input-row conservation cannot be checked",
        ))
    else:
        checks.append(check_constraint_activation(result_dir, stats))
    checks.append(check_closure_certificate(result_dir))
    checks.append(check_determinism(result_dir, compare_dir))

    failures = [item for item in checks if item["status"] == FAIL]
    not_run = [item for item in checks if item["status"] == NOT_RUN]
    if failures:
        overall = FAIL
        next_blocker = failures[0]["name"]
    elif not_run:
        overall = "INCOMPLETE"
        next_blocker = not_run[0]["name"]
    else:
        overall = PASS
        next_blocker = None
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "result_dir": str(result_dir),
        "compare_dir": str(compare_dir) if compare_dir is not None else None,
        "overall": overall,
        "next_blocker": next_blocker,
        "checks": checks,
    }


def print_report(report):
    print(f"Step 4 gate: {report['overall']}")
    for item in report["checks"]:
        print(f"[{item['status']:<7}] {item['name']}: {item['summary']}")
    if report["next_blocker"]:
        print(f"next blocker: {report['next_blocker']}")


def write_tsv(path, header, rows):
    with path.open("w") as out:
        out.write("\t".join(header) + "\n")
        for row in rows:
            out.write("\t".join(str(value) for value in row) + "\n")


def write_fixture(path):
    path.mkdir(parents=True)
    stats = {
        "batch": "all",
        "policy": {"value_slice": "all", "call_flow": "callsite"},
        "input": {
            "object_schema_version": 3,
            "point_rows": 2,
            "memory_rows": 1,
            "call_rows": 3,
        },
        "solver": {
            "tuples": 3,
            "value_tuples": 2,
            "memory_tuples": 1,
            "pending_tuples": 0,
            "truncated": False,
            "load_seconds": 1.0,
            "solve_seconds": 2.0,
        },
    }
    (path / "fixpoint_stats.json").write_text(json.dumps(stats, sort_keys=True))
    write_tsv(path / "points_to.tsv", CORE_ARTIFACTS["points_to.tsv"], [("v", "o")])
    write_tsv(
        path / "memory_points_to.tsv", CORE_ARTIFACTS["memory_points_to.tsv"],
        [("o", "f")],
    )
    write_tsv(
        path / "indirect_call_targets.tsv",
        CORE_ARTIFACTS["indirect_call_targets.tsv"],
        [("cs", "f", "handler")],
    )
    write_tsv(
        path / "fixpoint_derivations.tsv",
        CORE_ARTIFACTS["fixpoint_derivations.tsv"],
        [("v", "o", "ADDR_OF", "-", "-", "points:1")],
    )
    write_tsv(
        path / "call_transfer_map.tsv", CALL_TRANSFER_HEADER,
        [("t1", "direct", "cs", "caller", "baseline", "callee", "ctx:1",
          "contextual", "active", 1, 1, 1, 1, "-", "calls:1")],
    )
    write_tsv(
        path / "call_arg_flows.tsv", CALL_ARG_HEADER,
        [("t1", "cs", "baseline", "actual", "callee", "ctx:1", "formal", 0,
          "calls:2")],
    )
    write_tsv(
        path / "call_return_flows.tsv", CALL_RETURN_HEADER,
        [("t1", "cs", "baseline", "callee", "ctx:1", "returned", "result",
          "calls:3")],
    )
    write_tsv(
        path / "dispatch_summary_relations.tsv", SUMMARY_RELATION_HEADER,
        [
            ("d1", "dispatch_field", "ops", "ioctl", "handler", "api:1"),
            ("d2", "context_field", "ops", "open", "open_handler", "api:2"),
        ],
    )
    write_tsv(
        path / "selector_summary_relations.tsv", SUMMARY_RELATION_HEADER,
        [("s1", "cmd_selector", "dispatch", "1", "cmd_handler", "api:3")],
    )
    write_tsv(
        path / "summary_relation_census.tsv", SUMMARY_CENSUS_HEADER,
        [
            ("dispatch_field", 1, 1, 0, 0),
            ("context_field", 1, 1, 0, 0),
            ("cmd_selector", 1, 1, 0, 0),
        ],
    )
    write_tsv(
        path / "constraint_activation_census.tsv", ACTIVATION_HEADER,
        [
            ("points_to_constraints", "COPY", 2, 0, 0, 2, 0, 2, 2, 0, 0, 0),
            ("memory_constraints", "LOAD", 1, 0, 0, 1, 0, 1, 1, 0, 0, 0),
            ("call_constraints", "CALL_ACTUAL", 3, 0, 0, 3, 0, 3, 3, 0, 0, 0),
        ],
    )
    obligation_rows = []
    for rule in sorted(REQUIRED_OBLIGATION_RULES):
        if rule == "COPY":
            obligation_rows.append((rule, 1, 1, 0, 0, 0))
        else:
            obligation_rows.append((rule, 0, 0, 0, 0, 0))
    write_tsv(
        path / "fixpoint_obligation_census.tsv", OBLIGATION_HEADER, obligation_rows
    )
    write_tsv(path / "fixpoint_violations.tsv", VIOLATION_HEADER, [])
    write_tsv(path / "policy_dispositions.tsv", DISPOSITION_HEADER, [])
    write_tsv(path / "unresolved_relation_frontier.tsv", DISPOSITION_HEADER, [])
    checker_stats = {
        "schema_version": 1,
        "truncated": False,
        "obligations": 1,
        "satisfied": 1,
        "policy_dispositions": 0,
        "unresolved": 0,
        "violations": 0,
    }
    (path / "fixpoint_checker_stats.json").write_text(
        json.dumps(checker_stats, sort_keys=True)
    )


def check_status(report, name):
    return next(item["status"] for item in report["checks"] if item["name"] == name)


def run_selftest():
    tests = []
    with tempfile.TemporaryDirectory(prefix="step4_gate_test_") as temporary:
        root = Path(temporary)
        first = root / "first"
        second = root / "second"
        write_fixture(first)
        shutil.copytree(first, second)

        report = evaluate_gate(first, second)
        tests.append(("complete fixture passes", report["overall"] == PASS))

        report = evaluate_gate(first)
        tests.append(("missing rerun is incomplete", report["overall"] == "INCOMPLETE"))

        broken_pending = root / "broken_pending"
        shutil.copytree(first, broken_pending)
        stats = read_json(broken_pending / "fixpoint_stats.json")
        stats["solver"]["pending_tuples"] = 1
        (broken_pending / "fixpoint_stats.json").write_text(json.dumps(stats))
        report = evaluate_gate(broken_pending, second)
        tests.append((
            "pending tuples fail",
            report["overall"] == FAIL
            and check_status(report, "global_stats_contract") == FAIL,
        ))

        broken_transfer = root / "broken_transfer"
        shutil.copytree(first, broken_transfer)
        (broken_transfer / "call_transfer_map.tsv").unlink()
        report = evaluate_gate(broken_transfer, second)
        tests.append((
            "missing transfer map fails",
            report["overall"] == FAIL
            and check_status(report, "call_transfer_conservation") == FAIL,
        ))

        partial_transfer = root / "partial_transfer"
        shutil.copytree(first, partial_transfer)
        write_tsv(
            partial_transfer / "call_transfer_map.tsv", CALL_TRANSFER_HEADER,
            [("t1", "direct", "cs", "caller", "baseline", "callee", "ctx:1",
              "contextual", "unresolved", 2, 1, 1, 1, "missing_formal:1",
              "calls:1")],
        )
        tests.append((
            "partial unresolved transfer preserves emitted flows",
            check_call_transfers(partial_transfer)["status"] == PASS,
        ))

        broken_closure = root / "broken_closure"
        shutil.copytree(first, broken_closure)
        write_tsv(
            broken_closure / "fixpoint_violations.tsv", VIOLATION_HEADER,
            [("o1", "COPY", "p1", "Pt(v,o)", "missing Pt(dst,o)")],
        )
        report = evaluate_gate(broken_closure, second)
        tests.append((
            "closure violation fails",
            report["overall"] == FAIL
            and check_status(report, "independent_closure_certificate") == FAIL,
        ))

    failed = [name for name, passed in tests if not passed]
    for name, passed in tests:
        print(f"[{'PASS' if passed else 'FAIL'}] {name}")
    if failed:
        raise SystemExit(f"selftest failed: {', '.join(failed)}")


def main():
    parser = argparse.ArgumentParser(
        description="Check the machine-verifiable Step 4 points-to analysis gate."
    )
    parser.add_argument("result_dir", nargs="?", help="Step 4 result directory")
    parser.add_argument(
        "--compare", help="independent rerun directory for deterministic comparison"
    )
    parser.add_argument("--json-out", help="write the complete gate report as JSON")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()

    if args.selftest:
        run_selftest()
        return 0
    if not args.result_dir:
        parser.error("result_dir is required unless --selftest is used")

    report = evaluate_gate(args.result_dir, args.compare)
    print_report(report)
    if args.json_out:
        output = Path(args.json_out)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return 0 if report["overall"] == PASS else 1


if __name__ == "__main__":
    sys.exit(main())

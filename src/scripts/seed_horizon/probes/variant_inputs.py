#!/usr/bin/env python3
import argparse
import collections
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from model.query_input import build_variant_input_model


DEFAULT_SH = "run/seed_horizon"


def json_cell(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def write_inputs(path, model):
    with path.open("w") as out:
        out.write(
            "#variant\tcall_name\tquery_kind\toperation_field\toperation_status\t"
            "input_resources\toutput_resources\tall_resources\tgrammar_consts\t"
            "constraint_count\tselector_count\tconstructor_count\tpath_count\t"
            "producer_branch_count\tgap_count\n"
        )
        for name in sorted(model.queries):
            query = model.queries[name]
            roles = collections.Counter(row["role"] for row in query.constraints)
            selector_count = sum(
                count for role, count in roles.items() if role.startswith("dispatch_selector")
            )
            out.write("\t".join([
                query.name,
                query.call_name,
                query.query_kind,
                query.operation_field or "-",
                query.operation_status,
                json_cell(query.input_resources),
                json_cell(query.output_resources),
                json_cell(query.all_resources),
                json_cell(query.grammar_consts),
                str(len(query.constraints)),
                str(selector_count),
                str(roles["constructor_constraint"]),
                str(roles["path_constraint"]),
                str(query.producer_branch_count),
                str(len(query.gaps)),
            ]) + "\n")


def write_producers(path, model):
    rows = 0
    with path.open("w") as out:
        out.write(
            "#variant\tresource_role\taccepted_resource\tproduced_resource\t"
            "producer_variant\tcompatibility\tsource\n"
        )
        for name in sorted(model.queries):
            query = model.queries[name]
            for resource in query.output_resources:
                out.write("\t".join([
                    name, "output", resource, resource, name, "self",
                    "horizon_model.json:syscalls.produces",
                ]) + "\n")
                rows += 1
            for accepted in query.input_resources:
                compatible = model.compatible_producers.get(accepted, ())
                if not compatible:
                    out.write("\t".join([
                        name, "input", accepted, "-", "-", "no-catalog-producer",
                        "horizon_model.json:resources.kind+syscalls.produces",
                    ]) + "\n")
                    rows += 1
                    continue
                for produced, producer in compatible:
                    out.write("\t".join([
                        name,
                        "input",
                        accepted,
                        produced,
                        producer,
                        "exact" if accepted == produced else "subtype",
                        "horizon_model.json:resources.kind+syscalls.produces",
                    ]) + "\n")
                    rows += 1
    return rows


def write_selectors(path, model):
    rows = 0
    with path.open("w") as out:
        out.write(
            "#variant\trole\tselector\tfield_path\tvalue_kind\tvalue\tstatus\t"
            "bitmask\ttype_id\ttype_name\tgrammar_evidence\tsource\n"
        )
        for name in sorted(model.queries):
            for row in model.queries[name].constraints:
                out.write("\t".join([
                    name,
                    row["role"],
                    row["selector"],
                    row["field_path"],
                    row["value_kind"],
                    json_cell(row["value"]),
                    row["status"],
                    "yes" if row["bitmask"] else "no",
                    str(row["type_id"]),
                    json_cell(row["type_name"]),
                    row["grammar_evidence"],
                    row["source"],
                ]) + "\n")
                rows += 1
    return rows


def write_gaps(path, model):
    rows = 0
    with path.open("w") as out:
        out.write("#variant\tstage\tsubject\tstatus\tdetail\tsource\n")
        for name in sorted(model.queries):
            for row in model.queries[name].gaps:
                out.write("\t".join([
                    name,
                    row["stage"],
                    row["subject"],
                    row["status"],
                    row["detail"],
                    row["source"],
                ]) + "\n")
                rows += 1
    return rows


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

    model = build_variant_input_model(hm, str(sh), str(root))
    if len(model.queries) != len(hm.get("syscalls", [])):
        raise RuntimeError(
            f"variant input conservation failed: {len(model.queries)} != {len(hm.get('syscalls', []))}"
        )

    inputs = sh / "variant_inputs.tsv"
    producers = sh / "variant_producers.tsv"
    selectors = sh / "variant_selectors.tsv"
    gaps = sh / "variant_input_gaps.tsv"
    write_inputs(inputs, model)
    producer_rows = write_producers(producers, model)
    selector_rows = write_selectors(selectors, model)
    gap_rows = write_gaps(gaps, model)

    query_kinds = collections.Counter(query.query_kind for query in model.queries.values())
    print(f"variant inputs={len(model.queries)}")
    print(f"producer branches={producer_rows}")
    print(f"selector/constraint facts={selector_rows}")
    print(f"input gaps={gap_rows}")
    for kind, count in sorted(query_kinds.items()):
        print(f"query_kind {kind}={count}")
    print(f"wrote {inputs}")
    print(f"wrote {producers}")
    print(f"wrote {selectors}")
    print(f"wrote {gaps}")


if __name__ == "__main__":
    main()

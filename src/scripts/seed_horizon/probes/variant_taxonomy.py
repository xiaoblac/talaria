#!/usr/bin/env python3
# Copyright 2026 reFuzz project author -------youngkk.
#
# CLI report for pure variant taxonomy.
import argparse
import collections
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from model.variant import *  # re-exported for older probes that import helpers here
from provenance.context import build_provenance_context


def top(xs, limit=5):
    xs = sorted(str(x) for x in xs if x and x != "-")
    if not xs:
        return "-"
    return ",".join(xs[:limit]) + ("..." if len(xs) > limit else "")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sh", default=SH)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    sh = args.sh
    out = args.out or os.path.join(sh, "variant_taxonomy.tsv")
    hm = json.load(open(os.path.join(sh, "horizon_model.json")))
    consts = load_consts()
    variant_consts = load_variant_consts(sh)
    syscall_bases = build_cmd_syscall_bases(sh)
    reg_rows = build_reg_rows(sh)
    prov = build_provenance_context(hm, reg_rows, ".")
    specs = build_variant_specs(hm, variant_consts, syscall_bases, prov.specific, prov.res_kinds, ".")

    rows = []
    counters = collections.defaultdict(collections.Counter)
    for spec in specs.values():
        entry_rows = prov.context_rows(
            spec.produced_resources if spec.base in OPEN_BASES else spec.resources,
            spec.name)
        ops_hits = sorted({reg_rows[row][2] for row in entry_rows})
        entries = sorted({reg_rows[row][3].get(spec.field) for row in entry_rows
                          if spec.field and reg_rows[row][3].get(spec.field)})
        suffix_const = cval(spec.suffix, consts, spec.base)
        inner_const = cval(spec.inner, consts, spec.base) if spec.inner else None
        reason = taxonomy_reason(spec, consts)
        rows.append([
            spec.name, spec.base, spec.suffix or "-", spec.auto_kind, spec.inner or "-",
            spec.intent, reason,
            "-" if suffix_const is None else str(suffix_const),
            "-" if inner_const is None else str(inner_const),
            "-" if spec.discriminant is None else str(spec.discriminant),
            str(len(spec.specific_resources)), top(spec.specific_resources),
            str(len(entry_rows)), top(ops_hits),
            str(len(entries)), top(entries),
        ])
        counters["auto_kind"][spec.auto_kind] += 1
        counters["intent"][spec.intent] += 1
        counters["reason"][reason] += 1

    with open(out, "w") as f:
        f.write("#variant\tbase\tsuffix\tauto_kind\tinner\tintent\treason\t"
                "suffix_const\tinner_const\tcmd_discriminant\tn_specific_resources\t"
                "specific_resources\tn_anchor_rows\tops_name_hits\tn_entry_handlers\tentry_handlers\n")
        for r in rows:
            f.write("\t".join(r) + "\n")

    print(f"# wrote {len(rows)} variant taxonomy rows -> {out}")
    for name in ("auto_kind", "intent", "reason"):
        print(f"# {name}:")
        for k, n in counters[name].most_common():
            print(f"#   {k}\t{n}")


if __name__ == "__main__":
    main()

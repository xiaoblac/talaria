#!/usr/bin/env python3
# Copyright 2026 reFuzz project author -------youngkk.
#
# Candidate-set funnel report.
import collections
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from resolve.candidates import build_candidate_run

SH = "run/seed_horizon"


def top(xs, limit=3):
    xs = sorted(str(x) for x in xs if x and x != "-")
    if not xs:
        return "-"
    return ",".join(xs[:limit]) + ("..." if len(xs) > limit else "")


def size_bucket(n):
    if n <= 1:
        return str(n)
    if n <= 5:
        return str(n)
    return "6+"


def main():
    run = build_candidate_run(SH, ".")
    out = open(f"{SH}/candidate_trace.tsv", "w")
    out.write("#variant\tbase\tauto_kind\tintent\tn_ctx_res\tctx_res\tn_anchor\t"
              "n_entry\tentry\thas_disc\tn_final\tfinal_size_bucket\tfinal\t"
              "resolver_pass\tfail_stage\tfail_class\tconfidence\n")

    fail_stage = collections.Counter()
    fail_class = collections.Counter()
    intent_ct = collections.Counter()
    final_size_ct = collections.Counter()
    gap_anchor_res = collections.Counter()
    all_ctx_res = set()

    for rec in run.records.values():
        spec = rec.spec
        all_ctx_res.update(spec.specific_resources)
        intent_ct[spec.intent] += 1
        fail_stage[rec.fail_stage] += 1
        fail_class[rec.fail_class] += 1
        final_size_ct[size_bucket(len(rec.leaves))] += 1
        if rec.fail_stage == "s4_no_anchor":
            for r in spec.specific_resources:
                gap_anchor_res[r] += 1
        out.write("\t".join([
            spec.name, spec.base, spec.auto_kind, spec.intent,
            str(len(spec.specific_resources)), top(spec.specific_resources),
            str(len(rec.anchor_rows)), str(len(rec.entry_handlers)), top(rec.entry_handlers),
            "y" if spec.discriminant is not None else "n",
            str(len(rec.leaves)), size_bucket(len(rec.leaves)), top(rec.leaves),
            rec.resolver_pass, rec.fail_stage, rec.fail_class, rec.confidence,
        ]) + "\n")
    out.close()

    print(f"# candidate_trace.tsv: {len(run.records)} variants")
    print(f"# recursive fixpoint: {run.rounds} round(s), "
          f"{sum(1 for r in run.records.values() if r.entry_handlers)} dispatch specs")
    for i, sat in enumerate(run.per_round):
        print(f"#   round {i}: " + ", ".join(f"{X}={lab}(n={n})" for X, lab, n in sat))
    print(f"#   negative-cache: {sorted(run.neg_cache)}")
    print(f"# distinct specific fd/sock context resources in catalog: {len(all_ctx_res)}; "
          f"structurally anchored: {len(run.provenance.res2rows)}; "
          f"variant-scoped anchors: {len(run.provenance.variant2rows)}")
    print("\n# INTENT distribution:")
    for k, n in intent_ct.most_common():
        print(f"#   {k:26} {n}")
    print("\n# FAIL STAGE:")
    for k, n in fail_stage.most_common():
        print(f"#   {k:26} {n}")
    print("\n# FINAL CANDIDATE SET SIZE:")
    for k in ["0", "1", "2", "3", "4", "5", "6+"]:
        if final_size_ct.get(k):
            print(f"#   |final|={k:2} {final_size_ct[k]}")
    print("\n# TRUST CLASS:")
    for k, n in fail_class.most_common():
        print(f"#   {k:24} {n}")
    print("\n# model_gap_anchor — top resources:")
    for r, n in gap_anchor_res.most_common(15):
        print(f"#   {r:34} {n}")


if __name__ == "__main__":
    main()

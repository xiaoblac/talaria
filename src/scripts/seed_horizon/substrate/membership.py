# Copyright 2026 reFuzz project author -------youngkk.
# Generic (angle-independent): REGION MEMBERSHIP. Maps each kernel function to the set of variants
# whose value-narrowed region runs it (func2var), and each (handler, cmdval) to its specific variant
# (hc2var, the cmd-scoped shallow key). This is how an angle's handler-level facts get attributed to
# VARIANTS — every angle reuses it. fn-hub: a function in too many regions is shared infrastructure,
# not a region marker, and is dropped from deep attribution.
import collections
import json

from substrate.consts import cval

CMD_BASES = {"ioctl", "setsockopt", "getsockopt"}
VARIANT_GRAMMAR = "run/seed_horizon/variant_grammar.jsonl"


def load_variant_consts(path=VARIANT_GRAMMAR):
    out = {}
    for ln in open(path):
        d = json.loads(ln)
        out[d["name"]] = [int(x) & 0xFFFFFFFF for x in d.get("consts") or []]
    return out


def cmd_discriminant(v, variant_consts):
    base = v.split("$", 1)[0] if "$" in v else v
    vals = variant_consts.get(v, [])
    if base == "ioctl":
        return vals[0] if vals else None
    if base in ("setsockopt", "getsockopt"):
        return vals[1] if len(vals) >= 2 else None
    return None


def build_membership(bind, consts, fn_hub_cutoff=8, variant_consts=None):
    """bind: variant -> (handler, owned, roots, mode). Returns (func2var, hc2var, FUNC_HUB)."""
    if variant_consts is None:
        variant_consts = load_variant_consts()
    func2var = collections.defaultdict(set)
    hc2var = {}
    for v, t in bind.items():
        h, _owned, roots, mode = t
        if mode not in ("cmd", "genl", "fsmount"):
            continue
        for fn in {h} | {x for x in roots.split(",") if x}:
            func2var[fn].add(v)
        if mode == "cmd" and "$" in v:
            base = v.split("$", 1)[0]
            cv = cmd_discriminant(v, variant_consts) if base in CMD_BASES else cval(v.split("$", 1)[1], consts)
            if cv is not None:
                hc2var[(h, cv)] = v
    FUNC_HUB = {fn for fn, vs in func2var.items() if len(vs) > fn_hub_cutoff}
    return func2var, hc2var, FUNC_HUB

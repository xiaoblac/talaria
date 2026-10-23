# Copyright 2026 reFuzz project author -------youngkk.
# Generic (angle-independent): ATTRIBUTION + COUPLING — the producer⋈consumer join that turns any
# angle's facts into variant->variant edges. `attribute` maps handler/cmd-keyed facts to the variants
# that run them (deep via region membership, shallow via the cmd-scoped key). `couple` joins writers
# and readers on the angle's coupling KEY (same key == the angle's match fired), hub-deflattening the
# generic-state blob. This is the machinery the constant-equality angle paid many rounds to get right;
# every future angle inherits it untouched.
import collections


def attribute(fn_facts, hc_facts, func2var, hc2var, FUNC_HUB):
    """fn_facts: {handler -> set[key]} (attributed to func2var[handler], deep).
       hc_facts: {(handler,cmdval) -> set[key]} (attributed to hc2var, shallow/cmd-scoped).
       Returns: {key -> set[variant]}."""
    by_key = collections.defaultdict(set)
    for fn, keys in fn_facts.items():
        if fn not in FUNC_HUB:
            m = func2var.get(fn) or set()
            for k in keys:
                by_key[k] |= m           # touches by_key[k] even when m empty (matches monolith)
    for hckey, keys in hc_facts.items():
        v = hc2var.get(hckey)
        if v is not None:
            for k in keys:
                by_key[k].add(v)
    return by_key


def couple(writers, readers, field_hub):
    """writers/readers: {key -> set[variant]}. Same key on both sides == the angle's match fired.
       Returns (impl_unlocks: {V_A -> set[V_B]}, coupled_site_count)."""
    impl = collections.defaultdict(set)
    coupled = 0
    for k in set(writers) & set(readers):
        ws, rs = writers[k], readers[k]
        if len(ws | rs) > field_hub:     # generic-state hub -> not a specific coupling
            continue
        coupled += 1
        for a in ws:
            for b in rs:
                if a != b:
                    impl[a].add(b)
    return impl, coupled


def couple_detailed(writers, readers, field_hub):
    """Like couple(), but retains per-edge provenance for the confidence/leverage layer:
       edges: {(V_A, V_B) -> set[key]}  (the keys whose match produced this edge — corroboration)
       fanout_w: {key -> |writers[key]|}  (producer count, for key-rarity = 1/fanout)."""
    edges = collections.defaultdict(set)
    fanout_w = {}
    for k in set(writers) & set(readers):
        ws, rs = writers[k], readers[k]
        if len(ws | rs) > field_hub:
            continue
        fanout_w[k] = len(ws)
        for a in ws:
            for b in rs:
                if a != b:
                    edges[(a, b)].add(k)
    return edges, fanout_w

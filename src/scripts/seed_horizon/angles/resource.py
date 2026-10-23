# Copyright 2026 reFuzz project author -------youngkk.
#
# Angle E1: EXPLICIT resource dependency (fd / sock / handle produce->consume). Proves the template
# covers explicit edges too — they are just producer⋈consumer on a different KEY (the resource type)
# from a different FACT SOURCE (the syzkaller model, not an IR scan).
#   producer = a variant that PRODUCES resource r ;  consumer = a variant that CONSUMES/uses r
#   coupling key = the resource type r ;  facts are already variant-keyed -> skip attribute()
# Deflatten is the model's SPECIFIC predicate (ambient / >25-producer resources dropped), so this
# angle sets field_hub = inf (no extra |writers∪readers| cut — a resource with many consumers is a
# real fan-out, not a generic-state blob). Tier A: syzkaller-declared, high precision.
NAME = "resource"
FIELD_HUB = 10 ** 9       # already deflattened via model.specific(); no per-key consumer-count cut
BASE_PRECISION = 0.95     # declared dependency -> high Beta prior


class Resource:
    name = NAME
    field_hub = FIELD_HUB
    base_precision = BASE_PRECISION
    base_blindness = 0.15         # P(dynamic won't find it): fd deps are table-stakes — HEALER finds them
    resource_scoped = True        # the edge IS a resource -> trivially shares (cred always 1.0)

    def writers(self, ctx):       # key = resource r -> {variants producing r}
        return {r: set(vs) for r, vs in ctx.prod.items() if ctx.specific(r)}

    def readers(self, ctx):       # key = resource r -> {variants consuming r}
        return {r: set(vs) for r, vs in ctx.cons.items() if ctx.specific(r)}

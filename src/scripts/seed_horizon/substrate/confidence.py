# Copyright 2026 reFuzz project author -------youngkk.
#
# The CONFIDENCE + LEVERAGE layer — turns the federation's raw edges into the calibrated PRIOR the
# whole research bet rests on. Per edge:
#   * PRIOR  Beta(alpha,beta) from rho = noisy-OR of the base_precision of every angle that produced
#            the edge (cross-angle CORROBORATION: two independent lenses agreeing raise P(real)).
#   * LEVERAGE = key-rarity (1/#writers of the coupling key — few producers ⇒ the consumer has no
#            alternative ⇒ a strong, dynamically-blind dependency).  [depth × mass deferred to the
#            PC-bridge; until then leverage = rarity, documented, not faked.]
#   * WEIGHT = rho * leverage  — the prior×leverage used to SELECT the signal-bearing subset.
# This is the static PRIOR only; the dynamic Bayesian update (alpha/beta bumped by observed PC
# coverage of the predicted region) is the next layer. rho is a starting belief, never a verdict.
import collections

PRIOR_STRENGTH = 4.0      # k: weak Dirichlet strength so a few observations move the posterior

# The unified belief-graph EDGE — the single object static and dynamic share. Static DRAWS it (va,vb),
# LABELS its mechanism (types) + SOURCE, and sets the PRIOR (alpha,beta from rho); dynamic CALIBRATES
# (alpha,beta) via the Q_e fingerprint. ρ=α/(α+β) is the confluence; backward (this seed) and forward
# (other seeds, via the shared edge) are the same posterior. A namedtuple so adding fields never churns
# the index-positional unpacks in observe/report.
Edge = collections.namedtuple("Edge", "va vb types source rho alpha beta rarity blindness mass weight")
STATIC, DYNAMIC = "static", "dynamic"
DYNAMIC_MECH = "dynamic-unresolved"   # mechanism slot for couplings dynamic finds but static can't label
DYNAMIC_PRIOR = (1.0, 1.0)            # Beta(1,1): no static evidence -> uniform prior, earns belief by obs


def make_dynamic_edge(va, vb, rarity=0.5, blindness=0.9, mass=0.5):
    """A coupling DISCOVERED dynamically with NO static edge (the E8/E10-class gap: refcount/ordering/
       runtime-ops static couldn't resolve): source=dynamic, mechanism=dynamic-unresolved, WEAK uniform
       prior (no static structure -> must earn belief from observation). The MAB rework calls this to add
       the edge onto the SAME graph; observe.update then calibrates alpha/beta exactly like a static edge.
       (A later post-hoc recognizer MAY relabel the mechanism to a specific dynamic-only category.)"""
    a, b = DYNAMIC_PRIOR
    r = a / (a + b)
    return Edge(va, vb, DYNAMIC_MECH, DYNAMIC, r, a, b, rarity, blindness, mass, r * rarity * blindness * mass)


def _noisy_or(ps):
    q = 1.0
    for p in ps:
        q *= (1.0 - p)
    return 1.0 - q


MASS_K = 64       # saturation scale for region-size mass; +8 floor so inlined (0-PC) regions != 0


XRES_CRED = 0.1   # cross-resource value/pointer coupling = likely coincidental (struct-state needs a
                  # shared object); down-weight, don't delete (honest — kept in the graph, sunk in rank)


def build_graph_M(results, region_size=None, var_res=None, prior_strength=PRIOR_STRENGTH, mass_k=MASS_K):
    """results: {angle: {edges:{(a,b):set(key)}, fanout_w:{key:n}, precision:float, blindness:float}}.
       region_size: {variant -> #PCs} (PC-bridge) -> MASS factor. var_res: {variant -> specific
       resources} -> SAME-RESOURCE credibility (a struct-state coupling across variants that share NO
       kernel object is almost surely a coincidental (struct,off,V) collision — the cross-subsystem
       false edges that scale surfaced). Returns rows:
       (V_A, V_B, types, rho, alpha, beta, rarity, blindness, mass, weight).
       weight = rho * rarity * blindness * mass * cred. blindness = MIN over contributing angles."""
    scoped = {n for n, R in results.items() if R.get("resource_scoped", True)}   # need a shared object
    family = {n: R.get("family", n) for n, R in results.items()}   # same-mechanism sub-detector grouping
    edge_ang = collections.defaultdict(dict)    # (a,b) -> {angle: precision}
    edge_rar = collections.defaultdict(float)   # (a,b) -> best key-rarity
    edge_blind = {}                             # (a,b) -> min blindness
    for name, R in results.items():
        p, fw, bl = R["precision"], R["fanout_w"], R.get("blindness", 1.0)
        for ab, keys in R["edges"].items():
            edge_ang[ab][name] = p
            r = max((1.0 / fw[k] for k in keys if fw.get(k)), default=0.0)
            if r > edge_rar[ab]:
                edge_rar[ab] = r
            edge_blind[ab] = min(edge_blind.get(ab, 1.0), bl)
    rows = []
    for ab, angs in edge_ang.items():
        # same-mechanism sub-detectors (e.g. the value-state family const/dyn/pointer/relational fire on
        # the SAME field write⋈read facts) are NOT independent: combine WITHIN a family by max, then
        # noisy-OR ACROSS families (genuine independent mechanisms still corroborate).
        fam_max = {}
        for name, p in angs.items():
            f = family[name]
            if p > fam_max.get(f, 0.0):
                fam_max[f] = p
        rho = _noisy_or(fam_max.values())
        rarity, blind = edge_rar[ab], edge_blind[ab]
        sz = (region_size or {}).get(ab[1], 0)
        mass = (sz + 8) / (sz + 8 + mass_k)     # saturating, floored (inlined regions under-count)
        cred = 1.0
        # same-resource cred applies only to RESOURCE-SCOPED mechanisms (struct-state needs a shared
        # object); global-only edges are exempt (globals couple across resources by nature).
        if var_res is not None and any(n in scoped for n in angs):
            cred = 1.0 if (var_res.get(ab[0]) or set()) & (var_res.get(ab[1]) or set()) else XRES_CRED
        weight = rho * rarity * blind * mass * cred
        rows.append(Edge(ab[0], ab[1], "+".join(sorted(angs)), STATIC, rho,
                         prior_strength * rho, prior_strength * (1.0 - rho), rarity, blind, mass, weight))
    return rows


def write_graph_M(rows, path):
    rows = sorted(rows, key=lambda e: -e.weight)
    with open(path, "w") as f:
        f.write("#V_A\tV_B\ttypes\tsource\trho\talpha\tbeta\trarity\tblindness\tmass\tweight\n")
        for e in rows:
            f.write(f"{e.va}\t{e.vb}\t{e.types}\t{e.source}\t{e.rho:.4f}\t{e.alpha:.3f}\t{e.beta:.3f}\t"
                    f"{e.rarity:.4f}\t{e.blindness:.3f}\t{e.mass:.3f}\t{e.weight:.4f}\n")
    return rows

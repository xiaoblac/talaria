# Copyright 2026 reFuzz project author -------youngkk.
#
# The OBSERVATION MODEL + Beta update — the dynamic half that closes static-prior → in-loop-learning.
# Calibrates each edge A->B's Beta(alpha,beta) from coverage, but the EFFECT is measured on the
# FRONTIER (newly-covered PCs), NOT on cumulative coverage. Why: cumulative "B's region lit" is born
# noisy — background (scheduler/alloc/lock/VFS/printk) and B's own validation/error/cleanup paths are
# covered on nearly every run, so "lit" says almost nothing. The new-coverage frontier is born clean:
# background is covered in the first few programs and is NEVER new again; only deep, dependency-gated
# code shows up as new coverage late — which is exactly the unlock we want to credit. So the asymmetry:
#   precondition (A ran)  : A's region ∩ coverage      (cumulative — A merely has to EXECUTE)
#   effect (B deepened)   : B's region ∩ new_coverage  (FRONTIER — B reached NEW deep code)
#
#   CONFIRMED  alpha++ : A ran AND B produced new frontier inside its region.
#   REFUTED    beta++  : A ran, B still had UNCOVERED region, yet produced no new frontier (unlock dark).
#   EXHAUSTED  (skip)  : A ran but B's region is already saturated (or B has no region) — absence of
#                        frontier is meaningless, NOT a refutation (a mined-out edge is still real;
#                        its value decays through mass→0, not through a spurious rho penalty).
#   UNOBSERVED (skip)  : A never ran.
#
# For the causal in-loop version pass PER-PROGRAM sets: coverage = this program's coverage (A ran HERE),
# new_coverage = this program's first-seen PCs (the frontier), covered = the GLOBAL cumulative set (so the
# saturation guard knows what's mined out). Offline replay of an accumulated bitmap has no per-program
# delta; leaving new_coverage/covered as None degrades to cumulative semantics (the old co-occurrence
# behavior) purely so the offline demo still runs — that path conflates not-reached with refuted.


_EMPTY = frozenset()


def region_lit(pcs, coverage):
    return bool((pcs or _EMPTY) & coverage)


def update(rows, var_pcs, coverage, new_coverage=None, covered=None, lr=1.0):
    """rows: Edge namedtuples (any source). var_pcs: {variant -> set(PC)} (PC-bridge).
       coverage: set(PC) — precondition (A executed). new_coverage: set(PC) — this-program FRONTIER for
       the effect; None -> = coverage (offline degenerate). covered: set(PC) — GLOBAL cumulative for the
       saturation guard; None -> = coverage. Returns (updated_edges, stats). One code path serves static-
       and dynamic-source edges (the unification). The frontier effect makes "B deepened" background-free;
       the per-program precondition makes the refute causal."""
    if new_coverage is None:
        new_coverage = coverage
    if covered is None:
        covered = coverage
    out = []
    obs = conf = ref = exh = 0
    for e in rows:
        alpha, beta = e.alpha, e.beta
        if region_lit(var_pcs.get(e.va, _EMPTY), coverage):       # precondition: A executed
            obs += 1
            b_pcs = var_pcs.get(e.vb, _EMPTY)
            if region_lit(b_pcs, new_coverage):                   # effect: B reached NEW frontier
                alpha += lr
                conf += 1
            elif b_pcs - covered:                                 # B had uncovered room but stayed dark
                beta += lr
                ref += 1
            else:                                                 # B saturated / no region: not a refute
                exh += 1
        rho = alpha / (alpha + beta)
        # NOTE: weight still uses the static e.mass; the natural follow-on (now that `covered` is here)
        # is uncovered-mass = |region(B) - covered| — a region mined out should also lose forward value.
        out.append(e._replace(rho=rho, alpha=alpha, beta=beta,
                              weight=rho * e.rarity * e.blindness * e.mass))
    return out, dict(observed=obs, confirmed=conf, refuted=ref, exhausted=exh)

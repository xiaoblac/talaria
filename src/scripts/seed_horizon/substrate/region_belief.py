# Copyright 2026 reFuzz project author -------youngkk.
#
# The NODE-analog of the edge belief. A variant's REGION is not a fixed PC-set but a per-PC MEMBERSHIP
# belief — {pc: [alpha, beta, source]} — exactly the unification applied to nodes (mirroring the edge's
# Beta(alpha,beta)). Static SEEDS predicted PCs (a forward prior); per-call coverage CONFIRMS them,
# gently PRUNES static over-approximation, and RECOVERS PCs static missed (honest-0 / over-narrowed).
# region = static-predicted ∪ dynamically-observed, each PC tagged static|dynamic.
#
# CRITICAL: observe() takes PER-CALL coverage (the PCs from THIS variant's execution), NOT the program
# union — otherwise you can't attribute a PC to this node (syzkaller/reFuzz collect per-call coverage).
import collections

from substrate.confidence import STATIC, DYNAMIC

STATIC_SEED = (2.0, 1.0)    # static "in region": mild prior (rho0≈0.67), prunable by SUSTAINED non-coverage
DYNAMIC_SEED = (1.0, 1.0)   # a dynamically-recovered member: uniform, earns membership by repeat coverage
PRUNE_RATE = 0.25           # gentle beta bump for a static PC not covered THIS run. Absence != not-member
                            # (a rare value-path PC is real but unseen this run); only SUSTAINED
                            # non-coverage sinks a PC below threshold -> dead/over-approx PCs prune slowly.


class RegionBelief:
    def __init__(self):
        self.pc = {}                       # pc -> [alpha, beta, source]

    def seed_static(self, static_pcs):
        a, b = STATIC_SEED
        for p in static_pcs:
            self.pc.setdefault(p, [a, b, STATIC])
        return self

    def observe(self, covered_pcs):
        """ONE per-call execution of this variant. covered member -> alpha++ (confirm); static member not
           covered -> beta += PRUNE_RATE (gentle prune); covered non-member -> RECOVER (dynamic member)."""
        cov = set(covered_pcs)
        for p, st in self.pc.items():
            if p in cov:
                st[0] += 1.0
            elif st[2] == STATIC:
                st[1] += PRUNE_RATE
        for p in cov - self.pc.keys():
            self.pc[p] = [DYNAMIC_SEED[0] + 1.0, DYNAMIC_SEED[1], DYNAMIC]   # first sighting = a member
        return self

    def region(self, thresh=0.5):
        """The believed region: PCs whose membership rho = alpha/(alpha+beta) >= thresh."""
        return {p for p, (a, b, _s) in self.pc.items() if a / (a + b) >= thresh}

    def stats(self, thresh=0.5):
        return dict(pcs=len(self.pc),
                    static=sum(1 for v in self.pc.values() if v[2] == STATIC),
                    dynamic_recovered=sum(1 for v in self.pc.values() if v[2] == DYNAMIC),
                    believed_region=len(self.region(thresh)))


def recover_binding(covered_pcs):
    """honest-0 variant (NO static region): the per-call covered PCs ARE the region — pure dynamic
       recovery (source=dynamic), the node-analog of make_dynamic_edge. The static failure-LABEL guides
       which PCs to keep: dynamic-ops -> the ICALL-resolved fn's PCs; computed-cmd -> the per-arg-value
       covered PCs; callback-list -> the resolved callback's PCs. Here: seed nothing, observe once."""
    return RegionBelief().observe(covered_pcs)

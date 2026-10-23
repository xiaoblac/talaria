# Copyright 2026 reFuzz project author -------youngkk.
#
# The Angle plugin contract — the one seam that separates a static lens from the substrate.
#
# An angle is ONE hidden-dependency mechanism (one row of the catalog). The substrate does everything
# generic: fact-source iteration, region membership, attribution to variants, hub-deflatten, coupling,
# (later) the graph / confidence / PC-bridge / Bayesian update. An angle supplies ONLY its vocabulary —
# which raw IR facts are PRODUCERS, which are CONSUMERS, and the coupling KEY.
#
# Equality / identity / membership matches are expressed as "SAME KEY": the substrate joins producers
# and consumers on key identity, so an angle folds its match into the key (value-defuse keys by
# (loc, value); resource keys by resource-type; fptr keys by (fptr-field, callee)). A range/predicate
# match is the only case that needs a custom join (a future `couple_keys` override); the catalog's
# Tier-A angles are all same-key.
#
# To add an angle:
#   1. implement writer_facts(SH) and reader_facts(SH), each returning
#        (fn_facts:  {handler            -> set[key]},     # facts attributed via region membership (deep)
#         hc_facts:  {(handler, cmdval)  -> set[key]})     # facts attributed via the cmd-scoped key (shallow)
#   2. set name, field_hub (deflatten cutoff), base_precision (P(real | this lens), the Beta-prior tier)
#   3. register the instance in substrate/run_angles.py:ANGLES
# The substrate turns (writer_facts, reader_facts) into variant->variant edges; nothing else is angle code.

from typing import Protocol, Hashable, Dict, Set, Tuple


class Angle(Protocol):
    name: str
    field_hub: int          # drop coupling keys touched by > field_hub variants (the generic hub blob)
    base_precision: float    # P(real | this lens) in [0,1] -> the Beta prior for its edges

    def writer_facts(self, SH: str) -> Tuple[Dict[str, Set[Hashable]],
                                             Dict[Tuple[str, int], Set[Hashable]]]: ...

    def reader_facts(self, SH: str) -> Tuple[Dict[str, Set[Hashable]],
                                             Dict[Tuple[str, int], Set[Hashable]]]: ...

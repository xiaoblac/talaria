# Copyright 2026 reFuzz project author -------youngkk.
# substrate/ — the angle-INDEPENDENT machinery for the static seed-value M. Every static-analysis
# "angle" (value-defuse, container, fptr-install, pointer-null, resource, ...) is the SAME producer⋈
# consumer-on-a-typed-location detector, re-parameterized. The substrate owns all the hard-won generic
# parts (region membership, fact attribution, hub-deflatten, coupling, and later: the multi-relational
# graph, confidence/leverage, the PC-bridge, the Bayesian update). An angle (see angles/) supplies ONLY
# its vocabulary. See substrate/angle.py for the contract.

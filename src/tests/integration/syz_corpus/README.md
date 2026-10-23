# Phase B B3 — Tiered syzkaller text corpus

Backed by `020_phase_b_corpus_compatibility.md` §B3. Each tier maps to a
set of constructs the round-trip test must handle:

| tier | constructs | acceptance |
|---|---|---|
| `tier0/` | scalar args only, `r0 = call(...)` + plain calls | 0 unsupported |
| `tier1/` | tier0 + filename / buffer pointers, hex / negative ints | 0 unsupported |
| `tier2/` | tier1 + result-chain, native pseudo calls | only pseudo execution gaps allowed |
| `tier3/` | image / compressed / fs / usb / kvm pseudos | unsupported feature set must match `tier3_expected_unsupported.json` exactly |

`tier3_expected_unsupported.json` is a JSON array of feature-id strings (one of
`syz::diag::k*` from `syz_diagnostics.hpp`). The test asserts the **set** of
feature ids actually emitted equals this set. If a tier 3 file gains or loses
a feature, the JSON file must be updated with the same change.

The runner is `tests/integration/syz_corpus_round_trip_test.cpp`.

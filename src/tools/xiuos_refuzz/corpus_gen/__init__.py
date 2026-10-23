"""XiUOS reFuzz corpus generator.

Reads a descriptor (lifecycle + parameter domain), enumerates programs by
source-rule class, and emits SeedProgram metadata that matches `corpus.py`'s
loader contract. See docs/xiuos-refuzz/050_corpus_generation_method.md.
"""

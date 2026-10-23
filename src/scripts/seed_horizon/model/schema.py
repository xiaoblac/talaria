#!/usr/bin/env python3
# Copyright 2026 reFuzz project author -------youngkk.
#
# Shared data structures for the candidate-region model.
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class VariantSpec:
    name: str
    base: str
    suffix: str
    auto_kind: str
    inner: str
    intent: str
    resources: frozenset[str]
    produced_resources: frozenset[str]
    used_resources: frozenset[str]
    specific_resources: tuple[str, ...]
    field: str | None
    discriminant: int | None
    no_dispatch_reason: str | None


@dataclass
class CandidateRecord:
    spec: VariantSpec
    anchor_rows: set[int] = field(default_factory=set)
    entry_handlers: set[str] = field(default_factory=set)
    leaves: set[str] = field(default_factory=set)
    trace: list[Any] = field(default_factory=list)
    demands: set[Any] = field(default_factory=set)
    region: set[str] = field(default_factory=set)
    resolver_pass: str = "unresolved"
    fail_stage: str = "unknown"
    fail_class: str = "unknown"
    confidence: str = "unknown"

    @property
    def final_size(self) -> int:
        return len(self.leaves)

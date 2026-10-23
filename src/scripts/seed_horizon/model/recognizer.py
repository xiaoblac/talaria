#!/usr/bin/env python3
from dataclasses import dataclass


@dataclass(frozen=True, order=True)
class InstallSeed:
    relation: str
    root_kind: str
    root: str
    method: str
    reg_row: int
    source: str
    parent_root: str

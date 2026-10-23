"""Lifecycle state machine parsed from descriptor.lifecycle."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class Transition:
    rule: str
    from_state: str
    api: str
    to_state: str
    invalid: bool


@dataclass(frozen=True)
class ObjectLifecycle:
    name: str
    slot_type: str
    states: tuple[str, ...]
    initial_state: str
    transitions: tuple[Transition, ...]

    def applicable(self, state: str, *, include_invalid: bool) -> tuple[Transition, ...]:
        return tuple(
            t for t in self.transitions
            if t.from_state == state and (include_invalid or not t.invalid)
        )


def parse_lifecycle(raw_lifecycle: Mapping[str, dict]) -> dict[str, ObjectLifecycle]:
    out: dict[str, ObjectLifecycle] = {}
    for name, raw in raw_lifecycle.items():
        transitions = tuple(
            Transition(
                rule=t["rule"],
                from_state=t["from"],
                api=t["api"],
                to_state=t["to"],
                invalid=bool(t.get("invalid", False)),
            )
            for t in raw["transitions"]
        )
        out[name] = ObjectLifecycle(
            name=name,
            slot_type=raw["slot_type"],
            states=tuple(raw["states"]),
            initial_state=raw["initial_state"],
            transitions=transitions,
        )
    return out

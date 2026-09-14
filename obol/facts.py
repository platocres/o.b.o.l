"""The fact layer — obol's single source of truth.

A Fact is one thing the operator has *proven* (or refuted, or found inconclusive)
about a target, always tied to the command/evidence that established it. Actions
are gated on facts, and the report is narrated from them. This is the piece that
distinguishes obol from a tool launcher: nothing becomes "true" unless a Fact
records it, scoped to exactly what the evidence supports.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from enum import Enum


class ProofState(str, Enum):
    """How strongly the evidence backs a fact.

    Kept deliberately small. The point is that "we ran a command" is never the
    same as "it worked" — a command that returned nothing useful yields an
    INCONCLUSIVE fact (or no fact), not a SUPPORTED one.
    """

    SUPPORTED = "supported"        # evidence affirmatively established this
    REFUTED = "refuted"            # evidence establishes this is NOT so
    INCONCLUSIVE = "inconclusive"  # attempted, ambiguous — no claim earned


@dataclass
class Fact:
    kind: str                      # e.g. "ldap.reachable", "ad.user", "cred.valid"
    scope: str                     # "host:10.10.10.161" | "domain:htb.local"
    value: dict = field(default_factory=dict)   # kind-specific payload
    state: ProofState = ProofState.SUPPORTED
    source: str = ""               # the command / run that produced it (lineage)
    created_at: float = field(default_factory=time.time)

    def to_json(self) -> dict:
        d = asdict(self)
        d["state"] = self.state.value
        return d

    @classmethod
    def from_json(cls, d: dict) -> "Fact":
        return cls(
            kind=d["kind"],
            scope=d.get("scope", ""),
            value=d.get("value", {}),
            state=ProofState(d.get("state", "supported")),
            source=d.get("source", ""),
            created_at=d.get("created_at", time.time()),
        )


class FactSet:
    """A small queryable collection of facts.

    Actions ask two questions of it: "is this kind proven?" and "what are the
    proven values for this kind?" — nothing heavier is needed for the planner.
    """

    def __init__(self, facts: list[Fact] | None = None):
        self.facts: list[Fact] = list(facts or [])

    def has(self, kind: str) -> bool:
        """True if at least one SUPPORTED fact of this kind exists."""
        return any(f.kind == kind and f.state is ProofState.SUPPORTED for f in self.facts)

    def values(self, kind: str) -> list[dict]:
        return [f.value for f in self.facts if f.kind == kind and f.state is ProofState.SUPPORTED]

    def kinds(self) -> set[str]:
        return {f.kind for f in self.facts if f.state is ProofState.SUPPORTED}

    def add(self, fact: Fact) -> bool:
        """Add a fact unless an identical (kind, scope, value) one is present.

        Returns True if it was actually new. Conservative de-dup keeps re-running
        the same action against the same target from inflating the picture — but
        the same (kind, value) on a *different* scope (another host, the domain)
        is a distinct fact and is kept. This matches the store's persistence key
        (`fact_hash(kind, scope, value)`); deduping without scope would silently
        drop one host's fact when two targets produce the same baseline finding.
        """
        for existing in self.facts:
            if (existing.kind == fact.kind and existing.scope == fact.scope
                    and existing.value == fact.value):
                return False
        self.facts.append(fact)
        return True

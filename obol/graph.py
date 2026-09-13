"""The path graph — one projection of facts+actions, rendered as mermaid.

This is deliberately the *only* place the graph is computed. The terminal board,
the web view, and (later) the OSCP report all consume this same projection, so
the "what's proven / unlocked / blocked" picture can never disagree between
surfaces. That single-source discipline is exactly what Charon lost by scattering
graph logic across several modules.
"""
from __future__ import annotations

import re

from .facts import FactSet
from .pack import Action, load_pack, next_actions, blocked_actions, friendly as _friendly


def _nid(text: str) -> str:
    return "n_" + re.sub(r"[^a-zA-Z0-9]", "_", text)


def build_mermaid(facts: FactSet, pack: list[Action] | None = None) -> str:
    pack = pack if pack is not None else load_pack()
    live = {a.id for a in next_actions(facts, pack)}
    blocked = {a.id for a in blocked_actions(facts, pack)}
    lines = ["flowchart LR"]
    seen_facts: set[str] = set()

    def fact_node(kind: str) -> str:
        nid = _nid("f_" + kind)
        if nid not in seen_facts:
            seen_facts.add(nid)
            proven = facts.has(kind)
            cls = "proven" if proven else "future"
            lines.append(f'  {nid}(["{_friendly(kind)}"]):::{cls}')
        return nid

    def relevant(a: Action) -> bool:
        # Keep the graph to the path around the current state: done, unlocked,
        # or blocked-but-near (at least one prerequisite already proven).
        if a.settled(facts) or a.id in live:
            return True
        return any(facts.has(k) for k in a.requires_all + a.requires_any)

    for a in pack:
        if not relevant(a):
            continue
        if a.settled(facts):
            cls = "done"
        elif a.id in live:
            cls = "next"
        elif a.id in blocked:
            cls = "blocked"
        else:
            cls = "future"
        anid = _nid("a_" + a.id)
        lines.append(f'  {anid}["{a.title}"]:::{cls}')
        for k in a.requires_all + a.requires_any:
            lines.append(f"  {fact_node(k)} --> {anid}")
        for kind in a.produces:
            lines.append(f"  {anid} --> {fact_node(kind)}")

    lines += [
        "  classDef proven fill:#1f7a1f,stroke:#0d3b0d,color:#fff;",
        "  classDef done fill:#2b5d8a,stroke:#173952,color:#fff;",
        "  classDef next fill:#0e7490,stroke:#083344,color:#fff;",
        "  classDef blocked fill:#4b5563,stroke:#1f2937,color:#cbd5e1,stroke-dasharray:4 3;",
        "  classDef future fill:#e5e7eb,stroke:#9ca3af,color:#374151,stroke-dasharray:2 2;",
    ]
    return "\n".join(lines)

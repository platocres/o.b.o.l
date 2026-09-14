"""The path map — one projection of facts+actions, rendered as mermaid.

This is deliberately the *only* place the map is computed, so the terminal, the
web view, and (later) the report never disagree. The map shows the path you have
walked and the live moves in front of you: proven facts, the actions that are
done or available now, and what those actions turn up next. It deliberately does
NOT draw blocked/far-off branches — the point is a clean forward path, not a
dependency web.

Layout note: this is a light top-down declutter. A fuller redesign to match the
prior obol's (platocres/obol) much more straightforward path view is a roadmap
item — see docs/ROADMAP.md.
"""
from __future__ import annotations

import re

from .facts import FactSet
from .pack import Action, load_packs, next_actions, friendly as _friendly


def _nid(text: str) -> str:
    return "n_" + re.sub(r"[^a-zA-Z0-9]", "_", text)


def build_mermaid(facts: FactSet, pack: list[Action] | None = None) -> str:
    pack = pack if pack is not None else load_packs()
    live = {a.id for a in next_actions(facts, pack)}
    lines = ["flowchart TD"]
    seen_facts: set[str] = set()

    def fact_node(kind: str) -> str:
        nid = _nid("f_" + kind)
        if nid not in seen_facts:
            seen_facts.add(nid)
            cls = "proven" if facts.has(kind) else "future"
            lines.append(f'  {nid}(["{_friendly(kind)}"]):::{cls}')
        return nid

    # Only done and live actions — no blocked/far-off branches.
    for a in pack:
        done = a.settled(facts)
        if not (done or a.id in live):
            continue
        anid = _nid("a_" + a.id)
        lines.append(f'  {anid}["{a.title}"]:::{"done" if done else "next"}')
        # Requires that are already proven show the path that reached this action.
        for k in a.requires_all + a.requires_any:
            if facts.has(k):
                lines.append(f"  {fact_node(k)} --> {anid}")
        # Produces show what this action turns up next.
        for kind in a.produces:
            lines.append(f"  {anid} --> {fact_node(kind)}")

    lines += [
        "  classDef proven fill:#1f7a1f,stroke:#0d3b0d,color:#fff;",
        "  classDef done fill:#2b5d8a,stroke:#173952,color:#fff;",
        "  classDef next fill:#0e7490,stroke:#083344,color:#fff;",
        "  classDef future fill:#e5e7eb,stroke:#9ca3af,color:#374151,stroke-dasharray:2 2;",
    ]
    return "\n".join(lines)

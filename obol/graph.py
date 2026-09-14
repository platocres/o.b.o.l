"""The path map — one projection of facts+actions, rendered to every surface.

`build_graph_model` computes the map exactly once as structured nodes/edges; the
terminal/report render it to mermaid via `build_mermaid`, and the web serves the
same model as JSON and draws it as an SVG flow chart. Computing it in one place is
what keeps the surfaces from ever disagreeing.

The map shows the path you have walked and the live moves in front of you: proven
facts, the actions that are done or available now, and what those actions turn up
next. It deliberately does NOT draw blocked/far-off branches — the point is a
clean forward path, not a dependency web (a product decision; see AGENTS.md).

Nodes carry a `phase` (recon -> enum -> creds -> access -> escalate -> loot) so a
surface can lay the path out left-to-right by engagement stage — the "phase/lane
progression" feel the roadmap asks for — instead of a raw dependency DAG.
"""
from __future__ import annotations

import re

from .facts import FactSet
from .pack import Action, load_packs, next_actions, friendly as _friendly

# Engagement phases, in order. A fact/action is placed in the latest phase any of
# its kinds map to, so the flow reads left (early recon) to right (loot/dominance).
PHASES = ["recon", "enum", "creds", "access", "escalate", "loot"]
_PHASE_INDEX = {name: i for i, name in enumerate(PHASES)}

# Prefix/exact rules mapping a fact kind to a phase. Ordered longest-first at use.
_PHASE_RULES: list[tuple[str, str]] = [
    ("target.", "recon"), ("host.", "recon"), ("ports.open", "recon"),
    ("port:", "recon"), ("scan.", "recon"),
    ("ldap.reachable", "recon"), ("smb.reachable", "recon"),
    ("kerberos.reachable", "recon"), ("winrm.reachable", "recon"),
    ("http.reachable", "recon"), ("service.", "recon"),
    ("ad.dc_candidate", "enum"), ("ad.domain_known", "enum"), ("ad.base_dn", "enum"),
    ("ad.anonymous_bind", "enum"), ("ad.user_list", "enum"),
    ("smb.null_session", "enum"), ("smb.guest_session", "enum"), ("smb.shares", "enum"),
    ("enum.deep", "enum"),
    ("web.content_map", "enum"), ("web.vhost", "enum"), ("web.source", "enum"),
    ("web.users", "enum"), ("web.parameterized", "enum"),
    ("hash.", "creds"), ("kerberos.tickets", "creds"), ("credential.", "creds"),
    ("ldap.authenticated", "access"), ("smb.authenticated", "access"),
    ("winrm.authenticated", "access"), ("web.authenticated", "access"),
    ("access.", "access"), ("foothold.", "access"),
    ("ad.graph.collected", "escalate"), ("ad.attack_paths", "escalate"),
    ("ad.control_paths", "escalate"), ("ad.trusts", "escalate"),
    ("ad.computer_added", "escalate"), ("adcs.", "escalate"),
    ("relay.success", "escalate"), ("lateral.movement", "escalate"),
    ("vuln.", "escalate"), ("exploit.candidate", "escalate"),
    ("web.lfi_confirmed", "escalate"), ("web.sqli_confirmed", "escalate"),
    ("web.cmdi_confirmed", "escalate"), ("web.ssrf_confirmed", "escalate"),
    ("web.upload_confirmed", "escalate"),
    ("loot.", "loot"), ("persistence.", "loot"), ("db.creds", "loot"),
    ("cloud.", "loot"), ("config.", "loot"),
]


def phase_of_kind(kind: str) -> str:
    """The engagement phase a fact kind belongs to (defaults to 'escalate')."""
    for prefix, phase in sorted(_PHASE_RULES, key=lambda r: -len(r[0])):
        if kind == prefix or kind.startswith(prefix):
            return phase
    return "escalate"


def _phase_of_action(action: Action) -> str:
    """An action's phase is the latest phase of anything it produces (fallback: the
    latest phase of its prerequisites), so a card sorts under the stage it advances."""
    kinds = list(action.produces) or (action.requires_all + action.requires_any)
    if not kinds:
        return "recon"
    return max((phase_of_kind(k) for k in kinds), key=lambda p: _PHASE_INDEX[p])


def _nid(text: str) -> str:
    return "n_" + re.sub(r"[^a-zA-Z0-9]", "_", text)


def build_graph_model(facts: FactSet, pack: list[Action] | None = None) -> dict:
    """Compute the forward-path map once as structured data.

    Returns ``{"phases": [...], "nodes": [...], "edges": [...]}`` where each node is
    ``{"id", "type": "fact"|"action", "label", "state", "phase"}`` — fact state is
    ``proven``/``future``; action state is ``done``/``next`` — and each edge is
    ``{"from", "to"}``. Only done and live actions (and the facts they touch) are
    included: no blocked branches.
    """
    pack = pack if pack is not None else load_packs()
    live = {a.id for a in next_actions(facts, pack)}

    nodes: list[dict] = []
    edges: list[dict] = []
    seen_facts: set[str] = set()

    def fact_node(kind: str) -> str:
        nid = _nid("f_" + kind)
        if nid not in seen_facts:
            seen_facts.add(nid)
            nodes.append({
                "id": nid, "type": "fact", "label": _friendly(kind),
                "kind": kind, "state": "proven" if facts.has(kind) else "future",
                "phase": phase_of_kind(kind),
            })
        return nid

    for a in pack:
        done = a.settled(facts)
        if not (done or a.id in live):
            continue
        anid = _nid("a_" + a.id)
        nodes.append({
            "id": anid, "type": "action", "label": a.title, "action_id": a.id,
            "state": "done" if done else "next", "phase": _phase_of_action(a),
        })
        # Requires that are already proven show the path that reached this action.
        for k in a.requires_all + a.requires_any:
            if facts.has(k):
                edges.append({"from": fact_node(k), "to": anid})
        # Produces show what this action turns up next.
        for kind in a.produces:
            edges.append({"from": anid, "to": fact_node(kind)})

    return {"phases": list(PHASES), "nodes": nodes, "edges": edges}


_MERMAID_CLASSES = {
    ("fact", "proven"): "proven", ("fact", "future"): "future",
    ("action", "done"): "done", ("action", "next"): "next",
}


def build_mermaid(facts: FactSet, pack: list[Action] | None = None) -> str:
    """Render the shared graph model to a mermaid flowchart (terminal/report)."""
    model = build_graph_model(facts, pack)
    lines = ["flowchart TD"]
    for node in model["nodes"]:
        cls = _MERMAID_CLASSES[(node["type"], node["state"])]
        label = node["label"].replace('"', "'")
        shape = (f'(["{label}"])' if node["type"] == "fact" else f'["{label}"]')
        lines.append(f'  {node["id"]}{shape}:::{cls}')
    for edge in model["edges"]:
        lines.append(f'  {edge["from"]} --> {edge["to"]}')
    lines += [
        "  classDef proven fill:#1f7a1f,stroke:#0d3b0d,color:#fff;",
        "  classDef done fill:#2b5d8a,stroke:#173952,color:#fff;",
        "  classDef next fill:#0e7490,stroke:#083344,color:#fff;",
        "  classDef future fill:#e5e7eb,stroke:#9ca3af,color:#374151,stroke-dasharray:2 2;",
    ]
    return "\n".join(lines)

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


def target_access_level(facts: FactSet) -> str:
    """Coarse access level for a target, from its facts — drives the engagement map."""
    if facts.has("access.system") or facts.has("access.admin"):
        return "privileged"
    if (facts.has("foothold.windows") or facts.has("foothold.linux")
            or facts.has("access.shell") or facts.has("winrm.authenticated")
            or facts.has("foothold.webshell")):
        return "foothold"
    if facts.has("credential.available") or facts.has("credential.candidate"):
        return "credentialed"
    if any(not f.kind.startswith(("target.", "host.")) for f in facts.facts):
        return "enumerated"
    return "discovered"


def target_phase(facts: FactSet) -> str:
    """The furthest engagement phase a target has reached (by proven fact kinds)."""
    kinds = [f.kind for f in facts.facts if f.state.value == "supported"]
    if not kinds:
        return "recon"
    return max((phase_of_kind(k) for k in kinds), key=lambda p: _PHASE_INDEX[p])


def build_engagement_graph(ws) -> dict:
    """The engagement-wide map: every target as a node, stitched to the shared domain
    and to each other by the evidence that connects them (a validated credential that
    spans hosts, a BloodHound domain overlay). Tiered top-to-bottom: domain / loot at
    tier 0, targets at tier 1, principals & credentials below.

    Returns ``{"nodes": [...], "edges": [...]}`` where nodes carry
    ``{"id","type","label","tier","meta"}`` and edges ``{"from","to","kind"}``.
    """
    nodes: list[dict] = []
    edges: list[dict] = []

    domain = ws.facts.values("ad.domain_known")
    domain_name = (domain[0].get("name") if domain else "") or ""
    dom_id = None
    if domain_name:
        dom_id = _nid("dom_" + domain_name)
        nodes.append({"id": dom_id, "type": "domain", "tier": 0,
                      "label": domain_name, "meta": {}})

    # A validated credential reused across hosts is the classic cross-target link.
    cred_facts = ws.facts.values("credential.available") + ws.facts.values("credential.plaintext")
    cred_id = None
    if cred_facts:
        who = cred_facts[0].get("user") or "credential"
        cred_id = _nid("cred_" + str(who))
        nodes.append({"id": cred_id, "type": "credential", "tier": 2,
                      "label": f"cred: {who}", "meta": {}})
        if dom_id:
            edges.append({"from": dom_id, "to": cred_id, "kind": "domain"})

    for t in ws.targets:
        host = t["host"]
        tf = ws.facts_for_target(host)
        level = target_access_level(tf)
        tid = _nid("tgt_" + host)
        nodes.append({
            "id": tid, "type": "target", "tier": 1,
            "label": t.get("label") or host,
            "meta": {"host": host, "access": level, "phase": target_phase(tf),
                     "os": t.get("os", ""), "dc": tf.has("ad.dc_candidate")},
        })
        if dom_id and (tf.has("ad.dc_candidate") or tf.has("ad.domain_known")
                       or tf.has("smb.reachable") or tf.has("ldap.reachable")):
            edges.append({"from": dom_id, "to": tid, "kind": "domain-joined"})
        # a validated credential that granted access on this host links them
        if cred_id and level in ("foothold", "privileged"):
            edges.append({"from": cred_id, "to": tid, "kind": "credential"})

    # BloodHound overlay (engagement-wide): high-value groups + roastable principals.
    bh = ws.bloodhound or {}
    if bh.get("domain") or bh.get("computers") or bh.get("domain_admins"):
        if not dom_id and bh.get("domain"):
            dom_id = _nid("dom_" + bh["domain"])
            nodes.append({"id": dom_id, "type": "domain", "tier": 0,
                          "label": bh["domain"], "meta": {}})
        for grp in ("domain_admins", "enterprise_admins"):
            members = bh.get(grp) or []
            if not members:
                continue
            gid = _nid("bh_" + grp)
            nodes.append({"id": gid, "type": "highvalue", "tier": 2,
                          "label": f"{grp.replace('_', ' ').title()} ({len(members)})",
                          "meta": {"members": members[:40]}})
            if dom_id:
                edges.append({"from": dom_id, "to": gid, "kind": "controls"})
        for kind, label in (("kerberoastable", "Kerberoastable"), ("asrep_roastable", "AS-REP-roastable")):
            items = bh.get(kind) or []
            if not items:
                continue
            kid = _nid("bh_" + kind)
            nodes.append({"id": kid, "type": "roastable", "tier": 3,
                          "label": f"{label} ({len(items)})", "meta": {"items": items[:40]}})
            if dom_id:
                edges.append({"from": dom_id, "to": kid, "kind": kind})

    return {"nodes": nodes, "edges": edges}


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

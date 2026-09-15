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
from .scope import target_in_scope

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
    ("privesc.", "escalate"),
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


_PORT_LABELS = {
    21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP",
    88: "Kerberos", 135: "RPC", 139: "NetBIOS", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 464: "Kerberos", 636: "LDAPS",
    3268: "GC LDAP", 3269: "GC LDAPS", 3389: "RDP",
    5985: "WinRM", 5986: "WinRM SSL", 8000: "HTTP", 8080: "HTTP",
    8443: "HTTPS",
}
_SERVICE_ALIASES = {
    "microsoft-ds": "SMB", "netbios-ssn": "SMB", "ldap": "LDAP",
    "kerberos-sec": "Kerberos", "domain": "DNS", "http": "HTTP",
    "https": "HTTPS", "ssl-http": "HTTPS", "ms-wbt-server": "RDP",
    "wsman": "WinRM", "winrm": "WinRM",
}
_REACHABLE_LABELS = {
    "ldap.reachable": "LDAP",
    "smb.reachable": "SMB",
    "kerberos.reachable": "Kerberos",
    "winrm.reachable": "WinRM",
    "http.reachable": "HTTP",
}


def _supported(fact) -> bool:
    return getattr(fact.state, "value", fact.state) == "supported"


def _host_factset(ws, host: str) -> FactSet:
    return FactSet([
        f for f in ws.facts.facts
        if _supported(f) and f.scope == f"host:{host}"
    ])


def _first_value(facts: FactSet, kind: str, *keys: str) -> str:
    for value in facts.values(kind):
        for key in keys:
            if value.get(key):
                return str(value[key])
    return ""


def _target_identity(target: dict, facts: FactSet) -> dict:
    hostname = (
        target.get("hostname")
        or _first_value(facts, "host.hostname", "name", "hostname")
        or _first_value(facts, "host.fqdn", "hostname")
        or _first_value(facts, "ad.dc_candidate", "name")
        or ""
    )
    fqdn = target.get("fqdn") or _first_value(facts, "host.fqdn", "fqdn", "name") or ""
    domain = (
        target.get("domain")
        or _first_value(facts, "host.domain", "domain", "name")
        or _first_value(facts, "host.fqdn", "domain")
        or _first_value(facts, "ad.dc_candidate", "domain")
        or ""
    )
    return {"hostname": hostname, "fqdn": fqdn, "domain": str(domain).lower() if domain else ""}


def _service_label(kind: str, value: dict) -> str:
    if kind in _REACHABLE_LABELS:
        return _REACHABLE_LABELS[kind]
    service = str(value.get("service") or "").lower()
    if service:
        return _SERVICE_ALIASES.get(service, service.replace("-", " ").title())
    port = value.get("port")
    if isinstance(port, int):
        return _PORT_LABELS.get(port, f"Port {port}")
    if kind.startswith("service."):
        raw = kind.split(".", 1)[1]
        return _SERVICE_ALIASES.get(raw, raw.replace("-", " ").title())
    return ""


def _host_services(facts: FactSet) -> list[dict]:
    services: dict[tuple[str, int, str], dict] = {}
    for fact in facts.facts:
        if not (
            fact.kind.startswith("port:")
            or fact.kind.startswith("service.")
            or fact.kind in _REACHABLE_LABELS
        ):
            continue
        value = dict(fact.value or {})
        port = value.get("port")
        if not isinstance(port, int):
            try:
                port = int(str(port)) if port not in (None, "") else 0
            except ValueError:
                port = 0
        proto = value.get("protocol") or ("tcp" if port else "")
        label = _service_label(fact.kind, value)
        if not label:
            continue
        key = (label.lower(), port, proto)
        row = {"label": label, "port": port, "protocol": proto, "kind": fact.kind}
        if value.get("version"):
            row["version"] = value["version"]
        services[key] = row
    return sorted(services.values(), key=lambda s: (s.get("port") or 99999, s["label"].lower()))


def _has_port(facts: FactSet, *ports: int) -> bool:
    wanted = set(ports)
    for fact in facts.facts:
        value = fact.value or {}
        if isinstance(value.get("ports"), list):
            for item in value["ports"]:
                try:
                    if int(item) in wanted:
                        return True
                except (TypeError, ValueError):
                    pass
        port = value.get("port")
        try:
            if int(port) in wanted:
                return True
        except (TypeError, ValueError):
            pass
    return False


def _is_domain_controller(facts: FactSet) -> bool:
    if not facts.has("ad.dc_candidate"):
        return False
    return (
        facts.has("ldap.reachable")
        or facts.has("kerberos.reachable")
        or _has_port(facts, 88, 389, 636, 3268, 3269)
    )


def _add_edge(edges: list[dict], seen: set[tuple[str, str, str]], source: str, target: str, kind: str) -> None:
    key = (source, target, kind)
    if key not in seen:
        seen.add(key)
        edges.append({"from": source, "to": target, "kind": kind})


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
    """The engagement-wide map populated from proven scan and path facts.

    Targets hang from the scope ranges or domains that evidence actually ties them
    to. Nmap/nxc/LDAP identity facts create hostname/domain metadata; port/service
    facts create service nodes under each target. No host-to-host edge is invented
    from a shared subnet alone.

    Returns ``{"nodes": [...], "edges": [...]}`` where nodes carry
    ``{"id","type","label","tier","meta"}`` and edges ``{"from","to","kind"}``.
    """
    nodes: list[dict] = []
    edges: list[dict] = []
    seen_edges: set[tuple[str, str, str]] = set()
    domain_ids: dict[str, str] = {}

    def add_domain(domain: str) -> str:
        domain = str(domain or "").strip().lower()
        if not domain:
            return ""
        if domain not in domain_ids:
            did = _nid("dom_" + domain)
            domain_ids[domain] = did
            nodes.append({"id": did, "type": "domain", "tier": 0,
                          "label": domain, "meta": {"domain": domain}})
        return domain_ids[domain]

    for value in ws.facts.values("ad.domain_known"):
        add_domain(value.get("name") or value.get("domain") or "")
    if (ws.bloodhound or {}).get("domain"):
        add_domain(ws.bloodhound["domain"])
    for target in ws.targets:
        if target.get("domain"):
            add_domain(target["domain"])

    scope_ids: dict[str, str] = {}
    target_hosts = {t.get("host") for t in ws.targets}
    for entry in ws.scope:
        if not entry or entry in target_hosts:
            continue
        sid = _nid("scope_" + entry)
        scope_ids[entry] = sid
        nodes.append({"id": sid, "type": "scope", "tier": 0,
                      "label": entry, "meta": {"scope": entry}})

    # A validated credential reused across hosts is the classic cross-target link.
    cred_facts = ws.facts.values("credential.available") + ws.facts.values("credential.plaintext")
    cred_id = None
    if cred_facts:
        who = cred_facts[0].get("user") or "credential"
        cred_domain = str(cred_facts[0].get("domain") or "").lower()
        cred_id = _nid("cred_" + str(who) + "_" + cred_domain)
        nodes.append({"id": cred_id, "type": "credential", "tier": 2,
                      "label": f"cred: {who}", "meta": {}})
        did = add_domain(cred_domain) if cred_domain else next(iter(domain_ids.values()), "")
        if did:
            _add_edge(edges, seen_edges, did, cred_id, "credential")

    for t in ws.targets:
        host = t["host"]
        tf = _host_factset(ws, host)
        identity = _target_identity(t, tf)
        services = _host_services(tf)
        level = target_access_level(tf)
        is_dc = _is_domain_controller(tf)
        tid = _nid("tgt_" + host)
        nodes.append({
            "id": tid, "type": "target", "tier": 1,
            "label": t.get("label") or host,
            "meta": {"host": host, "access": level, "phase": target_phase(tf),
                     "os": t.get("os", ""), "dc": is_dc,
                     "hostname": identity["hostname"], "fqdn": identity["fqdn"],
                     "domain": identity["domain"], "services": services[:8],
                     "service_count": len(services)},
        })

        did = add_domain(identity["domain"])
        if did:
            kind = "domain-controller" if is_dc else "domain-service"
            _add_edge(edges, seen_edges, did, tid, kind)
        for entry, sid in scope_ids.items():
            allowed, _ = target_in_scope(host, [entry])
            if allowed:
                _add_edge(edges, seen_edges, sid, tid, "in-scope")

        for service in services[:8]:
            port = service.get("port") or 0
            proto = service.get("protocol") or ""
            sid = _nid(f"svc_{host}_{service['label']}_{port}_{proto}")
            label = f"{service['label']} {port}" if port else service["label"]
            nodes.append({
                "id": sid, "type": "service", "tier": 2, "label": label,
                "meta": {"host": host, **service},
            })
            _add_edge(edges, seen_edges, tid, sid, "exposes")

        # a validated credential that granted access on this host links them
        if cred_id and level in ("foothold", "privileged"):
            _add_edge(edges, seen_edges, cred_id, tid, "authenticates")

    # BloodHound overlay (engagement-wide): high-value groups + roastable principals.
    bh = ws.bloodhound or {}
    if bh.get("domain") or bh.get("computers") or bh.get("domain_admins"):
        dom_id = add_domain(bh.get("domain", "")) or next(iter(domain_ids.values()), "")
        for grp in ("domain_admins", "enterprise_admins"):
            members = bh.get(grp) or []
            if not members:
                continue
            gid = _nid("bh_" + grp)
            nodes.append({"id": gid, "type": "highvalue", "tier": 2,
                          "label": f"{grp.replace('_', ' ').title()} ({len(members)})",
                          "meta": {"members": members[:40]}})
            if dom_id:
                _add_edge(edges, seen_edges, dom_id, gid, "controls")
        for kind, label in (("kerberoastable", "Kerberoastable"), ("asrep_roastable", "AS-REP-roastable")):
            items = bh.get(kind) or []
            if not items:
                continue
            kid = _nid("bh_" + kind)
            nodes.append({"id": kid, "type": "roastable", "tier": 3,
                          "label": f"{label} ({len(items)})", "meta": {"items": items[:40]}})
            if dom_id:
                _add_edge(edges, seen_edges, dom_id, kid, kind)

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

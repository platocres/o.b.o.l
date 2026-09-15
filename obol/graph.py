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

import html
import re

from .facts import FactSet
from .pack import Action, load_packs, next_actions, friendly as _friendly
from .phases import (  # the one phase model — shared with the planner, re-exported here
    PHASES,
    PHASE_INDEX as _PHASE_INDEX,
    phase_of_kind,
    phase_of_action as _phase_of_action,
    target_phase,
)
from .scope import target_in_scope


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


def build_topology(ws) -> dict:
    """The pivot topology (§6f): network segments joined by tunnels.

    A focused projection (distinct from the full engagement graph): each authorized
    network is a **segment** carrying its hosts; each live/attempted tunnel is a **hop**
    from a pivot host on one segment to the segment it exposes, tagged with transport,
    status, proxychains, and the staged transport binary's on-target path. This is the
    recursive-segment-mapper's map — scope range → its hosts → the multi-homed host →
    its tunnel → the next segment.

    Read-only; it invents no reachability, only draws the hops proven tunnels created.
    """
    import ipaddress

    foothold_kinds = ("foothold.linux", "foothold.windows", "access.shell",
                      "access.admin", "access.system")
    active_session_hosts = {s.get("host") for s in ws.sessions if s.get("status") == "active"}

    tunnel_subnets = {}
    for t in ws.tunnels:
        sub = t.get("exposed_subnet", "")
        if sub:
            tunnel_subnets.setdefault(sub, t.get("id", ""))

    # segments: every CIDR scope entry (operator- or pivot-authorized)
    segments: list[dict] = []
    seg_index: dict[str, dict] = {}
    for entry in ws.scope:
        if "/" not in entry:
            continue
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            continue
        seg = {"cidr": entry, "source": "pivot" if entry in tunnel_subnets else "operator",
               "via_tunnel": tunnel_subnets.get(entry, ""), "hosts": []}
        seg_index[entry] = seg
        segments.append(seg)

    def _place_host(host: str, target: dict) -> None:
        tf = ws.facts_for_target(host)
        foothold = any(tf.has(k) for k in foothold_kinds)
        row = {"host": host, "label": target.get("label") or host,
               "foothold": foothold, "session": host in active_session_hosts}
        placed = False
        try:
            ip = ipaddress.ip_address(host)
            for seg in segments:
                if ip in ipaddress.ip_network(seg["cidr"], strict=False):
                    seg["hosts"].append(row)
                    placed = True
                    break
        except ValueError:
            pass
        if not placed:
            row["placed"] = False
            unsegmented.append(row)

    unsegmented: list[dict] = []
    for target in ws.targets:
        _place_host(target["host"], target)

    # hops: a tunnel from its pivot host to the segment it exposes
    hops: list[dict] = []
    for t in ws.tunnels:
        pivot = t.get("host", "")
        exposed = t.get("exposed_subnet", "")
        from_seg = ""
        try:
            pip = ipaddress.ip_address(pivot)
            for seg in segments:
                if pip in ipaddress.ip_network(seg["cidr"], strict=False):
                    from_seg = seg["cidr"]
                    break
        except ValueError:
            pass
        hops.append({
            "tunnel_id": t.get("id", ""), "kind": t.get("kind", ""),
            "transport": t.get("transport", ""), "status": t.get("status", ""),
            "proxychains": bool(t.get("proxychains")), "pivot_host": pivot,
            "from_segment": from_seg, "to_segment": exposed,
            "staged_material": t.get("staged_material", ""), "staged_path": t.get("staged_path", ""),
            "staged_verified": bool(t.get("staged_verified")),
        })

    return {"segments": segments, "hops": hops, "unsegmented": unsegmented,
            "sessions": [s for s in ws.sessions if s.get("status") == "active"]}


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

    # Credentials: one node per DISTINCT (user, domain), tied to a host only where a
    # fact or a session actually connects that credential to that host — never one
    # credential node glued to every foothold, and never an arbitrary domain fallback.
    creds: dict[tuple[str, str], dict] = {}
    for f in ws.facts.facts:
        if f.kind not in ("credential.available", "credential.plaintext") or not _supported(f):
            continue
        v = f.value or {}
        user = str(v.get("user") or "").strip()
        domain = str(v.get("domain") or "").strip().lower()
        rec = creds.setdefault((user.lower(), domain),
                               {"user": user or "credential", "domain": domain, "hosts": set()})
        if f.scope.startswith("host:"):
            rec["hosts"].add(f.scope[5:])   # a host-scoped credential fact ties them
    # a live session is direct evidence a credential's user logged into that host
    for s in getattr(ws, "sessions", []):
        suser = str(s.get("user") or "").strip().lower()
        shost = s.get("host") or ""
        if not suser or not shost:
            continue
        for (user, _domain), rec in creds.items():
            if user == suser:
                rec["hosts"].add(shost)

    cred_ids: dict[tuple[str, str], str] = {}
    for key, rec in creds.items():
        cid = _nid("cred_" + rec["user"] + "_" + rec["domain"])
        cred_ids[key] = cid
        nodes.append({"id": cid, "type": "credential", "tier": 2,
                      "label": f"cred: {rec['user']}",
                      "meta": {"user": rec["user"], "domain": rec["domain"]}})
        # link to the credential's OWN domain only (evidence-backed by the cred fact)
        if rec["domain"]:
            _add_edge(edges, seen_edges, add_domain(rec["domain"]), cid, "credential")

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

        # a credential links to this host only where evidence ties them (a host-scoped
        # credential fact, or a session logged in as that user) — not merely a foothold.
        for key, cid in cred_ids.items():
            if host in creds[key]["hosts"]:
                _add_edge(edges, seen_edges, cid, tid, "authenticates")

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


# Node fills for the offline SVG — the same palette as the mermaid classes above and
# the live surface's flow chart, so all three renderers read alike.
_SVG_NODE_STYLE = {
    ("fact", "proven"): ("#1f7a1f", "#0d3b0d", "#ffffff", False),
    ("fact", "future"): ("#e5e7eb", "#9ca3af", "#374151", True),
    ("action", "done"): ("#2b5d8a", "#173952", "#ffffff", False),
    ("action", "next"): ("#0e7490", "#083344", "#ffffff", False),
}
_PHASE_SVG_COLOR = {
    "recon": "#6b7ba6", "enum": "#4f8ac9", "creds": "#c9a227",
    "access": "#3fb950", "escalate": "#d2691e", "loot": "#a371f7",
}


def _svg_text(label: str, limit: int = 24) -> str:
    label = label if len(label) <= limit else label[: limit - 1].rstrip() + "…"
    return html.escape(label)


def build_graph_svg(facts: FactSet, pack: list[Action] | None = None) -> str:
    """Render the shared graph model to a self-contained inline SVG flow chart.

    This is the offline counterpart to the live web surface's JS renderer and the
    terminal/report mermaid: phase columns left-to-right, proven/future facts and
    done/next actions, edges as curves. Pure SVG — no script, no web font, no CDN —
    so the static `obol web` snapshot's path graph works on an offline exam box.
    """
    model = build_graph_model(facts, pack)
    by_phase: dict[str, list[dict]] = {p: [] for p in PHASES}
    for node in model["nodes"]:
        by_phase.setdefault(node["phase"], []).append(node)
    cols = [p for p in PHASES if by_phase.get(p)]
    if not cols:
        return ('<svg viewBox="0 0 320 60" width="320" height="60" '
                'xmlns="http://www.w3.org/2000/svg"><text x="12" y="34" fill="#8b98a5" '
                'font-family="system-ui,sans-serif" font-size="13">Nothing on the path '
                'yet — run a scan.</text></svg>')

    NW, NH, COLW, ROW, PADX, PADY = 178, 42, 214, 56, 22, 46
    pos: dict[str, dict] = {}
    for ci, p in enumerate(cols):
        for ri, node in enumerate(by_phase[p]):
            pos[node["id"]] = {"x": PADX + ci * COLW, "y": PADY + ri * ROW, "node": node}
    tallest = max(len(by_phase[p]) for p in cols)
    height = PADY + tallest * ROW + 14
    width = PADX * 2 + (len(cols) - 1) * COLW + NW

    edges: list[str] = []
    for e in model["edges"]:
        a, b = pos.get(e["from"]), pos.get(e["to"])
        if not a or not b:
            continue
        x1, y1 = a["x"] + NW, a["y"] + NH / 2
        x2, y2 = b["x"], b["y"] + NH / 2
        mx = (x1 + x2) / 2
        future = b["node"]["type"] == "fact" and b["node"]["state"] == "future"
        dash = ' stroke-dasharray="4 4"' if future else ""
        edges.append(f'<path d="M{x1},{y1} C{mx},{y1} {mx},{y2} {x2},{y2}" fill="none" '
                     f'stroke="{"#3D4D75" if future else "#4b5a86"}" stroke-width="1.5"{dash}/>')

    headers: list[str] = []
    for ci, p in enumerate(cols):
        cx = PADX + ci * COLW
        color = _PHASE_SVG_COLOR.get(p, "#8b98a5")
        headers.append(
            f'<text x="{cx + NW // 2}" y="24" text-anchor="middle" fill="{color}" '
            f'font-size="11" font-weight="700" letter-spacing="1.2">{p.upper()}</text>'
            f'<line x1="{cx}" y1="32" x2="{cx + NW}" y2="32" stroke="{color}" '
            f'stroke-opacity="0.35" stroke-width="1.5"/>')

    node_svg: list[str] = []
    for meta in pos.values():
        node = meta["node"]
        fill, stroke, text_color, dashed = _SVG_NODE_STYLE[(node["type"], node["state"])]
        x, y = meta["x"], meta["y"]
        rx = 16 if node["type"] == "fact" else 6   # facts rounded (stadium-ish), actions boxy
        dash = ' stroke-dasharray="3 2"' if dashed else ""
        node_svg.append(
            f'<rect x="{x}" y="{y}" width="{NW}" height="{NH}" rx="{rx}" fill="{fill}" '
            f'stroke="{stroke}" stroke-width="1.5"{dash}/>'
            f'<text x="{x + NW // 2}" y="{y + NH // 2 + 4}" text-anchor="middle" '
            f'fill="{text_color}" font-size="12" font-family="system-ui,sans-serif">'
            f'<title>{html.escape(node["label"])}</title>{_svg_text(node["label"])}</text>')

    return (f'<svg viewBox="0 0 {width} {height}" width="{width}" height="{height}" '
            f'preserveAspectRatio="xMinYMin meet" xmlns="http://www.w3.org/2000/svg" '
            f'font-family="system-ui,sans-serif">'
            f'{"".join(headers)}{"".join(edges)}{"".join(node_svg)}</svg>')


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

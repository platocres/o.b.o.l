"""OSCP-style markdown report generation.

The report is a read-only projection of the same workspace state used by the
terminal board and local web view: run ledger, facts, and evidence lineage. It
never turns project metadata into engagement proof. These helpers take an explicit
`include_secrets` flag; the library default is conservative (redact), which the
shareable debug package relies on, but the operator-facing surfaces pass it True —
`obol report` and the localhost web console SHOW secrets by default (a lab/exam
product call), with redaction opt-in (`obol report --redact`, the web toggle).
"""
from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from .board import action_desc, fill_command
from .facts import Fact, FactSet, ProofState
from .graph import (
    build_engagement_graph,
    build_graph_model,
    build_mermaid,
    target_access_level,
    target_phase,
)
from .pack import friendly, load_packs, next_actions
from .workspace import Workspace

# Access ladder for the report/web progress meter: each stage plus the fact kinds
# that count as reaching it. Ordered from foothold to full domain dominance.
_ACCESS_LADDER: list[tuple[str, tuple[str, ...]]] = [
    ("Recon", ("host.up", "scan.nmap.quick", "ports.open")),
    ("Service enum", ("ad.domain_known", "ad.anonymous_bind", "ad.user_list",
                      "smb.shares", "web.content_map")),
    ("Credential material", ("hash.asrep", "hash.tgs", "hash.ntlm",
                             "credential.candidate")),
    ("Valid credential", ("credential.available", "credential.plaintext",
                          "credential.ntlm_hash")),
    ("Foothold", ("foothold.windows", "foothold.linux", "access.shell",
                  "winrm.authenticated", "foothold.webshell")),
    ("Privileged access", ("access.admin", "access.system")),
    ("Domain / loot", ("loot.ntds", "hash.krbtgt", "persistence.domain")),
]

_SECRET_KEYS = {
    "password",
    "passwd",
    "pwd",
    "hash",
    "hashes",
    "ntlm",
    "ntlm_hash",
    "secret",
    "secrets",
    "ticket",
    "tickets",
    "cpassword",
    "value",
    "values",
}

_AUTH_TOOL_RE = re.compile(
    r"\b(nxc|crackmapexec|evil-winrm|bloodhound-python|impacket-[a-z0-9_-]+|secretsdump\.py)\b",
    re.IGNORECASE,
)
_PASSWORD_FLAG_RE = re.compile(
    r"(?P<prefix>\s(?:-p|--password)\s+)(?P<value>'[^']*'|\"[^\"]*\"|\S+)",
    re.IGNORECASE,
)
_IMPACKET_SECRET_RE = re.compile(
    r"(?P<left>\b[^\s/'\"]+/[^\s:'\"]+:)(?P<secret>[^@\s'\"]+)(?P<quote>['\"]?)(?P<right>@)"
)
_CATEGORY_ORDER = {
    "target": 0,
    "scan": 1,
    "service": 2,
    "ad": 3,
    "credential": 4,
    "access": 5,
    "loot": 6,
    "config": 7,
    "web": 8,
    "other": 99,
}


def _stamp(ts: float | int | None) -> str:
    if not ts:
        return "unknown time"
    try:
        return datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "unknown time"


def _fact_category(kind: str) -> str:
    if kind.startswith(("target.", "host.", "port:", "ports.open")):
        return "target"
    if kind.startswith("scan."):
        return "scan"
    if kind.startswith(("service.", "ldap.", "smb.", "winrm.", "kerberos.", "http.")):
        return "service"
    if kind.startswith(("ad.", "hash.", "kerberos.")):
        return "ad"
    if kind.startswith("credential."):
        return "credential"
    if kind.startswith(("access.", "foothold.")):
        return "access"
    if kind.startswith("loot."):
        return "loot"
    if kind.startswith(("config.", "vuln.")):
        return "config"
    if kind.startswith("web."):
        return "web"
    return "other"


def _redact_value(value: Any, *, include_secrets: bool) -> Any:
    if include_secrets:
        return value
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            lowered = str(key).lower()
            if lowered in _SECRET_KEYS or any(token in lowered for token in ("password", "hash", "secret", "ticket")):
                out[str(key)] = "<redacted>"
            else:
                out[str(key)] = _redact_value(item, include_secrets=include_secrets)
        return out
    if isinstance(value, list):
        return [_redact_value(item, include_secrets=include_secrets) for item in value]
    return value


def redact_command(command: str, *, include_secrets: bool = False) -> str:
    """Redact obvious credential material from report commands.

    This is intentionally tool-aware so nmap's `-p 80,443` port flag is not
    mistaken for a password.
    """
    if include_secrets or not command:
        return command
    redacted = _IMPACKET_SECRET_RE.sub(r"\g<left><redacted>\g<quote>\g<right>", command)
    if _AUTH_TOOL_RE.search(redacted):
        redacted = _PASSWORD_FLAG_RE.sub(r"\g<prefix><redacted>", redacted)
    return redacted


def _json(value: dict, *, include_secrets: bool) -> str:
    safe = _redact_value(value, include_secrets=include_secrets)
    return json.dumps(safe, sort_keys=True)


def _source_for(fact: Fact, *, include_secrets: bool) -> str:
    src = fact.source or "manual/seeded workspace evidence"
    return redact_command(src, include_secrets=include_secrets)


def _fact_sort_key(fact: Fact) -> tuple[int, str, str, str]:
    category = _fact_category(fact.kind)
    return (_CATEGORY_ORDER.get(category, 99), fact.kind, fact.scope, fact.state.value)


def _open_ports(ws: Workspace) -> list[str]:
    ports: list[str] = []
    for fact in ws.facts.facts:
        if not fact.kind.startswith("port:") or fact.state is not ProofState.SUPPORTED:
            continue
        port = fact.kind.split(":", 1)[1]
        proto = fact.value.get("protocol", "tcp")
        service = fact.value.get("service", "")
        ports.append(f"{port}/{proto}" + (f" {service}" if service else ""))
    return sorted(set(ports), key=lambda item: (int(item.split("/", 1)[0]) if item.split("/", 1)[0].isdigit() else 99999, item))


def _run_status(row: dict) -> str:
    if row.get("dry_run"):
        return "dry run"
    if row.get("timed_out"):
        return "timed out"
    if "returncode" in row:
        return f"return code {row.get('returncode')}"
    return "recorded"


def _render_summary(ws: Workspace) -> list[str]:
    lines = ["## Executive summary", ""]
    lines.append(f"- Workspace: `{ws.name}`")
    lines.append(f"- Target: `{ws.target or 'not configured'}`")
    lines.append(f"- Scope entries: `{', '.join(ws.scope) if ws.scope else 'none recorded'}`")
    ports = _open_ports(ws)
    if ports:
        rendered = ", ".join(ports[:24])
        if len(ports) > 24:
            rendered += f", +{len(ports) - 24} more"
        lines.append(f"- Open ports parsed: {rendered}")
    else:
        lines.append("- Open ports parsed: none yet")

    domain = ws.facts.values("ad.domain_known")
    if domain and domain[0].get("name"):
        lines.append(f"- Domain identified: `{domain[0]['name']}`")
    if ws.facts.has("access.system"):
        lines.append("- Access state: SYSTEM access is proven.")
    elif ws.facts.has("access.admin"):
        lines.append("- Access state: administrative access is proven.")
    elif ws.facts.has("foothold.windows"):
        lines.append("- Access state: Windows foothold is proven, privilege still needs evidence.")
    else:
        lines.append("- Access state: no shell or administrative access proven yet.")

    if ws.facts.has("credential.available"):
        lines.append("- Credential state: at least one usable credential has evidence.")
    elif ws.facts.has("credential.candidate"):
        lines.append("- Credential state: candidate material exists, but no usable credential is proven.")
    else:
        lines.append("- Credential state: no credentials proven yet.")
    lines.append("")
    return lines


def _render_runs(ws: Workspace, *, include_secrets: bool) -> list[str]:
    lines = ["## Activity timeline", ""]
    if not ws.runs:
        lines.append("No command runs are recorded yet.")
        lines.append("")
        return lines

    for index, row in enumerate(ws.runs, 1):
        tool = row.get("tool", "tool")
        lines.append(f"### {index}. {tool} at {_stamp(row.get('at'))}")
        lines.append("")
        lines.append("```bash")
        lines.append(redact_command(row.get("command", ""), include_secrets=include_secrets))
        lines.append("```")
        lines.append("")
        lines.append(f"- Status: {_run_status(row)}")
        if row.get("duration_ms") is not None:
            lines.append(f"- Duration: {row.get('duration_ms')} ms")
        produced = row.get("produced") or []
        if produced:
            lines.append("- Parsed facts: " + ", ".join(f"`{kind}`" for kind in produced))
        else:
            lines.append("- Parsed facts: none")
        if row.get("stdout"):
            lines.append(f"- Raw stdout saved to: `{row['stdout']}`")
        if row.get("stderr"):
            lines.append(f"- Raw stderr saved to: `{row['stderr']}`")
        lines.append("")
    return lines


def _render_facts(ws: Workspace, *, include_secrets: bool) -> list[str]:
    lines = ["## Evidence-backed findings", ""]
    if not ws.facts.facts:
        lines.append("No facts are recorded yet.")
        lines.append("")
        return lines

    current_category = ""
    for fact in sorted(ws.facts.facts, key=_fact_sort_key):
        category = _fact_category(fact.kind)
        if category != current_category:
            current_category = category
            lines.append(f"### {category.title()}")
            lines.append("")
        state = fact.state.value
        label = friendly(fact.kind)
        lines.append(f"- **{label}** (`{fact.kind}`, {state})")
        lines.append(f"  - Scope: `{fact.scope or 'unscoped'}`")
        if fact.value:
            lines.append(f"  - Value: `{_json(fact.value, include_secrets=include_secrets)}`")
        lines.append(f"  - Evidence: `{_source_for(fact, include_secrets=include_secrets)}`")
    lines.append("")
    return lines


def _render_next(ws: Workspace, *, include_secrets: bool, max_next: int) -> list[str]:
    lines = ["## Recommended next actions", ""]
    actions = next_actions(ws.facts)[:max_next]
    if not actions:
        lines.append("No next actions are currently queued by the planner.")
        lines.append("")
        return lines
    for index, action in enumerate(actions, 1):
        lines.append(f"### {index}. {action.title}")
        desc = action_desc(action)
        if desc:
            lines.append(desc)
            lines.append("")
        if action.commands:
            lines.append("```bash")
            lines.append(redact_command(fill_command(action, ws, 0), include_secrets=include_secrets))
            lines.append("```")
            lines.append("")
        if action.report:
            finding = action.report.get("finding", "")
            severity = action.report.get("severity", "")
            if finding or severity:
                report_line = finding
                if severity:
                    report_line += f" ({severity})" if report_line else severity
                lines.append(f"- Report mapping: {report_line}")
                lines.append("")
    return lines


def _render_targets(ws: Workspace, *, include_secrets: bool) -> list[str]:
    if not ws.targets:
        return []
    lines = ["## Targets", ""]
    for t in ws.targets:
        host = t["host"]
        tf = ws.facts_for_target(host)
        lines.append(f"### {t.get('label') or host} (`{host}`)")
        lines.append("")
        lines.append(f"- Access: {target_access_level(tf)} · phase: {target_phase(tf)}")
        ports = _target_open_ports([f for f in tf.facts if f.scope == f'host:{host}'])
        if ports:
            lines.append(f"- Open ports: {', '.join(ports[:24])}")
        if t.get("notes"):
            lines.append(f"- Notes: {t['notes']}")
        ev = ws.evidence_for(host)
        if ev:
            lines.append("- Evidence:")
            for e in ev:
                cap = e.get("caption") or e.get("filename")
                tag = f" [{e['phase']}]" if e.get("phase") else ""
                lines.append(f"  - `{e.get('stored')}`{tag} — {cap}")
        lines.append("")
    return lines


def _render_evidence(ws: Workspace) -> list[str]:
    if not ws.evidence:
        return []
    lines = ["## Evidence & screenshots", ""]
    for e in ws.evidence:
        cap = e.get("caption") or e.get("filename")
        who = e.get("target") or "engagement"
        tag = f" · {e['phase']}" if e.get("phase") else ""
        lines.append(f"- **{cap}** ({who}{tag}) — `.obol/evidence/{e.get('stored')}`")
    lines.append("")
    return lines


def _render_graph(ws: Workspace) -> list[str]:
    return [
        "## Evidence path diagram",
        "",
        "```mermaid",
        build_mermaid(ws.facts),
        "```",
        "",
    ]


def report_status_rows(ws: Workspace) -> list[tuple[str, str]]:
    """Small read-only status block for the local web view."""
    default_path = ws.root / "report.md"
    rows = [
        ("Markdown report", f"run `obol report` to write {default_path}"),
        ("Secret handling", "passwords and hashes are redacted unless `--include-secrets` is used"),
        ("Evidence source", "facts, run ledger, and raw-output paths from this workspace"),
    ]
    if default_path.exists():
        rows.insert(1, ("Last generated", str(default_path)))
    return rows


def _target_open_ports(facts: list[Fact]) -> list[str]:
    ports = []
    for f in facts:
        if f.kind.startswith("port:") and f.state is ProofState.SUPPORTED:
            port = f.kind.split(":", 1)[1]
            proto = f.value.get("protocol", "tcp")
            svc = f.value.get("service", "")
            ports.append(f"{port}/{proto}" + (f" {svc}" if svc else ""))
    return sorted(set(ports), key=lambda i: (int(i.split("/", 1)[0]) if i.split("/", 1)[0].isdigit() else 99999))


def _evidence_view(e: dict) -> dict:
    return {
        "id": e.get("id"), "target": e.get("target", ""), "phase": e.get("phase", ""),
        "caption": e.get("caption", ""), "filename": e.get("filename", ""),
        "added_at": e.get("added_at"),
        "url": f"/api/evidence/{e.get('id')}",   # served by the web surface
    }


def _access_ladder(ws: Workspace) -> list[dict]:
    """Ordered engagement stages with whether each has been reached — drives the
    report/web progress meter."""
    facts = ws.facts
    return [
        {"stage": stage, "reached": any(facts.has(k) for k in kinds)}
        for stage, kinds in _ACCESS_LADDER
    ]


def _category_counts(ws: Workspace) -> dict[str, int]:
    counts: dict[str, int] = {}
    for fact in ws.facts.facts:
        if fact.state is not ProofState.SUPPORTED:
            continue
        cat = _fact_category(fact.kind)
        counts[cat] = counts.get(cat, 0) + 1
    return counts


# Canonical severity keys (packs write "informational"; the UI keys on "info").
_SEVERITY_ALIASES = {"informational": "info", "information": "info", "": "info"}


def normalize_severity(value: str) -> str:
    sev = str(value or "").strip().lower()
    return _SEVERITY_ALIASES.get(sev, sev)


def _severity_counts(ws: Workspace, pack=None) -> dict[str, int]:
    """Severity tally from the report mappings of actions whose produced facts are
    now proven — obol's facts carry no severity of their own, so a finding's weight
    comes from the Orange card that established it. Keys are canonical
    (critical/high/medium/low/info)."""
    pack = pack if pack is not None else load_packs()
    proven = ws.facts.kinds()
    counts: dict[str, int] = {}
    for action in pack:
        if not action.report or not action.produces:
            continue
        if not set(action.produces).issubset(proven):
            continue
        sev = normalize_severity(action.report.get("severity", ""))
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def build_report_context(ws: Workspace, *, include_secrets: bool = False,
                         max_next: int = 8) -> dict:
    """Structured report data for the web report view.

    A read-only projection of the same workspace state the markdown report is built
    from (facts, run ledger, lineage) plus the shared graph model — so the HTML
    report and `obol report` never disagree. Secrets are redacted unless asked.
    """
    facts = ws.facts
    domain = facts.values("ad.domain_known")
    if facts.has("access.system"):
        access_state = "SYSTEM access proven"
    elif facts.has("access.admin"):
        access_state = "Administrative access proven"
    elif facts.has("foothold.windows") or facts.has("foothold.linux") or facts.has("access.shell"):
        access_state = "Foothold proven, privilege not yet proven"
    else:
        access_state = "No access proven yet"
    if facts.has("credential.available"):
        cred_state = "Validated credential available"
    elif facts.has("credential.candidate"):
        cred_state = "Candidate material only"
    else:
        cred_state = "No validated credential"

    facts_out: list[dict] = []
    for fact in sorted(facts.facts, key=_fact_sort_key):
        facts_out.append({
            "kind": fact.kind,
            "label": friendly(fact.kind),
            "category": _fact_category(fact.kind),
            "state": fact.state.value,
            "scope": fact.scope,
            "value": _redact_value(fact.value, include_secrets=include_secrets),
            "evidence": _source_for(fact, include_secrets=include_secrets),
            "at": fact.created_at,
        })

    timeline: list[dict] = []
    for index, row in enumerate(ws.runs, 1):
        timeline.append({
            "index": index,
            "tool": row.get("tool", "tool"),
            "command": redact_command(row.get("command", ""), include_secrets=include_secrets),
            "status": _run_status(row),
            "produced": list(row.get("produced") or []),
            "duration_ms": row.get("duration_ms"),
            "at": row.get("at"),
            "at_display": _stamp(row.get("at")),
            "action_id": row.get("action_id"),
            "playbook": row.get("playbook"),
        })

    next_out: list[dict] = []
    for action in next_actions(facts)[:max_next]:
        entry = {"id": action.id, "title": action.title, "desc": action_desc(action)}
        if action.report:
            entry["report"] = {
                "finding": action.report.get("finding", ""),
                "severity": action.report.get("severity", ""),
            }
        next_out.append(entry)

    # per-target rollup — each target's scoped findings + evidence feed the report
    targets_out: list[dict] = []
    for t in ws.targets:
        host = t["host"]
        tf = ws.facts_for_target(host)
        tfacts = [f for f in tf.facts if f.scope == f"host:{host}"]
        targets_out.append({
            "host": host,
            "label": t.get("label") or host,
            "hostname": t.get("hostname", ""),
            "fqdn": t.get("fqdn", ""),
            "domain": t.get("domain", ""),
            "os": t.get("os", ""),
            "status": t.get("status", ""),
            "notes": t.get("notes", ""),
            "access": target_access_level(tf),
            "phase": target_phase(tf),
            "open_ports": _target_open_ports(tfacts),
            "findings": [{
                "kind": f.kind, "label": friendly(f.kind), "category": _fact_category(f.kind),
                "value": _redact_value(f.value, include_secrets=include_secrets),
                "evidence": _source_for(f, include_secrets=include_secrets),
            } for f in sorted(tfacts, key=_fact_sort_key)],
            "evidence": [_evidence_view(e) for e in ws.evidence_for(host)],
        })

    return {
        "meta": {
            "name": ws.name,
            "target": ws.target,
            "scope": list(ws.scope),
            "domain": (domain[0].get("name") if domain else "") or "",
            "generated_at": _stamp(None if not ws.runs else max((r.get("at") or 0) for r in ws.runs)),
            "include_secrets": include_secrets,
        },
        "targets": targets_out,
        "evidence": [_evidence_view(e) for e in ws.evidence],
        "engagement_graph": build_engagement_graph(ws),
        "bloodhound": ws.bloodhound or {},
        "tiles": {
            "facts": len([f for f in facts.facts if f.state is ProofState.SUPPORTED]),
            "ports": len(_open_ports(ws)),
            "runs": len(ws.runs),
            "access_state": access_state,
            "credential_state": cred_state,
        },
        "open_ports": _open_ports(ws),
        "access_ladder": _access_ladder(ws),
        "category_counts": _category_counts(ws),
        "severity_counts": _severity_counts(ws),
        "facts": facts_out,
        "timeline": timeline,
        "next_actions": next_out,
        "graph": build_graph_model(facts),
    }


def build_report(ws: Workspace, *, include_secrets: bool = False, max_next: int = 8) -> str:
    """Build a markdown report from workspace facts, runs, and lineage."""
    lines: list[str] = [
        f"# OSCP-Style Evidence Report: {ws.name}",
        "",
        "> Generated from the local obol workspace. Treat every finding below as only as strong as its cited command/source evidence.",
        "",
    ]
    if not include_secrets:
        lines.extend([
            "> Secrets are redacted in this draft. Re-run with `obol report --include-secrets` for private exam notes.",
            "",
        ])
    lines.extend(_render_summary(ws))
    lines.extend(_render_targets(ws, include_secrets=include_secrets))
    lines.extend(_render_runs(ws, include_secrets=include_secrets))
    lines.extend(_render_facts(ws, include_secrets=include_secrets))
    lines.extend(_render_evidence(ws))
    lines.extend(_render_next(ws, include_secrets=include_secrets, max_next=max_next))
    lines.extend(_render_graph(ws))
    return "\n".join(lines).rstrip() + "\n"


def write_report(ws: Workspace, out: str | Path | None = None, *, include_secrets: bool = False, max_next: int = 8) -> Path:
    """Write the markdown report. Defaults to `report.md` in the workspace root."""
    path = Path(out) if out is not None else (ws.root / "report.md")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(build_report(ws, include_secrets=include_secrets, max_next=max_next))
    return path

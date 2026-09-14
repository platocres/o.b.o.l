"""OSCP-style markdown report generation.

The report is a read-only projection of the same workspace state used by the
terminal board and local web view: run ledger, facts, and evidence lineage. It
never turns project metadata into engagement proof, and it redacts secrets by
default so operators can safely review or share a draft before intentionally
including credentials.
"""
from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from .board import action_desc, fill_command
from .facts import Fact, ProofState
from .graph import build_mermaid
from .pack import friendly, next_actions
from .workspace import Workspace

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
    lines.extend(_render_runs(ws, include_secrets=include_secrets))
    lines.extend(_render_facts(ws, include_secrets=include_secrets))
    lines.extend(_render_next(ws, include_secrets=include_secrets, max_next=max_next))
    lines.extend(_render_graph(ws))
    return "\n".join(lines).rstrip() + "\n"


def write_report(ws: Workspace, out: str | Path | None = None, *, include_secrets: bool = False, max_next: int = 8) -> Path:
    """Write the markdown report. Defaults to `report.md` in the workspace root."""
    path = Path(out) if out is not None else (ws.root / "report.md")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(build_report(ws, include_secrets=include_secrets, max_next=max_next))
    return path

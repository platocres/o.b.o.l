"""FastAPI backend for the O.B.O.L web surface (the engagement library).

One app over an app-managed library of engagements, each holding many targets, all
sharing one runner/parser/store with the terminal:

* **Library.** `create_app(base)` serves every engagement under the base dir; create,
  list, and switch engagements from the web. Endpoints act on the *active*
  engagement; per-target endpoints take `?target=<host>`.
* **One store / one runner.** Reads load the workspace fresh; run-from-site calls
  `service.run_action(target=…)` — the same scope-checked runner/parser/ledger the
  terminal uses. The browser sends an action id + target; the server fills the
  command from that target's facts, so secrets never reach the browser.
* **Real-time.** `/api/events` (SSE) tails the active engagement's store change
  feed (the `events` table in `state.db`) and the active-engagement pointer,
  pushing *what changed* — new facts, runs, targets, evidence — as a JSON payload
  on every change, web- or terminal-driven. The browser patches only the affected
  UI and shows a toast, instead of blindly re-fetching everything. Quick Start job
  progress (in-memory, not in the store) rides the same stream via a version tick.

Localhost-only, token-gated (`X-Obol-Token` header or `?token=`).
"""
from __future__ import annotations

import asyncio
import copy
import json
import mimetypes
import re
import shlex
import shutil
import secrets
import threading
import time
import uuid
from pathlib import Path
from typing import Optional

from .. import (board, bloodhound, discovery, library, sessions as session_layer,
                tools as tool_inventory, tunnels as tunnel_layer)
from ..sessions import SessionError
from ..tunnels import TunnelError
from ..graph import (
    build_engagement_graph,
    build_graph_model,
    phase_of_kind,
    target_access_level,
    target_phase,
)
from ..pack import friendly, load_packs, next_actions
from ..pivot import pivot_summary
from ..quickstart import (
    QUICKSTART_ACTION_IDS,
    action_done as _action_done,
    action_phase as _action_phase,
    variant_indices as _quickstart_variant_indices,
)
from ..report import (
    build_report,
    build_report_context,
    redact_command,
    _CATEGORY_ORDER,
    _evidence_view,
    _fact_category,
    _redact_value,
    _run_status,
    _stamp,
    _target_open_ports,
)
from ..runner import RunnerError
from ..scope import normalize_target, target_in_scope
from ..store import STATE_DB, Store
from ..service import (
    ActionError,
    build_command,
    eligible_actions,
    find_action,
    run_action,
)
from ..workspace import Workspace

try:
    from fastapi import Body, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
    from fastapi.responses import (
        FileResponse,
        JSONResponse,
        PlainTextResponse,
        Response,
        StreamingResponse,
    )
    from fastapi.staticfiles import StaticFiles
    _HAVE_FASTAPI = True
except ModuleNotFoundError:  # pragma: no cover
    Body = FastAPI = File = Form = HTTPException = Query = Request = UploadFile = None
    FileResponse = JSONResponse = PlainTextResponse = Response = StreamingResponse = None
    StaticFiles = None
    _HAVE_FASTAPI = False

STATIC_DIR = Path(__file__).parent / "static"
# The live web surface is a single-operator localhost lab/exam console, so it SHOWS
# secrets by default (passwords, hashes, tickets in commands and fact values).
# Redaction is opt-in — the report view's toggle, and the roadmapped engagement-wide
# redact switch. This is deliberately the opposite of a shareable artifact like the
# debug package, which stays redacted-by-default. See docs/ROADMAP.md.
WEB_SHOW_SECRETS = True
PHASES = ["recon", "enum", "creds", "access", "escalate", "loot"]
PHASE_LABEL = {"recon": "Recon", "enum": "Enumerate", "creds": "Credentials",
               "access": "Access", "escalate": "Escalate", "loot": "Loot / domain"}

_RUN_LOCK = threading.Lock()
_TOKEN_RE = re.compile(r"{{\s*([^}]+?)\s*}}|<([^>]+)>")
_INPUT_KEY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")
_SHELL_META_RE = re.compile(r"[|;&<>`]")
_EVIDENCE_ONLY_INPUTS = {"target", "nmap_ports"}
_INPUT_HINTS = {
    "nmap_ports": "Run the open-port nmap prelude first so O.B.O.L can fill the discovered ports.",
    "domain": "Set this if you already know the AD DNS domain, or run domain/DC identification first.",
    "basedn": "Set the LDAP base DN, for example DC=example,DC=local.",
    "dc": "Set the domain controller hostname or domain when the command needs it.",
    "user": "Set a username or let O.B.O.L fill this from a validated credential fact.",
    "password": "Set a password or let O.B.O.L fill this from a validated credential fact.",
    "userlist": "Set the path to a username file, for example users.txt.",
    "hashfile": "Set the output/input hash file path, for example hashes.asrep.",
    "wordlist": "Set the wordlist path, for example /usr/share/wordlists/rockyou.txt.",
    "hash": "Paste or point at the hash/cpassword value this command consumes.",
    "lhost": "Set your callback/listener host.",
    "lport": "Set your callback/listener port.",
}
def _missing_dep() -> "SystemExit":
    return SystemExit('the web surface needs the "web" extra:\n    pip install "obol[web]"')


def _issue(kind: str, severity: str, message: str, fix: str = "") -> dict:
    return {"kind": kind, "severity": severity, "message": message, "fix": fix}


def _token_names(command: str) -> list[str]:
    names: list[str] = []
    for match in _TOKEN_RE.finditer(command or ""):
        name = (match.group(1) or match.group(2) or "").strip().strip("{}<> ")
        if name and name not in names:
            names.append(name)
    return names


def _input_view(name: str) -> dict:
    promptable = name not in _EVIDENCE_ONLY_INPUTS
    return {
        "name": name,
        "promptable": promptable,
        "source": "fact" if not promptable else "input",
        "hint": _INPUT_HINTS.get(name, f"Set a value for {{{{{name}}}}}.")
    }


def _tool_binary(argv: list[str]) -> str:
    if not argv:
        return ""
    if argv[0] == "sudo" and len(argv) > 1:
        return argv[1]
    return argv[0]


def _tool_state(binary: str, declared_tool: str) -> dict:
    label = declared_tool or binary
    key = ""
    manual = False
    for tool in tool_inventory.REGISTRY:
        names = tool.all_names()
        if binary in names or declared_tool in names:
            key = tool.key
            label = tool.label
            manual = tool.manual
            break

    path = shutil.which(binary) if binary else ""
    source = "path" if path else ""
    if binary and not path:
        resolved = tool_inventory.resolve_binary(binary)
        if resolved:
            path = resolved
            source = "inventory"
    return {
        "binary": binary,
        "declared": declared_tool,
        "key": key,
        "label": label,
        "found": bool(path),
        "path": path or "",
        "source": source,
        "manual": manual,
    }


def _parser_status(action, command: str) -> dict:
    lowered = (command or "").lower()
    padded = f" {lowered} "
    supported = (
        any(f" {name} " in padded for name in (
            "nmap", "nxc", "ldapsearch", "smbclient", "smbmap", "rpcclient",
            "enum4linux", "hashcat", "john", "penelope", "certipy", "pywhisker",
            "feroxbuster", "ffuf", "nikto", "dirb", "gobuster", "whatweb",
            "curl", "snmpwalk", "snmp-check", "onesixtyone", "ftp", "lftp",
            "nc", "ncat", "telnet",
        ))
        or any(marker in lowered for marker in (
            "getnpusers", "getuserspns", "secretsdump", "bloodhound-python",
            "sharphound", "evil-winrm", "wmiexec", "psexec", "atexec", "smbexec",
            "kerberoast", "asreproast", "host: fuzz",
        ))
    )
    expected = [friendly(kind) for kind in action.produces]
    if supported:
        return {"state": "supported", "label": "Parser-supported", "facts": expected}
    if expected:
        return {
            "state": "raw",
            "label": "Raw evidence first",
            "facts": expected,
            "message": "This action declares expected facts, but no parser coverage is known for this command shape yet.",
        }
    return {"state": "raw", "label": "Raw evidence only", "facts": []}


def _command_preflight(action, ws: Workspace, *, target: str = "", command_index: int = 0,
                       args_extra: str = "", require_approval: bool = False) -> dict:
    command, tool = build_command(action, ws, command_index=command_index,
                                  args_extra=args_extra, target=target)
    issues: list[dict] = []
    missing = [_input_view(name) for name in _token_names(command)]
    for item in missing:
        issues.append(_issue("missing_input", "blocker", item["hint"],
                             "Set the value or collect the prerequisite fact."))

    command_without_tokens = _TOKEN_RE.sub("", command)
    needs_handoff = bool(_SHELL_META_RE.search(command_without_tokens))
    if needs_handoff:
        issues.append(_issue(
            "guided_handoff", "blocker",
            "This command uses shell metacharacters; copy it into a terminal so the operator can verify the pipeline/redirection.",
            "Use Copy and run it manually, then import or paste the output."
        ))

    argv: list[str] = []
    try:
        argv = shlex.split(command)
    except ValueError as exc:
        issues.append(_issue("parse_error", "blocker", f"Command could not be parsed: {exc}"))

    binary = _tool_binary(argv)
    tool_state = _tool_state(binary, tool)
    if binary and not tool_state["found"]:
        issues.append(_issue(
            "missing_tool", "blocker",
            f"{tool_state['label'] or binary} was not found on PATH or in O.B.O.L's tool inventory.",
            "Install it from the Tools page or add the absolute path."
        ))

    scoped_target = target or ws.target
    scope_ok = False
    if not scoped_target:
        issues.append(_issue("scope", "blocker", "No target is selected for this command."))
    else:
        allowed, reason = target_in_scope(scoped_target, ws.scope)
        command_text = " ".join(argv) if argv else command
        if not allowed:
            issues.append(_issue("scope", "blocker", f"Scope refused {scoped_target}: {reason}"))
        elif scoped_target not in command_text:
            issues.append(_issue(
                "scope", "blocker",
                f"The rendered command does not include scoped target {scoped_target}.",
                "Use copy/manual handoff until this action declares a different target field."
            ))
        else:
            scope_ok = True

    if require_approval:
        issues.append(_issue(
            "approval", "warning",
            "This step is marked noisy or intrusive and asks for confirmation before running."
        ))

    blockers = [i for i in issues if i.get("severity") == "blocker"]
    can_run = not blockers
    status = "ready" if can_run else ("manual" if needs_handoff else "blocked")
    return {
        "action_id": action.id,
        "command_index": command_index + 1,
        "command": redact_command(command, include_secrets=WEB_SHOW_SECRETS),
        "tool": tool_state,
        "parser": _parser_status(action, command),
        "missing_inputs": missing,
        "issues": issues,
        "can_run": can_run,
        "can_copy": bool(command),
        "needs_handoff": needs_handoff,
        "scope_ok": scope_ok,
        "requires_approval": require_approval,
        "status": status,
        "summary": "Ready to run" if can_run else blockers[0]["message"],
    }


def _apply_inputs(ws: Workspace, raw_inputs: dict) -> list[str]:
    if not isinstance(raw_inputs, dict):
        raise HTTPException(422, "inputs must be an object")
    saved: list[str] = []
    for raw_key, raw_value in raw_inputs.items():
        key = str(raw_key).strip().strip("{}<> ")
        if not _INPUT_KEY_RE.match(key):
            raise HTTPException(422, f"invalid input name {raw_key!r}")
        value = str(raw_value or "").strip()
        if not value:
            continue
        ws.set_input(key, value)
        saved.append(key)
    return saved


def _action_view(action, ws: Workspace, target: str = "") -> dict:
    variants = []
    for i in range(len(action.commands or [{"run": action.command}])):
        try:
            preflight = _command_preflight(action, ws, command_index=i, target=target)
        except ActionError:
            continue
        note = (action.commands[i].get("note", "") if action.commands else "")
        variants.append({
            "index": i + 1,
            "command": preflight["command"],
            "tool": preflight["tool"]["declared"] or preflight["tool"]["binary"],
            "note": note,
            "preflight": preflight,
        })
    return {
        "id": action.id, "title": action.title, "desc": board.action_desc(action),
        "hypothesis": action.hypothesis,
        "tools": action.tools or ([action.tool] if action.tool else []),
        "phase": _action_phase(action), "refs": action.refs,
        "produces": [friendly(k) for k in action.produces],
        "report": action.report or None, "variants": variants,
    }


def _first_runnable_variant(action, ws: Workspace, target: str) -> tuple[int | None, dict | None]:
    fallback = None
    for i in _quickstart_variant_indices(action):
        try:
            preflight = _command_preflight(action, ws, command_index=i, target=target)
        except ActionError:
            continue
        fallback = fallback or preflight
        if preflight["can_run"] and not preflight["needs_handoff"]:
            return i, preflight
    return None, fallback


def _quickstart_plan(ws: Workspace, target: str) -> dict:
    steps = []
    ready = 0
    tf = ws.facts_for_target(target)
    for action_id in QUICKSTART_ACTION_IDS:
        try:
            action = find_action(action_id)
        except ActionError:
            continue
        applicable = action.eligible(tf)
        done = _action_done(ws, target, action)
        preflight = None
        status = "done" if done else "waiting"
        summary = "Already has facts or a prior run for this target." if done else "Waiting for nmap/service facts."
        if applicable and not done:
            _idx, preflight = _first_runnable_variant(action, ws, target)
            status = (preflight or {}).get("status", "blocked")
            summary = (preflight or {}).get("summary", "No runnable command variant.")
            if (preflight or {}).get("can_run"):
                ready += 1
        steps.append({
            "action_id": action.id,
            "title": action.title,
            "phase": _action_phase(action),
            "applicable": applicable,
            "done": done,
            "status": status,
            "summary": summary,
            "preflight": preflight,
        })
    return {
        "title": "Quick Start",
        "description": "Runs nmap first, then safe baseline enumeration unlocked by the discovered services.",
        "action_ids": QUICKSTART_ACTION_IDS,
        "ready_count": ready,
        "steps": steps,
    }



def _text_preview(text: str, limit: int = 1800) -> str:
    """Small output preview for the web run-result panel.

    Raw evidence still lives on disk; this is only enough to explain a failure or
    an empty parse without making the user hunt through the run ledger.
    """
    text = (text or "").strip()
    if not text:
        return ""
    if len(text) <= limit:
        return text
    return "..." + text[-limit:]


def _fact_view(f) -> dict:
    return {
        "kind": f.kind, "label": friendly(f.kind), "category": _fact_category(f.kind),
        "scope": f.scope, "state": f.state.value,
        "value": _redact_value(f.value, include_secrets=WEB_SHOW_SECRETS),
        "evidence": redact_command(f.source or "", include_secrets=WEB_SHOW_SECRETS),
        "created_at": f.created_at,
    }


# Human titles for the engagement-wide findings roll-up (0e). Keys are the
# categories `_fact_category` emits; order comes from report._CATEGORY_ORDER so the
# web roll-up and the markdown report agree.
CATEGORY_TITLE = {
    "target": "Target & network",
    "scan": "Scans",
    "service": "Services",
    "ad": "Directory / AD",
    "credential": "Credentials & hashes",
    "access": "Access",
    "pivot": "Pivot candidates",
    "privesc": "Privilege escalation",
    "objective": "Flags & objectives",
    "loot": "Loot",
    "config": "Config / vuln",
    "web": "Web",
    "other": "Other",
}


def _job_feed(job: dict) -> dict:
    """A slim view of one background job for the engagement activity feed.

    The full per-target job payload carries preflight blobs and raw output; the
    engagement feed only needs each job's identity, live status, and step
    progress, so this trims it to keep the (all-jobs) endpoint cheap.
    """
    kind = job.get("kind") or ("sweep" if job.get("range") else "quickstart")
    steps = [{
        "action_id": s.get("action_id", ""),
        "title": s.get("title", ""),
        "phase": s.get("phase", ""),
        "status": s.get("status", ""),
        "success": s.get("success"),
        "added_count": s.get("added_count", 0),
        "summary": s.get("summary") or s.get("reason", ""),
    } for s in job.get("steps", [])]
    view = {
        "id": job.get("id"),
        "kind": kind,
        "status": job.get("status", ""),
        "pending": job.get("status") in {"queued", "running"},
        "success": job.get("success"),
        "target": job.get("target", ""),
        "range": job.get("range", ""),
        "message": job.get("message", ""),
        "created_at": job.get("created_at"),
        "updated_at": job.get("updated_at"),
        "started_at": job.get("started_at"),
        "ended_at": job.get("ended_at"),
        "added_count": len(job.get("facts") or []),
        "steps": steps,
    }
    if kind == "sweep":
        view["found"] = job.get("found", 0)
        view["created"] = list(job.get("created", []))
        view["existing"] = list(job.get("existing", []))
        view["enumerated"] = list(job.get("enumerated", []))
    return view


def _engagement_findings(ws: Workspace) -> dict:
    """Every proven fact across all targets, grouped by category and tagged with the
    host (or domain) that produced it — the engagement-level findings roll-up (0e).

    Proof-bound like everywhere else: only `supported` facts appear, each still
    carrying the command that established it. Secrets are redacted (the report view
    owns the secrets toggle)."""
    host_labels = {t["host"]: (t.get("label") or t["host"]) for t in ws.targets}
    host_domain = {t["host"]: t.get("domain", "") for t in ws.targets}
    buckets: dict[str, list[dict]] = {}
    host_counts: dict[str, int] = {}
    total = 0
    for f in ws.facts.facts:
        if f.state.value != "supported":
            continue
        cat = _fact_category(f.kind)
        scope = f.scope or ""
        host = ""
        if scope.startswith("host:"):
            host = scope[5:]
            origin, origin_kind = host_labels.get(host, host), "host"
        elif scope.startswith("domain:"):
            origin, origin_kind = scope[7:], "domain"
        else:
            origin, origin_kind = "engagement", "engagement"
        buckets.setdefault(cat, []).append({
            "kind": f.kind, "label": friendly(f.kind), "category": cat,
            "host": host, "origin": origin, "origin_kind": origin_kind,
            "value": _redact_value(f.value, include_secrets=WEB_SHOW_SECRETS),
            "evidence": redact_command(f.source or "", include_secrets=WEB_SHOW_SECRETS),
            "at": f.created_at,
        })
        total += 1
        if host:
            host_counts[host] = host_counts.get(host, 0) + 1

    categories = []
    for cat in sorted(buckets, key=lambda c: _CATEGORY_ORDER.get(c, 99)):
        items = sorted(buckets[cat], key=lambda x: (x["origin"], x["kind"], x["at"] or 0))
        categories.append({"id": cat, "title": CATEGORY_TITLE.get(cat, cat.title()),
                           "count": len(items), "findings": items})
    hosts = [{"host": t["host"], "label": host_labels[t["host"]],
              "domain": host_domain.get(t["host"], ""),
              "count": host_counts.get(t["host"], 0)} for t in ws.targets]
    return {"categories": categories, "total": total, "hosts": hosts}


def _engagement_timeline(ws: Workspace, limit: int = 40) -> list[dict]:
    """Recent command runs across every target, newest first — the engagement run
    ledger (as opposed to the per-target Commands tab)."""
    host_labels = {t["host"]: (t.get("label") or t["host"]) for t in ws.targets}
    out: list[dict] = []
    for row in ws.runs[::-1][:limit]:
        tgt = row.get("target", "") or ""
        out.append({
            "tool": row.get("tool", "tool"),
            "command": redact_command(row.get("command", ""), include_secrets=WEB_SHOW_SECRETS),
            "status": _run_status(row),
            "produced": list(row.get("produced") or []),
            "at": row.get("at"),
            "at_display": _stamp(row.get("at")),
            "target": tgt,
            "target_label": host_labels.get(tgt, tgt),
            "playbook": row.get("playbook"),
            "sweep": bool(row.get("sweep")),
            "range": row.get("range", ""),
        })
    return out


def _target_fact_summary(tf) -> list[dict]:
    """Grouped, useful facts for a target overview.

    Findings are still the report-ish evidence table. This summary is the operator
    working memory: ports/services, domain context, creds, access, web leads, loot.
    Shared domain facts remain visible on each target because they change what the
    target can do next.
    """
    supported = sorted(
        [f for f in tf.facts if f.state.value == "supported"],
        key=lambda f: (f.created_at, f.kind),
    )
    sections = [
        ("target", "Target", lambda k: k in {"target.configured", "host.up", "host.os_family", "host.os_hint"}),
        ("network", "Network & services",
         lambda k: k.startswith("port:") or k.startswith("scan.") or k.startswith("service.")
         or k in {"ldap.reachable", "smb.reachable", "kerberos.reachable", "winrm.reachable", "http.reachable"}),
        ("domain", "Directory / domain", lambda k: k.startswith("ad.")),
        ("credentials", "Credentials & hashes",
         lambda k: k.startswith("credential.") or k.startswith("hash.") or k.startswith("kerberos.")),
        ("access", "Access", lambda k: k.startswith("access.") or k.startswith("foothold.")),
        ("privesc", "Privilege escalation",
         lambda k: k.startswith("privesc.") or k in {"host.kernel", "host.arch"}),
        ("web", "Web leads",
         lambda k: k.startswith("web.") or k in {"db.creds", "exploit.candidate", "cloud.aws_access"}),
        ("loot", "Loot / review",
         lambda k: k.startswith("loot.") or k in {"config.review", "enum.deep", "vuln.candidates", "lateral.movement", "persistence.domain"}),
    ]

    out: list[dict] = []
    used: set[int] = set()
    for sid, title, pred in sections:
        facts = []
        for f in supported:
            if id(f) in used:
                continue
            if pred(f.kind):
                facts.append(_fact_view(f))
                used.add(id(f))
        if facts:
            out.append({"id": sid, "title": title, "count": len(facts), "facts": facts})

    other = [_fact_view(f) for f in supported if id(f) not in used]
    if other:
        out.append({"id": "other", "title": "Other facts", "count": len(other), "facts": other})
    return out


def _outcome_view(outcome) -> dict:
    r = outcome.result
    if outcome.dry_run:
        status, success = "dry-run", True
        message = "Command was rendered but not executed."
    elif r.timed_out:
        status, success = "timeout", False
        message = "Command timed out before completion."
    elif r.returncode == 0:
        status, success = "success", True
        message = "Command completed successfully."
    else:
        status, success = "failed", False
        message = f"Command exited with return code {r.returncode}."

    added = [_fact_view(f) for f in outcome.added]
    return {
        "action_id": outcome.action_id,
        "command": redact_command(outcome.command, include_secrets=WEB_SHOW_SECRETS),
        "tool": outcome.tool,
        "dry_run": outcome.dry_run,
        "success": success,
        "status": status,
        "message": message,
        "returncode": r.returncode,
        "timed_out": r.timed_out,
        "duration_ms": r.duration_ms,
        "stdout_path": str(r.stdout_path),
        "stderr_path": str(r.stderr_path),
        "stdout_preview": _text_preview(r.stdout),
        "stderr_preview": _text_preview(r.stderr),
        "added": added,
        "facts": added,
        "added_count": len(added),
    }


def _quickstart_aggregate(target: str, ran: list[dict], skipped: list[dict],
                          facts: list[dict], *, duration_ms: int = 0) -> dict:
    failures = [step for step in ran if not step.get("success")]
    status = "success" if ran and not failures else ("partial" if ran else "blocked")
    message = f"Quick Start ran {len(ran)} command(s), stored {len(facts)} fact(s), skipped {len(skipped)} step(s)."
    return {
        "quickstart": True,
        "target": target,
        "tool": "quick-start",
        "command": "quick-start baseline: " + " -> ".join(step.get("action_id", "") for step in ran),
        "success": status == "success",
        "pending": False,
        "status": status,
        "message": message,
        "dry_run": False,
        "returncode": None,
        "timed_out": any(step.get("timed_out") for step in ran),
        "duration_ms": duration_ms or sum(int(step.get("duration_ms") or 0) for step in ran),
        "stdout_path": "",
        "stderr_path": "",
        "stdout_preview": "",
        "stderr_preview": "",
        "ran": ran,
        "skipped": skipped,
        "facts": facts,
        "added": facts,
        "added_count": len(facts),
    }


def _target_bundle(ws: Workspace, host: str) -> dict:
    """Everything a target's tabbed view needs, in one payload."""
    t = ws.get_target(host)
    if not t:
        raise KeyError(host)
    tf = ws.facts_for_target(host)
    proven_phases = {phase_of_kind(f.kind) for f in tf.facts if f.state.value == "supported"}
    cur = target_phase(tf)
    palette = eligible_actions(tf)
    nxt = next_actions(tf)

    # attack-chain bar: each phase, whether reached, and the moves available in it
    chain = []
    for ph in PHASES:
        moves = [a for a in nxt if _action_phase(a) == ph]
        chain.append({
            "phase": ph, "label": PHASE_LABEL[ph], "reached": ph in proven_phases,
            "current": ph == cur, "move_count": len(moves),
            "moves": [{"id": a.id, "title": a.title} for a in moves[:8]],
        })

    # service-aware tool palette grouped by phase
    tools_by_phase = {ph: [] for ph in PHASES}
    for a in palette:
        tools_by_phase[_action_phase(a)].append(_action_view(a, ws, target=host))
    tools = [{"phase": ph, "label": PHASE_LABEL[ph], "actions": tools_by_phase[ph]}
             for ph in PHASES if tools_by_phase[ph]]

    # static checklist: the full pack by attack chain (reference), with tick state
    ticks = ws.checklist.get(host, {})
    checklist = []
    for ph in PHASES:
        items = []
        for a in sorted(load_packs(), key=lambda x: x.priority, reverse=True):
            if _action_phase(a) != ph:
                continue
            try:
                cmd, _ = build_command(a, ws, target=host)
            except ActionError:
                cmd = a.command
            items.append({"id": a.id, "title": a.title,
                          "command": redact_command(cmd, include_secrets=WEB_SHOW_SECRETS),
                          "tools": a.tools or ([a.tool] if a.tool else []),
                          "checked": bool(ticks.get(a.id))})
        if items:
            checklist.append({"phase": ph, "label": PHASE_LABEL[ph], "items": items})

    host_facts = [f for f in tf.facts if f.scope == f"host:{host}"]
    findings = [{"kind": f.kind, "label": friendly(f.kind), "category": _fact_category(f.kind),
                 "value": _redact_value(f.value, include_secrets=WEB_SHOW_SECRETS),
                 "evidence": redact_command(f.source or "", include_secrets=WEB_SHOW_SECRETS),
                 "state": f.state.value} for f in host_facts]

    commands = [{"tool": r.get("tool"), "command": redact_command(r.get("command", ""), include_secrets=WEB_SHOW_SECRETS),
                 "status": _run_status(r), "produced": r.get("produced") or [],
                 "at": r.get("at"), "playbook": r.get("playbook")}
                for r in ws.runs if r.get("target") == host or (not r.get("target") and host == ws.target)][::-1][:60]

    return {
        "meta": {"host": host, "label": t.get("label") or host,
                 "hostname": t.get("hostname", ""), "fqdn": t.get("fqdn", ""),
                 "domain": t.get("domain", ""), "os": t.get("os", ""),
                 "status": t.get("status", ""), "notes": t.get("notes", ""),
                 "active": host == ws.target},
        "access": target_access_level(tf), "phase": cur,
        "open_ports": _target_open_ports(host_facts),
        "facts_total": len([f for f in tf.facts if f.state.value == "supported"]),
        "facts_summary": _target_fact_summary(tf),
        "quickstart": _quickstart_plan(ws, host),
        "chain": chain, "next": [_action_view(a, ws, target=host) for a in nxt],
        "tools": tools, "checklist": checklist, "findings": findings,
        "commands": commands,
        "evidence": [_evidence_view(e) for e in ws.evidence_for(host)],
        "graph": build_graph_model(tf),
        # sessions layer (§6a): live interactive sessions for this host + which
        # logins are offerable now. Stored login_command is already redacted.
        "sessions": list(ws.sessions_for(host)),
        "logins": session_layer.eligible_sessions(ws, host),
        # pivot candidates (§6c): multi-homed status + candidate adjacent subnets
        # parsed from post-foothold local enum, the precondition for a tunnel.
        "pivots": pivot_summary(ws, host),
        # tunnels (§6d): live pivot transports from this foothold + offerable kinds.
        "tunnels": list(ws.tunnels_for(host)),
        "tunnel_kinds": tunnel_layer.eligible_tunnels(ws, host),
    }


def create_app(base, *, token: Optional[str] = None):
    if not _HAVE_FASTAPI:  # pragma: no cover
        raise _missing_dep()
    library.set_base(Path(base))
    library.engagements_dir().mkdir(parents=True, exist_ok=True)

    app = FastAPI(title="O.B.O.L", docs_url=None, redoc_url=None, openapi_url=None)
    token = token if token is not None else secrets.token_urlsafe(24)
    app.state.obol_token = token
    quickstart_jobs: dict[str, dict] = {}
    quickstart_jobs_lock = threading.Lock()
    quickstart_signal = {"version": 0}

    def _job_view(job: dict) -> dict:
        view = copy.deepcopy(job)
        view["pending"] = view.get("status") in {"queued", "running"}
        view["steps"] = view.get("steps", [])
        view["skipped"] = [
            step for step in view["steps"]
            if step.get("status") in {"done", "waiting", "blocked", "refused", "missing", "skipped"}
        ]
        view["added"] = view.get("facts", [])
        view["added_count"] = len(view.get("facts", []))
        return view

    def _job_update(job_id: str, mutator=None, **updates) -> dict:
        with quickstart_jobs_lock:
            job = quickstart_jobs[job_id]
            if mutator is not None:
                mutator(job)
            job.update(updates)
            job["updated_at"] = time.time()
            quickstart_signal["version"] += 1
            return _job_view(job)

    def _step_update(job_id: str, action_id: str, **updates) -> dict:
        def mutate(job: dict) -> None:
            for step in job.get("steps", []):
                if step.get("action_id") == action_id:
                    step.update(updates)
                    break
        return _job_update(job_id, mutate)

    def _active_quickstart_job(slug: str, target: str) -> dict | None:
        with quickstart_jobs_lock:
            for job in quickstart_jobs.values():
                if (job.get("slug") == slug and job.get("target") == target
                        and job.get("status") in {"queued", "running"}):
                    return _job_view(job)
        return None

    def _new_quickstart_job(slug: str, ws: Workspace, target: str) -> dict:
        now = time.time()
        plan = _quickstart_plan(ws, target)
        steps = []
        for step in plan.get("steps", []):
            step_status = step.get("status") or "waiting"
            if step.get("applicable") and not step.get("done") and step_status == "ready":
                step_status = "queued"
            steps.append({
                "action_id": step.get("action_id", ""),
                "title": step.get("title", ""),
                "phase": step.get("phase", ""),
                "status": step_status,
                "success": None,
                "summary": step.get("summary", ""),
                "preflight": step.get("preflight"),
                "facts": [],
                "added_count": 0,
            })
        job_id = uuid.uuid4().hex[:12]
        job = {
            "id": job_id,
            "job_id": job_id,
            "quickstart": True,
            "slug": slug,
            "target": target,
            "tool": "quick-start",
            "command": "quick-start baseline",
            "status": "queued",
            "success": False,
            "pending": True,
            "message": "Quick Start queued.",
            "created_at": now,
            "updated_at": now,
            "started_at": None,
            "ended_at": None,
            "duration_ms": 0,
            "returncode": None,
            "timed_out": False,
            "dry_run": False,
            "stdout_path": "",
            "stderr_path": "",
            "stdout_preview": "",
            "stderr_preview": "",
            "steps": steps,
            "facts": [],
            "added": [],
            "added_count": 0,
        }
        with quickstart_jobs_lock:
            quickstart_jobs[job_id] = job
            quickstart_signal["version"] += 1
            return _job_view(job)

    def _run_quickstart_job(job_id: str) -> None:
        started = time.time()
        current = _job_update(
            job_id,
            status="running",
            started_at=started,
            message="Quick Start running nmap first, then service-aware baseline enumeration.",
        )
        slug = current["slug"]
        host = current["target"]
        ran: list[dict] = []
        facts: list[dict] = []

        for action_id in QUICKSTART_ACTION_IDS:
            try:
                with _RUN_LOCK:
                    ws = library.get_engagement(slug)
                    if ws is None:
                        raise ActionError(f"engagement {slug!r} no longer exists")
                    if not ws.get_target(host):
                        raise ActionError(f"unknown target {host!r} in this engagement")

                    try:
                        action = find_action(action_id)
                    except ActionError as exc:
                        _step_update(job_id, action_id, status="missing", success=False,
                                     reason=str(exc), summary=str(exc))
                        continue

                    tf = ws.facts_for_target(host)
                    if _action_done(ws, host, action):
                        _step_update(job_id, action.id, status="done", success=True,
                                     reason="already has facts or a prior run",
                                     summary="Already has facts or a prior run for this target.")
                        continue
                    if not action.eligible(tf):
                        _step_update(job_id, action.id, status="waiting", success=None,
                                     reason="waiting for service facts from earlier quick-start steps",
                                     summary="Waiting for service facts from earlier quick-start steps.")
                        continue

                    cmd_index, preflight = _first_runnable_variant(action, ws, host)
                    if cmd_index is None:
                        reason = (preflight or {}).get("summary", "no runnable command variant")
                        _step_update(job_id, action.id, status="blocked", success=False,
                                     reason=reason, summary=reason, preflight=preflight)
                        continue

                    _step_update(job_id, action.id, status="running", success=None,
                                 summary="Running command.", preflight=preflight,
                                 command=(preflight or {}).get("command", ""))
                    try:
                        outcome = run_action(
                            ws, action, command_index=cmd_index, target=host,
                            ledger_extra={"surface": "web", "quickstart": True,
                                          "quickstart_job": job_id, "target": host},
                        )
                    except RunnerError as exc:
                        _step_update(job_id, action.id, status="refused", success=False,
                                     reason=str(exc), summary=str(exc), preflight=preflight)
                        continue

                view = _outcome_view(outcome)
                view["title"] = action.title
                ran.append(view)
                facts.extend(view.get("facts", []))
                _step_update(
                    job_id,
                    action.id,
                    status=view.get("status", "success"),
                    success=bool(view.get("success")),
                    summary=view.get("message", ""),
                    added_count=view.get("added_count", 0),
                    facts=view.get("facts", []),
                    command=view.get("command", ""),
                    duration_ms=view.get("duration_ms", 0),
                    returncode=view.get("returncode"),
                )
            except Exception as exc:  # keep the job visible instead of losing the thread
                _step_update(job_id, action_id, status="failed", success=False,
                             reason=str(exc), summary=str(exc))

        with quickstart_jobs_lock:
            job = quickstart_jobs[job_id]
            skipped = [
                step for step in job.get("steps", [])
                if step.get("status") in {"done", "waiting", "blocked", "refused", "missing", "skipped"}
            ]
        aggregate = _quickstart_aggregate(host, ran, skipped, facts,
                                          duration_ms=int((time.time() - started) * 1000))

        def finish(job: dict) -> None:
            job.update(aggregate)
            job["steps"] = job.get("steps", [])
            job["status"] = aggregate["status"]
            job["success"] = aggregate["success"]
            job["pending"] = False
            job["message"] = aggregate["message"]
            job["ended_at"] = time.time()

        _job_update(job_id, finish)

    # ── discovery sweep job ──────────────────────────────────────────────────
    # A sweep discovers live hosts in an authorized range and auto-creates a
    # target for each, through the one scope-enforced runner (obol/discovery.py).
    # It rides the same background-job map and SSE signal as Quick Start, and the
    # new targets reach the browser live as `target_added` store events.
    def _new_sweep_job(slug: str, range_: str, enumerate_: bool = True) -> dict:
        now = time.time()
        job_id = uuid.uuid4().hex[:12]
        job = {
            "id": job_id, "job_id": job_id, "kind": "sweep", "range": range_,
            "slug": slug, "tool": "nmap", "command": "", "status": "queued",
            "success": False, "pending": True, "enumerate": enumerate_,
            "message": f"Discovery sweep of {range_} queued.",
            "created_at": now, "updated_at": now, "started_at": None, "ended_at": None,
            "steps": [], "facts": [], "found": 0, "created": [], "existing": [],
            "enumerated": [], "enum_jobs": [],
        }
        with quickstart_jobs_lock:
            quickstart_jobs[job_id] = job
            quickstart_signal["version"] += 1
            return _job_view(job)

    def _active_sweep_job(slug: str, range_: str) -> dict | None:
        with quickstart_jobs_lock:
            for job in quickstart_jobs.values():
                if (job.get("kind") == "sweep" and job.get("slug") == slug
                        and job.get("range") == range_
                        and job.get("status") in {"queued", "running"}):
                    return _job_view(job)
        return None

    def _run_sweep_job(job_id: str) -> None:
        with quickstart_jobs_lock:
            job = quickstart_jobs[job_id]
            range_, slug, enumerate_ = job["range"], job["slug"], job.get("enumerate", True)
        _job_update(job_id, status="running", started_at=time.time(),
                    message=f"Sweeping {range_} for live hosts…")
        try:
            with _RUN_LOCK:
                ws = library.get_engagement(slug)
                if ws is None:
                    raise ActionError(f"engagement {slug!r} no longer exists")
                summary = discovery.run_sweep(ws, range_)
        except Exception as exc:  # RunnerError, ActionError, or an unexpected fault
            _job_update(job_id, status="failed", success=False, pending=False,
                        message=str(exc), ended_at=time.time())
            return
        found, created = len(summary["hosts"]), summary["created"]
        base = (f"Swept {range_}: {found} live host{'' if found == 1 else 's'}, "
                f"{len(created)} new target{'' if len(created) == 1 else 's'}")
        _job_update(job_id, command=summary["command"], found=found,
                    created=created, existing=summary["existing"])

        # Fan out: run the service-aware Quick Start baseline against each new host,
        # one at a time, so services and facts populate without the operator opening
        # each target. Each host's run is a normal Quick Start job (same engine), so
        # its steps and facts stream to the page live. Only newly discovered hosts
        # are enumerated — a re-sweep never re-runs enumeration on existing targets.
        enumerated: list[str] = []
        if enumerate_ and created:
            for i, host in enumerate(created):
                _job_update(job_id,
                            message=f"{base}. Enumerating {host} ({i + 1}/{len(created)})…")
                try:
                    if _active_quickstart_job(slug, host):
                        continue
                    with _RUN_LOCK:
                        ws = library.get_engagement(slug)
                        if ws is None or not ws.get_target(host):
                            continue
                        qs = _new_quickstart_job(slug, ws, host)
                    # run synchronously in this thread (it takes _RUN_LOCK per step
                    # itself, so it must not be held here); the sweep waits for the
                    # baseline before moving to the next host.
                    _run_quickstart_job(qs["id"])
                    enumerated.append(host)

                    def _record(j, cid=qs["id"], en=list(enumerated)):
                        j["enum_jobs"].append(cid)
                        j["enumerated"] = en
                    _job_update(job_id, _record)
                except Exception:
                    # one host's enumeration failing must not strand the sweep job;
                    # the host is still a target, and can be Quick-Started by hand.
                    continue

        tail = (f". Enumerated {len(enumerated)} host{'' if len(enumerated) == 1 else 's'}."
                if enumerate_ and created else ".")
        _job_update(job_id, status="success", success=True, pending=False,
                    enumerated=enumerated, ended_at=time.time(), message=base + tail)

    def active() -> Workspace:
        ws = library.resolve_active()
        if ws is None:
            raise HTTPException(404, "no active engagement — create one first")
        return ws

    def target_or_404(ws: Workspace, host: str):
        if not host or not ws.get_target(host):
            raise HTTPException(404, f"unknown target {host!r} in this engagement")
        return host

    @app.middleware("http")
    async def _require_token(request, call_next):
        if request.url.path.startswith("/api/"):
            supplied = request.headers.get("x-obol-token") or request.query_params.get("token")
            if not supplied or not secrets.compare_digest(supplied, token):
                return JSONResponse({"detail": "missing or invalid token — open the URL from `obol serve`"},
                                    status_code=401)
        return await call_next(request)

    # ── engagements ──────────────────────────────────────────────────────────
    @app.get("/api/engagements")
    def api_engagements():
        return {"engagements": library.list_engagements(), "active": library.active_slug()}

    @app.post("/api/engagements")
    def api_create_engagement(payload: dict = Body(...)):
        name = (payload or {}).get("name", "").strip()
        if not name:
            raise HTTPException(422, "name is required")
        ws = library.create_engagement(name)
        return {"ok": True, "slug": ws.root.name, "name": ws.name}

    @app.post("/api/engagements/activate")
    def api_activate_engagement(payload: dict = Body(...)):
        slug = (payload or {}).get("slug", "")
        if not library.get_engagement(slug):
            raise HTTPException(404, f"no engagement {slug!r}")
        library.set_active(slug)
        return {"ok": True, "active": slug}

    @app.get("/api/meta")
    def api_meta():
        ws = active()
        dom = ws.facts.values("ad.domain_known")
        return {"name": ws.name, "slug": ws.root.name,
                "domain": (dom[0].get("name") if dom else "") or "",
                "targets": ws.targets, "active_target": ws.target,
                "scope": list(ws.scope), "phases": PHASES,
                "phase_labels": PHASE_LABEL}

    # ── engagement overview + graph + report ─────────────────────────────────
    @app.get("/api/overview")
    def api_overview():
        ws = active()
        ctx = build_report_context(ws, include_secrets=WEB_SHOW_SECRETS)
        activity = [{"tool": r["tool"], "command": r["command"], "status": r["status"],
                     "produced": r["produced"], "at_display": r["at_display"],
                     "playbook": r.get("playbook")} for r in ctx["timeline"][-14:][::-1]]
        return {"meta": ctx["meta"], "tiles": ctx["tiles"], "targets": ctx["targets"],
                "scope": list(ws.scope),
                "category_counts": ctx["category_counts"], "severity_counts": ctx["severity_counts"],
                "access_ladder": ctx["access_ladder"], "activity": activity,
                "engagement_graph": ctx["engagement_graph"], "bloodhound": ctx["bloodhound"]}

    @app.get("/api/engagement/graph")
    def api_engagement_graph():
        return build_engagement_graph(active())

    @app.get("/api/engagement/activity")
    def api_engagement_activity():
        """Engagement-level operations console (0e): the live run feed (sweeps and
        per-host Quick Start jobs, in-flight and recent) plus a category-organized
        findings roll-up across every discovered host and the cross-host run
        ledger. Reads are fresh; the page repaints on the same SSE change feed."""
        ws = active()
        with quickstart_jobs_lock:
            jobs = [_job_feed(job) for job in quickstart_jobs.values()]
        jobs.sort(key=lambda j: j.get("updated_at") or 0, reverse=True)
        active_jobs = [j for j in jobs if j["pending"]]
        # Keep every in-flight job, then a bounded slice of recent finished ones so a
        # big sweep (one job per host) does not grow this response without bound.
        recent = active_jobs + [j for j in jobs if not j["pending"]][:16]
        findings = _engagement_findings(ws)
        return {
            "jobs": recent,
            "active_count": len(active_jobs),
            "timeline": _engagement_timeline(ws),
            "findings": findings["categories"],
            "findings_total": findings["total"],
            "hosts": findings["hosts"],
        }

    @app.get("/api/report")
    def api_report(include_secrets: bool = Query(True)):
        return build_report_context(active(), include_secrets=include_secrets)

    @app.get("/api/report.md")
    def api_report_md(include_secrets: bool = Query(True)):
        md = build_report(active(), include_secrets=include_secrets)
        return PlainTextResponse(md, headers={"Content-Disposition": 'attachment; filename="obol-report.md"'})

    # ── scope ────────────────────────────────────────────────────────────────
    # Engagement scope is the runner's authorization boundary (obol/scope.py): the
    # runner may only touch a host inside one of these entries. Exposing it here
    # lets the operator authorize hosts and CIDR ranges from the web before a
    # discovery sweep can run against them.
    @app.get("/api/scope")
    def api_scope():
        return {"scope": list(active().scope)}

    @app.post("/api/scope")
    def api_add_scope(payload: dict = Body(...)):
        value = (payload or {}).get("value", "").strip()
        if not value:
            raise HTTPException(422, "value is required (a host, IP, or CIDR)")
        with _RUN_LOCK:
            ws = active()
            entry = ws.add_scope(value)
            if not entry:
                raise HTTPException(422, f"could not parse scope entry {value!r}")
            ws.save()
            return {"scope": list(ws.scope), "added": entry}

    @app.delete("/api/scope")
    def api_remove_scope(value: str = Query(...)):
        with _RUN_LOCK:
            ws = active()
            # Never strip authorization out from under a live target: the exact host
            # entry that add_target created keeps it in scope for the runner.
            norm = normalize_target(value)
            if norm and any(t.get("host") == norm for t in ws.targets):
                raise HTTPException(
                    409, f"{value} is an active target — remove the target first")
            if not ws.remove_scope(value):
                raise HTTPException(404, f"{value} is not in scope")
            ws.save()
            return {"scope": list(ws.scope), "removed": value}

    # ── targets ──────────────────────────────────────────────────────────────
    @app.post("/api/targets")
    def api_add_target(payload: dict = Body(...)):
        host = (payload or {}).get("host", "").strip()
        if not host:
            raise HTTPException(422, "host is required")
        with _RUN_LOCK:
            ws = active()
            rec = ws.add_target(host, (payload or {}).get("label", "").strip())
            ws.save()
        return {"ok": True, "target": rec}

    @app.post("/api/target/activate")
    def api_activate_target(payload: dict = Body(...)):
        with _RUN_LOCK:
            ws = active()
            host = target_or_404(ws, (payload or {}).get("target", ""))
            ws.set_active_target(host)
            ws.save()
        return {"ok": True, "active_target": host}

    @app.delete("/api/target")
    def api_remove_target(target: str = Query(...)):
        with _RUN_LOCK:
            ws = active()
            if not ws.remove_target(target):
                raise HTTPException(404, f"unknown target {target!r}")
            ws.save()
        return {"ok": True}

    @app.get("/api/target")
    def api_target(target: str = Query(...)):
        ws = active()
        target_or_404(ws, target)
        return _target_bundle(ws, target)

    @app.post("/api/target/checklist")
    def api_checklist(payload: dict = Body(...)):
        with _RUN_LOCK:
            ws = active()
            host = target_or_404(ws, (payload or {}).get("target", ""))
            item = (payload or {}).get("item", "")
            checked = bool((payload or {}).get("checked", False))
            ws.checklist.setdefault(host, {})[item] = checked
            ws.save()
        return {"ok": True}

    @app.post("/api/target/notes")
    def api_notes(payload: dict = Body(...)):
        with _RUN_LOCK:
            ws = active()
            host = target_or_404(ws, (payload or {}).get("target", ""))
            ws.get_target(host)["notes"] = str((payload or {}).get("notes", ""))
            ws.save()
        return {"ok": True}

    @app.post("/api/inputs")
    def api_inputs(payload: dict = Body(...)):
        with _RUN_LOCK:
            ws = active()
            target = (payload or {}).get("target", "")
            if target:
                target_or_404(ws, target)
            saved = _apply_inputs(ws, (payload or {}).get("inputs", {}) or {})
            ws.save()
        return {"ok": True, "saved": saved}

    @app.get("/api/action/preflight")
    def api_action_preflight(action_id: str = Query(...), target: str = Query(""),
                             cmd_index: int = Query(1)):
        ws = active()
        if target:
            target_or_404(ws, target)
        try:
            action = find_action(action_id)
            return _command_preflight(action, ws, target=target,
                                      command_index=max(0, cmd_index - 1))
        except ActionError as exc:
            raise HTTPException(404, str(exc))

    # ── evidence ─────────────────────────────────────────────────────────────
    @app.post("/api/target/evidence")
    async def api_add_evidence(target: str = Form(...), file: UploadFile = File(...),
                               phase: str = Form(""), caption: str = Form("")):
        data = await file.read()
        with _RUN_LOCK:
            ws = active()
            target_or_404(ws, target)
            rec = ws.add_evidence(filename=file.filename or "upload", data=data,
                                  target=target, phase=phase, caption=caption)
            ws.save()
        return {"ok": True, "evidence": _evidence_view(rec)}

    @app.delete("/api/evidence/{eid}")
    def api_del_evidence(eid: str):
        with _RUN_LOCK:
            ws = active()
            if not ws.remove_evidence(eid):
                raise HTTPException(404, "no such evidence")
            ws.save()
        return {"ok": True}

    @app.get("/api/evidence/{eid}")
    def api_get_evidence(eid: str):
        ws = active()
        for e in ws.evidence:
            if e.get("id") == eid:
                path = ws.evidence_dir / e.get("stored", "")
                if not path.exists():
                    raise HTTPException(404, "evidence file missing")
                ctype = mimetypes.guess_type(e.get("filename", ""))[0] or "application/octet-stream"
                return FileResponse(str(path), media_type=ctype)
        raise HTTPException(404, "no such evidence")

    # ── BloodHound ingestion ─────────────────────────────────────────────────
    @app.post("/api/bloodhound")
    async def api_bloodhound(files: list[UploadFile] = File(...)):
        uploads = [(f.filename or "upload", await f.read()) for f in files]
        with _RUN_LOCK:
            ws = active()
            summary = bloodhound.ingest(ws, uploads)
        return {"ok": True, "domain": summary.get("domain"), "users": summary.get("users"),
                "computers": len(summary.get("computers", [])),
                "domain_admins": len(summary.get("domain_admins", [])),
                "kerberoastable": len(summary.get("kerberoastable", [])),
                "asrep_roastable": len(summary.get("asrep_roastable", [])),
                "added_facts": summary.get("added_facts", [])}

    # ── tool inventory ───────────────────────────────────────────────────────
    @app.get("/api/tools")
    def api_tools():
        return tool_inventory.scan()

    @app.post("/api/tools/add")
    def api_tools_add(payload: dict = Body(...)):
        key = (payload or {}).get("tool", "")
        path = (payload or {}).get("path", "").strip()
        try:
            d = tool_inventory.add_override(key, path)
        except KeyError:
            raise HTTPException(404, f"unknown tool {key!r}")
        except FileNotFoundError:
            raise HTTPException(400, f"no file at {path!r}")
        return {"ok": True, **d}

    @app.post("/api/tools/install")
    def api_tools_install(payload: dict = Body(...)):
        key = (payload or {}).get("tool", "")
        if key not in {t.key for t in tool_inventory.REGISTRY}:
            raise HTTPException(404, f"unknown tool {key!r}")
        return tool_inventory.install(key)

    # ── run-from-site ────────────────────────────────────────────────────────
    @app.post("/api/run/action")
    def api_run_action(payload: dict = Body(...)):
        action_id = (payload or {}).get("action_id", "")
        if not action_id:
            raise HTTPException(422, "action_id is required")
        cmd_index = max(0, int((payload or {}).get("cmd_index", 1)) - 1)
        dry_run = bool((payload or {}).get("dry_run", False))
        target = (payload or {}).get("target", "")
        args_extra = str((payload or {}).get("args_extra", "") or "")
        allow_shell = bool((payload or {}).get("allow_shell", False))
        with _RUN_LOCK:
            ws = active()
            if target:
                target_or_404(ws, target)
            inputs = (payload or {}).get("inputs", {}) or {}
            if inputs:
                _apply_inputs(ws, inputs)
                ws.save()
            try:
                action = find_action(action_id)
                outcome = run_action(ws, action, command_index=cmd_index, dry_run=dry_run,
                                     allow_shell=allow_shell, args_extra=args_extra,
                                     target=target, ledger_extra={"surface": "web", "target": target or ws.target})
            except ActionError as exc:
                raise HTTPException(404, str(exc))
            except RunnerError as exc:
                raise HTTPException(400, str(exc))
        return _outcome_view(outcome)

    # ── sessions layer (one-click login + live session state) ────────────────
    @app.post("/api/run/login")
    def api_run_login(payload: dict = Body(...)):
        """Validate access with the non-interactive proof and, on success, record a
        live session. Returns the proof outcome + the recorded session, whose
        login_command is the full ready-to-paste command (secrets shown by default —
        this is the operator's localhost lab/exam box)."""
        target = (payload or {}).get("target", "")
        kind = (payload or {}).get("kind", "")
        method = (payload or {}).get("method", "")
        if not target or not kind:
            raise HTTPException(422, "target and kind are required")
        with _RUN_LOCK:
            ws = active()
            target_or_404(ws, target)
            try:
                res = session_layer.open_session(ws, target, kind, method=method, surface="web")
            except SessionError as exc:
                raise HTTPException(400, str(exc))
            except ActionError as exc:
                raise HTTPException(404, str(exc))
            except RunnerError as exc:
                raise HTTPException(400, str(exc))
        return {
            "ok": res["ok"], "kind": res["kind"], "method": res.get("method", ""),
            "reason": res.get("reason", ""),
            "session": res.get("session"),
            "outcome": _outcome_view(res["outcome"]),
        }

    @app.get("/api/session/login_command")
    def api_session_login_command(target: str = Query(...), kind: str = Query(...),
                                  method: str = Query("")):
        """The full interactive login command, rebuilt from facts — used to copy an
        existing session's command without re-running the proof."""
        ws = active()
        target_or_404(ws, target)
        try:
            return {"command": session_layer.build_login_command(ws, target, kind, method)}
        except SessionError as exc:
            raise HTTPException(404, str(exc))

    @app.post("/api/session/probe")
    def api_session_probe(payload: dict = Body(...)):
        sid = (payload or {}).get("id", "")
        with _RUN_LOCK:
            ws = active()
            if not ws.get_session(sid):
                raise HTTPException(404, f"no session {sid!r}")
            try:
                res = session_layer.probe_session(ws, sid)
            except (SessionError, ActionError) as exc:
                raise HTTPException(404, str(exc))
            except RunnerError as exc:
                raise HTTPException(400, str(exc))
        return {"ok": True, "alive": res["alive"], "session": res["session"]}

    @app.post("/api/session/close")
    def api_session_close(payload: dict = Body(...)):
        sid = (payload or {}).get("id", "")
        with _RUN_LOCK:
            ws = active()
            if not ws.close_session(sid):
                raise HTTPException(404, f"no session {sid!r}")
            ws.save()
        return {"ok": True}

    @app.delete("/api/session")
    def api_session_remove(id: str = Query(...)):
        with _RUN_LOCK:
            ws = active()
            if not ws.remove_session(id):
                raise HTTPException(404, f"no session {id!r}")
            ws.save()
        return {"ok": True}

    # ── tunnels layer (§6d: pivot transports + route-aware runner) ────────────
    @app.post("/api/run/tunnel")
    def api_run_tunnel(payload: dict = Body(...)):
        """Record a tunnel from a foothold, auto-extend scope to its exposed subnet,
        and return the setup command to launch. A tunnel is live state, not a fact;
        its status defaults to up (a §6e health sweep will confirm it)."""
        payload = payload or {}
        target = payload.get("target", "")
        kind = payload.get("kind", "")
        if not target or not kind:
            raise HTTPException(422, "target and kind are required")
        with _RUN_LOCK:
            ws = active()
            target_or_404(ws, target)
            try:
                res = tunnel_layer.open_tunnel(
                    ws, target, kind,
                    subnet=payload.get("subnet", ""), lhost=payload.get("lhost", ""),
                    local_port=int(payload.get("local_port", 0) or 0),
                    remote=payload.get("remote", ""),
                    remote_port=int(payload.get("remote_port", 0) or 0),
                    surface="web",
                )
            except TunnelError as exc:
                raise HTTPException(400, str(exc))
        return {"ok": res["ok"], "tunnel": res["tunnel"], "setup_command": res["setup_command"],
                "proxychains": res["proxychains"], "scope_added": res["scope_added"]}

    @app.post("/api/tunnel/close")
    def api_tunnel_close(payload: dict = Body(...)):
        tid = (payload or {}).get("id", "")
        with _RUN_LOCK:
            ws = active()
            try:
                tunnel_layer.close_tunnel(ws, tid)
            except TunnelError as exc:
                raise HTTPException(404, str(exc))
        return {"ok": True}

    @app.delete("/api/tunnel")
    def api_tunnel_remove(id: str = Query(...)):
        with _RUN_LOCK:
            ws = active()
            try:
                res = tunnel_layer.remove_tunnel(ws, id)
            except TunnelError as exc:
                raise HTTPException(404, str(exc))
        return {"ok": True, "scope_retracted": res["scope_retracted"]}

    @app.post("/api/run/quickstart")
    def api_run_quickstart(payload: dict = Body(...)):
        target = (payload or {}).get("target", "")
        if not target:
            raise HTTPException(422, "target is required")
        with _RUN_LOCK:
            ws = active()
            slug = library.active_slug() or ws.root.name
            host = target_or_404(ws, target)
            existing = _active_quickstart_job(slug, host)
            if existing:
                return existing
            job = _new_quickstart_job(slug, ws, host)

        threading.Thread(target=_run_quickstart_job, args=(job["id"],), daemon=True).start()
        return job

    @app.get("/api/quickstart/jobs")
    def api_quickstart_jobs(target: str = Query("")):
        with quickstart_jobs_lock:
            jobs = [_job_view(job) for job in quickstart_jobs.values()]
        if target:
            jobs = [job for job in jobs if job.get("target") == target]
        jobs.sort(key=lambda job: job.get("updated_at") or 0, reverse=True)
        return {"jobs": jobs}

    @app.get("/api/quickstart/jobs/{job_id}")
    def api_quickstart_job(job_id: str):
        with quickstart_jobs_lock:
            job = quickstart_jobs.get(job_id)
            if not job:
                raise HTTPException(404, "no such Quick Start job")
            return _job_view(job)

    # ── discovery sweep ──────────────────────────────────────────────────────
    @app.post("/api/run/sweep")
    def api_run_sweep(payload: dict = Body(...)):
        range_ = (payload or {}).get("range", "").strip()
        # Default on: a sweep discovers hosts AND runs the safe baseline enumeration
        # against each new one. `enumerate: false` does discovery only.
        enumerate_ = bool((payload or {}).get("enumerate", True))
        if not range_:
            raise HTTPException(422, "range is required (an authorized scope entry)")
        with _RUN_LOCK:
            ws = active()
            slug = library.active_slug() or ws.root.name
            if range_ not in ws.scope:
                raise HTTPException(
                    400, f"{range_} is not in scope — authorize the range first")
            existing = _active_sweep_job(slug, range_)
            if existing:
                return existing
            job = _new_sweep_job(slug, range_, enumerate_)
        threading.Thread(target=_run_sweep_job, args=(job["id"],), daemon=True).start()
        return job

    @app.get("/api/sweep/jobs/{job_id}")
    def api_sweep_job(job_id: str):
        with quickstart_jobs_lock:
            job = quickstart_jobs.get(job_id)
            if not job or job.get("kind") != "sweep":
                raise HTTPException(404, "no such sweep job")
            return _job_view(job)


    @app.post("/api/run/playbook")
    def api_run_playbook(payload: dict = Body(...)):
        from .. import playbook
        name = (payload or {}).get("name", "")
        step_no = int((payload or {}).get("step", 0))
        approve = bool((payload or {}).get("approve", False))
        dry_run = bool((payload or {}).get("dry_run", False))
        target = (payload or {}).get("target", "")
        inputs = (payload or {}).get("inputs", {}) or {}
        if not name or step_no < 1:
            raise HTTPException(422, "name and a 1-based step are required")
        with _RUN_LOCK:
            ws = active()
            if target:
                target_or_404(ws, target)
            if inputs:
                _apply_inputs(ws, inputs)
                ws.save()
            try:
                pb = playbook.load_playbook(name)
            except FileNotFoundError:
                raise HTTPException(404, f"no playbook named {name!r}")
            try:
                steps = playbook.resolve_steps(pb, load_packs())
            except KeyError as exc:
                raise HTTPException(500, f"playbook references unknown action {exc}")
            if not 1 <= step_no <= len(steps):
                raise HTTPException(404, f"playbook {name!r} has {len(steps)} step(s)")
            step, action = steps[step_no - 1]
            if step.require_approval and not approve and not dry_run:
                raise HTTPException(409, {"reason": "require_approval",
                                          "message": f"step {step_no} ({step.label}) is noisy/intrusive"})
            try:
                outcome = run_action(ws, action, command_index=max(0, (step.cmd or 1) - 1),
                                     dry_run=dry_run, args_extra=step.args_extra, target=target,
                                     ledger_extra={"surface": "web", "playbook": pb.name,
                                                   "playbook_step": step_no, "target": target or ws.target})
            except ActionError as exc:
                raise HTTPException(404, str(exc))
            except RunnerError as exc:
                raise HTTPException(400, str(exc))
        view = _outcome_view(outcome)
        view.update({"playbook": pb.name, "step": step_no, "has_next": step_no < len(steps)})
        return view

    @app.get("/api/playbooks")
    def api_playbooks():
        from .. import playbook
        return {"playbooks": [{"name": pb.name, "title": pb.title, "description": pb.description}
                              for pb in playbook.list_playbooks()]}

    @app.get("/api/playbook/{name}")
    def api_playbook(name: str, target: str = Query("")):
        from .. import playbook
        ws = active()
        try:
            pb = playbook.load_playbook(name)
        except FileNotFoundError:
            raise HTTPException(404, f"no playbook named {name!r}")
        try:
            steps = playbook.resolve_steps(pb, load_packs())
        except KeyError as exc:
            raise HTTPException(500, f"playbook references unknown action {exc}")
        out = []
        for i, (step, action) in enumerate(steps, 1):
            try:
                preflight = _command_preflight(
                    action, ws, target=target, command_index=max(0, (step.cmd or 1) - 1),
                    args_extra=step.args_extra, require_approval=bool(step.require_approval),
                )
                cmd = preflight["command"]
            except Exception:
                preflight = {}
                cmd = action.command
            out.append({"step": i, "label": step.label, "action_id": action.id, "title": action.title,
                        "command": cmd,
                        "preflight": preflight,
                        "require_approval": bool(step.require_approval),
                        "note": getattr(step, "note", "") or ""})
        return {"name": pb.name, "title": pb.title, "description": pb.description, "steps": out}

    # ── real-time ────────────────────────────────────────────────────────────
    def _active_store() -> tuple[Optional[str], Optional[Store]]:
        slug = library.active_slug()
        if not slug:
            return None, None
        return slug, Store(library.engagement_path(slug) / ".obol" / STATE_DB)

    @app.get("/api/events")
    async def api_events(request: Request):
        """Server-sent change feed. Each `state` event carries JSON describing what
        changed in the active engagement's store since the last one — so the page
        patches the affected panels and shows a toast rather than re-fetching
        wholesale. An engagement switch emits `{reset:true}` (full reload); Quick
        Start job progress rides along as `qs` (a version the client uses to refetch
        the running job)."""
        async def gen():
            slug, store = _active_store()
            # Start from the current tail: the initial page load already fetched the
            # full state, so we stream only events that happen from now on.
            last_slug = slug
            last_event_id = store.latest_event_id() if store else 0
            last_qs = quickstart_signal["version"]
            yield "event: hello\ndata: connected\n\n"
            while True:
                if await request.is_disconnected():
                    break
                slug, store = _active_store()
                payload: dict = {}
                if slug != last_slug:
                    # active engagement changed under us — tell the client to reload.
                    last_slug = slug
                    last_event_id = store.latest_event_id() if store else 0
                    last_qs = quickstart_signal["version"]
                    payload = {"engagement": slug, "reset": True}
                else:
                    events = store.read_events(last_event_id) if store else []
                    if events:
                        last_event_id = events[-1]["id"]
                    qs = quickstart_signal["version"]
                    if events or qs != last_qs:
                        payload = {"engagement": slug, "events": events, "qs": qs}
                        last_qs = qs
                if payload:
                    yield f"event: state\ndata: {json.dumps(payload)}\n\n"
                else:
                    yield ": keep-alive\n\n"
                await asyncio.sleep(0.8)
        return StreamingResponse(gen(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    # ── static SPA ───────────────────────────────────────────────────────────
    @app.get("/")
    def index():
        return FileResponse(STATIC_DIR / "index.html")

    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    return app


def serve(ws: Optional[Workspace] = None, host: str = "127.0.0.1", port: int = 8765,
          token: Optional[str] = None, base: Optional[Path] = None) -> None:
    """Start the localhost server (blocking) over the engagement library. If `ws` is
    given (a directory-based engagement), it is registered into the library and made
    active so `obol serve` from an engagement dir just works."""
    try:
        import uvicorn
    except ModuleNotFoundError as exc:  # pragma: no cover
        raise _missing_dep() from exc
    token = token if token is not None else secrets.token_urlsafe(24)
    base_dir = Path(base) if base else library.base_dir()
    library.set_base(base_dir)
    library.engagements_dir().mkdir(parents=True, exist_ok=True)
    # If launched from a directory engagement that isn't in the library, link it in.
    if ws is not None and ws.exists():
        slug = ws.root.name
        target = library.engagement_path(slug)
        if ws.root.resolve() != target.resolve() and not library.get_engagement(slug):
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.symlink_to(ws.root.resolve(), target_is_directory=True)
            except OSError:
                pass
        if library.get_engagement(slug):
            library.set_active(slug)
    app = create_app(base_dir, token=token)
    url = f"http://{host}:{port}/?token={token}"
    print("O.B.O.L web surface (localhost) — open this URL (the token gates the API):")
    print(f"    {url}")
    print(f"    engagement library: {base_dir}")
    print("Ctrl-C to stop.")
    uvicorn.run(app, host=host, port=port, log_level="warning")

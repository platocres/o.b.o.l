"""Enum run-and-rank (§8) — stage a read-only enumeration tool onto a foothold, run
it over the proven exec channel, and surface the promising findings.

This is the enum tier of the staging layer (`docs/PAYLOAD_STAGING.md`): linPEAS /
winPEAS / PowerUp change nothing on the target, so obol may push and run them behind
a one-click approval, then rank what came back. Two proof-bound outputs result:

- the existing `privesc.*` **lead** parsers fire on the tool's output (the run uses
  the `linux-enum` / `windows-enum` action id), so sudo rights, SUID binaries,
  capabilities, and dangerous Windows privileges land as the same narrow leads a
  hand-run enum would produce; and
- a ranked `enum.findings` fact records the lines the tool itself flagged
  (known-exploit names, probability markers, credential hints) — **candidate leads,
  never proof**: a highlighted line is a place to look, not a win.

Nothing here escalates on its own; the exploit tier (§8 PR#5) consumes these leads.
PowerView and other interactive tools are *staged + guided* rather than auto-run.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from . import provision, sessions, staging
from .facts import Fact, ProofState
from .pack import Action
from .scope import normalize_target
from .workspace import Workspace


class EnumError(Exception):
    """An enum-run request that cannot be built."""


@dataclass(frozen=True)
class EnumTool:
    material: str                    # provision material key
    os: str                          # "linux" | "windows"
    action_id: str                   # privesc-parser action id, so leads are extracted
    run_template: str                # exec-channel command; {{remote}} is the staged path
    guided: bool = False             # staged + guided (interactive), not auto-run
    timeout: int = 900
    note: str = ""


# The auto-runnable enum tools, plus guided ones. Run over the same proven exec
# channel the sessions layer uses (sshpass ssh / nxc winrm -x).
ENUM_TOOLS: dict[str, EnumTool] = {
    "linpeas": EnumTool(
        material="linpeas", os="linux", action_id="linux-enum",
        run_template="sshpass -p {{password}} ssh -o StrictHostKeyChecking=no -o ConnectTimeout=8 {{user}}@{{target}} sh {{remote}}"),
    "winpeas": EnumTool(
        material="winpeas", os="windows", action_id="windows-enum",
        run_template="nxc winrm {{target}} -u {{user}} -p {{password}} -x {{remote}}"),
    "linenum": EnumTool(
        material="linenum", os="linux", action_id="linux-enum",
        run_template="sshpass -p {{password}} ssh -o StrictHostKeyChecking=no -o ConnectTimeout=8 {{user}}@{{target}} sh {{remote}}"),
    "linux-exploit-suggester": EnumTool(
        material="linux-exploit-suggester", os="linux", action_id="linux-enum",
        run_template="sshpass -p {{password}} ssh -o StrictHostKeyChecking=no -o ConnectTimeout=8 {{user}}@{{target}} sh {{remote}}"),
    "powerup": EnumTool(
        material="powerup", os="windows", action_id="windows-enum", guided=True,
        run_template="nxc winrm {{target}} -u {{user}} -p {{password}} -x \"powershell -ep bypass -c . {{remote}}; Invoke-AllChecks\"",
        note="PowerShell checks; review before running against a monitored host"),
}


# ── highlight extraction ──────────────────────────────────────────────────────
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# (weight, label, pattern) — higher weight = stronger signal. A line's rank is the
# strongest signal it matches. Deliberately conservative so the ranked list stays a
# short "look here" set, not a re-print of the whole tool output.
_SIGNALS: tuple[tuple[int, str, re.Pattern], ...] = (
    (5, "known-exploit", re.compile(
        r"(?i)\b(CVE-\d{4}-\d{3,7}|dirty ?cow|dirty ?pipe|pwnkit|printnightmare|"
        r"god ?potato|juicy ?potato|rogue ?potato|sweet ?potato|print ?spoofer|zerologon)\b")),
    (4, "priv-signal", re.compile(
        r"(?i)(SeImpersonatePrivilege|SeAssignPrimaryTokenPrivilege|SeBackupPrivilege|"
        r"SeDebugPrivilege|AlwaysInstallElevated|unquoted service path|no ?root ?squash)")),
    (4, "vuln-language", re.compile(r"(?i)\b(vulnerable|exploitable|likely to be)\b")),
    (3, "probability", re.compile(r"\b([5-9]\d|100)\s?%")),
    (3, "credential", re.compile(
        r"(?i)(\bpassword\b|\bcredential|id_rsa|\.kdbx|\bunattend\b|web\.config|"
        r"private key|api[_-]?key)")),
    (2, "sudo-suid", re.compile(r"(?i)(NOPASSWD|\bsudo\b|\bsuid\b|setuid|cap_[a-z_]+)")),
)

_MAX_HIGHLIGHTS = 30


def extract_highlights(text: str) -> list[dict]:
    """Rank the lines an enum tool flagged as interesting. Pure and tool-agnostic:
    strips ANSI colour, scores each line by the strongest signal it matches, dedupes,
    and returns the top findings (candidate leads, not proof)."""
    scored: dict[str, dict] = {}
    for raw in text.splitlines():
        line = _ANSI_RE.sub("", raw).strip()
        if not line or len(line) > 300:
            continue
        best = None
        for weight, label, pat in _SIGNALS:
            if pat.search(line):
                if best is None or weight > best[0]:
                    best = (weight, label)
        if not best:
            continue
        prev = scored.get(line)
        if prev is None or best[0] > prev["weight"]:
            scored[line] = {"line": line, "weight": best[0], "signal": best[1]}
    ordered = sorted(scored.values(), key=lambda f: (-f["weight"], f["line"]))[:_MAX_HIGHLIGHTS]
    for i, f in enumerate(ordered, 1):
        f["rank"] = i
    return ordered


# ── run orchestration ─────────────────────────────────────────────────────────
def _run_action(tool: EnumTool) -> Action:
    return Action(id=tool.action_id, title=f"Run {tool.material}",
                  tool=tool.run_template.strip().split()[0],
                  commands=[{"tool": tool.run_template.strip().split()[0], "run": tool.run_template}],
                  produces=[])


def _existing_remote(ws: Workspace, host: str, material: str) -> str:
    for sf in ws.staged_for(host):
        if sf.get("material") == material and sf.get("status") in {"staged", "verified"}:
            return sf.get("remote_path", "")
    return ""


def eligible_enum(ws: Workspace, host: str) -> list[dict]:
    """Which enum tools fit this foothold (by OS), and whether obol has a credential
    and a cached copy to run them."""
    host = normalize_target(host)
    fos = staging._foothold_os(ws, host)
    cred = sessions.password_credential(ws, host)
    rows: list[dict] = []
    for key, tool in ENUM_TOOLS.items():
        if fos and tool.os != fos:
            continue
        st = provision.status(provision.get_material(tool.material))
        rows.append({
            "key": key, "material": tool.material, "os": tool.os, "guided": tool.guided,
            "cached": st["status"] in {"cached", "installed"},
            "ready": bool(cred) and bool(fos), "note": tool.note,
        })
    return rows


def run_enum(ws: Workspace, host: str, tool_key: str, *, surface: str = "cli") -> dict:
    """Stage (if needed) and run a read-only enum tool on a foothold, then rank the
    output. Returns {ok, tool, remote_path, channel, privesc_leads, highlights,
    guided}. Guided tools are staged and their run command returned, but not executed.
    """
    host = normalize_target(host)
    tool = ENUM_TOOLS.get(tool_key)
    if not tool:
        raise EnumError(f"unknown enum tool {tool_key!r}")
    if not ws.get_target(host):
        raise EnumError(f"unknown target {host!r} in this engagement")
    cred = sessions.password_credential(ws, host)
    if not cred:
        raise EnumError(f"no validated password credential for {host} to run over")

    # stage the tool (reusing an existing staged copy if present)
    remote = _existing_remote(ws, host, tool.material)
    channel = "existing"
    if not remote:
        staged = staging.stage(ws, host, tool.material, surface=surface)
        if not staged.get("ok"):
            raise EnumError(f"could not stage {tool.material}: {staged.get('reason', 'transfer failed')}")
        remote = staged["staged"]["remote_path"]
        channel = staged["channel"]

    context = {"user": cred.get("user", ""), "password": cred.get("password", ""), "remote": remote}
    run_cmd = _run_action(tool)

    if tool.guided:
        from .board import fill_template
        return {"ok": True, "guided": True, "tool": tool_key, "remote_path": remote,
                "channel": channel, "privesc_leads": [], "highlights": [],
                "run_command": fill_template(tool.run_template, ws, host, context),
                "note": tool.note or "review and run this interactively"}

    before = {f.kind for f in ws.facts_for_target(host).facts if f.kind.startswith("privesc.")}
    from .service import run_action
    outcome = run_action(ws, run_cmd, target=host, context=context, timeout=tool.timeout,
                         ledger_extra={"surface": surface, "enum": tool.material, "target": host})

    # privesc.* leads were extracted through the shared parser pipeline; diff them out
    after_tf = ws.facts_for_target(host)
    new_leads = sorted(k for k in {f.kind for f in after_tf.facts if f.kind.startswith("privesc.")}
                       if k not in before)

    # rank the highlighted lines the tool itself flagged
    highlights: list[dict] = []
    try:
        text = Path(outcome.result.stdout_path).read_text(errors="ignore")
    except (OSError, AttributeError):
        text = ""
    if text.strip():
        highlights = extract_highlights(text)
    if highlights:
        ws.facts.add(Fact("enum.findings", f"host:{host}",
                          {"tool": tool.material, "count": len(highlights),
                           "remote_path": remote, "findings": highlights},
                          ProofState.SUPPORTED, source=outcome.command))
        ws.save()

    return {"ok": outcome.result.returncode == 0, "guided": False, "tool": tool_key,
            "remote_path": remote, "channel": channel, "privesc_leads": new_leads,
            "highlights": highlights, "returncode": outcome.result.returncode}


__all__ = ["EnumError", "EnumTool", "ENUM_TOOLS", "extract_highlights",
           "eligible_enum", "run_enum"]

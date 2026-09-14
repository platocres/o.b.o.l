"""Sessions layer — one-click interactive login, paired with a non-interactive proof.

The first brick of the pivoting feature (`docs/ROADMAP.md §6`). When facts prove
access is possible (a validated credential + a reachable service), obol offers a
single-click login for a host. Interactive tools (evil-winrm, xfreerdp, an ssh
shell) do not fit the capture-and-parse runner, so each login is *paired with a
non-interactive proof* — a command obol DOES run through the shared runner/parser
(`nxc winrm … -x whoami`, `sshpass … ssh … id`, `nxc rdp …`) whose captured output
establishes the access fact. Only then is the interactive login command handed to
the operator, and a **session** recorded as live state (`Workspace.sessions`).

Two obol contracts this preserves:
- **Facts stay the source of truth.** The shell is proven by a captured, parsed
  command, never by an unparseable interactive handoff. The access fact
  (`foothold.windows`/`foothold.linux`/`rdp.authenticated`/`access.*`) is what
  unlocks the privesc packs (§6b) — this module produces no facts of its own.
- **Sessions are live state, not facts.** A session carries a status that can flip
  (active/dead/closed); `probe_session` re-runs the proof to refresh it. Only the
  discoveries a session leads to are facts.

Login/proof command shapes live here as a curated registry (like `tools.py`, and
like the tunnel registry §6d will), not as planner branching.
"""
from __future__ import annotations

from dataclasses import dataclass

from . import board
from .pack import Action
from .scope import normalize_target
from .workspace import Workspace


class SessionError(Exception):
    """A login/session request that cannot be honored (unknown kind/target, or no
    credential to build the command from)."""


@dataclass(frozen=True)
class SessionKind:
    key: str
    label: str
    os: str
    service_facts: tuple[str, ...]   # any present ⇒ the service is reachable
    service_ports: tuple[int, ...]   # any open ⇒ the service is reachable
    proof_tool: str
    proof_template: str              # non-interactive, run + parsed → access fact
    login_tool: str
    login_template: str              # interactive, handed to the operator
    proven_facts: tuple[str, ...]    # facts that mean access is established


# The credentialed logins covered by the first slice. Reverse-shell listeners
# (penelope) are a separate async flow, tracked in §6 as a follow-up.
SESSION_KINDS: tuple[SessionKind, ...] = (
    SessionKind(
        key="winrm", label="WinRM (evil-winrm)", os="windows",
        service_facts=("winrm.reachable", "winrm.authenticated"), service_ports=(5985, 5986),
        proof_tool="nxc",
        proof_template="nxc winrm {{target}} -u {{user}} -p {{password}} -x whoami",
        login_tool="evil-winrm",
        login_template="evil-winrm -i {{target}} -u {{user}} -p {{password}}",
        proven_facts=("winrm.authenticated", "foothold.windows"),
    ),
    SessionKind(
        key="ssh", label="SSH", os="linux",
        service_facts=("ssh.reachable",), service_ports=(22,),
        proof_tool="sshpass",
        proof_template="sshpass -p {{password}} ssh -o StrictHostKeyChecking=no -o ConnectTimeout=8 {{user}}@{{target}} id",
        login_tool="ssh",
        login_template="ssh {{user}}@{{target}}",
        proven_facts=("foothold.linux", "access.shell"),
    ),
    SessionKind(
        key="rdp", label="RDP (xfreerdp)", os="windows",
        service_facts=("rdp.reachable",), service_ports=(3389,),
        proof_tool="nxc",
        proof_template="nxc rdp {{target}} -u {{user}} -p {{password}}",
        login_tool="xfreerdp",
        login_template="xfreerdp /v:{{target}} /u:{{user}} /p:{{password}} +clipboard /dynamic-resolution /cert:ignore",
        proven_facts=("rdp.authenticated", "foothold.windows"),
    ),
)

_BY_KEY = {k.key: k for k in SESSION_KINDS}


def get_kind(key: str) -> SessionKind | None:
    return _BY_KEY.get(key)


def _open_ports(tf) -> set[int]:
    ports: set[int] = set()
    for f in tf.facts:
        if f.kind.startswith("port:"):
            try:
                ports.add(int(f.kind.split(":", 1)[1]))
            except ValueError:
                continue
    return ports


def _password_cred(tf) -> dict | None:
    """A validated credential carrying a plaintext password, from this target's fact
    view (host- and domain-scoped). Hash-only creds don't fit the password login
    templates yet — pass-the-hash is a §6 follow-up."""
    for kind in ("credential.available", "credential.plaintext"):
        for value in tf.values(kind):
            if value.get("password"):
                return value
    return None


def eligible_sessions(ws: Workspace, host: str) -> list[dict]:
    """Which logins to offer for a host, and whether each is ready to run.

    A kind is offered when its service is reachable (a reachable fact or an open
    port) or access to it is already proven; it is *ready* only when a validated
    password credential also exists to fill the command."""
    tf = ws.facts_for_target(host)
    ports = _open_ports(tf)
    cred = _password_cred(tf)
    # "proven" means an active session of THIS kind already exists — not merely that
    # the host has some foothold (foothold.windows is shared across winrm/rdp/exec,
    # so keying the badge on it would mark RDP proven off a WinRM login).
    open_kinds = {s.get("kind") for s in ws.sessions_for(host) if s.get("status") == "active"}
    offers: list[dict] = []
    for k in SESSION_KINDS:
        reachable = any(tf.has(sf) for sf in k.service_facts) or any(p in ports for p in k.service_ports)
        proven = k.key in open_kinds
        if not reachable and not proven:
            continue
        if not cred:
            reason = "needs a validated credential with a password"
        elif not reachable:
            reason = "service not confirmed reachable yet"
        else:
            reason = ""
        offers.append({
            "kind": k.key, "label": k.label, "os": k.os,
            "ready": bool(cred) and reachable, "proven": proven,
            "reason": reason, "user": (cred or {}).get("user", ""),
        })
    return offers


def _proof_action(kind: SessionKind) -> Action:
    return Action(
        id=f"session-{kind.key}-login",
        title=f"Log in over {kind.label}",
        tool=kind.proof_tool,
        commands=[{"tool": kind.proof_tool, "run": kind.proof_template}],
        produces=list(kind.proven_facts),
    )


def build_login_command(ws: Workspace, host: str, kind_key: str) -> str:
    """The interactive login command, filled from facts (secrets included — this is
    the operator's own localhost lab/exam box, where secrets are shown by default).
    Re-buildable any time from facts."""
    kind = get_kind(kind_key)
    if not kind:
        raise SessionError(f"unknown session kind {kind_key!r}")
    return board.fill_template(kind.login_template, ws, normalize_target(host))


def open_session(ws: Workspace, host: str, kind_key: str, *, dry_run: bool = False,
                 surface: str = "cli") -> dict:
    """Validate access with the non-interactive proof, and on success record a live
    session and return the interactive login command for the operator to launch.

    Returns a dict: ``ok`` (proof confirmed access), ``session`` (the recorded live
    state, or None), ``login_command`` (full, with secrets — the handoff), and the
    proof ``outcome``. Raises SessionError for a request that can't be built.
    """
    kind = get_kind(kind_key)
    if not kind:
        raise SessionError(f"unknown session kind {kind_key!r}")
    host = normalize_target(host)
    if not ws.get_target(host):
        raise SessionError(f"unknown target {host!r} in this engagement")
    tf = ws.facts_for_target(host)
    cred = _password_cred(tf)
    if not cred:
        raise SessionError(
            "no validated credential with a password for this target — obtain one "
            "first (hash-only pass-the-hash login is a §6 follow-up)")

    # run the proof through the ONE shared runner/parser/store — same scope gate,
    # ledger, and fact discipline as every other run.
    from .service import run_action  # local import: service imports workspace
    outcome = run_action(ws, _proof_action(kind), target=host, dry_run=dry_run,
                         ledger_extra={"surface": surface, "session": kind.key, "target": host})

    login_cmd = board.fill_template(kind.login_template, ws, host)
    if dry_run:
        return {"ok": True, "dry_run": True, "kind": kind.key, "session": None,
                "login_command": login_cmd, "outcome": outcome}

    tf2 = ws.facts_for_target(host)
    proven = next((pf for pf in kind.proven_facts if tf2.has(pf)), "")
    if not proven:
        return {"ok": False, "kind": kind.key, "session": None,
                "reason": "login validation did not confirm access — check the credential/output",
                "login_command": login_cmd, "outcome": outcome}

    session = ws.add_session(
        host=host, kind=kind.key, user=cred.get("user", ""), os=kind.os,
        login_command=login_cmd,   # full, ready to paste (this is the operator's box)
        proof_fact=proven, proof_run=outcome.command, label=kind.label,
    )
    ws.save()
    return {"ok": True, "kind": kind.key, "session": session,
            "login_command": login_cmd, "outcome": outcome}


def probe_session(ws: Workspace, sid: str) -> dict:
    """Re-run a session's proof to refresh its live status (active/dead).

    This is the manual form of the periodic health probe §6 calls for: a background
    loop would call it on a timer. It never fabricates access — a failed re-proof
    flips the session to ``dead`` but records no fact removal (facts are immutable).
    """
    s = ws.get_session(sid)
    if not s:
        raise SessionError(f"no session {sid!r}")
    kind = get_kind(s.get("kind", ""))
    if not kind:
        raise SessionError(f"session {sid!r} has unknown kind {s.get('kind')!r}")
    host = s.get("host", "")
    from .service import run_action
    outcome = run_action(ws, _proof_action(kind), target=host,
                         ledger_extra={"surface": "probe", "session": kind.key, "target": host})
    tf = ws.facts_for_target(host)
    alive = any(tf.has(pf) for pf in kind.proven_facts) and outcome.result.returncode == 0
    ws.update_session(sid, status="active" if alive else "dead")
    ws.save()
    return {"ok": True, "alive": alive, "session": ws.get_session(sid), "outcome": outcome}


__all__ = [
    "SessionError", "SessionKind", "SESSION_KINDS", "get_kind",
    "eligible_sessions", "open_session", "probe_session", "build_login_command",
]

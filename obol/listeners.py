"""Listener layer (§8 / §6a) — catch a reverse shell back to obol.

The exploit tier's "reverse shell back to obol" outcome (and any manual reverse
shell) needs somewhere to land. This module is the catcher: it records a **listener**
as live state (like a session or tunnel — a status that can flip), hands the operator
the exact listen command plus a matching reverse-shell payload set for the target, and
lets the operator confirm a caught shell.

obol's terminal surface is one-shot commands, so v1 is a **guided** flow: obol
generates the listener command (penelope by default; nc/rlwrap or an msf handler as
fallbacks) for the operator to run, and the reverse-shell one-liners to fire on the
target. When a shell lands, `record_catch` flips the listener to *caught* and, if the
operator supplies the shell's `id`/`whoami` output, records the access **fact from
that proof** and registers a live session — facts stay the source of truth, proven by
captured output, never by the listener merely existing. (An automatic catch loop over
the long-running `obol serve` process is a follow-up.)

The reverse-shell payloads are data (`obol/payloads/reverse_shells.json`), reused by
the exploit tier so both surfaces speak the same payloads.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from . import parsers, sessions
from .scope import normalize_target
from .workspace import Workspace


class ListenerError(Exception):
    """A listener request that cannot be honored."""


@dataclass(frozen=True)
class ListenerKind:
    key: str
    label: str
    bin: str
    listen_template: str             # {{lport}} is filled
    note: str = ""


# penelope first (rich TTY auto-upgrade), then the always-available fallbacks.
LISTENER_KINDS: tuple[ListenerKind, ...] = (
    ListenerKind("penelope", "penelope", "penelope",
                 "penelope {{lport}}", note="auto-upgrades the TTY and logs the session"),
    ListenerKind("nc", "netcat", "nc", "nc -lvnp {{lport}}"),
    ListenerKind("rlwrap-nc", "rlwrap + nc", "rlwrap", "rlwrap nc -lvnp {{lport}}",
                 note="readline history/editing on the caught shell"),
    ListenerKind("msf", "metasploit handler", "msfconsole",
                 "msfconsole -q -x \"use exploit/multi/handler; set payload generic/shell_reverse_tcp; "
                 "set LHOST {{lhost}}; set LPORT {{lport}}; run\""),
)

_BY_KEY = {k.key: k for k in LISTENER_KINDS}
_DEFAULT_KIND = "penelope"


def get_kind(key: str) -> ListenerKind | None:
    return _BY_KEY.get(key)


@lru_cache(maxsize=1)
def _payload_catalog() -> dict:
    path = Path(__file__).parent / "payloads" / "reverse_shells.json"
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return {"linux": [], "windows": []}


def reverse_payloads(os_name: str, lhost: str, lport: int) -> list[dict]:
    """Filled reverse-shell one-liners for a target OS. {{lhost}}/{{lport}} resolved."""
    out: list[dict] = []
    for entry in _payload_catalog().get(os_name, []):
        tmpl = entry.get("template", "")
        if tmpl.startswith("#"):
            out.append({"name": entry.get("name", ""), "command": tmpl})
            continue
        out.append({"name": entry.get("name", ""),
                    "command": tmpl.replace("{{lhost}}", lhost or "<lhost>").replace("{{lport}}", str(lport))})
    return out


def _listen_command(kind: ListenerKind, lhost: str, lport: int) -> str:
    return kind.listen_template.replace("{{lport}}", str(lport)).replace("{{lhost}}", lhost or "<lhost>")


def start_listener(ws: Workspace, port: int, *, kind: str = _DEFAULT_KIND, lhost: str = "",
                   host: str = "", os_name: str = "linux") -> dict:
    """Record a listener as live state and return the listen command + the matching
    reverse-shell payloads. Guided: obol does not spawn the process, it hands the
    operator the exact command to run in a terminal."""
    lk = get_kind(kind)
    if not lk:
        raise ListenerError(f"unknown listener kind {kind!r}")
    if not (1 <= int(port) <= 65535):
        raise ListenerError(f"invalid port {port!r}")
    if not lhost:
        from .staging import lhost as detect_lhost
        lhost = detect_lhost()
    cmd = _listen_command(lk, lhost, port)
    rec = ws.add_listener(kind=lk.key, port=int(port), lhost=lhost, host=host,
                          status="listening", listen_command=cmd, label=f"{lk.key}:{port}")
    ws.save()
    return {"ok": True, "listener": rec, "listen_command": cmd,
            "payloads": reverse_payloads(os_name, lhost, int(port)), "note": lk.note}


def record_catch(ws: Workspace, lid: str, *, host: str, proof_output: str = "",
                 proof_command: str = "") -> dict:
    """Mark a listener as having caught a shell. If the operator supplies the shell's
    `id`/`whoami` output, the access fact is recorded **from that proof** and a live
    session is registered; without proof the listener flips to caught but no fact is
    invented (facts stay the source of truth)."""
    ln = ws.get_listener(lid)
    if not ln:
        raise ListenerError(f"no listener {lid!r}")
    host = normalize_target(host)
    if not ws.get_target(host):
        raise ListenerError(f"unknown target {host!r} in this engagement")

    proven = ""
    session = None
    added: list[str] = []
    if proof_output.strip():
        ws.set_active_target(host) or ws.add_target(host)
        src = proof_command or f"reverse-shell:{lid}"
        facts = parsers.parse_action_output(
            _proof_action(), ws, proof_command or "id", proof_output, "", source=src)
        for f in facts:
            if ws.facts.add(f):
                added.append(f.kind)
        ws.apply_fact_enrichment(list(facts))
        # the access fact this shell proves is one the proof output just established
        priority = ("access.admin", "access.system", "foothold.windows",
                    "foothold.linux", "access.shell")
        proven = next((k for k in priority if k in added), "")
        if proven:
            os_name = "windows" if proven == "foothold.windows" else "linux"
            session = ws.add_session(host=host, kind="revshell", os=os_name,
                                     status="active", proof_fact=proven, proof_run=src,
                                     label=f"reverse shell (listener {lid})")
    ws.update_listener(lid, status="caught", host=host)
    ws.save()
    return {"ok": True, "listener": ws.get_listener(lid), "proof_fact": proven,
            "session": session, "added_facts": added}


def _proof_action():
    from .pack import Action
    return Action(id="linux-enum", title="reverse-shell proof",
                  commands=[{"run": "id"}], produces=[])


def close_listener(ws: Workspace, lid: str) -> bool:
    if not ws.get_listener(lid):
        return False
    ws.update_listener(lid, status="closed")
    ws.save()
    return True


def remove_listener(ws: Workspace, lid: str) -> bool:
    ok = ws.remove_listener(lid)
    if ok:
        ws.save()
    return ok


__all__ = [
    "ListenerError", "ListenerKind", "LISTENER_KINDS", "get_kind",
    "reverse_payloads", "start_listener", "record_catch", "close_listener", "remove_listener",
]

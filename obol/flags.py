"""Flag-capture parsers — turning a proven foothold into an objective fact.

Once a host has a proven foothold, O.B.O.L can run a thorough, non-interactive
search of the box for the well-known flag files (`user.txt`, `root.txt`,
`local.txt`, `proof.txt`, `flag.txt`, …) and *read* them through the same
runner/parser/store path as every other run. Only when the command output shows
the file was actually read — and its content looks like a real flag — is an
`objective.*` fact recorded, host-scoped, citing the command that captured it.

This keeps the facts-first contract: a captured flag is proof, not a checkbox.
Finding a file's *name* is not the flag; the recorded fact carries the value the
command actually printed. Parsing is action-id scoped so unrelated command output
elsewhere never becomes an objective fact.
"""
from __future__ import annotations

import re

from . import profile as _profile
from .facts import Fact
from .scope import normalize_target

FLAG_HUNT_ACTION_IDS = {"flag-hunt-linux", "flag-hunt-windows"}

# The default filename set (used when an engagement has no profile). The effective
# set is resolved per-engagement from the profile (ROADMAP §7): a capture is only
# recorded for a line whose path ends in a *configured* name, so gating on the name
# keeps a stray `path:value` line from being mistaken for a flag.
_FLAG_NAMES = set(_profile.DEFAULT_FLAG_NAMES)

# NetExec prepends rows like ``WINRM 10.10.10.5 5985 HOST`` before command output.
_NXC_PREFIX_RE = re.compile(r"^(?:SMB|WINRM|WMI|RPC|SSH)\s+\S+\s+\d+\s+\S+\s+(?P<body>.*)$", re.I)
# Windows foreach marker: ``===FLAG:<full path>::<content>``.
_WIN_MARKER_RE = re.compile(r"===FLAG:(?P<path>.*?)::(?P<content>.*)$")
# Linux ``grep -H`` shape: ``/abs/path:content`` (absolute path, no space before ':').
_LINUX_LINE_RE = re.compile(r"^(?P<path>/[^\s:]+):(?P<content>.*)$")

def _scope(ws, target: str = "") -> str:
    host = normalize_target(target or getattr(ws, "target", "") or "")
    return f"host:{host}" if host else ""


def _strip_prefix(line: str) -> str:
    match = _NXC_PREFIX_RE.match(line)
    return match.group("body") if match else line


def _basename(path: str) -> str:
    # Handle both POSIX and Windows separators without importing os on a remote path.
    return re.split(r"[\\/]", path.strip().strip('"').strip("'"))[-1]


def _slot_for(name: str, slots: dict[str, str] | None = None) -> str:
    lowered = name.lower()
    mapping = slots if slots is not None else _profile.DEFAULT_SLOTS
    return mapping.get(lowered, "unknown")


def _kind_for(slot: str) -> str:
    return {
        "local": "objective.local_flag",
        "root": "objective.root_flag",
    }.get(slot, "objective.flag")


def extract_flag_value(content: str, formats: list[str] | None = None) -> str:
    """Pull a plausible flag value out of captured file content, or "".

    Conservative on purpose, and profile-aware: only the *configured* value formats
    count (a brace token like ``THM{…}``/``HTB{…}``, a 32/64-char hash, a UUID, or a
    lone short token as a last resort), tried in order. So an OSCP profile that
    accepts a proof hash but not a brace flag, or a CTF profile that accepts
    ``flag{…}`` but not a bare token, records only what its platform actually uses.
    Multi-line noise, an error message, or an empty read yields no value — and
    therefore no fact. Default (no formats given) is obol's original full order.
    """
    text = (content or "").strip()
    if not text:
        return ""
    keys = formats or _profile.DEFAULT_FORMATS
    for key in keys:
        pattern = _profile.FORMAT_PATTERNS.get(key)
        if not pattern:
            continue
        if key == "token":
            if pattern.match(text) and any(ch.isalnum() for ch in text):
                return text
            continue
        match = pattern.search(text)
        if match:
            return match.group(0)
    return ""


def _emit(out: list[Fact], seen: set[tuple[str, str]], kind: str, scope: str,
          value: dict, source: str) -> None:
    key = (kind, value.get("flag", ""))
    if key in seen:
        return
    seen.add(key)
    out.append(Fact(kind, scope, value, source=source))


def parse_flag_output(action, ws, command: str, stdout: str, stderr: str = "", *,
                      source: str = "") -> list[Fact]:
    """Parse a flag-hunt run's output into ``objective.*`` facts.

    Action-id scoped so only the flag-hunt actions produce objective facts. Each
    recorded fact is host-scoped and carries the flag's filename, path, slot
    (local/root/unknown), and the captured value.
    """
    if getattr(action, "id", "") not in FLAG_HUNT_ACTION_IDS:
        return []
    scope = _scope(ws)
    if not scope:
        return []
    # Resolve the engagement's flag config (names/formats/slots) from its profile;
    # an engagement with no profile gets obol's full defaults (unchanged behavior).
    cfg = ws.flag_config() if hasattr(ws, "flag_config") else _profile.resolve_flag_config(None)
    names = set(cfg.get("names") or _profile.DEFAULT_FLAG_NAMES)
    formats = cfg.get("formats") or _profile.DEFAULT_FORMATS
    slots = cfg.get("slots") or _profile.DEFAULT_SLOTS
    out: list[Fact] = []
    seen: set[tuple[str, str]] = set()
    src = source or command
    for raw in (stdout or "").splitlines():
        line = _strip_prefix(raw.rstrip()).strip()
        if not line:
            continue
        marker = _WIN_MARKER_RE.search(line)
        if marker:
            path, content = marker.group("path").strip(), marker.group("content")
        else:
            linux = _LINUX_LINE_RE.match(line)
            if not linux:
                continue
            path, content = linux.group("path"), linux.group("content")
        name = _basename(path)
        if name.lower() not in names:
            continue
        value = extract_flag_value(content, formats)
        if not value:
            continue
        slot = _slot_for(name, slots)
        _emit(out, seen, _kind_for(slot), scope,
              {"name": name, "path": path, "slot": slot, "flag": value}, src)
    return out


__all__ = ["FLAG_HUNT_ACTION_IDS", "parse_flag_output", "extract_flag_value"]

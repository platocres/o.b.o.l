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

from .facts import Fact
from .scope import normalize_target

FLAG_HUNT_ACTION_IDS = {"flag-hunt-linux", "flag-hunt-windows"}

# Filenames the hunt targets. A capture is only recorded for a line whose path
# ends in one of these — the search itself only reads these, but gating on the
# name keeps a stray `path:value` line from being mistaken for a flag.
_FLAG_NAMES = {"user.txt", "root.txt", "local.txt", "proof.txt", "flag.txt", "flag"}

# NetExec prepends rows like ``WINRM 10.10.10.5 5985 HOST`` before command output.
_NXC_PREFIX_RE = re.compile(r"^(?:SMB|WINRM|WMI|RPC|SSH)\s+\S+\s+\d+\s+\S+\s+(?P<body>.*)$", re.I)
# Windows foreach marker: ``===FLAG:<full path>::<content>``.
_WIN_MARKER_RE = re.compile(r"===FLAG:(?P<path>.*?)::(?P<content>.*)$")
# Linux ``grep -H`` shape: ``/abs/path:content`` (absolute path, no space before ':').
_LINUX_LINE_RE = re.compile(r"^(?P<path>/[^\s:]+):(?P<content>.*)$")

# Flag value shapes, most specific first.
_BRACE_RE = re.compile(r"\b[A-Za-z0-9_]{2,20}\{[^}\r\n]{1,200}\}")
_HEX64_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")
_HEX32_RE = re.compile(r"\b[0-9a-fA-F]{32}\b")
_SINGLE_TOKEN_RE = re.compile(r"^\S{1,64}$")


def _scope(ws, target: str = "") -> str:
    host = normalize_target(target or getattr(ws, "target", "") or "")
    return f"host:{host}" if host else ""


def _strip_prefix(line: str) -> str:
    match = _NXC_PREFIX_RE.match(line)
    return match.group("body") if match else line


def _basename(path: str) -> str:
    # Handle both POSIX and Windows separators without importing os on a remote path.
    return re.split(r"[\\/]", path.strip().strip('"').strip("'"))[-1]


def _slot_for(name: str) -> str:
    lowered = name.lower()
    if lowered in {"user.txt", "local.txt"}:
        return "local"
    if lowered in {"root.txt", "proof.txt"}:
        return "root"
    return "unknown"


def _kind_for(slot: str) -> str:
    return {
        "local": "objective.local_flag",
        "root": "objective.root_flag",
    }.get(slot, "objective.flag")


def extract_flag_value(content: str) -> str:
    """Pull a plausible flag value out of captured file content, or "".

    Conservative on purpose: a brace token (``THM{…}``/``HTB{…}``/``flag{…}``) or a
    32/64-char hex string is a confident flag; otherwise only a lone short token on
    its own (a single-line file with no spaces) is accepted. Multi-line noise, an
    error message, or an empty read yields no value — and therefore no fact.
    """
    text = (content or "").strip()
    if not text:
        return ""
    for pattern in (_BRACE_RE, _HEX64_RE, _HEX32_RE):
        match = pattern.search(text)
        if match:
            return match.group(0)
    if _SINGLE_TOKEN_RE.match(text) and any(ch.isalnum() for ch in text):
        return text
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
        if name.lower() not in _FLAG_NAMES:
            continue
        value = extract_flag_value(content)
        if not value:
            continue
        slot = _slot_for(name)
        _emit(out, seen, _kind_for(slot), scope,
              {"name": name, "path": path, "slot": slot, "flag": value}, src)
    return out


__all__ = ["FLAG_HUNT_ACTION_IDS", "parse_flag_output", "extract_flag_value"]

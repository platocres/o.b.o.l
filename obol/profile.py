"""Engagement profile — platform/exam awareness (ROADMAP §7).

An engagement is *for* something: an HTB box, an OffSec/OSCP exam machine, a
TryHackMe room, a generic CTF. That choice decides **what obol hunts for** — the
flag file names and the value formats that count as a captured flag — so the flag
hunt (§7 / `flags.py`) is not hard-wired to one lab's conventions.

The profile is engagement-level state (one per engagement, stored in the store's
`meta`), not a fact: it is operator configuration, not proven evidence. It never
relaxes a proof boundary — a captured flag is still recorded only when a file was
actually read and its content matches a configured format. The profile only
narrows *which names/formats* the hunt looks for and how a captured file maps to
the local/root objective slot.

Kept dependency-light (only `re`, and the flag value patterns) so `flags.py`,
`board.py` (command tokens), the CLI, and the web can all read one source of
truth for the flag config.
"""
from __future__ import annotations

import re

# ---- flag value format vocabulary ------------------------------------------ #
# Each format key maps to a matcher over captured file content. `extract_flag_value`
# (in flags.py) tries the profile's configured formats in order and records the
# first match — so a profile can accept only brace-style flags, only hashes, etc.
_BRACE_RE = re.compile(r"\b[A-Za-z0-9_]{2,20}\{[^}\r\n]{1,200}\}")
_HEX64_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")
_HEX32_RE = re.compile(r"\b[0-9a-fA-F]{32}\b")
_UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
_SINGLE_TOKEN_RE = re.compile(r"^\S{1,64}$")

FORMAT_PATTERNS: dict[str, re.Pattern] = {
    "brace": _BRACE_RE,
    "hex64": _HEX64_RE,
    "hex32": _HEX32_RE,
    "uuid": _UUID_RE,
    "token": _SINGLE_TOKEN_RE,
}
# The full default order (obol's original behavior when no profile is set): a brace
# token, then a 64/32-char hash, then a lone short token as a last resort.
DEFAULT_FORMATS: list[str] = ["brace", "hex64", "hex32", "token"]

# The full default filename set the hunt has always searched. Slot mapping decides
# which objective a captured file proves (local vs root); "unknown" files record a
# generic `objective.flag`.
DEFAULT_FLAG_NAMES: list[str] = ["user.txt", "root.txt", "local.txt", "proof.txt", "flag.txt", "flag"]
DEFAULT_SLOTS: dict[str, str] = {
    "user.txt": "local", "local.txt": "local",
    "root.txt": "root", "proof.txt": "root",
}

# ---- preset table ---------------------------------------------------------- #
# Each preset carries the platform's flag conventions. `flag_names` is the ordered
# search set; `flag_formats` the accepted value shapes; `slots` maps a filename to
# its objective slot. Aliases let the operator type the common names.
PRESETS: dict[str, dict] = {
    "htb": {
        "name": "Hack The Box",
        "aliases": ["hackthebox", "hack-the-box"],
        "flag_names": ["user.txt", "root.txt"],
        "flag_formats": ["hex32", "hex64", "brace"],
        "slots": {"user.txt": "local", "root.txt": "root"},
    },
    "oscp": {
        "name": "OffSec / OSCP",
        "aliases": ["offsec", "offensive-security", "pen-200", "pen200"],
        "flag_names": ["local.txt", "proof.txt"],
        "flag_formats": ["hex32", "hex64", "token"],
        "slots": {"local.txt": "local", "proof.txt": "root"},
    },
    "thm": {
        "name": "TryHackMe",
        "aliases": ["tryhackme", "try-hack-me"],
        "flag_names": ["user.txt", "root.txt", "flag.txt", "flag1.txt", "flag2.txt"],
        "flag_formats": ["brace", "hex32", "token"],
        "slots": {"user.txt": "local", "root.txt": "root"},
    },
    "ctf": {
        "name": "Capture the Flag",
        "aliases": ["capture-the-flag"],
        "flag_names": ["flag.txt", "flag", "flag1.txt", "proof.txt"],
        "flag_formats": ["brace", "uuid", "hex32", "hex64", "token"],
        "slots": {},
    },
    "custom": {
        "name": "Custom",
        "aliases": ["default", "generic", "lab"],
        "flag_names": list(DEFAULT_FLAG_NAMES),
        "flag_formats": list(DEFAULT_FORMATS),
        "slots": dict(DEFAULT_SLOTS),
    },
}
DEFAULT_PLATFORM = "custom"

_ALIAS_TO_ID = {}
for _pid, _preset in PRESETS.items():
    _ALIAS_TO_ID[_pid] = _pid
    for _alias in _preset.get("aliases", []):
        _ALIAS_TO_ID[_alias] = _pid


def normalize_platform(value: str) -> str:
    """Resolve a platform name/alias to a preset id, or '' if unknown."""
    key = re.sub(r"[^a-z0-9]+", "-", str(value or "").strip().lower()).strip("-")
    if key in _ALIAS_TO_ID:
        return _ALIAS_TO_ID[key]
    # tolerate the un-slugged alias too (e.g. "hack the box")
    return _ALIAS_TO_ID.get(str(value or "").strip().lower(), "")


def list_presets() -> list[dict]:
    """The preset catalogue for a picker (id, name, names, formats)."""
    out = []
    for pid, preset in PRESETS.items():
        out.append({
            "id": pid,
            "name": preset["name"],
            "flag_names": list(preset["flag_names"]),
            "flag_formats": list(preset["flag_formats"]),
        })
    return out


def _clean_names(names) -> list[str]:
    seen, out = set(), []
    for raw in names or []:
        name = str(raw or "").strip().lower()
        if name and name not in seen:
            seen.add(name)
            out.append(name)
    return out


def _clean_formats(formats) -> list[str]:
    out = [str(f or "").strip().lower() for f in (formats or [])]
    return [f for f in out if f in FORMAT_PATTERNS]


def normalize_profile(data: dict | None) -> dict:
    """Canonicalize a stored/operator profile dict to `{platform, flag_names,
    flag_formats}`. An unknown platform falls back to 'custom'. Explicit
    flag_names/flag_formats (operator overrides) are cleaned and de-duped."""
    data = data or {}
    platform = normalize_platform(data.get("platform", "")) or DEFAULT_PLATFORM
    out = {"platform": platform}
    names = _clean_names(data.get("flag_names"))
    formats = _clean_formats(data.get("flag_formats"))
    if names:
        out["flag_names"] = names
    if formats:
        out["flag_formats"] = formats
    # operator autonomy overrides (kind -> auto|ask|never) ride on the profile so they
    # persist with it; the autonomy layer validates and interprets them (obol/autonomy.py).
    autonomy = data.get("autonomy")
    if isinstance(autonomy, dict):
        clean = {str(k): str(v) for k, v in autonomy.items() if v in ("auto", "ask", "never")}
        if clean:
            out["autonomy"] = clean
    return out


def resolve_flag_config(profile: dict | None) -> dict:
    """Effective flag config for the hunt: `{names, formats, slots, platform}`.

    Precedence: an explicit operator override (flag_names/flag_formats on the
    profile) wins; otherwise the selected preset's values; otherwise obol's full
    defaults. `slots` always comes from the preset (or defaults) so a captured
    file maps to the right local/root objective; a name with no slot records the
    generic `objective.flag`.
    """
    prof = normalize_profile(profile)
    preset = PRESETS.get(prof["platform"], PRESETS[DEFAULT_PLATFORM])
    names = prof.get("flag_names") or list(preset["flag_names"]) or list(DEFAULT_FLAG_NAMES)
    formats = prof.get("flag_formats") or list(preset["flag_formats"]) or list(DEFAULT_FORMATS)
    slots = dict(DEFAULT_SLOTS)
    slots.update(preset.get("slots") or {})
    return {
        "platform": prof["platform"],
        "platform_name": preset["name"],
        "names": _clean_names(names),
        "formats": _clean_formats(formats) or list(DEFAULT_FORMATS),
        "slots": slots,
    }


def linux_iname_expr(names) -> str:
    """The `-iname a.txt -o -iname b.txt` fragment for a `find` command, built from
    the configured flag names. Names are validated to safe filename chars so the
    fragment can never inject shell/find syntax."""
    safe = [n for n in _clean_names(names) if re.fullmatch(r"[a-z0-9._-]{1,64}", n)]
    if not safe:
        safe = list(DEFAULT_FLAG_NAMES)
    return " -o ".join(f"-iname {n}" for n in safe)


def windows_name_list(names) -> str:
    """The comma-separated `-Include` list for the Windows PowerShell hunt. Windows
    -Include needs each name as a wildcard-safe token; validated like the Linux
    form so nothing but flag filenames reaches the remote shell."""
    safe = [n for n in _clean_names(names) if re.fullmatch(r"[a-z0-9._-]{1,64}", n)]
    if not safe:
        safe = list(DEFAULT_FLAG_NAMES)
    return ",".join(safe)


__all__ = [
    "PRESETS", "DEFAULT_PLATFORM", "DEFAULT_FLAG_NAMES", "DEFAULT_FORMATS",
    "FORMAT_PATTERNS", "normalize_platform", "normalize_profile", "list_presets",
    "resolve_flag_config", "linux_iname_expr", "windows_name_list",
]

"""Tool inventory — what obol can actually run on this box.

A curated registry of the tools obol's packs invoke, each with the binary names to
look for, the default Kali locations to check, and how to install it. The web Tools
page scans the host (like Pentest Companion's kali_tools), shows how many of the
catalogue are present, greys out the missing, and offers a one-click install or an
"I have it here" path override. The runner consults the same resolver so a tool we
found — including one you pointed us at — is guaranteed to launch.

Availability is a property of the machine, not an engagement, so overrides live in
`$OBOL_HOME/tools.json`.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import library
from .pack import load_packs

# Categories, in display order.
CATEGORIES = ["Recon", "AD / Windows", "Impacket", "Web", "Password", "Manual / Windows"]

# Common non-PATH locations Kali tools land in (searched shallowly when `which` misses).
_COMMON_DIRS = ["/usr/bin", "/usr/local/bin", "/usr/sbin", "/snap/bin",
                "/opt", "/usr/share"]


@dataclass
class ToolDef:
    key: str
    label: str
    category: str
    bins: list[str]                 # candidate binaries / script names, in preference order
    match: list[str] = field(default_factory=list)  # pack tool-names/argv0 that map here
    apt: str = ""                   # apt package (install hint)
    pipx: str = ""                  # pipx package (install hint)
    paths: list[str] = field(default_factory=list)   # explicit default locations to check
    manual: bool = False            # operator-supplied (e.g. Windows .exe) — add-path only
    note: str = ""

    def all_names(self) -> set[str]:
        return set(self.bins) | set(self.match) | {self.key}


# ── the curated catalogue ─────────────────────────────────────────────────────
REGISTRY: list[ToolDef] = [
    # Recon / network
    ToolDef("nmap", "Nmap", "Recon", ["nmap"], apt="nmap"),
    ToolDef("netexec", "NetExec (nxc)", "Recon", ["nxc", "netexec", "crackmapexec"],
            match=["nxc", "crackmapexec"], apt="netexec", pipx="netexec"),
    ToolDef("ldapsearch", "ldapsearch", "Recon", ["ldapsearch"], apt="ldap-utils"),
    ToolDef("smbclient", "smbclient", "Recon", ["smbclient"], apt="smbclient"),
    ToolDef("smbmap", "smbmap", "Recon", ["smbmap"], apt="smbmap"),
    ToolDef("rpcclient", "rpcclient", "Recon", ["rpcclient"], apt="smbclient"),
    ToolDef("enum4linux", "enum4linux", "Recon", ["enum4linux-ng", "enum4linux"], apt="enum4linux"),
    ToolDef("nbtscan", "nbtscan", "Recon", ["nbtscan"], apt="nbtscan"),
    ToolDef("windapsearch", "windapsearch", "Recon", ["windapsearch", "windapsearch.py"],
            paths=["/opt/windapsearch/windapsearch.py"], pipx="windapsearch",
            note="git tool; add its path if not packaged"),
    ToolDef("nslookup", "nslookup", "Recon", ["nslookup"], apt="dnsutils"),
    ToolDef("ntpdate", "ntpdate", "Recon", ["ntpdate", "ntpdig"], apt="ntpsec-ntpdate"),
    ToolDef("xfreerdp", "xfreerdp", "Recon", ["xfreerdp", "xfreerdp3"], apt="freerdp2-x11"),
    # AD / Windows tooling that runs on Linux
    ToolDef("evil-winrm", "Evil-WinRM", "AD / Windows", ["evil-winrm"], apt="evil-winrm"),
    ToolDef("kerbrute", "Kerbrute", "AD / Windows", ["kerbrute"], apt="kerbrute",
            paths=["/opt/kerbrute/kerbrute"]),
    ToolDef("bloodhound-python", "BloodHound.py", "AD / Windows", ["bloodhound-python"], pipx="bloodhound"),
    ToolDef("certipy", "Certipy", "AD / Windows", ["certipy", "certipy-ad"], pipx="certipy-ad"),
    ToolDef("bloodyad", "bloodyAD", "AD / Windows", ["bloodyAD", "bloodyad"],
            match=["bloodyAD", "bloodyad"], pipx="bloodyAD"),
    ToolDef("pywhisker", "pyWhisker", "AD / Windows", ["pywhisker", "pywhisker.py"], pipx="pywhisker"),
    ToolDef("targetedkerberoast", "targetedKerberoast", "AD / Windows",
            ["targetedKerberoast", "targetedKerberoast.py"],
            paths=["/opt/targetedKerberoast/targetedKerberoast.py"],
            note="git tool; add its path"),
    ToolDef("sprayhound", "sprayhound", "AD / Windows", ["sprayhound"], pipx="sprayhound"),
    ToolDef("sccmhunter", "sccmhunter", "AD / Windows", ["sccmhunter", "sccmhunter.py"],
            paths=["/opt/sccmhunter/sccmhunter.py"], note="git tool; add its path"),
    ToolDef("kinit", "kinit / klist", "AD / Windows", ["kinit"], match=["klist"], apt="krb5-user"),
    ToolDef("nltest", "nltest", "AD / Windows", ["nltest"], manual=True,
            note="Windows utility; run from a Windows foothold or add a Linux equivalent"),
    # Impacket suite (one entry — the whole apt/pipx package)
    ToolDef("impacket", "Impacket suite", "Impacket",
            ["impacket-GetNPUsers", "impacket-secretsdump", "impacket-getST", "impacket-getTGT",
             "impacket-GetUserSPNs", "impacket-addcomputer", "impacket-psexec", "impacket-wmiexec",
             "impacket-lookupsid", "impacket-ticketer", "impacket-dacledit", "impacket-rbcd"],
            match=["impacket-GetNPUsers", "impacket-secretsdump", "impacket-getST", "impacket-getTGT",
                   "impacket-GetUserSPNs", "impacket-addcomputer", "impacket-psexec", "impacket-wmiexec",
                   "impacket-lookupsid", "impacket-ticketer", "impacket-dacledit", "impacket-rbcd"],
            apt="python3-impacket", pipx="impacket"),
    # Web
    ToolDef("gobuster", "gobuster", "Web", ["gobuster"], apt="gobuster"),
    ToolDef("feroxbuster", "feroxbuster", "Web", ["feroxbuster"], apt="feroxbuster"),
    ToolDef("ffuf", "ffuf", "Web", ["ffuf"], apt="ffuf"),
    ToolDef("wfuzz", "wfuzz", "Web", ["wfuzz"], apt="wfuzz"),
    ToolDef("nikto", "Nikto", "Web", ["nikto"], apt="nikto"),
    ToolDef("wpscan", "WPScan", "Web", ["wpscan"], apt="wpscan"),
    ToolDef("sqlmap", "sqlmap", "Web", ["sqlmap"], apt="sqlmap"),
    ToolDef("gitdumper", "git-dumper", "Web", ["git-dumper"], pipx="git-dumper"),
    ToolDef("curl", "curl", "Web", ["curl"], apt="curl"),
    # Password / cracking
    ToolDef("hashcat", "hashcat", "Password", ["hashcat"], apt="hashcat"),
    ToolDef("john", "John the Ripper", "Password", ["john"], apt="john"),
    ToolDef("gpp-decrypt", "gpp-decrypt", "Password", ["gpp-decrypt"], apt="gpp-decrypt"),
    ToolDef("responder", "Responder", "Password", ["responder", "Responder.py"], apt="responder"),
    ToolDef("msfvenom", "msfvenom", "Password", ["msfvenom"], apt="metasploit-framework"),
    # Manual / Windows binaries the operator supplies
    ToolDef("rubeus", "Rubeus", "Manual / Windows", ["Rubeus.exe", "rubeus"], manual=True,
            note="Windows .exe — add its path once you've staged it"),
    ToolDef("sharphound", "SharpHound", "Manual / Windows", ["SharpHound.exe", "SharpHound.ps1"], manual=True),
    ToolDef("sharpwsus", "SharpWSUS", "Manual / Windows", ["SharpWSUS.exe"], manual=True),
    ToolDef("psexec", "PsExec", "Manual / Windows", ["PsExec.exe", "PsExec64.exe"], manual=True),
    ToolDef("mimikatz", "mimikatz", "Manual / Windows", ["mimikatz.exe", "mimikatz"], manual=True),
    ToolDef("powerview", "PowerView", "Manual / Windows", ["PowerView.ps1"], manual=True,
            note="PowerShell script run from a Windows foothold"),
    ToolDef("ysoserial", "ysoserial", "Manual / Windows", ["ysoserial.jar", "ysoserial"], manual=True,
            note="Java jar — add its path"),
]

_BY_KEY = {t.key: t for t in REGISTRY}


# ── overrides store ($OBOL_HOME/tools.json) ───────────────────────────────────
def _overrides_file() -> Path:
    return library.base_dir() / "tools.json"


def load_overrides() -> dict:
    f = _overrides_file()
    if f.exists():
        try:
            return json.loads(f.read_text())
        except (ValueError, OSError):
            return {}
    return {}


def save_overrides(data: dict) -> None:
    library.base_dir().mkdir(parents=True, exist_ok=True)
    _overrides_file().write_text(json.dumps(data, indent=2))


# ── detection ────────────────────────────────────────────────────────────────
def _locate(bins: list[str], paths: list[str]) -> str:
    """Return an absolute path to the first binary found: PATH, then explicit default
    locations, then a shallow scan of common Kali dirs. '' if not found."""
    for b in bins:
        hit = shutil.which(b)
        if hit:
            return hit
    for p in paths:
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
        if os.path.isfile(p):        # scripts may not be +x but are still runnable
            return p
    names = set(bins)
    for root in _COMMON_DIRS:
        rp = Path(root)
        if not rp.is_dir():
            continue
        try:
            # shallow: root/* and root/*/  (depth 2) — bounded, avoids deep walks
            for entry in rp.iterdir():
                if entry.name in names and entry.is_file():
                    return str(entry)
                if entry.is_dir():
                    for sub in (entry / n for n in names):
                        if sub.is_file():
                            return str(sub)
        except (OSError, PermissionError):
            continue
    return ""


def detect(tool: ToolDef, overrides: dict | None = None) -> dict:
    overrides = overrides if overrides is not None else load_overrides()
    ov = overrides.get(tool.key)
    if ov and os.path.isfile(ov):
        return {"found": True, "path": ov, "source": "added"}
    path = _locate(tool.bins, tool.paths)
    return {"found": bool(path), "path": path, "source": "path" if path else ""}


def _actions_by_tool() -> dict[str, list[dict]]:
    """Map each registry key to the pack actions that use it (by tool name or the
    command's binary)."""
    out: dict[str, list[dict]] = {t.key: [] for t in REGISTRY}
    # name -> key lookup
    name_to_key: dict[str, str] = {}
    for t in REGISTRY:
        for n in t.all_names():
            name_to_key.setdefault(n, t.key)
    for a in load_packs():
        keys = set()
        for n in list(a.tools or []) + ([a.tool] if a.tool else []):
            if n in name_to_key:
                keys.add(name_to_key[n])
        for c in (a.commands or []):
            run = (c.get("run") or "").strip().split()
            if run:
                b = run[1] if run[0] == "sudo" and len(run) > 1 else run[0]
                if b in name_to_key:
                    keys.add(name_to_key[b])
        for k in keys:
            out[k].append({"id": a.id, "title": a.title})
    return out


def scan() -> dict:
    """Full inventory for the Tools page: every catalogue tool with found/path +
    install hints + the actions that use it, grouped by category, plus counts."""
    overrides = load_overrides()
    actions = _actions_by_tool()
    cats: dict[str, list[dict]] = {c: [] for c in CATEGORIES}
    found = 0
    for t in REGISTRY:
        d = detect(t, overrides)
        if d["found"]:
            found += 1
        cats.setdefault(t.category, []).append({
            "key": t.key, "label": t.label, "category": t.category, "bins": t.bins,
            "found": d["found"], "path": d["path"], "source": d["source"],
            "manual": t.manual, "note": t.note,
            "install_cmd": install_command(t.key), "actions": actions.get(t.key, []),
        })
    groups = [{"category": c, "tools": cats[c]} for c in CATEGORIES if cats.get(c)]
    return {"groups": groups, "found": found, "total": len(REGISTRY),
            "scanned_at": time.time()}


def install_command(key: str) -> str:
    t = _BY_KEY.get(key)
    if not t:
        return ""
    if t.manual:
        return ""            # nothing to apt/pipx — the operator supplies these
    if t.apt:
        return f"sudo apt-get install -y {t.apt}"
    if t.pipx:
        return f"pipx install {t.pipx}"
    return ""


# ── mutations ─────────────────────────────────────────────────────────────────
def add_override(key: str, path: str) -> dict:
    if key not in _BY_KEY:
        raise KeyError(key)
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    ov = load_overrides()
    ov[key] = path
    save_overrides(ov)
    return detect(_BY_KEY[key], ov)


def install(key: str, timeout: int = 900) -> dict:
    """Best-effort local install via the catalogue's install command. Point-and-click;
    if it fails (no passwordless sudo, offline), the same command is shown to copy."""
    cmd = install_command(key)
    if not cmd:
        return {"ok": False, "command": "", "output": "no install command for this tool"}
    try:
        proc = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=timeout)
        out = (proc.stdout or "") + (proc.stderr or "")
        ok = proc.returncode == 0
    except (subprocess.TimeoutExpired, OSError) as exc:
        out, ok = f"{exc}", False
    d = detect(_BY_KEY[key])
    return {"ok": ok and d["found"], "command": cmd, "output": out[-4000:],
            "found": d["found"], "path": d["path"]}


def resolve_binary(argv0: str) -> str:
    """For the runner: an absolute path for a command's binary when it isn't on PATH
    but we know where it is (an override or a default location). '' otherwise — the
    runner then falls back to its own PATH check."""
    if shutil.which(argv0):
        return ""                    # already runnable as-is
    overrides = load_overrides()
    for t in REGISTRY:
        if argv0 in t.all_names():
            d = detect(t, overrides)
            if d["found"]:
                return d["path"]
    if argv0 in overrides and os.path.isfile(overrides[argv0]):
        return overrides[argv0]
    return ""

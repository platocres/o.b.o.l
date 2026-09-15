"""Kali-side material cache — the tools and exploits obol stages onto a foothold.

This is the §8 provisioner spine (see `docs/PAYLOAD_STAGING.md`). Before obol
pushes anything to a target, it must first prove it has the material locally. This
module is that check-and-fetch layer: a curated registry of stageable materials
(privesc enum scripts, potato exploits, tunnel binaries, common OSCP-lab tooling),
a global cache under `$OBOL_HOME/cache/`, and a one-click download that verifies
what it fetched.

Design decisions (from `docs/PAYLOAD_STAGING.md`):

- **One global cache**, not per-engagement — obol is single-operator, and a
  downloaded linpeas is a property of the Kali box, not of one engagement (the same
  reasoning as `tools.py`'s machine-scoped overrides).
- **Integrity is trust-on-first-use with optional pinning.** Every download's actual
  sha256 is computed and recorded. When a material pins a `sha256`, a mismatch
  rejects and deletes the file. obol never fabricates a digest to look pinned.
- **A staged file is not a Fact.** This module only manages *local* material; pushing
  it to a target (live state, scope-gated) is `staging.py`'s job.

NOTICE — third-party materials. obol does not vendor any of the binaries or scripts
below; it records their public download URLs and licenses so an operator can fetch
them on demand. Each stays the property of its upstream project under that project's
own license (PEASS-ng: GPL-3.0; ligolo-ng: GPL-3.0; chisel: MIT; GodPotato/
PrintSpoofer/JuicyPotato/RoguePotato/SweetPotato/RunasCs: MIT-family; pspy: MIT;
linux-exploit-suggester: GPL-2.0). obol's own code here is the cache/registry
machinery, not the tools.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from . import library

# Categories, in display order for the cache page.
CATEGORIES = [
    "Linux enum",
    "Linux privesc",
    "Windows enum",
    "Windows privesc",
    "AD",
    "Tunnel / support",
]

_DOWNLOAD_TIMEOUT = 300


@dataclass
class Material:
    """One stageable material obol can cache on Kali and later push to a foothold."""

    key: str
    label: str
    category: str
    os: str                          # "linux" | "windows" | "multi"
    kind: str                        # "cache-source" | "cache-binary" | "apt" | "pipx" | "manual"
    purpose: str = ""
    url: str = ""                    # download source for cache-* kinds
    version: str = "latest"          # pinned release tag, or "latest"
    sha256: str = ""                 # pinned digest; enforced when set
    dest: str = ""                   # filename inside the cache (defaults to key)
    arch: str = ""                   # informational (e.g. "amd64")
    bins: list[str] = field(default_factory=list)  # names used to detect a system copy
    apt: str = ""                    # apt package for kind == "apt"
    pipx: str = ""                   # pipx package for kind == "pipx"
    license: str = ""
    source: str = ""                 # upstream project (attribution)
    note: str = ""

    def dest_name(self) -> str:
        return self.dest or self.key


# ── the curated material slate ────────────────────────────────────────────────
# URLs track each project's latest release asset where a stable per-version digest
# is not pinned here; an operator/maintainer can pin `version` + `sha256` per entry.
_PEASS = "https://github.com/peass-ng/PEASS-ng/releases/latest/download"

REGISTRY: list[Material] = [
    # ── Linux enum (read-only; safe to run behind one-click approval) ──────────
    Material("linpeas", "linPEAS", "Linux enum", "linux", "cache-source",
             purpose="Linux privilege-escalation enumeration",
             url=f"{_PEASS}/linpeas.sh", dest="linpeas.sh", bins=["linpeas.sh"],
             license="GPL-3.0", source="peass-ng/PEASS-ng"),
    Material("linenum", "LinEnum", "Linux enum", "linux", "cache-source",
             purpose="Linux local enumeration script",
             url="https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh",
             dest="LinEnum.sh", bins=["LinEnum.sh"],
             license="GPL-3.0", source="rebootuser/LinEnum"),
    Material("linux-exploit-suggester", "linux-exploit-suggester", "Linux enum", "linux",
             "cache-source", purpose="Linux kernel/local exploit suggestion",
             url="https://raw.githubusercontent.com/The-Z-Labs/linux-exploit-suggester/master/linux-exploit-suggester.sh",
             dest="linux-exploit-suggester.sh", bins=["linux-exploit-suggester.sh"],
             license="GPL-2.0", source="The-Z-Labs/linux-exploit-suggester"),
    Material("pspy64", "pspy64", "Linux enum", "linux", "cache-binary", arch="amd64",
             purpose="unprivileged process/cron snooping",
             url="https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64",
             dest="pspy64", bins=["pspy64", "pspy"],
             license="MIT", source="DominicBreuker/pspy"),
    # ── Linux privesc (stage + guided) ────────────────────────────────────────
    Material("pwnkit", "PwnKit (CVE-2021-4034)", "Linux privesc", "linux", "manual",
             purpose="pkexec local root; operator supplies a vetted build/source",
             bins=["PwnKit", "pwnkit"], license="various", source="various",
             note="Public PoCs vary; supply a source/binary you trust via an override."),
    # ── Windows enum (read-only) ──────────────────────────────────────────────
    Material("winpeas", "winPEAS (x64)", "Windows enum", "windows", "cache-binary", arch="amd64",
             purpose="Windows privilege-escalation enumeration",
             url=f"{_PEASS}/winPEASx64.exe", dest="winPEASx64.exe", bins=["winPEASx64.exe"],
             license="GPL-3.0", source="peass-ng/PEASS-ng"),
    Material("winpeas-bat", "winPEAS (.bat)", "Windows enum", "windows", "cache-source",
             purpose="winPEAS batch variant for constrained shells",
             url=f"{_PEASS}/winPEAS.bat", dest="winPEAS.bat", bins=["winPEAS.bat"],
             license="GPL-3.0", source="peass-ng/PEASS-ng"),
    Material("seatbelt", "Seatbelt", "Windows enum", "windows", "manual",
             purpose="host security-posture enumeration (.NET)",
             bins=["Seatbelt.exe"], license="BSD-3-Clause", source="GhostPack/Seatbelt",
             note="Compiled .NET assembly; supply a build via an override."),
    Material("powerup", "PowerUp", "Windows enum", "windows", "manual",
             purpose="Windows privesc checks (PowerShell)",
             bins=["PowerUp.ps1"], license="BSD-3-Clause", source="PowerShellMafia/PowerSploit",
             note="PowerShell script; supply a copy via an override."),
    # ── Windows privesc (stage + craft) ───────────────────────────────────────
    Material("godpotato", "GodPotato", "Windows privesc", "windows", "cache-binary", arch="amd64",
             purpose="SeImpersonate -> SYSTEM (modern Windows)",
             url="https://github.com/BeichenDream/GodPotato/releases/latest/download/GodPotato-NET4.exe",
             dest="GodPotato-NET4.exe", bins=["GodPotato-NET4.exe", "GodPotato.exe"],
             license="MIT", source="BeichenDream/GodPotato"),
    Material("printspoofer", "PrintSpoofer", "Windows privesc", "windows", "cache-binary", arch="amd64",
             purpose="SeImpersonate -> SYSTEM via spooler named pipe",
             url="https://github.com/itm4n/PrintSpoofer/releases/latest/download/PrintSpoofer64.exe",
             dest="PrintSpoofer64.exe", bins=["PrintSpoofer64.exe", "PrintSpoofer.exe"],
             license="Unlicense", source="itm4n/PrintSpoofer"),
    Material("runascs", "RunasCs", "Windows privesc", "windows", "manual",
             purpose="run a command as another user / catch a shell from creds",
             bins=["RunasCs.exe"], license="MIT", source="antonioCoco/RunasCs",
             note="Release ships a zip; supply the extracted .exe via an override."),
    # ── AD ────────────────────────────────────────────────────────────────────
    Material("sharphound", "SharpHound", "AD", "windows", "manual",
             purpose="BloodHound collection from a Windows foothold",
             bins=["SharpHound.exe", "SharpHound.ps1"], license="GPL-3.0",
             source="BloodHoundAD/SharpHound", note="Supply the collector build via an override."),
    Material("rubeus", "Rubeus", "AD", "windows", "manual",
             purpose="Kerberos abuse (asktgt, s4u, kerberoast) from a foothold",
             bins=["Rubeus.exe"], license="BSD-3-Clause", source="GhostPack/Rubeus",
             note="Compiled .NET assembly; supply a build via an override."),
    # ── Tunnel / support (feeds §6d) ──────────────────────────────────────────
    Material("chisel", "chisel", "Tunnel / support", "multi", "cache-binary", arch="amd64",
             purpose="reverse SOCKS / static port forward pivoting",
             url="https://github.com/jpillora/chisel/releases/latest/download/chisel_linux_amd64.gz",
             dest="chisel_linux_amd64.gz", bins=["chisel"],
             license="MIT", source="jpillora/chisel",
             note="Release asset is gzipped; unpack before staging."),
    Material("ligolo-agent", "ligolo-ng (agent)", "Tunnel / support", "multi", "manual",
             purpose="route-backed pivoting agent (runs on the target)",
             bins=["agent", "ligolo-agent"], license="GPL-3.0", source="nicocha30/ligolo-ng",
             note="Release ships per-OS tarballs; supply the agent binary via an override."),
    Material("ligolo-proxy", "ligolo-ng (proxy)", "Tunnel / support", "multi", "manual",
             purpose="ligolo-ng proxy (runs on Kali)",
             bins=["proxy", "ligolo-proxy"], license="GPL-3.0", source="nicocha30/ligolo-ng",
             note="Release ships per-OS tarballs; supply the proxy binary via an override."),
    Material("nc64", "nc64.exe", "Tunnel / support", "windows", "manual",
             purpose="Windows netcat for callbacks",
             bins=["nc64.exe", "nc.exe"], license="various", source="static-binaries",
             note="Supply a static nc64.exe you trust via an override."),
    Material("socat", "socat (static)", "Tunnel / support", "linux", "manual",
             purpose="single-port relays / shell upgrade on the target",
             bins=["socat"], license="GPL-2.0", source="static-binaries",
             note="Supply a static socat binary via an override, or apt-install locally."),
]

_BY_KEY = {m.key: m for m in REGISTRY}


# ── cache location + index ─────────────────────────────────────────────────────
def cache_dir() -> Path:
    return library.base_dir() / "cache"


def _index_file() -> Path:
    return cache_dir() / "index.json"


def load_index() -> dict:
    f = _index_file()
    if f.exists():
        try:
            return json.loads(f.read_text())
        except (ValueError, OSError):
            return {}
    return {}


def save_index(data: dict) -> None:
    cache_dir().mkdir(parents=True, exist_ok=True)
    _index_file().write_text(json.dumps(data, indent=2, sort_keys=True))


# ── detection ──────────────────────────────────────────────────────────────────
def _which_any(bins: list[str]) -> str:
    for b in bins:
        hit = shutil.which(b)
        if hit:
            return hit
    return ""


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def status(material: Material, index: dict | None = None) -> dict:
    """Resolve one material against the cache and the local system.

    status values:
      - "cached": obol has a copy in its cache (or an operator-registered local file)
      - "installed": a system copy is on PATH (apt/pipx tools, or a hand-installed one)
      - "missing": not present; downloadable if a url/apt/pipx exists, else manual
    """
    index = index if index is not None else load_index()
    entry = index.get(material.key)
    if entry:
        p = entry.get("path", "")
        if p and Path(p).is_file():
            return {
                "status": "cached", "path": p,
                "sha256": entry.get("sha256", ""), "bytes": entry.get("bytes", 0),
                "verified": bool(entry.get("verified")), "version": entry.get("version", ""),
                "source": entry.get("source", "cache"),
            }
    syspath = _which_any(material.bins)
    if syspath:
        return {"status": "installed", "path": syspath, "sha256": "", "bytes": 0,
                "verified": False, "version": "", "source": "path"}
    downloadable = bool(material.url) or material.kind in {"apt", "pipx"}
    return {"status": "missing", "path": "", "sha256": "", "bytes": 0,
            "verified": False, "version": "", "source": "",
            "downloadable": downloadable}


def install_command(key: str) -> str:
    """The local install/fetch hint for a material (apt/pipx), or '' when the
    material is fetched into the cache or supplied manually."""
    m = _BY_KEY.get(key)
    if not m:
        return ""
    if m.kind == "apt" and m.apt:
        return f"sudo apt-get install -y {m.apt}"
    if m.kind == "pipx" and m.pipx:
        return f"pipx install {m.pipx}"
    return ""


def scan() -> dict:
    """Full inventory for the cache page: every material with its status, grouped by
    category, plus counts of what is present."""
    index = load_index()
    cats: dict[str, list[dict]] = {c: [] for c in CATEGORIES}
    present = 0
    for m in REGISTRY:
        st = status(m, index)
        if st["status"] in {"cached", "installed"}:
            present += 1
        row = {
            "key": m.key, "label": m.label, "category": m.category, "os": m.os,
            "kind": m.kind, "purpose": m.purpose, "version": m.version,
            "arch": m.arch, "license": m.license, "source": m.source, "note": m.note,
            "url": m.url, "install_cmd": install_command(m.key),
        }
        row.update(st)
        cats.setdefault(m.category, []).append(row)
    groups = [{"category": c, "materials": cats[c]} for c in CATEGORIES if cats.get(c)]
    return {"groups": groups, "present": present, "total": len(REGISTRY),
            "cache_dir": str(cache_dir()), "scanned_at": time.time()}


# ── fetching ────────────────────────────────────────────────────────────────────
def _http_fetch(url: str, dest: Path, timeout: int = _DOWNLOAD_TIMEOUT) -> int:
    """Default fetcher: download `url` to `dest`, honoring proxy env vars. Returns the
    byte count written. Injectable so tests never touch the network."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": "obol-provision"})
    written = 0
    with urllib.request.urlopen(req, timeout=timeout) as resp, dest.open("wb") as out:
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            out.write(chunk)
            written += len(chunk)
    return written


def _mark_executable(path: Path) -> None:
    try:
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except OSError:
        pass


def download(key: str, *, fetcher=None, timeout: int = _DOWNLOAD_TIMEOUT) -> dict:
    """Fetch a material into the cache and verify it. One-click: on success the cache
    index records the path, actual sha256, size, and whether it matched a pinned
    digest. A pinned-digest mismatch rejects and deletes the download."""
    m = _BY_KEY.get(key)
    if not m:
        raise KeyError(key)
    if not m.url:
        return {"ok": False, "key": key, "error": (
            "no download URL — supply a local file with `obol cache use` "
            f"({m.note})" if m.kind == "manual" else "this material is not downloadable")}
    fetcher = fetcher or _http_fetch
    cache_dir().mkdir(parents=True, exist_ok=True)
    dest = cache_dir() / m.dest_name()
    tmp = dest.with_suffix(dest.suffix + ".part")
    try:
        fetcher(m.url, tmp, timeout)
    except Exception as exc:  # noqa: BLE001 — surface any fetch failure to the operator
        if tmp.exists():
            tmp.unlink()
        return {"ok": False, "key": key, "url": m.url, "error": f"download failed: {exc}"}
    actual = _sha256(tmp)
    if m.sha256 and actual.lower() != m.sha256.lower():
        tmp.unlink()
        return {"ok": False, "key": key, "url": m.url, "verified": False,
                "error": f"sha256 mismatch: expected {m.sha256}, got {actual}"}
    tmp.replace(dest)
    if m.kind == "cache-binary" or dest.suffix in {".sh", ".py", ".pl"}:
        _mark_executable(dest)
    verified = bool(m.sha256) and actual.lower() == m.sha256.lower()
    index = load_index()
    index[key] = {"path": str(dest), "sha256": actual, "bytes": dest.stat().st_size,
                  "version": m.version, "verified": verified, "source": "cache",
                  "fetched_at": time.time()}
    save_index(index)
    return {"ok": True, "key": key, "url": m.url, "path": str(dest),
            "sha256": actual, "bytes": dest.stat().st_size, "verified": verified,
            "version": m.version}


def ensure(key: str, *, fetcher=None) -> dict:
    """The preface primitive: return the material's status if already present, else
    download it. Callers (stage/tunnel) invoke this before touching a target."""
    m = _BY_KEY.get(key)
    if not m:
        raise KeyError(key)
    st = status(m)
    if st["status"] in {"cached", "installed"}:
        return {"ok": True, "already": True, **st, "key": key}
    result = download(key, fetcher=fetcher)
    result["already"] = False
    return result


def use_local(key: str, path: str) -> dict:
    """Register an operator-supplied local file as this material's cached copy — the
    `tools.py` add-path override, for materials with no stable public asset (manual
    kind) or when the operator already has a trusted build."""
    m = _BY_KEY.get(key)
    if not m:
        raise KeyError(key)
    p = Path(path).expanduser()
    if not p.is_file():
        raise FileNotFoundError(path)
    index = load_index()
    index[key] = {"path": str(p), "sha256": _sha256(p), "bytes": p.stat().st_size,
                  "version": "local", "verified": False, "source": "added",
                  "fetched_at": time.time()}
    save_index(index)
    return {"ok": True, "key": key, **status(m, index)}


def remove(key: str) -> dict:
    """Drop a material from the cache. Deletes obol's own cached copy; an
    operator-supplied local file (source 'added') is de-registered but left on disk."""
    m = _BY_KEY.get(key)
    if not m:
        raise KeyError(key)
    index = load_index()
    entry = index.pop(key, None)
    save_index(index)
    if entry and entry.get("source") == "cache":
        p = Path(entry.get("path", ""))
        try:
            if p.is_file() and p.parent == cache_dir():
                p.unlink()
        except OSError:
            pass
    return {"ok": True, "key": key, **status(m, index)}


def resolve_path(key: str) -> str:
    """Absolute path to a material's local copy (cache, override, or system), or ''."""
    m = _BY_KEY.get(key)
    if not m:
        return ""
    st = status(m)
    return st.get("path", "")

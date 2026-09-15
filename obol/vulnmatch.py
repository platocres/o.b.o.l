"""Fingerprint -> probable-exploit matcher (ROADMAP §15b).

Given a host's proven facts — open ports with service/version, OS family, web
fingerprints — this matches a curated registry of well-known remote and kernel exploits
common in OSCP/HTB/THM/Vulnhub-style environments (`packs/known_exploits_*.json`) and
returns ranked candidate leads. It records each match as an ``exploit.candidate`` fact.

**Proof-bound, always:** a fingerprint match is a *candidate lead*, not proof the target
is vulnerable — matching `vsftpd 2.3.4` says "probably backdoored", not "confirmed". The
value carries the CVE/EDB, the probability, a stageable material (if any) and a
craft/searchsploit command, but confirmation is the operator running it. Running a remote
exploit is *exploitation*, so its move is `exploit`-kind (manual — never auto-fired; the
exam floor). obol vendors no exploit code: entries cite public CVE/EDB ids and point at a
material or a searchsploit term.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .facts import Fact, ProofState
from .scope import normalize_target

_DATA = Path(__file__).parent / "packs" / "known_exploits_2026_09.json"
_PROB_RANK = {"high": 3, "medium": 2, "low": 1}


@dataclass
class KnownExploit:
    key: str
    name: str
    cve: str = ""
    edb: str = ""
    kind: str = "rce"          # rce | privesc | leak | auth-bypass
    os: str = "multi"
    target: str = ""
    probability: str = "medium"
    match: dict = field(default_factory=dict)
    material: str = ""
    searchsploit: str = ""
    command: str = ""
    note: str = ""
    refs: list = field(default_factory=list)


def load_known() -> list[KnownExploit]:
    try:
        data = json.loads(_DATA.read_text())
    except Exception:  # noqa: BLE001
        return []
    out: list[KnownExploit] = []
    for e in data.get("exploits", []):
        out.append(KnownExploit(
            key=e["key"], name=e.get("name", e["key"]), cve=e.get("cve", ""),
            edb=e.get("edb", ""), kind=e.get("kind", "rce"), os=e.get("os", "multi"),
            target=e.get("target", ""), probability=e.get("probability", "medium"),
            match=e.get("match", {}) or {}, material=e.get("material", ""),
            searchsploit=e.get("searchsploit", ""), command=e.get("command", ""),
            note=e.get("note", ""), refs=list(e.get("refs", []))))
    return out


def _host_corpus(tf) -> dict:
    """Build the fingerprint corpus from a host's facts: open ports with their
    'service version' strings, the OS family, and a combined web-fingerprint string."""
    ports: dict[int, str] = {}
    for f in tf.facts:
        if f.state is not ProofState.SUPPORTED:
            continue
        if f.kind.startswith("port:"):
            try:
                p = int(f.kind.split(":", 1)[1])
            except ValueError:
                continue
            v = f.value or {}
            ports[p] = f"{v.get('service', '')} {v.get('version', '')}".strip().lower()
    os_family = ""
    for v in tf.values("host.os_family"):
        os_family = str(v.get("family") or v.get("os") or v).lower()
        break
    web_bits: list[str] = []
    for kind in ("web.tech", "web.content_map", "http.reachable", "service.http",
                 "web.generator", "web.title"):
        for v in tf.values(kind):
            web_bits.append(" ".join(str(x) for x in v.values()))
    # service/version strings on web ports also feed the web corpus (nmap -sV http tech)
    for p, s in ports.items():
        if p in (80, 443, 8080, 8443, 8000, 8888, 10000, 8983, 50000):
            web_bits.append(s)
    return {"ports": ports, "os_family": os_family, "web": " ".join(web_bits).lower(),
            "kinds": tf.kinds()}


def _matches(ke: KnownExploit, corpus: dict) -> bool:
    m = ke.match
    # fact-gated entries (e.g. Zerologon on a DC, kernel privesc post-foothold)
    facts_any = m.get("facts_any") or []
    if facts_any and not any(k in corpus["kinds"] for k in facts_any):
        return False
    # OS family, when known and required (unknown OS stays permissive)
    want_os = m.get("os_family", "")
    if want_os and corpus["os_family"] and want_os not in corpus["os_family"]:
        return False
    # port + service/version rules must all hold on the SAME open port
    ports = m.get("ports") or []
    svc_re = m.get("service_re", "")
    ver_re = m.get("version_re", "")
    if ports or svc_re or ver_re:
        ok = False
        for p, s in corpus["ports"].items():
            if ports and p not in ports:
                continue
            if svc_re and not re.search(svc_re, s, re.I):
                continue
            if ver_re and not re.search(ver_re, s, re.I):
                continue
            ok = True
            break
        if not ok:
            return False
    # web fingerprint
    web_re = m.get("web_re", "")
    if web_re and not re.search(web_re, corpus["web"], re.I):
        return False
    # an entry with no rules at all never matches (guards against a mis-authored card)
    if not (facts_any or want_os or ports or svc_re or ver_re or web_re):
        return False
    return True


def match_exploits(ws, host: str) -> list[dict]:
    """Ranked candidate exploits whose fingerprint matches the host — highest probability
    first. Each is a candidate lead, not a confirmed vuln."""
    tf = ws.facts_for_target(normalize_target(host))
    corpus = _host_corpus(tf)
    out: list[dict] = []
    for ke in load_known():
        if not _matches(ke, corpus):
            continue
        out.append({"key": ke.key, "name": ke.name, "cve": ke.cve, "edb": ke.edb,
                    "kind": ke.kind, "os": ke.os, "target": ke.target,
                    "probability": ke.probability, "material": ke.material,
                    "searchsploit": ke.searchsploit, "command": ke.command,
                    "note": ke.note, "refs": ke.refs})
    out.sort(key=lambda c: -_PROB_RANK.get(c["probability"], 0))
    return out


def record_candidates(ws, host: str) -> list[str]:
    """Record each matched exploit as a proof-bound ``exploit.candidate`` fact (a LEAD,
    citing the fingerprint, never a confirmed vuln). Returns the candidate keys added."""
    host = normalize_target(host)
    added: list[str] = []
    for c in match_exploits(ws, host):
        fact = Fact("exploit.candidate", f"host:{host}",
                    {"key": c["key"], "name": c["name"], "cve": c["cve"],
                     "probability": c["probability"], "kind": c["kind"],
                     "material": c["material"], "searchsploit": c["searchsploit"]},
                    ProofState.SUPPORTED,
                    source=f"fingerprint match ({c['cve'] or c['key']}) — candidate lead, not confirmed")
        if ws.facts.add(fact):
            added.append(c["key"])
    if added:
        ws.save()
    return added


def get_known(key: str) -> KnownExploit | None:
    for ke in load_known():
        if ke.key == key:
            return ke
    return None


def craft(ws, host: str, key: str) -> dict:
    """Craft (never fire) a matched remote/kernel exploit for review: stage its material if
    one exists, fill {{target}}/{{remote}}, and return the command + searchsploit term +
    references. Manual by construction — the operator runs it (the exam floor)."""
    host = normalize_target(host)
    ke = get_known(key)
    if not ke:
        raise ValueError(f"unknown known-exploit {key!r}")
    remote = ""
    if ke.material:
        from . import staging
        for sf in ws.staged_for(host):
            if sf.get("material") == ke.material and sf.get("status") in ("staged", "verified"):
                remote = sf.get("remote_path", "")
                break
        remote = remote or f"<stage {ke.material}: obol stage {ke.material} {host}>"
    command = (ke.command or "").replace("{{target}}", host).replace("{{remote}}", remote)
    return {"key": ke.key, "name": ke.name, "cve": ke.cve, "edb": ke.edb,
            "kind": ke.kind, "target": ke.target, "probability": ke.probability,
            "command": command, "material": ke.material, "staged": bool(remote and "<" not in remote),
            "searchsploit": (f"searchsploit {ke.searchsploit}" if ke.searchsploit else ""),
            "note": ke.note, "refs": ke.refs}

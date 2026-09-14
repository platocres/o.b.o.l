"""BloodHound ingestion — turn a SharpHound/BloodHound export into an engagement-wide
domain overlay.

Deliberately tolerant: BloodHound's JSON schema has drifted across versions (legacy
SharpHound and BloodHound CE differ in casing and nesting), so we read defensively
and extract the high-signal facts an operator actually pivots on — the domain, who
the Domain/Enterprise Admins are, and which principals are Kerberoast- or
AS-REP-roastable. It records `ad.graph.collected` / `ad.control_paths` facts and
stores a summary the engagement graph overlays. It is not a full BloodHound.

Accepts a `.zip` of the export or individual `.json` files (as bytes).
"""
from __future__ import annotations

import io
import json
import time
import zipfile

from .facts import Fact, ProofState
from .workspace import Workspace


def _prop(entry: dict, *keys: str, default=None):
    """Read a property from a BloodHound object, tolerant of casing/nesting.
    Looks in top-level and in a "Properties"/"properties" sub-object."""
    props = entry.get("Properties") or entry.get("properties") or {}
    for src in (entry, props):
        for k in keys:
            for variant in (k, k.lower(), k.capitalize()):
                if variant in src and src[variant] is not None:
                    return src[variant]
    return default


def _kind_of(name: str, blob: dict) -> str:
    meta = blob.get("meta") or blob.get("Meta") or {}
    t = str(meta.get("type") or meta.get("Type") or "").lower()
    if t:
        return t
    low = name.lower()
    for k in ("users", "computers", "groups", "domains", "gpos", "ous", "containers"):
        if k in low:
            return k
    return ""


def _merge_json(summary: dict, name: str, raw: bytes) -> None:
    try:
        blob = json.loads(raw.decode("utf-8", "replace"))
    except (ValueError, UnicodeError):
        return
    if not isinstance(blob, dict):
        return
    kind = _kind_of(name, blob)
    data = blob.get("data") or blob.get("Data") or []
    if not isinstance(data, list):
        return

    if kind == "domains":
        for d in data:
            nm = _prop(d, "name", "domain")
            if nm:
                summary["domain"] = str(nm).split("@")[-1].upper() if "@" in str(nm) else str(nm)
    elif kind == "users":
        for u in data:
            nm = str(_prop(u, "name", default="") or "")
            summary["users"] += 1
            if _prop(u, "hasspn", "hasSPN", default=False):
                summary["kerberoastable"].append(nm)
            if _prop(u, "dontreqpreauth", "dontReqPreAuth", default=False):
                summary["asrep_roastable"].append(nm)
            if _prop(u, "highvalue", "highValue", "system_tags", default=False):
                summary["high_value"].append(nm)
    elif kind == "computers":
        for c in data:
            nm = str(_prop(c, "name", default="") or "")
            summary["computers"].append(nm)
    elif kind == "groups":
        for g in data:
            nm = str(_prop(g, "name", default="") or "")
            base = nm.split("@")[0].upper()
            members = g.get("Members") or g.get("members") or []
            member_names = [str(m.get("ObjectIdentifier") or m.get("MemberId") or m)
                            for m in members] if isinstance(members, list) else []
            if base == "DOMAIN ADMINS":
                summary["domain_admins"] = member_names or summary["domain_admins"]
            elif base == "ENTERPRISE ADMINS":
                summary["enterprise_admins"] = member_names or summary["enterprise_admins"]


def parse(uploads: list[tuple[str, bytes]]) -> dict:
    """Parse one or more uploaded files (a .zip export, or individual .json files)
    into a domain summary."""
    summary = {
        "domain": "", "users": 0, "computers": [], "domain_admins": [],
        "enterprise_admins": [], "kerberoastable": [], "asrep_roastable": [],
        "high_value": [], "ingested_at": time.time(), "files": [],
    }
    for name, raw in uploads:
        if name.lower().endswith(".zip"):
            try:
                zf = zipfile.ZipFile(io.BytesIO(raw))
            except zipfile.BadZipFile:
                continue
            for inner in zf.namelist():
                if inner.lower().endswith(".json"):
                    summary["files"].append(inner)
                    _merge_json(summary, inner, zf.read(inner))
        elif name.lower().endswith(".json"):
            summary["files"].append(name)
            _merge_json(summary, name, raw)
    # de-dup lists
    for k in ("computers", "domain_admins", "enterprise_admins", "kerberoastable",
              "asrep_roastable", "high_value"):
        summary[k] = sorted(set(summary[k]))
    return summary


def apply_to_workspace(ws: Workspace, summary: dict) -> list[str]:
    """Store the summary on the workspace and record the domain facts it establishes.
    Returns the fact kinds added. Narrow by design: a graph collection proves the
    graph was collected and that control paths exist — not that any is exploitable."""
    ws.bloodhound = summary
    scope = f"domain:{summary['domain']}" if summary.get("domain") else "domain:unknown"
    added: list[str] = []
    def add(kind, value):
        if ws.facts.add(Fact(kind, scope, value, ProofState.SUPPORTED, "bloodhound ingest")):
            added.append(kind)
    add("ad.graph.collected", {"users": summary["users"], "computers": len(summary["computers"])})
    if summary.get("domain_admins") or summary.get("enterprise_admins"):
        add("ad.control_paths", {"domain_admins": len(summary.get("domain_admins", [])),
                                 "enterprise_admins": len(summary.get("enterprise_admins", []))})
    if summary.get("domain") and not ws.facts.has("ad.domain_known"):
        add("ad.domain_known", {"name": summary["domain"]})
    ws.save()
    return added


def ingest(ws: Workspace, uploads: list[tuple[str, bytes]]) -> dict:
    """Parse + apply in one step. Returns the summary plus the facts it added."""
    summary = parse(uploads)
    summary["added_facts"] = apply_to_workspace(ws, summary)
    return summary

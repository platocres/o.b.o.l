"""Durable workspace state under .obol/ in the engagement directory.

Everything obol knows lives here as plain JSON so a run is inspectable and
resumable, and so the terminal loop and the read-only web view can read the
exact same source of truth. The terminal is the only writer; the web only reads.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from .facts import Fact, FactSet
from .scope import normalize_target

STATE_DIR = ".obol"


class Workspace:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.dir = self.root / STATE_DIR
        self.name: str = self.root.name
        self.created_at: float = 0.0
        self.target: str = ""            # the ACTIVE target host (per-target pivot)
        self.targets: list[dict] = []    # [{host, label, os, status, notes, added_at}]
        self.scope: list[str] = []
        self.inputs: dict[str, str] = {}
        self.facts = FactSet()
        self.runs: list[dict] = []   # activity ledger: what was run, in order (report lineage)
        self.evidence: list[dict] = []   # attachments: [{id, target, phase, caption, filename, path, added_at}]
        self.checklist: dict[str, dict] = {}  # {host: {item_id: bool}} — manual per-target checklist ticks
        self.bloodhound: dict = {}       # last BloodHound ingest summary (engagement-wide)

    # ---- persistence ---------------------------------------------------------
    @property
    def state_file(self) -> Path:
        return self.dir / "state.json"

    @property
    def runs_dir(self) -> Path:
        return self.dir / "runs"

    def exists(self) -> bool:
        return self.state_file.exists()

    @property
    def evidence_dir(self) -> Path:
        return self.dir / "evidence"

    def load(self) -> "Workspace":
        if self.exists():
            data = json.loads(self.state_file.read_text())
            self.name = data.get("name", self.name)
            self.created_at = data.get("created_at", 0.0)
            self.target = data.get("target", "")
            self.targets = list(data.get("targets", []))
            self.scope = list(data.get("scope", []))
            self.inputs = dict(data.get("inputs", {}))
            self.facts = FactSet([Fact.from_json(f) for f in data.get("facts", [])])
            self.runs = data.get("runs", [])
            self.evidence = list(data.get("evidence", []))
            self.checklist = dict(data.get("checklist", {}))
            self.bloodhound = dict(data.get("bloodhound", {}))
        return self

    def save(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "name": self.name,
            "created_at": self.created_at,
            "target": self.target,
            "targets": self.targets,
            "scope": self.scope,
            "inputs": self.inputs,
            "facts": [f.to_json() for f in self.facts.facts],
            "runs": self.runs,
            "evidence": self.evidence,
            "checklist": self.checklist,
            "bloodhound": self.bloodhound,
        }
        self.state_file.write_text(json.dumps(payload, indent=2))

    # ---- scope / operator inputs --------------------------------------------
    def add_scope(self, value: str) -> str:
        target = normalize_target(value) if "/" not in str(value) else str(value).strip()
        if target and target not in self.scope:
            self.scope.append(target)
        return target

    def set_input(self, key: str, value: str) -> None:
        self.inputs[str(key)] = str(value)

    # ---- targets -------------------------------------------------------------
    def get_target(self, host: str) -> dict | None:
        norm = normalize_target(host)
        for t in self.targets:
            if t.get("host") == norm or t.get("host") == host:
                return t
        return None

    def add_target(self, host: str, label: str = "") -> dict:
        """Add a host as a target (idempotent), put it in scope, and make it active
        if it is the first one. Returns the target record."""
        norm = self.add_scope(host)          # normalizes + scopes
        existing = self.get_target(norm)
        if existing:
            if label:
                existing["label"] = label
            return existing
        rec = {
            "host": norm, "label": label or norm, "os": "",
            "status": "active", "notes": "", "added_at": time.time(),
        }
        self.targets.append(rec)
        # Seed the configured-target fact so the nmap prelude unlocks for this host
        # (same fact `obol init --target` records), scoped to the host.
        self.facts.add(Fact("target.configured", f"host:{norm}", {"target": norm},
                            source="target added"))
        if not self.target:
            self.target = norm
        return rec

    def remove_target(self, host: str) -> bool:
        rec = self.get_target(host)
        if not rec:
            return False
        self.targets.remove(rec)
        self.checklist.pop(rec["host"], None)
        if self.target == rec["host"]:
            self.target = self.targets[0]["host"] if self.targets else ""
        return True

    def set_active_target(self, host: str) -> bool:
        rec = self.get_target(host)
        if not rec:
            return False
        self.target = rec["host"]
        return True

    def facts_for_target(self, host: str) -> FactSet:
        """Facts relevant to one target: everything scoped to that host, plus shared
        engagement-wide facts (domain-scoped, and anything not host-scoped) so
        per-target planning still sees the domain and reusable material."""
        norm = normalize_target(host)
        host_scope = f"host:{norm}"
        out = []
        for f in self.facts.facts:
            scope = f.scope or ""
            if scope == host_scope or not scope.startswith("host:"):
                out.append(f)
        return FactSet(out)

    # ---- evidence / screenshots ---------------------------------------------
    def add_evidence(self, *, filename: str, data: bytes, target: str = "",
                     phase: str = "", caption: str = "") -> dict:
        """Store an uploaded file (screenshot etc.) under .obol/evidence/ and record
        its metadata, tagged to a target and optionally a phase — so the report can
        embed it in the matching section."""
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        eid = f"ev{int(time.time()*1000)}_{len(self.evidence)}"
        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in (filename or "file"))
        stored = f"{eid}_{safe}"
        (self.evidence_dir / stored).write_bytes(data)
        rec = {
            "id": eid, "target": normalize_target(target) if target else "",
            "phase": phase, "caption": caption, "filename": filename or safe,
            "stored": stored, "added_at": time.time(),
        }
        self.evidence.append(rec)
        return rec

    def remove_evidence(self, eid: str) -> bool:
        for rec in self.evidence:
            if rec.get("id") == eid:
                try:
                    (self.evidence_dir / rec.get("stored", "")).unlink(missing_ok=True)
                except OSError:
                    pass
                self.evidence.remove(rec)
                return True
        return False

    def evidence_for(self, target: str) -> list[dict]:
        norm = normalize_target(target) if target else ""
        return [e for e in self.evidence if e.get("target") == norm]

    # ---- activity ledger -----------------------------------------------------
    def record_run(self, tool: str, command: str, produced: list[str], **extra) -> None:
        """Append a run to the ledger. This is what the OSCP report is built from."""
        row = {
            "tool": tool,
            "command": command,
            "produced": produced,
            "at": time.time(),
        }
        row.update(extra)
        self.runs.append(row)


def find_workspace(start: Path | None = None) -> Workspace | None:
    """Walk up from the current directory looking for an existing .obol/ workspace."""
    cur = Path(start or Path.cwd()).resolve()
    for candidate in [cur, *cur.parents]:
        if (candidate / STATE_DIR / "state.json").exists():
            return Workspace(candidate).load()
    return None

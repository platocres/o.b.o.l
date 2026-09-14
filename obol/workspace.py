"""Durable workspace state under `.obol/` in the engagement directory.

Everything obol knows about an engagement lives here so a run is inspectable and
resumable, and so the terminal loop and the web surface read (and now write) the
exact same source of truth. The durable store is SQLite (`.obol/state.db`, see
`store.py`) — chosen because both surfaces are separate processes writing the same
engagement, which a single `state.json` cannot do safely.

`Workspace` keeps the whole engagement in memory as a plain domain model (a
`FactSet`, target/run/evidence lists, …) exactly as before: `ws.facts.add(...)`,
`ws.record_run(...)`, `ws.add_target(...)` all mutate memory and nothing hits disk
until `save()`. `save()` reconciles the in-memory model into the database with
targeted, idempotent writes (facts by content hash, runs by id), so a concurrent
`obol run` in the terminal and a run-from-site in the browser both land instead of
clobbering each other. `state.json` remains the interchange format for export,
migration, the offline `obol web` snapshot, and the debug package.
"""
from __future__ import annotations

import json
import time
import uuid
from pathlib import Path

from .facts import Fact, FactSet
from .scope import normalize_scope_entry, normalize_target
from .store import STATE_DB, Store, fact_hash

STATE_DIR = ".obol"
LEGACY_STATE_FILE = "state.json"


def has_state(engagement_dir: Path) -> bool:
    """True if a `.obol/` directory holds an engagement — either the SQLite store
    or a legacy `state.json` not yet migrated. Used everywhere the library used to
    test for `state.json` directly."""
    d = Path(engagement_dir) / STATE_DIR
    return (d / STATE_DB).exists() or (d / LEGACY_STATE_FILE).exists()


class Workspace:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.dir = self.root / STATE_DIR
        self.store = Store(self.dir / STATE_DB)
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
        # persistence bookkeeping: what is already on disk, and what this session
        # has explicitly removed (so save() writes only diffs and never resurrects
        # or clobbers rows another process wrote).
        self._persisted_fact_hashes: set[str] = set()
        self._persisted_run_ids: set[str] = set()
        self._deleted_targets: set[str] = set()
        self._deleted_evidence: set[str] = set()

    # ---- persistence ---------------------------------------------------------
    @property
    def db_file(self) -> Path:
        return self.dir / STATE_DB

    @property
    def legacy_state_file(self) -> Path:
        return self.dir / LEGACY_STATE_FILE

    @property
    def runs_dir(self) -> Path:
        return self.dir / "runs"

    @property
    def evidence_dir(self) -> Path:
        return self.dir / "evidence"

    def exists(self) -> bool:
        return has_state(self.root)

    def load(self) -> "Workspace":
        """Populate the in-memory model from the SQLite store. If only a legacy
        `state.json` exists, read it in (the next `save()` migrates it to the
        database); a fresh directory loads as empty."""
        if self.store.exists():
            self.apply_payload(self.store.read_all())
        elif self.legacy_state_file.exists():
            self.apply_payload(json.loads(self.legacy_state_file.read_text()))
            # legacy load: nothing is in the database yet, so save() will insert all.
            self._persisted_fact_hashes.clear()
            self._persisted_run_ids.clear()
        return self

    def save(self) -> None:
        """Reconcile the in-memory model into the database (targeted, idempotent,
        concurrency-safe). Returns nothing; the change events it appends drive the
        web SSE feed."""
        self.store.reconcile(
            self.to_payload(),
            persisted_fact_hashes=self._persisted_fact_hashes,
            persisted_run_ids=self._persisted_run_ids,
            deleted_targets=self._deleted_targets,
            deleted_evidence=self._deleted_evidence,
        )
        self._deleted_targets.clear()
        self._deleted_evidence.clear()

    # ---- JSON interchange (export / import / migration) ----------------------
    def to_payload(self) -> dict:
        """The engagement as a plain JSON-serializable dict — the same shape the
        old single-file store used. Source of truth for export, migration, the
        offline snapshot, and the debug package."""
        return {
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

    def apply_payload(self, data: dict) -> "Workspace":
        """Load an interchange payload into the in-memory model and record which
        facts/runs it represents as already-persisted."""
        self.name = data.get("name", self.name)
        self.created_at = data.get("created_at", 0.0)
        self.target = data.get("target", "")
        self.targets = list(data.get("targets", []))
        self.scope = list(data.get("scope", []))
        self.inputs = dict(data.get("inputs", {}))
        self.facts = FactSet([Fact.from_json(f) for f in data.get("facts", [])])
        self.runs = list(data.get("runs", []))
        self.evidence = list(data.get("evidence", []))
        self.checklist = dict(data.get("checklist", {}))
        self.bloodhound = dict(data.get("bloodhound", {}))
        self._persisted_fact_hashes = {
            fact_hash(f.kind, f.scope, f.value) for f in self.facts.facts
        }
        self._persisted_run_ids = {r["id"] for r in self.runs if r.get("id")}
        return self

    def export_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_payload(), indent=indent, default=str)

    # ---- scope / operator inputs --------------------------------------------
    def add_scope(self, value: str) -> str:
        target = normalize_scope_entry(value)
        if target and target not in self.scope:
            self.scope.append(target)
        return target

    def remove_scope(self, value: str) -> bool:
        """Remove a scope entry. Matches the entry as stored (CIDRs are kept raw,
        hosts are normalized), so callers can pass either form. Returns True if an
        entry was removed."""
        raw = str(value or "").strip()
        for candidate in (raw, normalize_target(raw)):
            if candidate and candidate in self.scope:
                self.scope.remove(candidate)
                return True
        return False

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
        self._deleted_targets.discard(norm)
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
        self._deleted_targets.add(rec["host"])
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
                self._deleted_evidence.add(eid)
                return True
        return False

    def evidence_for(self, target: str) -> list[dict]:
        norm = normalize_target(target) if target else ""
        return [e for e in self.evidence if e.get("target") == norm]

    # ---- activity ledger -----------------------------------------------------
    def record_run(self, tool: str, command: str, produced: list[str], **extra) -> None:
        """Append a run to the ledger. This is what the OSCP report is built from.
        Each run carries a stable id so `save()` can persist it idempotently even
        with the terminal and web both writing."""
        row = {
            "id": uuid.uuid4().hex,
            "tool": tool,
            "command": command,
            "produced": produced,
            "at": time.time(),
        }
        row.update(extra)
        self.runs.append(row)


def find_workspace(start: Path | None = None) -> Workspace | None:
    """Walk up from the current directory looking for an existing `.obol/`
    workspace (SQLite store or legacy JSON), like git finds its root."""
    cur = Path(start or Path.cwd()).resolve()
    for candidate in [cur, *cur.parents]:
        if has_state(candidate):
            return Workspace(candidate).load()
    return None

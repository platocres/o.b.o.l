"""SQLite persistence for an engagement's `.obol` store.

Why SQLite and not a single `state.json`? Two surfaces write the same engagement
— the terminal loop (`obol run`) and the web surface (run-from-site), in *separate
processes*. A whole-file JSON rewrite means read-modify-write races (the second
writer clobbers the first) and torn reads for anything watching the file. SQLite in
WAL mode gives us:

* **safe concurrent access** — many readers plus one writer at a time, writers
  serialized with a short busy-timeout instead of silently losing data;
* **atomic, targeted writes** — each mutation is its own transaction that touches
  only the rows it changes, so two processes appending different facts/runs keep
  both (see `reconcile`, which is idempotent by content hash / row id and never
  deletes rows another process added);
* **a real change feed** — the `events` table is an append-only log the web SSE
  loop tails, so "what changed" is pushed to the browser instead of polling a file
  mtime and re-fetching everything.

`state.json` stays the *interchange* format: `Workspace` exports/imports it for the
report, the offline `obol web` snapshot, the debug package, and migrating a legacy
`.obol/state.json` into the database on first load. This module only knows rows;
`Workspace` owns the domain model and calls `reconcile`/`read_all`.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path

STATE_DB = "state.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    k TEXT PRIMARY KEY,
    v TEXT
);
CREATE TABLE IF NOT EXISTS targets (
    host     TEXT PRIMARY KEY,
    label    TEXT,
    hostname TEXT,
    fqdn     TEXT,
    domain   TEXT,
    os       TEXT,
    status   TEXT,
    notes    TEXT,
    added_at REAL,
    ord      INTEGER
);
CREATE TABLE IF NOT EXISTS scope (
    value TEXT PRIMARY KEY,
    ord   INTEGER
);
CREATE TABLE IF NOT EXISTS inputs (
    k TEXT PRIMARY KEY,
    v TEXT
);
CREATE TABLE IF NOT EXISTS facts (
    hash       TEXT PRIMARY KEY,
    kind       TEXT NOT NULL,
    scope      TEXT,
    value      TEXT,
    state      TEXT,
    source     TEXT,
    created_at REAL
);
CREATE INDEX IF NOT EXISTS idx_facts_scope ON facts(scope);
CREATE INDEX IF NOT EXISTS idx_facts_kind  ON facts(kind);
CREATE TABLE IF NOT EXISTS runs (
    seq  INTEGER PRIMARY KEY AUTOINCREMENT,
    id   TEXT UNIQUE,
    at   REAL,
    data TEXT
);
CREATE TABLE IF NOT EXISTS evidence (
    id       TEXT PRIMARY KEY,
    added_at REAL,
    data     TEXT
);
CREATE TABLE IF NOT EXISTS checklist (
    host    TEXT,
    item    TEXT,
    checked INTEGER,
    PRIMARY KEY (host, item)
);
CREATE TABLE IF NOT EXISTS bloodhound (
    k    INTEGER PRIMARY KEY CHECK (k = 0),
    data TEXT
);
CREATE TABLE IF NOT EXISTS events (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts     REAL,
    type   TEXT,
    target TEXT,
    detail TEXT
);
"""

# The event log can grow unbounded over a long engagement; the SSE feed only ever
# needs the tail, so we trim to the most recent N rows after each write.
_EVENT_KEEP = 2000


def _ensure_schema(conn: sqlite3.Connection) -> None:
    """Create the schema and apply tiny additive migrations for older stores."""
    conn.executescript(_SCHEMA)
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(targets)")}
    for name in ("hostname", "fqdn", "domain"):
        if name not in cols:
            conn.execute(f"ALTER TABLE targets ADD COLUMN {name} TEXT")


def fact_hash(kind: str, scope: str, value: dict) -> str:
    """Stable identity for a fact row: same (kind, scope, value) always hashes the
    same, so re-recording a fact is an idempotent no-op and two processes that both
    observe the same fact do not create duplicate rows. Deliberately excludes
    `source`/`created_at`/`state` so lineage noise never forks a fact's identity —
    this mirrors `FactSet.add`'s in-memory de-dup."""
    payload = json.dumps([kind, scope or "", value or {}], sort_keys=True,
                          separators=(",", ":"), default=str)
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()


class Store:
    """Row-level access to one engagement database (`<dir>/.obol/state.db`)."""

    def __init__(self, path: Path):
        self.path = Path(path)

    # ---- connection ----------------------------------------------------------
    def connect(self) -> sqlite3.Connection:
        """Open a WAL-mode connection with a generous busy-timeout so a concurrent
        writer waits its turn instead of raising `database is locked`."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=10000")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def exists(self) -> bool:
        return self.path.exists()

    def initialize(self) -> None:
        conn = self.connect()
        try:
            _ensure_schema(conn)
            conn.commit()
        finally:
            conn.close()

    # ---- reads ---------------------------------------------------------------
    def read_all(self) -> dict:
        """Hydrate the full engagement state as a plain dict (the same shape the
        JSON payload uses), for `Workspace.load` to build its in-memory model."""
        conn = self.connect()
        try:
            _ensure_schema(conn)
            meta = {r["k"]: r["v"] for r in conn.execute("SELECT k, v FROM meta")}
            targets = [
                {"host": r["host"], "label": r["label"], "os": r["os"] or "",
                 "hostname": r["hostname"] or "", "fqdn": r["fqdn"] or "",
                 "domain": r["domain"] or "",
                 "status": r["status"] or "active", "notes": r["notes"] or "",
                 "added_at": r["added_at"] or 0.0}
                for r in conn.execute("SELECT * FROM targets ORDER BY ord, rowid")
            ]
            scope = [r["value"] for r in conn.execute("SELECT value FROM scope ORDER BY ord, rowid")]
            inputs = {r["k"]: r["v"] for r in conn.execute("SELECT k, v FROM inputs")}
            facts = [
                {"kind": r["kind"], "scope": r["scope"] or "",
                 "value": json.loads(r["value"] or "{}"),
                 "state": r["state"] or "supported", "source": r["source"] or "",
                 "created_at": r["created_at"] or 0.0}
                for r in conn.execute("SELECT * FROM facts ORDER BY created_at, rowid")
            ]
            runs = [json.loads(r["data"]) for r in conn.execute("SELECT data FROM runs ORDER BY seq")]
            evidence = [json.loads(r["data"]) for r in
                        conn.execute("SELECT data FROM evidence ORDER BY added_at, rowid")]
            checklist: dict[str, dict] = {}
            for r in conn.execute("SELECT host, item, checked FROM checklist"):
                checklist.setdefault(r["host"], {})[r["item"]] = bool(r["checked"])
            bh_row = conn.execute("SELECT data FROM bloodhound WHERE k=0").fetchone()
            bloodhound = json.loads(bh_row["data"]) if bh_row and bh_row["data"] else {}
        finally:
            conn.close()
        return {
            "name": meta.get("name", ""),
            "created_at": float(meta.get("created_at") or 0.0),
            "target": meta.get("target", ""),
            "targets": targets,
            "scope": scope,
            "inputs": inputs,
            "facts": facts,
            "runs": runs,
            "evidence": evidence,
            "checklist": checklist,
            "bloodhound": bloodhound,
        }

    def data_version(self, conn: sqlite3.Connection | None = None) -> int:
        """`PRAGMA data_version` changes whenever *another* connection commits, so a
        cheap "did anything change?" probe that works across processes."""
        own = conn is None
        conn = conn or self.connect()
        try:
            return int(conn.execute("PRAGMA data_version").fetchone()[0])
        finally:
            if own:
                conn.close()

    def read_events(self, after_id: int, limit: int = 200) -> list[dict]:
        """The change feed the SSE loop tails: events with id greater than the last
        one it forwarded, oldest first."""
        conn = self.connect()
        try:
            _ensure_schema(conn)
            rows = conn.execute(
                "SELECT id, ts, type, target, detail FROM events WHERE id > ? ORDER BY id LIMIT ?",
                (int(after_id), int(limit)),
            ).fetchall()
        finally:
            conn.close()
        return [
            {"id": r["id"], "ts": r["ts"], "type": r["type"], "target": r["target"] or "",
             "detail": json.loads(r["detail"]) if r["detail"] else {}}
            for r in rows
        ]

    def latest_event_id(self) -> int:
        conn = self.connect()
        try:
            _ensure_schema(conn)
            row = conn.execute("SELECT MAX(id) AS m FROM events").fetchone()
        finally:
            conn.close()
        return int(row["m"] or 0)

    # ---- writes --------------------------------------------------------------
    def reconcile(self, payload: dict, *, persisted_fact_hashes: set[str],
                  persisted_run_ids: set[str], deleted_targets: set[str],
                  deleted_evidence: set[str]) -> list[dict]:
        """Persist the in-memory engagement state in a single transaction, writing
        only what changed and never clobbering another process's concurrent rows.

        Mutable singletons (meta, targets, scope, inputs, checklist, bloodhound) are
        upserted (last-writer-wins per row, which is safe because they are small and
        rarely contended). Append-only rows (facts, runs) are inserted idempotently
        — facts keyed by content hash, runs by their generated id — so a fact or run
        another process already wrote is left untouched and ours is added alongside.
        Only rows this session explicitly removed (`deleted_targets`,
        `deleted_evidence`) are deleted.

        Returns the change events appended for the SSE feed (new facts, new runs,
        new/removed targets), so the caller can forward them or update its snapshot.
        """
        events: list[dict] = []
        conn = self.connect()
        try:
            _ensure_schema(conn)
            conn.execute("BEGIN IMMEDIATE")

            # meta -------------------------------------------------------------
            for k, v in (("name", payload.get("name", "")),
                         ("created_at", payload.get("created_at", 0.0)),
                         ("target", payload.get("target", ""))):
                conn.execute(
                    "INSERT INTO meta(k, v) VALUES(?, ?) "
                    "ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                    (k, str(v)),
                )

            # targets ----------------------------------------------------------
            for host in deleted_targets:
                conn.execute("DELETE FROM targets WHERE host=?", (host,))
                conn.execute("DELETE FROM checklist WHERE host=?", (host,))
            live_hosts = {t.get("host") for t in payload.get("targets", [])}
            for i, t in enumerate(payload.get("targets", [])):
                host = t.get("host")
                if not host:
                    continue
                existed = conn.execute("SELECT 1 FROM targets WHERE host=?", (host,)).fetchone()
                conn.execute(
                    "INSERT INTO targets(host, label, hostname, fqdn, domain, os, status, notes, added_at, ord) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(host) DO UPDATE SET "
                    "label=CASE "
                    "WHEN excluded.label IS NULL OR excluded.label='' THEN targets.label "
                    "WHEN lower(excluded.label)=lower(excluded.host) "
                    "AND targets.label IS NOT NULL AND targets.label!='' "
                    "AND lower(targets.label)!=lower(targets.host) THEN targets.label "
                    "ELSE excluded.label END, "
                    "hostname=COALESCE(NULLIF(excluded.hostname, ''), targets.hostname), "
                    "fqdn=COALESCE(NULLIF(excluded.fqdn, ''), targets.fqdn), "
                    "domain=COALESCE(NULLIF(excluded.domain, ''), targets.domain), "
                    "os=COALESCE(NULLIF(excluded.os, ''), targets.os), status=excluded.status, "
                    "notes=excluded.notes, ord=excluded.ord",
                    (host, t.get("label") or host, t.get("hostname", ""),
                     t.get("fqdn", ""), t.get("domain", ""), t.get("os", ""),
                     t.get("status", "active"), t.get("notes", ""),
                     t.get("added_at", time.time()), i),
                )
                if not existed:
                    events.append({"type": "target_added", "target": host,
                                   "detail": {"label": t.get("label") or host}})

            # scope (rewrite: tiny set, order matters) -------------------------
            conn.execute("DELETE FROM scope")
            for i, value in enumerate(payload.get("scope", [])):
                conn.execute("INSERT OR IGNORE INTO scope(value, ord) VALUES(?, ?)", (value, i))

            # inputs -----------------------------------------------------------
            for k, v in (payload.get("inputs") or {}).items():
                conn.execute(
                    "INSERT INTO inputs(k, v) VALUES(?, ?) "
                    "ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                    (str(k), str(v)),
                )

            # facts (idempotent insert by content hash) ------------------------
            for f in payload.get("facts", []):
                h = fact_hash(f["kind"], f.get("scope", ""), f.get("value", {}))
                if h in persisted_fact_hashes:
                    continue
                conn.execute(
                    "INSERT OR IGNORE INTO facts(hash, kind, scope, value, state, source, created_at) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (h, f["kind"], f.get("scope", ""),
                     json.dumps(f.get("value", {}), default=str),
                     f.get("state", "supported"), f.get("source", ""),
                     f.get("created_at", time.time())),
                )
                persisted_fact_hashes.add(h)
                events.append({"type": "fact_added", "target": _host_of(f.get("scope", "")),
                               "detail": {"kind": f["kind"], "scope": f.get("scope", "")}})

            # runs (idempotent insert by id) -----------------------------------
            for r in payload.get("runs", []):
                rid = r.get("id")
                if not rid or rid in persisted_run_ids:
                    continue
                conn.execute(
                    "INSERT OR IGNORE INTO runs(id, at, data) VALUES(?,?,?)",
                    (rid, r.get("at", time.time()), json.dumps(r, default=str)),
                )
                persisted_run_ids.add(rid)
                events.append({"type": "run", "target": r.get("target", ""),
                               "detail": {"tool": r.get("tool", ""),
                                          "produced": r.get("produced", []),
                                          "action_id": r.get("action_id", "")}})

            # evidence ---------------------------------------------------------
            for eid in deleted_evidence:
                conn.execute("DELETE FROM evidence WHERE id=?", (eid,))
                events.append({"type": "evidence_removed", "target": "", "detail": {"id": eid}})
            for e in payload.get("evidence", []):
                eid = e.get("id")
                if not eid:
                    continue
                existed = conn.execute("SELECT 1 FROM evidence WHERE id=?", (eid,)).fetchone()
                conn.execute(
                    "INSERT INTO evidence(id, added_at, data) VALUES(?,?,?) "
                    "ON CONFLICT(id) DO UPDATE SET data=excluded.data",
                    (eid, e.get("added_at", time.time()), json.dumps(e, default=str)),
                )
                if not existed:
                    events.append({"type": "evidence_added", "target": e.get("target", ""),
                                   "detail": {"id": eid, "phase": e.get("phase", "")}})

            # checklist --------------------------------------------------------
            for host, items in (payload.get("checklist") or {}).items():
                if host not in live_hosts and host in deleted_targets:
                    continue
                for item, checked in (items or {}).items():
                    conn.execute(
                        "INSERT INTO checklist(host, item, checked) VALUES(?,?,?) "
                        "ON CONFLICT(host, item) DO UPDATE SET checked=excluded.checked",
                        (host, item, 1 if checked else 0),
                    )

            # bloodhound -------------------------------------------------------
            bh = payload.get("bloodhound") or {}
            conn.execute(
                "INSERT INTO bloodhound(k, data) VALUES(0, ?) "
                "ON CONFLICT(k) DO UPDATE SET data=excluded.data",
                (json.dumps(bh, default=str),),
            )

            # change feed ------------------------------------------------------
            now = time.time()
            for ev in events:
                conn.execute(
                    "INSERT INTO events(ts, type, target, detail) VALUES(?,?,?,?)",
                    (now, ev["type"], ev.get("target", ""),
                     json.dumps(ev.get("detail", {}), default=str)),
                )
            if events:
                conn.execute(
                    "DELETE FROM events WHERE id <= "
                    "(SELECT MAX(id) FROM events) - ?", (_EVENT_KEEP,),
                )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
        return events


def _host_of(scope: str) -> str:
    """`host:10.10.10.5` -> `10.10.10.5`; anything else (domain-scoped, unscoped)
    carries no single target."""
    return scope[5:] if scope.startswith("host:") else ""

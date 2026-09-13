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

STATE_DIR = ".obol"


class Workspace:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.dir = self.root / STATE_DIR
        self.name: str = self.root.name
        self.target: str = ""
        self.facts = FactSet()
        self.runs: list[dict] = []   # activity ledger: what was run, in order (report lineage)

    # ---- persistence ---------------------------------------------------------
    @property
    def state_file(self) -> Path:
        return self.dir / "state.json"

    def exists(self) -> bool:
        return self.state_file.exists()

    def load(self) -> "Workspace":
        if self.exists():
            data = json.loads(self.state_file.read_text())
            self.name = data.get("name", self.name)
            self.target = data.get("target", "")
            self.facts = FactSet([Fact.from_json(f) for f in data.get("facts", [])])
            self.runs = data.get("runs", [])
        return self

    def save(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "name": self.name,
            "target": self.target,
            "facts": [f.to_json() for f in self.facts.facts],
            "runs": self.runs,
        }
        self.state_file.write_text(json.dumps(payload, indent=2))

    # ---- activity ledger -----------------------------------------------------
    def record_run(self, tool: str, command: str, produced: list[str]) -> None:
        """Append a run to the ledger. This is what the OSCP report is built from."""
        self.runs.append({
            "tool": tool,
            "command": command,
            "produced": produced,
            "at": time.time(),
        })


def find_workspace(start: Path | None = None) -> Workspace | None:
    """Walk up from the current directory looking for an existing .obol/ workspace."""
    cur = Path(start or Path.cwd()).resolve()
    for candidate in [cur, *cur.parents]:
        if (candidate / STATE_DIR / "state.json").exists():
            return Workspace(candidate).load()
    return None

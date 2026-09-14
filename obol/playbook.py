"""Playbooks: named, ordered sequences of pack actions, expressed as data.

A playbook is **not** a second engine. Each step names an existing pack Action by
id; running a step goes through the exact same scope-enforced runner
(`runner.run_command`) and evidence parser (`parsers.parse_action_output`) as
`obol run`, and writes the same `.obol` store. Playbooks only let the operator
gather a batch of related evidence as one deliberate, ordered move, with per-step
approval gating for the noisy/risky steps (the shape modeled on Pentest
Companion's playbook engine — see docs/SOURCES.md §5).

Playbooks live as JSON under ``obol/playbooks/``. A step references a pack action
id, so a step that invokes a GPL Orange-derived AD action inherits that action's
attribution (``obol/packs/NOTICE.md``); the *ordering* itself is original obol
composition, not Orange-derived content.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .pack import Action, load_pack

PLAYBOOKS_DIR = Path(__file__).parent / "playbooks"


@dataclass
class PlaybookStep:
    label: str
    action_id: str
    cmd: int = 1                       # 1-based command variant on the action
    args_extra: str = ""              # extra tokens appended to the rendered command
    require_approval: bool = False
    note: str = ""

    @classmethod
    def from_json(cls, d: dict) -> "PlaybookStep":
        return cls(
            label=d.get("label", d.get("action_id", "")),
            action_id=d["action_id"],
            cmd=int(d.get("cmd", 1)),
            args_extra=d.get("args_extra", ""),
            require_approval=bool(d.get("require_approval", False)),
            note=d.get("note", ""),
        )


@dataclass
class Playbook:
    name: str
    title: str = ""
    description: str = ""
    steps: list[PlaybookStep] = field(default_factory=list)

    @classmethod
    def from_json(cls, d: dict) -> "Playbook":
        return cls(
            name=d["name"],
            title=d.get("title", d["name"]),
            description=d.get("description", ""),
            steps=[PlaybookStep.from_json(s) for s in d.get("steps", [])],
        )


def list_playbooks() -> list[Playbook]:
    """All playbooks shipped under obol/playbooks/, sorted by file name."""
    if not PLAYBOOKS_DIR.is_dir():
        return []
    return [Playbook.from_json(json.loads(p.read_text())) for p in sorted(PLAYBOOKS_DIR.glob("*.json"))]


def load_playbook(name: str) -> Playbook:
    """Load one playbook by name (or explicit .json path). Raises FileNotFoundError."""
    path = Path(name if name.endswith(".json") else str(PLAYBOOKS_DIR / f"{name}.json"))
    if not path.exists():
        raise FileNotFoundError(name)
    return Playbook.from_json(json.loads(path.read_text()))


def resolve_step(step: PlaybookStep, pack: list[Action] | None = None) -> Action:
    """Map a step to its pack Action. Raises KeyError if the pack no longer has it."""
    pack = pack if pack is not None else load_pack()
    for a in pack:
        if a.id == step.action_id:
            return a
    raise KeyError(step.action_id)


def resolve_steps(pb: Playbook, pack: list[Action] | None = None) -> list[tuple[PlaybookStep, Action]]:
    """Resolve every step to its Action, preserving order. Raises KeyError on drift."""
    pack = pack if pack is not None else load_pack()
    return [(s, resolve_step(s, pack)) for s in pb.steps]

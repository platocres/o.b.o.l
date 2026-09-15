"""Per-target objective ladder (ROADMAP §7) — the OSCP progress spine.

A target's engagement goal, as a ladder of milestones: initial access → privilege
escalation → local flag → root flag. Read by two consumers, so they never disagree:

* **`obol cruise`** — its *goal function*: cruise stops with ``objective-complete`` once
  the root objective is captured, instead of wandering past the win.
* **the report** — the per-target objective/proof checklist and progress meter.

It is a projection over facts, **not new state**: a rung is "reached" only when a
proof-bound fact records it — a foothold, privileged access, or a captured flag
(``objective.*`` from `flags.py`, which is already profile-aware about which file is the
local vs the root flag, §7). It never marks a rung reached without the fact that proves
it, and it carries each reached rung's evidence lineage so the report can cite it. The
richer OSCP *proof* validation (a flag shown with host identity in one capture, §14) rides
on top of this ladder later; here a rung's proof is the command that captured it.
"""
from __future__ import annotations

from .scope import normalize_target

# (rung id, label, the fact kinds that count as reaching it — any one suffices).
LADDER: list[tuple[str, str, tuple[str, ...]]] = [
    ("initial-access", "Initial access",
     ("foothold.windows", "foothold.linux", "access.shell", "winrm.authenticated",
      "foothold.webshell")),
    ("privesc", "Privilege escalation", ("access.admin", "access.system")),
    ("local-flag", "Local flag", ("objective.local_flag", "objective.flag")),
    ("root-flag", "Root flag", ("objective.root_flag",)),
]


def _first_evidence(tf, kinds: tuple[str, ...]) -> str:
    for f in tf.facts:
        if f.kind in kinds and f.state.value == "supported":
            return f.source or ""
    return ""


def ladder_for(ws, host: str) -> list[dict]:
    """The ladder for a host: each rung with whether it is reached and its evidence."""
    tf = ws.facts_for_target(normalize_target(host))
    rungs = []
    for rid, label, kinds in LADDER:
        reached = any(tf.has(k) for k in kinds)
        rungs.append({"id": rid, "label": label, "reached": reached,
                      "evidence": _first_evidence(tf, kinds) if reached else ""})
    return rungs


def is_complete(ws, host: str) -> bool:
    """The target's objective is met when the root flag is captured — or, in a
    single-flag lab, a captured flag together with privileged access."""
    tf = ws.facts_for_target(normalize_target(host))
    if tf.has("objective.root_flag"):
        return True
    return tf.has("objective.flag") and (tf.has("access.admin") or tf.has("access.system"))


def next_rung(ws, host: str) -> dict | None:
    """The next unreached rung (what to aim at), or None when the ladder is complete."""
    for r in ladder_for(ws, host):
        if not r["reached"]:
            return r
    return None


def progress(ws, host: str) -> dict:
    """A compact objective summary for a host (the shared shape terminal/web/report read)."""
    host = normalize_target(host)
    rungs = ladder_for(ws, host)
    complete = is_complete(ws, host)
    nxt = None if complete else next((r for r in rungs if not r["reached"]), None)
    return {"host": host, "rungs": rungs,
            "reached": sum(1 for r in rungs if r["reached"]),
            "total": len(rungs), "complete": complete, "next": nxt}

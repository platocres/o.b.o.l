"""obol cruise — supervised cruise control (ROADMAP cruise-control pillar II).

The loop that drives the engagement move by move, with the operator's foot on the
brake. It stands on the three pieces already built:

* `moves.frontier_moves` — the ranked candidate moves for a target (pillar I),
* `dispatch.run_move`     — run one move through its shared, scope-enforced primitive,
* `autonomy`             — how autonomous obol may be with each move (the stop-contract).

Each iteration considers the **highest-ranked move not yet attempted** and:

* if it is an ``auto`` move (recon/enum + the safe baseline) → run it, re-parse, re-rank,
  and continue — obol advancing on its own;
* if it is an ``approve``/``manual`` move → **stop** and hand that move back as a
  checkpoint (a login/exploit/tunnel/noisy step the operator must approve or run) —
  cruise never fires it unattended.

It runs each move at most once per cruise (so a move that yields no new facts can't spin
the loop), records every step, and stops at the first checkpoint, when nothing is left to
auto-run, or at a safety step cap. This is *not* a new engine: it only orders calls to
the primitives above; every command still goes through the one runner/parser/store, the
scope gate, and the proof boundaries. When it stops, the operator handles the checkpoint
(or does the stuck thing by hand and re-ingests — the resumable-handoff pillar) and runs
`obol cruise` again to continue.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import autonomy, dispatch
from . import moves as moves_layer
from .scope import normalize_target

DEFAULT_MAX_STEPS = 25


@dataclass
class CruiseStep:
    id: str
    label: str
    kind: str
    phase: str
    posture: str
    ok: bool
    summary: str = ""
    added: list = field(default_factory=list)


@dataclass
class CruiseResult:
    target: str
    ran: list = field(default_factory=list)          # list[CruiseStep]
    stop_reason: str = ""                             # checkpoint|done|blocked|max-steps|no-target
    stop_move: dict | None = None                    # the move cruise stopped at (checkpoint)
    message: str = ""

    @property
    def ran_ok(self) -> int:
        return sum(1 for s in self.ran if s.ok)

    def to_dict(self) -> dict:
        return {"target": self.target,
                "ran": [vars(s) for s in self.ran],
                "stop_reason": self.stop_reason,
                "stop_move": self.stop_move,
                "message": self.message}


def _checkpoint_message(move) -> str:
    if not move.ready:
        return f"{move.label} — {move.reason or 'needs an input first'}"
    if move.autonomy == "manual":
        return (f"{move.label} is manual — obol will craft it, you run it: "
                f"`obol do {move.id}`")
    return (f"{move.label} needs your approval ({move.kind}) — "
            f"`obol do {move.id}` to run it, then `obol cruise` again")


def cruise(ws, host: str = "", *, max_steps: int = DEFAULT_MAX_STEPS,
           surface: str = "cli", on_step=None) -> CruiseResult:
    """Auto-advance a target through its ``auto`` moves, stopping at the first checkpoint.

    Runs the highest-ranked un-attempted move while it is ``auto``; the first time the
    highest-ranked un-attempted move needs approval, stops and returns it as the
    checkpoint. A move that fails to run (e.g. a missing tool) is recorded and skipped,
    not fatal. `on_step` (if given) is called with each `CruiseStep` as it completes, for
    live terminal output.
    """
    host = normalize_target(host or getattr(ws, "target", "") or "")
    result = CruiseResult(target=host)
    if not host:
        result.stop_reason = "no-target"
        result.message = "no active target to cruise — add one or pass a host"
        return result

    attempted: set[str] = set()
    for _ in range(max_steps):
        frontier = moves_layer.frontier_moves(ws, host)
        candidate = next((m for m in frontier if m.id not in attempted), None)
        if candidate is None:
            result.stop_reason = "done"
            result.message = "nothing left to auto-run — cruise has done the safe work"
            return result
        if autonomy.needs_approval(candidate.autonomy):
            result.stop_reason = "checkpoint"
            result.stop_move = candidate.to_dict()
            result.message = _checkpoint_message(candidate)
            return result

        # an auto move: run it through its primitive (a failure is recorded, not fatal).
        attempted.add(candidate.id)
        try:
            res = dispatch.run_move(ws, candidate.id, host=host, approve=False, surface=surface)
        except dispatch.DispatchError as exc:
            step = CruiseStep(candidate.id, candidate.label, candidate.kind, candidate.phase,
                              posture="blocked", ok=False, summary=str(exc))
        else:
            step = CruiseStep(candidate.id, candidate.label, candidate.kind, candidate.phase,
                              posture=res.get("posture", ""), ok=bool(res.get("ok")),
                              summary=res.get("summary", ""), added=list(res.get("added", [])))
        result.ran.append(step)
        if on_step:
            on_step(step)

    result.stop_reason = "max-steps"
    result.message = (f"reached the {max_steps}-step cap — run `obol cruise` again to "
                      "keep going")
    return result

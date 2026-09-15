"""obol cruise — supervised cruise control + the pause briefing (pillar II, with III).

The loop that drives the engagement move by move with the operator's foot on the
brake (see the module history for the loop contract), plus the **checkpoint briefing**
it produces when it stops: everything the operator needs to decide what to do before
going back into cruise, without reassembling context by hand.

The briefing is where cruise control meets the **resumable-handoff pillar** (III): for a
move obol will not run (a manual exploit) or cannot yet (a login missing a credential),
the briefing hands over the exact crafted command and the way back in — `obol ingest`
(paste the output you ran yourself) or `obol assert` (attest the outcome). The operator
acts outside obol, re-enters from facts, and runs `obol cruise` again.

Nothing here is a new engine: it only orders calls to the built primitives
(`moves.frontier_moves` / `dispatch.run_move` / `autonomy`) and reads facts to explain
the stop; every command still goes through the one runner/parser/store and the proof
boundaries. The briefing's command previews are all **pure** (they render, never run).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import autonomy, dispatch, phases
from . import moves as moves_layer
from .scope import normalize_target

DEFAULT_MAX_STEPS = 25
_TOOL_MISSING_RE = re.compile(r"binary [`']?([\w.+-]+)[`']? was not found")


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
    briefing: dict = field(default_factory=dict)     # the pause briefing (assembled below)

    @property
    def ran_ok(self) -> int:
        return sum(1 for s in self.ran if s.ok)

    def to_dict(self) -> dict:
        return {"target": self.target,
                "ran": [vars(s) for s in self.ran],
                "stop_reason": self.stop_reason,
                "stop_move": self.stop_move,
                "message": self.message,
                "briefing": self.briefing}


# ── the loop ──────────────────────────────────────────────────────────────────
def cruise(ws, host: str = "", *, max_steps: int = DEFAULT_MAX_STEPS,
           surface: str = "cli", auto_kinds=frozenset(), on_step=None) -> CruiseResult:
    """Auto-advance a target through its ``auto`` moves, stopping at the first checkpoint,
    and attach a rich briefing describing the stop. `on_step` (if given) is called with
    each `CruiseStep` as it completes, for live terminal output.

    ``auto_kinds`` elevates specific approve-tier move kinds to run unattended this cruise
    — e.g. ``{"sweep"}`` lets cruise run a through-tunnel sweep of an already-opened,
    scope-extended pivot without stopping (the pivot decision itself, opening the tunnel,
    is never elevated). It never elevates a ``manual`` move (a privesc exploit).
    """
    host = normalize_target(host or getattr(ws, "target", "") or "")
    result = CruiseResult(target=host)
    if not host:
        result.stop_reason = "no-target"
        result.message = "no active target to cruise — add one or pass a host"
        return result

    from . import objectives
    attempted: set[str] = set()
    for _ in range(max_steps):
        if objectives.is_complete(ws, host):
            result.stop_reason = "objective-complete"
            result.message = "root objective captured — the engagement goal is met for this target"
            break
        frontier = moves_layer.frontier_moves(ws, host)
        candidate = next((m for m in frontier if m.id not in attempted), None)
        if candidate is None:
            result.stop_reason = "done"
            result.message = "nothing left to auto-run — cruise has done the safe work"
            break
        elevated = candidate.autonomy != "manual" and candidate.kind in auto_kinds
        if autonomy.needs_approval(candidate.autonomy) and not elevated:
            result.stop_reason = "checkpoint"
            result.stop_move = candidate.to_dict()
            result.message = _checkpoint_message(candidate)
            break
        attempted.add(candidate.id)
        try:
            res = dispatch.run_move(ws, candidate.id, host=host, approve=elevated, surface=surface)
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
    else:
        result.stop_reason = "max-steps"
        result.message = (f"reached the {max_steps}-step cap — run `obol cruise` again to "
                          "keep going")

    result.briefing = build_briefing(ws, result)
    return result


@dataclass
class EngagementCruiseResult:
    """The result of cruising every in-scope target (the recursion across segments)."""
    hosts: list = field(default_factory=list)   # [{host, stop_reason, message, ran, checkpoint, complete}]

    @property
    def checkpoints(self) -> list:
        return [h for h in self.hosts if h["stop_reason"] == "checkpoint"]

    @property
    def complete(self) -> list:
        return [h for h in self.hosts if h.get("complete")]

    def to_dict(self) -> dict:
        return {"engagement": True, "hosts": self.hosts,
                "summary": {"cruised": len(self.hosts),
                            "checkpoints": len(self.checkpoints),
                            "complete": len(self.complete)}}


def cruise_engagement(ws, *, max_steps: int = DEFAULT_MAX_STEPS, max_hosts: int = 64,
                      surface: str = "cli", auto_kinds=frozenset(),
                      on_host=None, on_step=None) -> EngagementCruiseResult:
    """Cruise every in-scope target, breadth-first — the supervised recursion across
    segments. Each target is driven through its safe moves and stopped at its own
    checkpoint; the target list is re-read every pass, so hosts a just-run through-tunnel
    sweep discovers (with ``auto_kinds={"sweep"}``, once the operator has opened the pivot)
    are picked up and cruised in the same run. Pivoting itself — opening a tunnel — stays a
    per-host checkpoint; obol never crosses into a new segment without the operator's nod.
    """
    result = EngagementCruiseResult()
    done: set[str] = set()
    while len(done) < max_hosts:
        pending = [t["host"] for t in ws.targets if normalize_target(t["host"]) not in done]
        if not pending:
            break
        host = pending[0]
        done.add(normalize_target(host))
        res = cruise(ws, host, max_steps=max_steps, surface=surface,
                     auto_kinds=auto_kinds, on_step=on_step)
        entry = {"host": normalize_target(host), "stop_reason": res.stop_reason,
                 "message": res.message, "ran": res.ran_ok,
                 "checkpoint": (res.briefing or {}).get("checkpoint"),
                 "complete": res.stop_reason == "objective-complete",
                 "briefing": res.briefing}
        result.hosts.append(entry)
        if on_host:
            on_host(entry, res)
    return result


def _checkpoint_message(move) -> str:
    if not move.ready:
        return f"{move.label} — {move.reason or 'needs an input first'}"
    if move.autonomy == "manual":
        return f"{move.label} is manual — obol will craft it, you run it: `obol do {move.id}`"
    return (f"{move.label} needs your approval ({move.kind}) — "
            f"`obol do {move.id}` to run it, then `obol cruise` again")


# ── the briefing ──────────────────────────────────────────────────────────────
def build_briefing(ws, result: CruiseResult) -> dict:
    """Assemble everything the operator needs at the pause: where they are, what cruise
    just learned and what it couldn't run, the full checkpoint (a pure command preview,
    the facts that triggered it, the ask, the risk, and the way back in), and the other
    moves waiting."""
    host = result.target
    tf = ws.facts_for_target(host) if host else None

    position = {}
    if tf is not None:
        access = sorted(k for k in tf.kinds()
                        if k.startswith(("foothold.", "access.")) or k.endswith(".authenticated"))
        position = {"phase": phases.target_phase(tf),
                    "frontier": phases.PHASES[phases.frontier_index(tf)],
                    "access": access}

    learned = _friendly_kinds(k for s in result.ran for k in s.added)
    blocked = [{"label": s.label, "reason": s.summary, "tool": _blocked_tool(s.summary)}
               for s in result.ran if s.posture == "blocked"]
    install = sorted({b["tool"] for b in blocked if b["tool"]})

    checkpoint = None
    if result.stop_move is not None:
        checkpoint = {**result.stop_move, **_checkpoint_detail(ws, host, result.stop_move)}

    options = []
    if host:
        cp_id = result.stop_move["id"] if result.stop_move else None
        for m in moves_layer.frontier_moves(ws, host):
            if m.id == cp_id:
                continue
            options.append({"id": m.id, "label": m.label, "kind": m.kind, "phase": m.phase,
                            "autonomy": m.autonomy, "ready": m.ready, "reason": m.reason})
            if len(options) >= 5:
                break

    from . import objectives
    return {"target": host, "position": position,
            "objectives": objectives.progress(ws, host) if host else {},
            "recap": {"ran": result.ran_ok, "learned": learned, "blocked": blocked, "install": install},
            "checkpoint": checkpoint, "options": options,
            "stop_reason": result.stop_reason, "message": result.message}


def _friendly_kinds(kinds) -> list:
    from .pack import friendly
    out: list[str] = []
    for k in kinds:
        f = friendly(k)
        if f not in out:
            out.append(f)
    return out


def _blocked_tool(msg: str) -> str:
    m = _TOOL_MISSING_RE.search(msg or "")
    return m.group(1) if m else ""


def _ask_of(move: dict) -> str:
    if not move.get("ready", True):
        return "input"
    return "manual" if move.get("autonomy") == "manual" else "approve"


def _resume_commands(move: dict, ask: str) -> list:
    mid = move.get("id", "")
    if ask == "approve":
        return [f"obol do {mid}", "obol cruise"]
    if ask == "manual":
        return ["# run the crafted command yourself, then bring the result back:",
                "obol ingest --note '<what you ran>'   # paste tool output to parse into facts",
                "#   or: obol assert <fact.kind> --note '<what you proved>'   # attest the outcome",
                "obol cruise"]
    return [f"# {move.get('reason') or 'obtain the missing input'}, then:", "obol cruise"]


def _checkpoint_detail(ws, host: str, move: dict) -> dict:
    """The rich checkpoint: a pure command preview, the 'why', the ask, the risk, and the
    resume path. Every branch renders — none executes."""
    kind = move.get("kind", "")
    detail = move.get("detail", {}) or {}
    ask = _ask_of(move)
    command = why = risk = ""
    try:
        if kind == "action":
            from .service import build_command, find_action
            action = find_action(move["id"])
            command, _ = build_command(action, ws, target=host)
            why = action.hypothesis or _requires_why(action, ws, host)
        elif kind == "login":
            from . import sessions
            try:
                command = sessions.build_login_command(ws, host, detail.get("kind", ""),
                                                        detail.get("method", ""))
            except sessions.SessionError:
                command = ""
            why = (f"validated credential {detail.get('user', '')} and "
                   f"{detail.get('kind', '')} reachable").strip()
        elif kind == "exploit":
            from . import exploits
            ex = exploits.get_exploit(detail.get("key", ""))
            outcome = list(ex.outcomes)[0] if ex and ex.outcomes else ""
            plan = exploits.plan_exploit(ws, host, detail.get("key", ""), outcome) if ex else {}
            command = plan.get("command", "")
            why = f"privesc lead present: {detail.get('lead', '')}"
            risk = "; ".join(x for x in (plan.get("cleanup", ""), plan.get("note", "")) if x)
        elif kind == "tunnel":
            from . import tunnels
            try:
                command = tunnels.build_setup_command(ws, host, detail.get("kind", ""))
            except Exception:  # noqa: BLE001 — a subnet-less preview just has no command
                command = ""
            why = f"proven foothold; {detail.get('transport', '')} transport"
            risk = "opening it auto-extends scope to the exposed subnet"
        elif kind == "enum":
            command = f"stage {detail.get('tool', '')} on {host} and run it over the foothold"
            why = "proven foothold + credential; read-only local enumeration"
        elif kind == "sweep":
            from . import discovery
            command = discovery.through_tunnel_discovery_command(
                detail.get("transport", "socks"), detail.get("subnet", ""))
            why = (f"tunnel {detail.get('tunnel', '')} is up and exposes "
                   f"{detail.get('subnet', '')} — sweep it to discover the next segment")
            risk = "active scan of the pivoted subnet (already scope-authorized via the tunnel)"
    except Exception:  # noqa: BLE001 — a preview must never break the briefing
        pass
    return {"ask": ask, "command": command, "why": why, "risk": risk,
            "resume": _resume_commands(move, ask)}


def _requires_why(action, ws, host: str) -> str:
    from .pack import friendly
    tf = ws.facts_for_target(host)
    have = [friendly(k) for k in (list(action.requires_all) + list(action.requires_any))
            if tf.has(k)]
    return ("unlocked by " + ", ".join(have)) if have else ""

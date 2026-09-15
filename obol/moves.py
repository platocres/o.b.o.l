"""The unified move frontier — cruise-control pillar I (see docs/ROADMAP.md).

obol's fact-gated planner already ranks the live *pack actions* for a target
(`pack.next_actions`). But the capabilities obol built on top of the packs — a
session login (§6a), enum run-and-rank (§8), an applicable privesc exploit (§8), a
pivot tunnel (§6d) — each live behind their own `eligible_*` function and their own
CLI/web entrypoint, *outside* that one ranked list. So `obol next` can say "run nxc
ldap" but not "log in over WinRM now" or "stage winPEAS and run it".

This module unifies them: `frontier_moves(ws, host)` returns ONE ranked list of
candidate **moves**, each a pack action OR a built-primitive offer, tagged with its
kind, engagement phase, and whether it is ready to run right now. It is the frontier
`obol cruise` (pillar II) will drive move-by-move, and a better answer on its own to
"what can I do on this host next".

It is **not** a second planner: it reuses `pack.next_actions` for the pack actions
and each primitive's existing `eligible_*` function verbatim, then ranks the merged
set by the *same* phase/frontier model the planner already uses (`obol/phases.py`).
It enumerates and ranks only; it never runs anything and produces no facts.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import autonomy, phases
from .pack import next_actions
from .scope import normalize_target

# Within-phase priority hints that place a primitive move sensibly among the pack
# actions of the same phase (pack actions keep their own pack priority). Ranking is
# dominated by the phase/frontier bucket; these only order within a band.
_PRIMITIVE_PRIORITY = {"login": 78, "enum": 66, "exploit": 60, "tunnel": 46, "sweep": 52}

# The phase each primitive move advances (the frontier layout the map/planner share).
# A through-tunnel sweep discovers the next segment, so it advances the escalate/pivot band.
_PRIMITIVE_PHASE = {"login": "access", "enum": "escalate",
                    "exploit": "escalate", "tunnel": "escalate", "sweep": "escalate"}


@dataclass
class Move:
    """One candidate next action on a target, from any surface obol can drive.

    ``kind`` is ``action`` for a pack action, else the primitive (``login``/``enum``/
    ``exploit``/``tunnel``). ``id`` is stable: a pack action's id, else ``kind:key``,
    so a future dispatcher (pillar II) can route it. ``ready`` is "runnable right now
    with what obol has"; a not-ready primitive carries an actionable ``reason`` (the
    one input it still needs), never blocked/proves language.
    """
    kind: str
    id: str
    label: str
    phase: str
    ready: bool
    reason: str = ""
    priority: int = 50
    autonomy: str = "auto"  # base tier (obol/autonomy.py): auto/approve/manual
    decision: str = "auto"  # effective policy decision for this engagement: auto/ask/never
    detail: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"kind": self.kind, "id": self.id, "label": self.label,
                "phase": self.phase, "ready": self.ready, "reason": self.reason,
                "priority": self.priority, "autonomy": self.autonomy,
                "decision": self.decision, "detail": self.detail}


def _rank(ws, moves: list[Move], frontier: int) -> list[Move]:
    """Resolve each move's effective policy decision, drop the ones this engagement
    forbids (``never`` — e.g. an automated exploiter in exam mode), and order the rest by
    the planner's own key: on-flow first, ready before not-ready within a band, then
    priority, then a stable label tiebreak.

    Mirrors `pack.next_actions`'s ``(prematurity, -priority)``, with a ready tier inserted
    so a primitive still waiting on one input sorts under the moves you can actually fire.
    """
    kept: list[Move] = []
    for m in moves:
        m.decision = autonomy.decide(ws, kind=m.kind, base_tier=m.autonomy,
                                     tool=(m.detail or {}).get("tool", ""))
        if m.decision == "never":
            continue  # forbidden this engagement (the exam floor) — not an option
        kept.append(m)
    return sorted(kept, key=lambda m: (
        max(0, phases.phase_index(m.phase) - frontier),
        0 if m.ready else 1,
        -m.priority,
        m.label,
    ))


def frontier_moves(ws, host: str = "") -> list[Move]:
    """The unified, phase-ranked candidate moves for a host (default: active target).

    Pack actions come from `pack.next_actions` (already the frontier-ranked live set);
    the primitives come from their own `eligible_*` functions, gated exactly as they
    already are (a login needs a reachable service + a validated credential; enum,
    exploits, and tunnels need a proven foothold). Pre-foothold a host shows pack
    actions and any login offers; once a foothold is proven the escalate/pivot moves
    appear — the frontier advancing on its own, no branching here.
    """
    host = normalize_target(host or getattr(ws, "target", "") or "")
    tf = ws.facts_for_target(host) if host else ws.facts
    frontier = phases.frontier_index(tf)
    moves: list[Move] = []

    # 1) pack actions — the planner's live, frontier-ranked set for this factset.
    for a in next_actions(tf):
        moves.append(Move(
            kind="action", id=a.id, label=a.title,
            phase=phases.phase_of_action(a), ready=True,
            priority=a.priority, autonomy=autonomy.tier_of_action(a),
            detail={"tool": a.tool, "action_id": a.id},
        ))

    if not host:
        return _rank(ws, moves, frontier)

    # 2) session logins (§6a) — offered on a reachable service; ready with a credential.
    from . import sessions
    for o in sessions.eligible_sessions(ws, host):
        if o.get("proven"):
            continue  # an active session of this kind already exists — not a next move
        moves.append(Move(
            kind="login", id=f"login:{o['kind']}",
            label=o.get("label") or f"Log in over {o['kind']}",
            phase=_PRIMITIVE_PHASE["login"], ready=bool(o.get("ready")),
            reason=o.get("reason", ""), priority=_PRIMITIVE_PRIORITY["login"],
            autonomy=autonomy.PRIMITIVE_TIER["login"],
            detail={"kind": o["kind"], "method": o.get("method", ""),
                    "user": o.get("user", ""), "pth": bool(o.get("pth"))},
        ))

    # 2b) reverse-shell listener (§8) — a LOCAL move (obol's own box) offered when the host
    #     has a code-execution path (a confirmed web RCE, or an exploit candidate) but no
    #     live session yet: start a listener + prep the payload so you can catch a shell.
    exec_facts = ("web.cmdi_confirmed", "web.upload_confirmed", "exploit.candidate")
    has_session = any(s.get("status") == "active" for s in ws.sessions_for(host))
    if not has_session and any(tf.has(k) for k in exec_facts):
        moves.append(Move(
            kind="listener", id="listener:start",
            label="Start a reverse-shell listener (catch a shell)",
            phase="access", ready=True, priority=70,
            autonomy=autonomy.PRIMITIVE_TIER.get("listener", "auto"),
            detail={"os": "windows" if tf.has("host.os_family") and "windows" in
                    str(tf.values("host.os_family")).lower() else "linux"},
        ))

    # 2c) fingerprint-matched remote/kernel exploits (§15b) — a candidate lead from a
    #     service/version/OS/web fingerprint. Offered as `exploit`-kind moves so the
    #     autonomy policy keeps them manual (craft + hand off; never auto-fired — a remote
    #     exploit IS exploitation). Ranked by probability via frontier priority.
    from . import vulnmatch
    _prob_prio = {"high": 64, "medium": 58, "low": 52}
    for c in vulnmatch.match_exploits(ws, host):
        moves.append(Move(
            kind="exploit", id=f"exploit:vuln:{c['key']}",
            label=f"{c['name']} — probable ({c['probability']})",
            phase="escalate" if c["kind"] == "privesc" else "access",
            ready=True, priority=_prob_prio.get(c["probability"], 55),
            autonomy=autonomy.PRIMITIVE_TIER["exploit"],
            detail={"key": f"vuln:{c['key']}", "vuln": c["key"], "cve": c["cve"],
                    "probability": c["probability"], "material": c["material"],
                    "lead": c["cve"] or c["key"]},
        ))

    # Escalate/pivot primitives are post-foothold by nature. `eligible_exploits` and
    # `eligible_tunnels` already self-gate on a foothold; `eligible_enum` is permissive
    # (it lists OS tools as not-ready pre-foothold), so gate all three here on a proven
    # foothold to keep the frontier a set of genuine next moves, not pre-foothold noise.
    from . import staging
    if not staging._foothold_os(ws, host):
        return _rank(ws, moves, frontier)

    # 3) enum run-and-rank (§8) — a read-only enum tool over a proven foothold.
    from . import enumrun
    for r in enumrun.eligible_enum(ws, host):
        moves.append(Move(
            kind="enum", id=f"enum:{r['key']}", label=f"Enumerate with {r['key']}",
            phase=_PRIMITIVE_PHASE["enum"], ready=bool(r.get("ready")),
            reason="" if r.get("ready") else "needs a validated credential on a proven foothold",
            priority=_PRIMITIVE_PRIORITY["enum"], autonomy=autonomy.PRIMITIVE_TIER["enum"],
            detail={"tool": r["key"], "material": r.get("material"),
                    "cached": bool(r.get("cached")), "guided": bool(r.get("guided"))},
        ))

    # 4) applicable privesc exploits (§8) — gated on the parsed privesc.* lead.
    from . import exploits
    for e in exploits.eligible_exploits(ws, host):
        moves.append(Move(
            kind="exploit", id=f"exploit:{e['key']}", label=e.get("label") or e["key"],
            phase=_PRIMITIVE_PHASE["exploit"], ready=True,
            priority=_PRIMITIVE_PRIORITY["exploit"], autonomy=autonomy.PRIMITIVE_TIER["exploit"],
            detail={"key": e["key"], "lead": e.get("lead"),
                    "outcomes": list(e.get("outcomes", [])), "guided": bool(e.get("guided"))},
        ))

    # 5) pivot tunnels (§6d) — offered on a proven foothold; ready when the transport
    #    has what it needs (an SSH transport needs a password).
    from . import tunnels
    for t in tunnels.eligible_tunnels(ws, host):
        moves.append(Move(
            kind="tunnel", id=f"tunnel:{t['kind']}", label=t.get("label") or t["kind"],
            phase=_PRIMITIVE_PHASE["tunnel"], ready=bool(t.get("ready")),
            reason=t.get("reason", ""), priority=_PRIMITIVE_PRIORITY["tunnel"],
            autonomy=autonomy.PRIMITIVE_TIER["tunnel"],
            detail={"kind": t["kind"], "transport": t.get("transport"),
                    "proxychains": bool(t.get("proxychains")),
                    "exposes_subnet": t.get("exposes_subnet", "")},
        ))

    # 6) through-tunnel sweep (§6e) — the recursion: once a tunnel is up and exposes a
    #    subnet obol has not swept yet, offer to sweep *through* it to discover the next
    #    segment's hosts (they become targets). Offered once per tunnel (a prior sweep run
    #    settles it); re-sweeping stays a manual `obol tunnel sweep`.
    swept = {r.get("tunnel") for r in ws.runs if r.get("sweep")}
    for t in ws.tunnels_for(host):
        tid, subnet = t.get("id"), t.get("exposed_subnet", "")
        if t.get("status") != "up" or not subnet or tid in swept:
            continue
        moves.append(Move(
            kind="sweep", id=f"sweep:{tid}",
            label=f"Sweep the pivoted segment {subnet} (tunnel {tid})",
            phase=_PRIMITIVE_PHASE["sweep"], ready=True,
            priority=_PRIMITIVE_PRIORITY["sweep"], autonomy=autonomy.PRIMITIVE_TIER["sweep"],
            detail={"tunnel": tid, "subnet": subnet, "transport": t.get("transport", "")},
        ))

    return _rank(ws, moves, frontier)

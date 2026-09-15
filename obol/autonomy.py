"""Move autonomy tiers — how much obol may do unattended (cruise stop-contract).

`moves.frontier_moves` says *what* the candidate moves are; this says *how autonomous*
obol may be with each one. It is the policy `obol cruise` (pillar II) reads to decide
where to stop, and the gate `dispatch.run_move` enforces so nothing box-touching runs
unattended without approval. Three tiers, increasing operator involvement:

* ``auto``    — safe to run without asking: recon and enumeration. Cruise auto-advances.
* ``approve`` — runnable, but noisy/state-changing/access-gaining, so it pauses for an
                explicit approval (a confirm on the web, a re-run with approval / cruise
                checkpoint). Everything past the recon/enum boundary defaults here.
* ``manual``  — obol prepares and hands off but **never fires it** (a privesc exploit —
                the OSCP/manual posture); cruise stops with the crafted command.

The classification is **data-driven, not a hardcoded lab rule** (AGENTS.md principle 10):
- a pack action's tier is an explicit ``autonomy`` in its pack data if set, else derived
  from the shared phase model (`obol/phases.py`) and Quick Start's existing safe-baseline
  list (`quickstart.QUICKSTART_ACTION_IDS`) — the boundary the ROADMAP already draws;
- a primitive move's tier is fixed by kind (login/enum/tunnel touch the box → approve; a
  privesc exploit → manual).

The default is deliberately **conservative**: anything not clearly recon/enum defaults to
``approve``, so cruise never auto-fires something risky just because it was unclassified.
"""
from __future__ import annotations

from . import phases

TIERS = ("auto", "approve", "manual")

# A primitive move's autonomy, by move kind. Post-foothold enum, a login, and a tunnel
# all touch the target/network (past the recon/enum boundary), so they pause for
# approval; a privesc exploit is never auto-fired (craft + hand off).
PRIMITIVE_TIER = {"login": "approve", "enum": "approve",
                  "tunnel": "approve", "exploit": "manual"}


def tier_of_action(action) -> str:
    """The autonomy tier for a pack action: an explicit ``autonomy`` in pack data if set,
    else ``auto`` when it is recon/enum or already in Quick Start's safe baseline, else
    the conservative ``approve``."""
    explicit = (getattr(action, "autonomy", "") or "").strip()
    if explicit in TIERS:
        return explicit
    # Quick Start's safe-baseline list is the existing, blessed "obol auto-runs this" set
    # (imported lazily to avoid pulling the run stack in at module load).
    from .quickstart import QUICKSTART_ACTION_IDS
    if getattr(action, "id", "") in QUICKSTART_ACTION_IDS:
        return "auto"
    if phases.phase_of_action(action) in ("recon", "enum"):
        return "auto"
    return "approve"


def tier_of_move(move) -> str:
    """A `moves.Move`'s tier: its pre-computed ``autonomy`` if present (frontier_moves
    sets it), else derived by kind for a primitive."""
    existing = getattr(move, "autonomy", "") or ""
    if existing in TIERS:
        return existing
    return PRIMITIVE_TIER.get(getattr(move, "kind", ""), "approve")


def needs_approval(tier: str) -> bool:
    """Whether a move of this tier requires an explicit approval before it may run
    (``approve``/``manual`` do; ``auto`` does not)."""
    return tier in ("approve", "manual")

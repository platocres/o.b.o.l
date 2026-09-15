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
PRIMITIVE_TIER = {"login": "approve", "enum": "approve", "tunnel": "approve",
                  "sweep": "approve", "exploit": "manual"}


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


# ── the operator autonomy policy (reach × mode × operator override) ───────────
# The base tier above says how risky a move is *in itself*. The policy below decides how
# autonomous obol may actually be with it in THIS engagement, from three inputs:
#
#   1. reach — does the move touch only obol's own attacker box, or the target/network?
#   2. mode  — the engagement's posture (exam / lab / default), from its §7 profile.
#   3. the operator's per-kind override, when set.
#
# It is enforced in ONE place (this function, read by `dispatch.run_move`, `cruise`, and
# `moves.frontier_moves`) so the exam/lab separation is a single auditable, default-deny,
# test-locked gate — not a flag scattered through the code (the Charon lesson).

# How far each move-kind reaches. "local" = obol's own box only (safe to run unattended);
# "target" = touches the target/network (consent-gated by default).
REACH = {
    "action": "target", "login": "target", "connect": "target", "enum": "target",
    "stage": "target", "tunnel": "target", "sweep": "target", "exploit": "target",
    "listener": "local", "cred": "local", "craft": "local",
}

# Decisions the policy resolves a move to.
DECISIONS = ("auto", "ask", "never")

# Automated-*exploitation* tools the OSCP exam forbids (they exploit *for* you). obol may
# still *prepare* an exploit in exam mode — fingerprint → stage → craft the command — it
# just may never auto-fire one, and must not run these tools at all. This is one half of
# the uncrossable exam floor.
EXAM_DISALLOWED_TOOLS = {
    "sqlmap", "sqlmap-automation", "commix", "nosqlmap",
    "metasploit", "msfconsole", "autopwn", "autorecon-exploit", "wpscan-attack",
}

_EXAM_PLATFORMS = {"oscp"}
_LAB_PLATFORMS = {"htb", "thm", "ctf"}
# In lab mode these target-touching primitives auto-run by default (the getting-on-the-box
# + setup flow, sped up). Exam mode leaves them at ask unless the operator opts in. Neither
# mode auto-*fires* an exploit — that is the floor, below.
_LAB_AUTO_KINDS = {"login", "stage", "tunnel", "sweep", "enum", "connect"}


def mode_of(ws) -> str:
    """The engagement's autonomy mode from its §7 profile platform: ``exam`` (OSCP — the
    uncrossable floor applies), ``lab`` (HTB/THM/CTF — auto the foothold/setup primitives),
    or ``default`` (conservative: ask before touching the target)."""
    platform = ""
    try:
        platform = (getattr(ws, "profile", None) or {}).get("platform", "")
    except Exception:  # noqa: BLE001
        platform = ""
    if platform in _EXAM_PLATFORMS:
        return "exam"
    if platform in _LAB_PLATFORMS:
        return "lab"
    return "default"


def _overrides(ws) -> dict:
    try:
        ov = (getattr(ws, "profile", None) or {}).get("autonomy", {}) or {}
        return {k: v for k, v in ov.items() if v in DECISIONS}
    except Exception:  # noqa: BLE001
        return {}


def decide(ws, *, kind: str, base_tier: str = "", tool: str = "") -> str:
    """The effective decision for a move — ``auto`` (run unattended), ``ask`` (checkpoint),
    or ``never`` (forbidden this engagement). The single gate the whole surface reads.

    Order (default-deny, floor wins over the operator):
      • local-reach prep (a listener on obol's box, crafting a command) → always ``auto``;
      • **exam floor** (uncrossable): an automated-exploitation tool → ``never``; and an
        exploit *run* is never ``auto`` (obol crafts + hands off, never fires it);
      • the operator's per-kind override, if set (within the floor);
      • a base ``auto`` move (recon/enum) → ``auto`` in every mode;
      • lab mode → ``auto`` for the foothold/setup primitives;
      • otherwise → ``ask`` (the conservative default).
    """
    mode = mode_of(ws)
    reach = REACH.get(kind, "target")

    # 1. local prep never touches the target — safe to run unattended in any mode.
    if reach == "local":
        return "auto"

    # 2. the exam floor — enforced before any operator override can widen it.
    if mode == "exam":
        if tool and tool.lower() in EXAM_DISALLOWED_TOOLS:
            return "never"
        if kind == "exploit":
            return "ask"     # craft + hand off; obol never auto-fires on the exam

    # 3. operator per-kind override (cannot cross the floor handled above).
    ov = _overrides(ws).get(kind)
    if ov in DECISIONS:
        return ov

    # 4. base auto (recon/enum) runs in every mode.
    if base_tier == "auto":
        return "auto"

    # 5. lab mode auto-runs the getting-on-the-box + setup primitives.
    if mode == "lab" and kind in _LAB_AUTO_KINDS:
        return "auto"

    # 6. conservative default.
    return "ask"


def effective_policy(ws) -> dict:
    """The resolved decision for every move-kind — what `obol autonomy` shows, so the
    operator can SEE the exam/lab separation rather than trust it. Uses each kind's base
    tier (a representative primitive tier; pack actions vary by card)."""
    mode = mode_of(ws)
    rows = []
    for kind in ("action", "login", "connect", "enum", "stage", "tunnel", "sweep",
                 "exploit", "listener"):
        base = "auto" if kind == "action" else PRIMITIVE_TIER.get(kind, "approve")
        rows.append({"kind": kind, "reach": REACH.get(kind, "target"),
                     "decision": decide(ws, kind=kind, base_tier=base)})
    return {"mode": mode, "overrides": _overrides(ws), "kinds": rows,
            "disallowed_tools": sorted(EXAM_DISALLOWED_TOOLS) if mode == "exam" else []}

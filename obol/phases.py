"""The engagement phase/flow model — one projection, shared by the planner and map.

Phases order an engagement recon -> enum -> creds -> access -> escalate -> loot. A
fact kind maps to a phase; an action's phase is the latest phase of what it produces
(fallback: its prerequisites), or an explicit ``phase`` the pack sets on the action.

Two consumers read this one model, so ranking and layout never disagree:

* the **planner** (`pack.next_actions`) ranks the live actions *relative to the
  target's current frontier* — the phase it is actively pushing into — so recon and
  low-risk enumeration sort ahead of premature high-value branches, **without** letting
  a deliberately low-priority recon step (a slow UDP sweep) jump ahead of the real next
  move. A single scalar priority could not express that: it conflated "how valuable is
  this fact" with "is it time for it yet". The frontier split separates the two.
* the **map** (`graph.py`) lays nodes out left-to-right by the same phases.

Kept in its own module (depending only on facts) so both `pack.py` and `graph.py` can
import it without a cycle — `graph.py` imports `pack.py`, so the phase primitives can
live in neither of them alone.
"""
from __future__ import annotations

from .facts import FactSet

# Engagement phases, in order. A fact/action is placed in the latest phase any of its
# kinds map to, so the flow reads left (early recon) to right (loot/dominance).
PHASES = ["recon", "enum", "creds", "access", "escalate", "loot"]
PHASE_INDEX = {name: i for i, name in enumerate(PHASES)}
_DEFAULT_PHASE = "escalate"

# Prefix/exact rules mapping a fact kind to a phase. Ordered longest-first at use.
_PHASE_RULES: list[tuple[str, str]] = [
    ("target.", "recon"), ("host.", "recon"), ("ports.open", "recon"),
    ("port:", "recon"), ("scan.", "recon"),
    ("ldap.reachable", "recon"), ("smb.reachable", "recon"),
    ("kerberos.reachable", "recon"), ("winrm.reachable", "recon"),
    ("http.reachable", "recon"), ("service.", "recon"),
    ("ad.dc_candidate", "enum"), ("ad.domain_known", "enum"), ("ad.base_dn", "enum"),
    ("ad.anonymous_bind", "enum"), ("ad.user_list", "enum"),
    ("smb.null_session", "enum"), ("smb.guest_session", "enum"), ("smb.shares", "enum"),
    ("enum.deep", "enum"),
    ("web.content_map", "enum"), ("web.vhost", "enum"), ("web.source", "enum"),
    ("web.users", "enum"), ("web.parameterized", "enum"),
    ("hash.", "creds"), ("kerberos.tickets", "creds"), ("credential.", "creds"),
    ("ldap.authenticated", "access"), ("smb.authenticated", "access"),
    ("winrm.authenticated", "access"), ("web.authenticated", "access"),
    ("access.", "access"), ("foothold.", "access"),
    ("ad.graph.collected", "escalate"), ("ad.attack_paths", "escalate"),
    ("ad.control_paths", "escalate"), ("ad.trusts", "escalate"),
    ("ad.computer_added", "escalate"), ("adcs.", "escalate"),
    ("privesc.", "escalate"),
    ("relay.success", "escalate"), ("lateral.movement", "escalate"),
    ("vuln.", "escalate"), ("exploit.candidate", "escalate"),
    ("web.lfi_confirmed", "escalate"), ("web.sqli_confirmed", "escalate"),
    ("web.cmdi_confirmed", "escalate"), ("web.ssrf_confirmed", "escalate"),
    ("web.upload_confirmed", "escalate"),
    ("loot.", "loot"), ("persistence.", "loot"), ("db.creds", "loot"),
    ("cloud.", "loot"), ("config.", "loot"),
]
_SORTED_RULES = sorted(_PHASE_RULES, key=lambda r: -len(r[0]))


def phase_index(phase: str) -> int:
    """The ordinal of a phase name (unknown names sort as the default phase)."""
    return PHASE_INDEX.get(phase, PHASE_INDEX[_DEFAULT_PHASE])


def phase_of_kind(kind: str) -> str:
    """The engagement phase a fact kind belongs to (defaults to 'escalate')."""
    for prefix, phase in _SORTED_RULES:
        if kind == prefix or kind.startswith(prefix):
            return phase
    return _DEFAULT_PHASE


def phase_of_action(action) -> str:
    """An action's phase: an explicit ``phase`` the pack set on it, else the latest
    phase of anything it produces (fallback: the latest phase of its prerequisites),
    so a card sorts under the stage it advances.

    Duck-typed on ``phase``/``produces``/``requires_all``/``requires_any`` so it can be
    called on an ``Action`` without this module importing ``pack`` (which would cycle).
    An explicit phase lets methodology data correct a card the derivation misplaces
    (e.g. a collection step that reads as escalate) without any planner branching.
    """
    explicit = getattr(action, "phase", "") or ""
    if explicit in PHASE_INDEX:
        return explicit
    kinds = list(getattr(action, "produces", []) or [])
    if not kinds:
        kinds = list(getattr(action, "requires_all", []) or []) + \
            list(getattr(action, "requires_any", []) or [])
    if not kinds:
        return "recon"
    return max((phase_of_kind(k) for k in kinds), key=phase_index)


def target_phase(facts: FactSet) -> str:
    """The furthest engagement phase a target has reached (by proven fact kinds)."""
    kinds = [f.kind for f in facts.facts if f.state.value == "supported"]
    if not kinds:
        return "recon"
    return max((phase_of_kind(k) for k in kinds), key=phase_index)


def frontier_index(facts: FactSet) -> int:
    """The phase index the target is actively pushing into: the furthest phase it has
    reached, plus one (capped at the last phase).

    Actions whose phase is at or below the frontier are *on-flow* (rank by priority);
    those beyond it are *premature* (demoted below every on-flow action). Using
    reached+1 keeps the natural next stage on-flow — after bare recon, enumeration is
    not "premature" — while an action two-plus stages ahead (a loot dump surfacing
    during enumeration) drops behind the recon/enum you should do first.
    """
    reached = phase_index(target_phase(facts))
    return min(reached + 1, len(PHASES) - 1)


def prematurity(action, facts: FactSet) -> int:
    """How many phases past the target's frontier an action reaches (0 == on-flow)."""
    return max(0, phase_index(phase_of_action(action)) - frontier_index(facts))

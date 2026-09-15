"""External-action ingestion — the resumable-handoff pillar (ROADMAP cruise pillar III).

When cruise (or the operator) hits something obol can't drive — a manual exploit, a
curveball, a tool obol doesn't know — the operator does the thing *outside* obol and
re-enters from facts here. Two ways in, matching the ROADMAP:

* **paste-and-parse** (`ingest_output`, the primary path): the operator pastes the output
  of a command they ran themselves; obol runs it through the **same parser pipeline** as
  its own runs (`parse_action_output` + the local-enum and flag parsers), so it earns
  exactly the same proof-bound facts — just from evidence obol didn't generate. Every fact
  is stamped with **operator lineage** (`source` begins ``operator:``) so the report and
  UI can show which facts came from obol's runner vs. the operator's own hands, and the
  run lands in the ledger flagged ``external`` so the OSCP write-up stays complete across
  manual detours.

* **operator-attested assertion** (`assert_fact`, the marked escape hatch): when there is
  no parseable output, the operator asserts a fact directly. It stays the narrowest claim
  and is stamped ``operator-attested:`` — same `ProofState`, honest lineage — so it is
  never mistaken for something obol proved. The last resort, not the encouraged path.

Because facts are the one interface and the planner runs off facts, either way "the
operator did something outside obol" becomes "new facts arrived": the frontier re-ranks
and `obol cruise` continues. This module invents no parser and no fact kind — it reuses
the exact pipeline, and records honest lineage.
"""
from __future__ import annotations

from .facts import Fact, ProofState
from .parsers import parse_action_output
from .flags import parse_flag_output
from .localenum import parse_local_enum_output
from .pack import Action
from .scope import normalize_target

OPERATOR_SOURCE = "operator"          # lineage prefix for parsed external output
OPERATOR_ATTESTED = "operator-attested"   # lineage prefix for a bare assertion


def fact_origin(fact) -> str:
    """Classify a fact's lineage from its ``source`` prefix, so surfaces can visibly
    distinguish operator-supplied evidence from obol's own runs:
    ``operator-attested`` (a bare assertion), ``operator-executed`` (parsed from output
    the operator ran), or ``obol`` (obol's own runner). This keeps the honesty story
    end-to-end — a fact the operator vouched for is never shown as one obol proved."""
    src = (getattr(fact, "source", "") or "")
    if src.startswith(OPERATOR_ATTESTED + ":"):
        return "operator-attested"
    if src.startswith(OPERATOR_SOURCE + ":"):
        return "operator-executed"
    return "obol"


def _resolve_action(action_id: str) -> Action:
    """The action whose parsers should run over the pasted output. A named id scopes the
    action-specific parsers (e.g. `linux-enum` local-enum, `flag-hunt-*` flags); with none
    given, a generic action still runs the shape-driven `parse_action_output` corpus."""
    if action_id:
        from .service import find_action, ActionError
        try:
            return find_action(action_id)
        except ActionError:
            pass
    return Action(id=action_id or "operator-ingest", title="operator-supplied output")


def ingest_output(ws, text: str, *, action_id: str = "", target: str = "",
                  note: str = "", surface: str = "cli") -> dict:
    """Parse operator-supplied tool output through obol's own parser pipeline and record
    the resulting facts with operator lineage. Returns {ok, added:[kinds], target, action}.

    `action_id` optionally scopes the action-specific parsers; `note` becomes the run's
    command/lineage label. Nothing is executed — this only parses text the operator
    already ran, so it is proof-bound exactly like a real run (a fact is earned only when
    the output shape supports it), never a way to fabricate a claim.
    """
    host = normalize_target(target or getattr(ws, "target", "") or "")
    if host:
        ws.set_active_target(host) or ws.add_target(host)
    action = _resolve_action(action_id)
    label = note.strip() or "pasted output"
    source = f"{OPERATOR_SOURCE}: {label}"

    facts: list[Fact] = []
    facts.extend(parse_action_output(action, ws, label, text or "", "", source=source))
    facts.extend(parse_local_enum_output(action, ws, label, text or "", "", source=source))
    facts.extend(parse_flag_output(action, ws, label, text or "", "", source=source))

    added: list[str] = []
    for fact in facts:
        if ws.facts.add(fact):
            added.append(fact.kind)
    ws.record_run("operator", label, added, surface=surface, external=True,
                  origin="operator", action_id=action.id, target=host)
    ws.save()
    return {"ok": True, "added": added, "target": host, "action": action.id,
            "parsed": len(facts)}


def assert_fact(ws, kind: str, *, value: dict | None = None, scope: str = "",
                target: str = "", note: str = "", state: str = "supported",
                surface: str = "cli") -> dict:
    """Record a single operator-attested fact directly (the escape hatch when there is no
    parseable output). Stamped with operator-attested lineage so it is visibly distinct
    from an obol-proven fact. Returns {ok, added:bool, kind, scope}."""
    if not kind:
        raise ValueError("a fact kind is required (e.g. access.shell, foothold.linux)")
    host = normalize_target(target or getattr(ws, "target", "") or "")
    if host:
        ws.set_active_target(host) or ws.add_target(host)
    scope = scope or (f"host:{host}" if host else "")
    try:
        pstate = ProofState(state)
    except ValueError:
        pstate = ProofState.SUPPORTED
    label = note.strip() or "operator assertion"
    fact = Fact(kind=kind, scope=scope, value=dict(value or {}), state=pstate,
                source=f"{OPERATOR_ATTESTED}: {label}")
    added = ws.facts.add(fact)
    ws.record_run("operator", f"assert {kind}", [kind] if added else [], surface=surface,
                  external=True, origin="operator", attested=True, target=host)
    ws.save()
    return {"ok": True, "added": added, "kind": kind, "scope": scope, "state": pstate.value}

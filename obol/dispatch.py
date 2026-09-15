"""Move dispatch — the per-move execution handle (cruise-control pillars I→II).

`moves.frontier_moves` unified *enumeration*: one ranked list of candidate moves
across pack actions and the built primitives. This unifies *execution*: `run_move`
takes a move id from that frontier and runs it through the right already-built,
scope-enforced, proof-bound primitive — `service.run_action` for a pack action,
`sessions.open_session` for a login, `enumrun.run_enum` for enum run-and-rank,
`tunnels.open_tunnel` for a pivot, `exploits.plan_exploit` to craft a privesc
exploit. It is the uniform "run this move" call `obol cruise` (pillar II) will make,
so the loop never has to branch per kind.

It is **not** a new runner and invents nothing: every kind dispatches to its existing
function (one runner, one parser, one store), and a move can only be run if it is
currently *offered on the frontier* (fact-gated) — you cannot `do login:winrm` with no
credential. Each result carries a **posture** that is the seed of cruise's stop-contract:

* ``ran``      — obol executed a real command and ingested any facts (a pack action, enum).
* ``dry-run``  — a preview only; nothing executed.
* ``handoff``  — obol ran the proof/record step and hands the operator an interactive
                 command to launch (a login's shell, a tunnel's setup) — a cruise checkpoint.
* ``craft``    — nothing executed; obol crafted a command to review (a privesc exploit is
                 never auto-fired here — the OSCP/manual posture) — a cruise checkpoint.

Exploit *execution* stays on the dedicated `obol exploit --run` path with its full
outcome/credential/listener surface; the dispatcher only crafts, by design.
"""
from __future__ import annotations

from . import moves as moves_layer

# Move-id prefixes that name a primitive; anything else is a pack action id.
_PRIMITIVE_KINDS = {"login", "enum", "exploit", "tunnel"}


class DispatchError(Exception):
    """A move that cannot be run as asked (unknown/not-offered/not-ready/failed)."""


def parse_move_id(move_id: str) -> tuple[str, str]:
    """Split a frontier move id into (kind, key). ``kind:key`` for a primitive move,
    else ``("action", <pack action id>)`` — pack ids are slugs, so a stray colon in
    one never masquerades as a primitive."""
    if ":" in move_id:
        kind, key = move_id.split(":", 1)
        if kind in _PRIMITIVE_KINDS:
            return kind, key
    return "action", move_id


def _result(move, *, ok: bool, posture: str, summary: str,
            command: str = "", added: list | None = None, detail: dict | None = None) -> dict:
    return {
        "ok": ok, "id": move.id, "kind": move.kind, "label": move.label,
        "phase": move.phase, "posture": posture, "summary": summary,
        "command": command, "added": added or [], "detail": detail or {},
    }


def run_move(ws, move_id: str, *, host: str = "", approve: bool = False,
             dry_run: bool = False, params: dict | None = None, surface: str = "cli") -> dict:
    """Run one frontier move by id, through its existing shared primitive.

    The move must be currently offered on the host's frontier (fact-gated) and, for a
    primitive that needs an input, ``ready`` — otherwise a `DispatchError` explains what
    is missing, rather than a raw primitive error. Returns a normalized result dict
    (see the module docstring for ``posture``). Raises `DispatchError` for a bad request
    or a failed run; the caller decides how to surface it.
    """
    params = params or {}
    host = host or getattr(ws, "target", "") or ""
    if not host:
        raise DispatchError("no target — pass a host or set an active target first")

    # The move must be on the frontier right now: this is the fact-gate for execution,
    # so `run_move` can never fire something the planner would not offer.
    frontier = {m.id: m for m in moves_layer.frontier_moves(ws, host)}
    move = frontier.get(move_id)
    if move is None:
        raise DispatchError(f"{move_id!r} is not an available move on {host} "
                            "(run `obol moves` to see what is)")
    if not move.ready and move.kind != "action":
        raise DispatchError(f"{move_id!r} is not ready: {move.reason or 'a required input is missing'}")

    kind, key = parse_move_id(move_id)
    try:
        if kind == "action":
            return _run_action_move(ws, move, key, host, dry_run=dry_run, surface=surface)
        if kind == "login":
            return _run_login_move(ws, move, key, host, params, dry_run=dry_run, surface=surface)
        if kind == "enum":
            return _run_enum_move(ws, move, key, host, surface=surface)
        if kind == "tunnel":
            return _run_tunnel_move(ws, move, key, host, params, surface=surface)
        if kind == "exploit":
            return _craft_exploit_move(ws, move, key, host, params)
    except DispatchError:
        raise
    except Exception as exc:  # a primitive's own refusal (scope, missing input, bad request)
        raise DispatchError(f"{move_id}: {exc}") from exc
    raise DispatchError(f"unknown move kind {kind!r}")


# ── per-kind dispatch (each calls one existing, tested primitive) ──────────────
def _run_action_move(ws, move, action_id, host, *, dry_run, surface):
    from .service import find_action, run_action
    action = find_action(action_id)
    outcome = run_action(ws, action, target=host, dry_run=dry_run,
                         ledger_extra={"surface": surface, "move": move.id, "target": host})
    added = [f.kind for f in outcome.added]
    if dry_run:
        return _result(move, ok=True, posture="dry-run",
                       summary=f"preview: {outcome.command}", command=outcome.command)
    summary = (f"ran {action.tool or action_id}; +{len(added)} fact(s)"
               if added else f"ran {action.tool or action_id}; no new facts")
    return _result(move, ok=True, posture="ran", summary=summary,
                   command=outcome.command, added=added)


def _run_login_move(ws, move, kind_key, host, params, *, dry_run, surface):
    from . import sessions
    res = sessions.open_session(ws, host, kind_key, method=params.get("method", ""),
                                dry_run=dry_run, surface=surface)
    if dry_run:
        return _result(move, ok=True, posture="dry-run",
                       summary=f"preview: {kind_key} login proof", detail=res)
    if not res.get("ok"):
        return _result(move, ok=False, posture="ran",
                       summary=f"{kind_key} proof did not confirm access", detail=res)
    sess = res.get("session") or {}
    added = [sess["proof_fact"]] if sess.get("proof_fact") else []
    return _result(move, ok=True, posture="handoff",
                   summary=f"logged in over {kind_key} — launch the handed-off command",
                   command=res.get("login_command", ""), added=added, detail=res)


def _run_enum_move(ws, move, tool_key, host, *, surface):
    from . import enumrun
    res = enumrun.run_enum(ws, host, tool_key, surface=surface)
    if res.get("guided"):
        return _result(move, ok=True, posture="handoff",
                       summary=f"staged {tool_key} — run the returned command", detail=res)
    leads = res.get("privesc_leads") or []
    hi = res.get("highlights") or []
    return _result(move, ok=bool(res.get("ok", True)), posture="ran",
                   summary=f"ran {tool_key}: {len(leads)} privesc lead(s), {len(hi)} highlight(s)",
                   added=list(leads), detail=res)


def _run_tunnel_move(ws, move, kind_key, host, params, *, surface):
    from . import tunnels
    res = tunnels.open_tunnel(ws, host, kind_key, subnet=params.get("subnet", ""),
                              surface=surface)
    return _result(move, ok=True, posture="handoff",
                   summary=f"opened {kind_key} tunnel — launch the setup command",
                   command=res.get("setup_command", ""), detail=res)


def _craft_exploit_move(ws, move, key, host, params):
    """Craft (never fire) a privesc exploit for review — the manual/approval posture.
    Execution stays on `obol exploit --run` with its full outcome/credential surface."""
    from . import exploits
    exploit = exploits.get_exploit(key)
    outcome = params.get("outcome") or (list(exploit.outcomes)[0] if exploit and exploit.outcomes else "")
    plan = exploits.plan_exploit(ws, host, key, outcome)
    return _result(move, ok=True, posture="craft",
                   summary=f"crafted {key} ({outcome}) — review, then run with `obol exploit`",
                   command=plan.get("command", ""), detail=plan)

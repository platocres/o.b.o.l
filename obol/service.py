"""Shared run service — the single run -> parse -> record -> save path.

Both surfaces call this: the terminal (`obol run`, `obol playbook --step`) and the
web (run-from-site). There is deliberately one runner, one parser, and one store,
so a command launched from the browser is executed and ingested exactly the way
the terminal executes it, and both surfaces stay synced through the one `.obol`
state file. This module does no printing — the CLI wraps it for scrollback, the
web serializes the returned outcome to JSON.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import board
from .facts import Fact, FactSet
from .flags import parse_flag_output
from .localenum import parse_local_enum_output
from .pack import Action, load_packs, next_actions
from .parsers import parse_action_output
from .runner import RunResult, RunnerError, run_command
from .workspace import Workspace


class ActionError(Exception):
    """A request that cannot be honored (unknown action, bad command variant).

    Distinct from RunnerError (a safe-execution refusal such as an out-of-scope
    target); callers map the two to different responses.
    """


@dataclass
class RunOutcome:
    action_id: str
    command: str
    tool: str
    result: RunResult
    added: list[Fact] = field(default_factory=list)

    @property
    def dry_run(self) -> bool:
        return self.result.dry_run


def find_action(action_id: str, pack: list[Action] | None = None) -> Action:
    """Resolve an action by its stable id (the web addresses actions by id, never
    by the volatile `obol next` position)."""
    pack = pack if pack is not None else load_packs()
    for action in pack:
        if action.id == action_id:
            return action
    raise ActionError(f"unknown action id: {action_id}")


def build_command(action: Action, ws: Workspace, *, command_index: int = 0,
                  args_extra: str = "", target: str = "",
                  context: dict | None = None) -> tuple[str, str]:
    """Render the exact argv-string the runner will build (no execution), plus the
    tool label. `target` renders the preview for a specific host. `context` pins
    specific {{token}} values (e.g. the exact credential a session login chose).
    Raises ActionError on a bad command variant."""
    commands = action.commands or [{"tool": action.tool, "run": action.command}]
    if not 0 <= command_index < len(commands):
        raise ActionError(
            f"action {action.id!r} has {len(commands)} command variant(s); "
            f"cannot use #{command_index + 1}."
        )
    command_meta = commands[command_index]
    cmd = board.fill_command(action, ws, command_index, target, context)
    extra = board.fill_template(args_extra, ws, target, context).strip() if args_extra else ""
    if extra:
        cmd = f"{cmd} {extra}"
    # tool label is derived before any route prefix, so it stays the real tool.
    tool = command_meta.get("tool") or action.tool or (cmd.split()[0] if cmd.split() else "")
    # route-aware runner (§6d): a host reachable only through a SOCKS tunnel gets
    # proxychains auto-prefixed; a transparent route or a directly-scoped host does
    # not. Keyed on the effective target so previews and execution agree.
    from .tunnels import route_prefix
    prefix = route_prefix(ws, target or ws.target)
    if prefix and not cmd.startswith(prefix):
        cmd = prefix + cmd
    return cmd, tool


def eligible_actions(facts: FactSet, pack: list[Action] | None = None) -> list[Action]:
    """Every pack action whose prerequisites the given facts satisfy — the
    service-aware 'tool palette' for a target (includes actions already settled, so
    a tool stays re-runnable), ranked by priority."""
    pack = pack if pack is not None else load_packs()
    live = [a for a in pack if a.eligible(facts)]
    return sorted(live, key=lambda a: a.priority, reverse=True)


def _parsed_facts(action: Action, ws: Workspace, cmd: str, result: RunResult) -> list[Fact]:
    """Run every parser family that knows about this action/output shape.

    `parsers.py` holds the broad external-tool parser corpus. `localenum.py` and
    `flags.py` are kept separate because post-foothold host/network output and
    flag-file captures are foothold-specific and should only become facts for the
    small set of action ids that request them.
    """
    facts: list[Fact] = []
    facts.extend(parse_action_output(action, ws, cmd, result.stdout, result.stderr, source=cmd))
    facts.extend(parse_local_enum_output(action, ws, cmd, result.stdout, result.stderr, source=cmd))
    facts.extend(parse_flag_output(action, ws, cmd, result.stdout, result.stderr, source=cmd))
    return facts


def run_action(ws: Workspace, action: Action, *, command_index: int = 0,
               timeout: int = 300, dry_run: bool = False, allow_shell: bool = False,
               args_extra: str = "", target: str = "", context: dict | None = None,
               ledger_extra: dict | None = None) -> RunOutcome:
    """Execute one action's command through the shared runner, parse its output into
    the narrowest supported facts, append them and a ledger row to the workspace,
    and persist. Returns the outcome; raises ActionError for a bad request and
    RunnerError for a safe-execution refusal (e.g. out of scope). The caller
    decides how to surface either.

    `target` pins the run to a specific host: it becomes the active target so the
    command context, the scope gate, and fact scoping all key off that host. This is
    how the web runs a tool from a particular target's tab.
    """
    if target:
        ws.set_active_target(target) or ws.add_target(target)
    cmd, tool = build_command(action, ws, command_index=command_index, args_extra=args_extra,
                              context=context)
    # run_command raises RunnerError on an unfilled token, shell metacharacters,
    # a missing binary, or an out-of-scope target — the hard scope gate applies
    # to web-launched runs exactly as it does to terminal runs.
    result = run_command(
        ws, command=cmd, tool=tool, timeout=timeout,
        dry_run=dry_run, allow_shell_tokens=allow_shell,
    )

    added: list[Fact] = []
    if not result.dry_run:
        for fact in _parsed_facts(action, ws, cmd, result):
            if ws.facts.add(fact):
                added.append(fact)
        ws.apply_fact_enrichment(added)
        # re-fingerprint the target from its refreshed facts: new service/version/OS
        # evidence may match a known exploit → record proof-bound exploit.candidate leads
        # (§15b). A version match is a candidate, never a confirmed vuln.
        if added and ws.target:
            try:
                from . import vulnmatch
                for k in vulnmatch.record_candidates(ws, ws.target):
                    added.append(next((f for f in ws.facts.facts
                                       if f.kind == "exploit.candidate"
                                       and f.value.get("key") == k), None))
                added = [f for f in added if f is not None]
            except Exception:  # noqa: BLE001 — matching must never break a run
                pass

    ledger = {"target": ws.target}
    ledger.update(ledger_extra or {})
    ws.record_run(
        tool, cmd, [f.kind for f in added],
        action_id=action.id,
        command_index=command_index + 1,
        returncode=result.returncode,
        timed_out=result.timed_out,
        dry_run=result.dry_run,
        stdout=str(result.stdout_path),
        stderr=str(result.stderr_path),
        duration_ms=result.duration_ms,
        **ledger,
    )
    ws.save()
    return RunOutcome(action_id=action.id, command=cmd, tool=tool, result=result, added=added)


__all__ = [
    "ActionError",
    "RunnerError",
    "RunOutcome",
    "find_action",
    "build_command",
    "run_action",
    "eligible_actions",
    "next_actions",
]

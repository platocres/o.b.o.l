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
from .facts import Fact
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
                  args_extra: str = "") -> tuple[str, str]:
    """Render the exact argv-string the runner will build (no execution), plus the
    tool label. Raises ActionError on a bad command variant."""
    commands = action.commands or [{"tool": action.tool, "run": action.command}]
    if not 0 <= command_index < len(commands):
        raise ActionError(
            f"action {action.id!r} has {len(commands)} command variant(s); "
            f"cannot use #{command_index + 1}."
        )
    command_meta = commands[command_index]
    cmd = board.fill_command(action, ws, command_index)
    extra = board.fill_template(args_extra, ws).strip() if args_extra else ""
    if extra:
        cmd = f"{cmd} {extra}"
    tool = command_meta.get("tool") or action.tool or (cmd.split()[0] if cmd.split() else "")
    return cmd, tool


def run_action(ws: Workspace, action: Action, *, command_index: int = 0,
               timeout: int = 300, dry_run: bool = False, allow_shell: bool = False,
               args_extra: str = "", ledger_extra: dict | None = None) -> RunOutcome:
    """Execute one action's command through the shared runner, parse its output into
    the narrowest supported facts, append them and a ledger row to the workspace,
    and persist. Returns the outcome; raises ActionError for a bad request and
    RunnerError for a safe-execution refusal (e.g. out of scope). The caller
    decides how to surface either.
    """
    cmd, tool = build_command(action, ws, command_index=command_index, args_extra=args_extra)
    # run_command raises RunnerError on an unfilled token, shell metacharacters,
    # a missing binary, or an out-of-scope target — the hard scope gate applies
    # to web-launched runs exactly as it does to terminal runs.
    result = run_command(
        ws, command=cmd, tool=tool, timeout=timeout,
        dry_run=dry_run, allow_shell_tokens=allow_shell,
    )

    added: list[Fact] = []
    if not result.dry_run:
        for fact in parse_action_output(action, ws, cmd, result.stdout, result.stderr, source=cmd):
            if ws.facts.add(fact):
                added.append(fact)

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
        **(ledger_extra or {}),
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
    "next_actions",
]

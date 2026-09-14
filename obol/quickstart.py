"""Shared Quick Start baseline for terminal and web surfaces.

Quick Start is the safe nmap-first baseline: discover ports, run the targeted
service scan, then let service facts unlock lightweight enumeration such as nxc,
LDAP, SMB share checks, and web content/vhost probes. This module keeps the
action ordering and variant preference in one place so the terminal and web do
not drift into two different operators.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .facts import Fact
from .graph import phase_of_kind
from .pack import Action
from .runner import RunnerError
from .service import ActionError, build_command, find_action, run_action
from .workspace import Workspace

QUICKSTART_ACTION_IDS = [
    "nmap-fast-open-ports",
    "nmap-version-scripts",
    "ad-dc-identify",
    "ad-anon-ldap-enum",
    "ad-user-enum",
    "gpp-passwords",
    "content-discovery",
    "vhost-discovery",
    "nikto-scan",
]

QUICKSTART_VARIANT_PREFERENCE = {
    # Prefer the lighter ffuf common-wordlist pass over recursive feroxbuster when
    # both are available; Quick Start should populate leads without surprise crawls.
    "content-discovery": [1, 0, 2],
}

_UNFILLED_TOKEN_RE = re.compile(r"{{[^}]+}}|<[^>]+>")


@dataclass
class QuickStartStep:
    action_id: str
    title: str = ""
    status: str = "waiting"
    command: str = ""
    reason: str = ""
    command_index: int = 0
    added: list[Fact] = field(default_factory=list)


@dataclass
class QuickStartResult:
    target: str
    ran: list[QuickStartStep] = field(default_factory=list)
    skipped: list[QuickStartStep] = field(default_factory=list)

    @property
    def facts(self) -> list[Fact]:
        return [fact for step in self.ran for fact in step.added]


def action_phase(action: Action) -> str:
    return phase_of_kind(action.produces[0]) if action.produces else "recon"


def action_done(ws: Workspace, target: str, action: Action) -> bool:
    if any(r.get("action_id") == action.id and r.get("target") == target and not r.get("dry_run")
           for r in ws.runs):
        return True
    tf = ws.facts_for_target(target)
    return bool(action.produces) and all(tf.has(kind) for kind in action.produces)


def variant_indices(action: Action) -> list[int]:
    total = len(action.commands or [{"run": action.command}])
    preferred = [i for i in QUICKSTART_VARIANT_PREFERENCE.get(action.id, []) if 0 <= i < total]
    return preferred + [i for i in range(total) if i not in preferred]


def first_renderable_variant(action: Action, ws: Workspace, target: str) -> tuple[int | None, str]:
    """Return the first variant with all evidence/input tokens filled."""
    fallback = ""
    for index in variant_indices(action):
        try:
            command, _tool = build_command(action, ws, command_index=index, target=target)
        except ActionError:
            continue
        fallback = fallback or command
        if not _UNFILLED_TOKEN_RE.search(command):
            return index, command
    return None, fallback


def quickstart_plan(ws: Workspace, target: str) -> list[QuickStartStep]:
    steps: list[QuickStartStep] = []
    tf = ws.facts_for_target(target)
    for action_id in QUICKSTART_ACTION_IDS:
        try:
            action = find_action(action_id)
        except ActionError:
            continue
        if action_done(ws, target, action):
            steps.append(QuickStartStep(action.id, action.title, "done",
                                        reason="already has facts or a prior run"))
            continue
        if not action.eligible(tf):
            steps.append(QuickStartStep(action.id, action.title, "waiting", reason=action.unmet(tf)))
            continue
        index, command = first_renderable_variant(action, ws, target)
        status = "ready" if index is not None else "blocked"
        reason = "" if index is not None else "missing evidence or inputs for every command variant"
        steps.append(QuickStartStep(action.id, action.title, status, command, reason, index or 0))
    return steps


def run_quickstart(
    ws: Workspace,
    target: str,
    *,
    timeout: int = 300,
    dry_run: bool = False,
    allow_shell: bool = False,
    on_step=None,
) -> QuickStartResult:
    """Run the safe baseline against one target.

    The workspace is mutated through :func:`service.run_action`, so every command
    uses the same runner, parser, ledger, and store path as `obol run` and the web
    run button. Variants are tried in Quick Start preference order; a runner
    refusal before execution falls through to the next variant.
    """
    result = QuickStartResult(target=target)
    for action_id in QUICKSTART_ACTION_IDS:
        try:
            action = find_action(action_id)
        except ActionError as exc:
            step = QuickStartStep(action_id, status="missing", reason=str(exc))
            result.skipped.append(step)
            if on_step:
                on_step(step)
            continue

        tf = ws.facts_for_target(target)
        if action_done(ws, target, action):
            step = QuickStartStep(action.id, action.title, "done",
                                  reason="already has facts or a prior run")
            result.skipped.append(step)
            if on_step:
                on_step(step)
            continue
        if not action.eligible(tf):
            step = QuickStartStep(action.id, action.title, "waiting", reason=action.unmet(tf))
            result.skipped.append(step)
            if on_step:
                on_step(step)
            continue

        last_error = ""
        for index in variant_indices(action):
            try:
                command, _tool = build_command(action, ws, command_index=index, target=target)
            except ActionError as exc:
                last_error = str(exc)
                continue
            if dry_run:
                if _UNFILLED_TOKEN_RE.search(command):
                    last_error = f"unfilled command token in: {command}"
                    continue
                step = QuickStartStep(action.id, action.title, "dry-run", command, command_index=index + 1)
                result.ran.append(step)
                if on_step:
                    on_step(step)
                break
            try:
                if on_step:
                    on_step(QuickStartStep(action.id, action.title, "running", command, command_index=index + 1))
                outcome = run_action(
                    ws,
                    action,
                    command_index=index,
                    target=target,
                    timeout=timeout,
                    allow_shell=allow_shell,
                    ledger_extra={"surface": "terminal", "quickstart": True, "target": target},
                )
            except RunnerError as exc:
                last_error = str(exc)
                continue
            status = "timeout" if outcome.result.timed_out else (
                "success" if outcome.result.returncode == 0 else "failed"
            )
            step = QuickStartStep(
                action.id,
                action.title,
                status,
                outcome.command,
                command_index=index + 1,
                added=outcome.added,
            )
            result.ran.append(step)
            if on_step:
                on_step(step)
            break
        else:
            step = QuickStartStep(action.id, action.title, "blocked", reason=last_error or "no runnable command variant")
            result.skipped.append(step)
            if on_step:
                on_step(step)
    return result


__all__ = [
    "QUICKSTART_ACTION_IDS",
    "QUICKSTART_VARIANT_PREFERENCE",
    "QuickStartResult",
    "QuickStartStep",
    "action_done",
    "action_phase",
    "first_renderable_variant",
    "quickstart_plan",
    "run_quickstart",
    "variant_indices",
]

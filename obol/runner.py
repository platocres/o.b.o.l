"""Safe external command runner for the terminal loop.

Commands are executed as fixed argv by default, never through a shell. Raw stdout
and stderr are saved before parsers run so the evidence ledger remains useful
even when obol cannot yet interpret a tool's output.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import time

from .scope import target_in_scope
from .workspace import Workspace

_UNFILLED_TOKEN_RE = re.compile(r"{{[^}]+}}|<[^>]+>")
_SHELL_META_RE = re.compile(r"[|;&<>`]")


class RunnerError(Exception):
    """Raised when a command cannot be safely executed."""


@dataclass
class RunResult:
    command: str
    argv: list[str]
    returncode: int | None
    stdout: str
    stderr: str
    stdout_path: Path
    stderr_path: Path
    started_at: float
    duration_ms: int
    timed_out: bool = False
    dry_run: bool = False


def _safe_name(value: str) -> str:
    keep = "-_.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(c if c in keep else "_" for c in value) or "run"


def _build_argv(command: str, *, allow_shell_tokens: bool = False) -> list[str]:
    if _UNFILLED_TOKEN_RE.search(command):
        raise RunnerError(f"unfilled command token in: {command}")
    if not allow_shell_tokens and _SHELL_META_RE.search(command):
        raise RunnerError("shell metacharacters require an explicit guided-handoff path")
    try:
        argv = shlex.split(command)
    except ValueError as exc:
        raise RunnerError(f"could not parse command: {exc}") from exc
    if not argv:
        raise RunnerError("empty command")
    return argv


def _scope_check(argv: list[str], ws: Workspace, scope_target: str = "") -> None:
    if scope_target:
        # A range/discovery sweep: the "target" is a whole network, so the gate is
        # stricter than host membership — the swept range must be an authorized
        # scope ENTRY the operator explicitly added (exact match), and must appear
        # in the command. This lets a sweep touch a CIDR without first having any
        # host in it, while never sweeping a range that isn't in scope.
        if scope_target not in ws.scope:
            raise RunnerError(
                f"scope refused {scope_target}: not an authorized scope entry")
        if scope_target not in " ".join(argv):
            raise RunnerError(f"command does not include scoped range {scope_target}")
        return
    if not ws.target:
        raise RunnerError("workspace has no target; run `obol init --target <ip-or-host>`")
    allowed, reason = target_in_scope(ws.target, ws.scope)
    if not allowed:
        raise RunnerError(f"scope refused {ws.target}: {reason}")
    if ws.target not in argv:
        # First slice: actions target the workspace target. Later pack metadata can
        # declare additional target fields such as target_sam or callback hosts.
        normalized_args = " ".join(argv)
        if ws.target not in normalized_args:
            raise RunnerError(f"command does not include scoped target {ws.target}")


def run_command(
    ws: Workspace,
    *,
    command: str,
    tool: str,
    timeout: int = 300,
    dry_run: bool = False,
    allow_shell_tokens: bool = False,
    scope_target: str = "",
) -> RunResult:
    """Execute command safely and save raw evidence under .obol/runs/.

    `scope_target` switches the scope gate from per-host to per-range: the value
    must be an authorized scope entry (a CIDR or host the operator added) and
    appear in the command. Used by the engagement discovery sweep, which runs
    against a network before any host in it is a target.
    """
    argv = _build_argv(command, allow_shell_tokens=allow_shell_tokens)
    _scope_check(argv, ws, scope_target=scope_target)
    binary_index = 1 if argv[0] == "sudo" and len(argv) > 1 else 0
    if shutil.which(argv[binary_index]) is None and not dry_run:
        # Not on PATH — but the tool inventory may know where it is (a default Kali
        # location, or a path the operator added on the Tools page). Resolve to an
        # absolute path so a tool the UI reports as "found" is guaranteed to launch.
        # For sudo-prefixed commands, resolve the actual tool after sudo.
        from .tools import resolve_binary
        resolved = resolve_binary(argv[binary_index])
        if resolved:
            argv[binary_index] = resolved
        else:
            raise RunnerError(f"binary `{argv[binary_index]}` was not found in PATH")

    started = time.time()
    ts = time.strftime("%Y%m%d-%H%M%S", time.localtime(started))
    runs_dir = ws.runs_dir
    runs_dir.mkdir(parents=True, exist_ok=True)
    base = f"{ts}_{_safe_name(tool or argv[0])}"
    stdout_path = runs_dir / f"{base}.stdout.txt"
    stderr_path = runs_dir / f"{base}.stderr.txt"

    if dry_run:
        return RunResult(command, argv, None, "", "", stdout_path, stderr_path, started, 0, dry_run=True)

    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        returncode: int | None = proc.returncode
        timed_out = False
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = (exc.stderr or "") + f"\n[timeout after {timeout}s]"
        returncode = None
        timed_out = True

    stdout_path.write_text(stdout)
    stderr_path.write_text(stderr)
    duration_ms = int((time.time() - started) * 1000)
    return RunResult(
        command=command,
        argv=argv,
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        started_at=started,
        duration_ms=duration_ms,
        timed_out=timed_out,
    )

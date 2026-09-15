"""Followed sessions (ROADMAP §15c) — obol follows you through a MANUAL login it does
not perform. You launch your own interactive tool (evil-winrm/ssh/…) *through* a thin
obol wrapper; obol logs the PTY transcript and live-parses it into facts as you type, so
you never copy-paste. It also tails a handler's own session logs (penelope), and — because
it has the transcript — it detects proof-shaped output and grabs a real desktop screenshot
at that moment.

obol does **not** log in for you here (that's a `login` move); it only *watches* the
channel you drive. Facts earned this way go through the same proof-bound parser pipeline,
stamped ``operator-session:`` lineage (you ran the commands; obol captured them). This is
the honest, higher-fidelity answer to "follow me through the box" — the reach is the
operator's own session, so it never crosses a proof boundary.

The transcript parse (`parse_transcript`) is the testable core; the PTY spawn and the
screenshot are best-effort integration that degrade gracefully when unavailable.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from pathlib import Path

from .facts import Fact
from .flags import parse_flag_output
from .localenum import parse_local_enum_output
from .pack import Action
from .parsers import parse_action_output
from .scope import normalize_target

_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_SCREENSHOT_TOOLS = ("scrot", "import", "gnome-screenshot", "spectacle", "flameshot")


def _clean(text: str) -> str:
    """Strip ANSI/control noise from a PTY transcript so the parsers see plain output."""
    return _ANSI.sub("", (text or "").replace("\r\n", "\n").replace("\r", "\n"))


def parse_transcript(ws, text: str, *, target: str = "", action_id: str = "",
                     note: str = "") -> list[str]:
    """Parse a captured interactive-session transcript into facts through obol's own
    parser pipeline, stamped ``operator-session:`` lineage. Returns the fact kinds added.

    Proof-bound exactly like a real run: a fact is earned only when the output shape
    supports it. `action_id` optionally scopes the action-specific parsers.
    """
    host = normalize_target(target or getattr(ws, "target", "") or "")
    if host:
        ws.set_active_target(host) or ws.add_target(host)
    action = Action(id=action_id or "operator-session", title="followed session")
    if action_id:
        from .service import ActionError, find_action
        try:
            action = find_action(action_id)
        except ActionError:
            pass
    clean = _clean(text)
    source = f"operator-session: {note or 'followed session'}"
    facts: list[Fact] = []
    facts.extend(parse_action_output(action, ws, note or "session", clean, "", source=source))
    facts.extend(parse_local_enum_output(action, ws, note or "session", clean, "", source=source))
    facts.extend(parse_flag_output(action, ws, note or "session", clean, "", source=source))
    added: list[str] = []
    for f in facts:
        if ws.facts.add(f):
            added.append(f.kind)
    ws.record_run("operator", note or "followed session", added, surface="follow",
                  external=True, origin="operator-session", target=host)
    ws.save()
    return added


def capture_screenshot(dest_dir: Path, *, name: str = "") -> str:
    """Best-effort REAL desktop screenshot (never a forgery) using whatever is present.
    Returns the saved path, or '' if no screenshot tool / no display. Meant to fire at a
    proof moment so the operator's actual screen (flag + host identity) is captured."""
    if not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
        return ""
    dest_dir.mkdir(parents=True, exist_ok=True)
    out = dest_dir / (name or f"proof-{int(time.time())}.png")
    for tool in _SCREENSHOT_TOOLS:
        if not shutil.which(tool):
            continue
        try:
            if tool == "import":
                subprocess.run([tool, "-window", "root", str(out)], timeout=15, check=True)
            elif tool == "gnome-screenshot":
                subprocess.run([tool, "-f", str(out)], timeout=15, check=True)
            elif tool == "flameshot":
                subprocess.run([tool, "full", "-p", str(out)], timeout=15, check=True)
            else:  # scrot / spectacle
                subprocess.run([tool, str(out)], timeout=15, check=True)
            if out.exists():
                return str(out)
        except Exception:  # noqa: BLE001 — degrade to no screenshot
            continue
    return ""


def run_followed(ws, argv: list[str], *, target: str = "", note: str = "",
                 shot_on_proof: bool = True) -> dict:
    """Run the operator's interactive command inside a logged PTY, then parse the
    transcript into `operator-session:` facts. If a flag/objective was captured and a
    screenshot tool is present, grab a real desktop screenshot and attach it.

    Best-effort: falls back to a plain subprocess if a PTY can't be allocated (e.g. no
    controlling terminal in a test). Returns {ok, added, transcript, screenshot, objective}.
    """
    host = normalize_target(target or getattr(ws, "target", "") or "")
    logdir = ws.root / ".obol" / "follow"
    logdir.mkdir(parents=True, exist_ok=True)
    transcript_path = logdir / f"session-{int(time.time())}.log"

    captured = _pty_capture(argv, transcript_path)
    text = ""
    try:
        text = transcript_path.read_text(errors="replace")
    except OSError:
        text = captured
    before_obj = {f.kind for f in ws.facts.facts if f.kind.startswith("objective.")}
    added = parse_transcript(ws, text, target=host, note=note or " ".join(argv))
    after_obj = {f.kind for f in ws.facts.facts if f.kind.startswith("objective.")}

    screenshot = ""
    got_objective = bool(after_obj - before_obj)
    if shot_on_proof and got_objective:
        screenshot = capture_screenshot(ws.root / ".obol" / "evidence",
                                        name=f"proof-{host or 'host'}-{int(time.time())}.png")
    return {"ok": True, "added": added, "transcript": str(transcript_path),
            "screenshot": screenshot, "objective": got_objective}


def _pty_capture(argv: list[str], log_path: Path) -> str:
    """Run argv in a PTY, teeing the child's output to `log_path` (and this terminal), and
    return the captured text. Falls back to a captured subprocess where no PTY is available."""
    buf = bytearray()
    try:
        import pty

        with open(log_path, "wb") as log:
            def _read(fd):
                data = os.read(fd, 1024)
                buf.extend(data)
                log.write(data)
                log.flush()
                return data
            pty.spawn(argv, _read)
        return buf.decode(errors="replace")
    except Exception:  # noqa: BLE001 — no PTY (e.g. under a test harness): plain capture
        try:
            r = subprocess.run(argv, capture_output=True, timeout=3600)
            out = (r.stdout or b"") + (r.stderr or b"")
            log_path.write_bytes(out)
            return out.decode(errors="replace")
        except Exception:  # noqa: BLE001
            return ""


def tail_penelope_logs(ws, *, log_dir: str = "", target: str = "") -> dict:
    """Ingest penelope's own per-session logs (no wrapper needed): parse any log file in
    the penelope log directory that obol has not already ingested. Returns {ok, files,
    added}. obol knows the dir because it started the listener, or from `--log-dir`."""
    base = Path(log_dir or _default_penelope_dir())
    if not base.is_dir():
        return {"ok": False, "reason": f"penelope log dir not found: {base}", "files": [], "added": []}
    seen = {r.get("penelope_log") for r in ws.runs if r.get("penelope_log")}
    files, added = [], []
    for p in sorted(base.rglob("*")):
        if not p.is_file() or str(p) in seen:
            continue
        try:
            text = p.read_text(errors="replace")
        except OSError:
            continue
        kinds = parse_transcript(ws, text, target=target, note=f"penelope log {p.name}")
        # tag the run with the log path so a re-run does not double-ingest
        if ws.runs:
            ws.runs[-1]["penelope_log"] = str(p)
        ws.save()
        files.append(str(p))
        added.extend(kinds)
    return {"ok": True, "files": files, "added": added}


def _default_penelope_dir() -> str:
    for cand in ("~/.penelope", "~/.local/share/penelope", "~/penelope"):
        p = Path(os.path.expanduser(cand))
        if p.is_dir():
            return str(p)
    return os.path.expanduser("~/.penelope")

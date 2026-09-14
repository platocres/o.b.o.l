"""FastAPI backend for the obol web surface.

This is a real second surface over the *same* `.obol` workspace, not a separate
app with its own state:

* **One store.** Every request loads the workspace fresh from disk, so changes made
  in the terminal show up here immediately, and every write goes back through the
  single state file.
* **One runner.** Run-from-site calls `service.run_action` — the exact scope-checked
  runner + parser + ledger path the terminal uses. The browser triggers a run by
  action id; the server fills the command template from workspace facts, so secrets
  never travel to the browser and the hard scope gate applies identically.
* **Real-time.** `/api/events` is a Server-Sent-Events stream that watches the state
  file's mtime and pushes a tick whenever it changes — from a web run OR a terminal
  run — so open pages refresh the affected views on their own.

Security posture: binds to 127.0.0.1 by default; every `/api/*` route requires a
per-start access token (printed in the terminal) supplied as an `X-Obol-Token`
header or `?token=` query parameter. A header token is also full CSRF protection.
"""
from __future__ import annotations

import asyncio
import secrets
import threading
from pathlib import Path
from typing import Optional

from .. import board
from ..pack import friendly, load_packs, next_actions
from ..report import (
    build_report,
    build_report_context,
    redact_command,
    _redact_value,
)
from ..graph import build_graph_model, phase_of_kind
from ..runner import RunnerError
from ..service import ActionError, build_command, find_action, run_action
from ..workspace import Workspace

# Imported at module level (not inside create_app) so FastAPI can resolve the
# string type-hints that `from __future__ import annotations` produces — a
# route's `request: Request` is otherwise mistaken for a query parameter. The
# import is optional: without the web extra these are None and create_app raises
# a clear install hint, while the terminal core keeps working.
try:
    from fastapi import Body, FastAPI, HTTPException, Query, Request
    from fastapi.responses import (
        FileResponse,
        JSONResponse,
        PlainTextResponse,
        StreamingResponse,
    )
    from fastapi.staticfiles import StaticFiles
    _HAVE_FASTAPI = True
except ModuleNotFoundError:  # pragma: no cover - exercised only without the extra
    Body = FastAPI = HTTPException = Query = Request = None
    FileResponse = JSONResponse = PlainTextResponse = StreamingResponse = None
    StaticFiles = None
    _HAVE_FASTAPI = False

STATIC_DIR = Path(__file__).parent / "static"

# Serialize run-from-site writes: single operator, but two quick clicks (or a web
# run racing a terminal run's reload) must not interleave load->mutate->save.
_RUN_LOCK = threading.Lock()


def _missing_dep() -> "SystemExit":
    return SystemExit(
        'the web surface needs the "web" extra. install it with:\n'
        '    pip install "obol[web]"'
    )


def _action_view(action, ws: Workspace) -> dict:
    """Serialize one action for the web (commands redacted for display; the real
    command is rebuilt server-side at run time)."""
    variants = []
    for i in range(len(action.commands or [{"run": action.command}])):
        try:
            cmd, tool = build_command(action, ws, command_index=i)
        except ActionError:
            continue
        note = (action.commands[i].get("note", "") if action.commands else "")
        variants.append({
            "index": i + 1,
            "command": redact_command(cmd, include_secrets=False),
            "tool": tool,
            "note": note,
        })
    return {
        "id": action.id,
        "title": action.title,
        "desc": board.action_desc(action),
        "hypothesis": action.hypothesis,
        "tools": action.tools or ([action.tool] if action.tool else []),
        "phase": phase_of_kind(action.produces[0]) if action.produces else "recon",
        "refs": action.refs,
        "produces": [friendly(k) for k in action.produces],
        "report": action.report or None,
        "variants": variants,
    }


def _outcome_view(outcome) -> dict:
    r = outcome.result
    return {
        "action_id": outcome.action_id,
        "command": redact_command(outcome.command, include_secrets=False),
        "tool": outcome.tool,
        "dry_run": outcome.dry_run,
        "returncode": r.returncode,
        "timed_out": r.timed_out,
        "duration_ms": r.duration_ms,
        "added": [
            {"kind": f.kind, "label": friendly(f.kind),
             "value": _redact_value(f.value, include_secrets=False)}
            for f in outcome.added
        ],
        "added_count": len(outcome.added),
    }


def create_app(root: Path, *, token: Optional[str] = None):
    if not _HAVE_FASTAPI:  # pragma: no cover - exercised via CLI without the extra
        raise _missing_dep()

    root = Path(root)
    app = FastAPI(title="obol", docs_url=None, redoc_url=None, openapi_url=None)
    token = token if token is not None else secrets.token_urlsafe(24)
    app.state.obol_token = token

    def load_ws() -> Workspace:
        ws = Workspace(root)
        if not ws.exists():
            raise HTTPException(404, "no obol workspace here (run `obol init` first)")
        return ws.load()

    @app.middleware("http")
    async def _require_token(request, call_next):
        if request.url.path.startswith("/api/"):
            supplied = request.headers.get("x-obol-token") or request.query_params.get("token")
            if not supplied or not secrets.compare_digest(supplied, token):
                return JSONResponse(
                    {"detail": "missing or invalid token — open the URL printed by `obol serve`"},
                    status_code=401,
                )
        return await call_next(request)

    # ── read endpoints ───────────────────────────────────────────────────────
    @app.get("/api/meta")
    def api_meta():
        ws = load_ws()
        return {"name": ws.name, "target": ws.target, "scope": ws.scope,
                "phases": ["recon", "enum", "creds", "access", "escalate", "loot"]}

    @app.get("/api/overview")
    def api_overview():
        ws = load_ws()
        ctx = build_report_context(ws)
        activity = [
            {"tool": r["tool"], "command": r["command"], "status": r["status"],
             "produced": r["produced"], "at_display": r["at_display"],
             "playbook": r.get("playbook")}
            for r in ctx["timeline"][-14:][::-1]
        ]
        return {
            "meta": ctx["meta"], "tiles": ctx["tiles"], "open_ports": ctx["open_ports"],
            "access_ladder": ctx["access_ladder"], "category_counts": ctx["category_counts"],
            "severity_counts": ctx["severity_counts"], "activity": activity,
        }

    @app.get("/api/findings")
    def api_findings():
        ws = load_ws()
        return {"findings": build_report_context(ws)["facts"]}

    @app.get("/api/graph")
    def api_graph():
        return build_graph_model(load_ws().facts)

    @app.get("/api/next")
    def api_next():
        ws = load_ws()
        return {"actions": [_action_view(a, ws) for a in next_actions(ws.facts)]}

    @app.get("/api/action/{action_id}")
    def api_action(action_id: str):
        ws = load_ws()
        try:
            action = find_action(action_id)
        except ActionError as exc:
            raise HTTPException(404, str(exc))
        return _action_view(action, ws)

    @app.get("/api/playbooks")
    def api_playbooks():
        from .. import playbook
        return {"playbooks": [
            {"name": pb.name, "title": pb.title, "description": pb.description}
            for pb in playbook.list_playbooks()
        ]}

    @app.get("/api/playbook/{name}")
    def api_playbook(name: str):
        from .. import playbook
        ws = load_ws()
        try:
            pb = playbook.load_playbook(name)
        except FileNotFoundError:
            raise HTTPException(404, f"no playbook named {name!r}")
        try:
            steps = playbook.resolve_steps(pb, load_packs())
        except KeyError as exc:
            raise HTTPException(500, f"playbook references unknown action {exc}")
        out = []
        for i, (step, action) in enumerate(steps, 1):
            out.append({
                "step": i, "label": step.label, "action_id": action.id,
                "title": action.title,
                "command": redact_command(board.render_step_command(step, action, ws),
                                          include_secrets=False),
                "require_approval": bool(step.require_approval),
                "note": getattr(step, "note", "") or "",
            })
        return {"name": pb.name, "title": pb.title, "description": pb.description, "steps": out}

    @app.get("/api/report")
    def api_report(include_secrets: bool = Query(False)):
        return build_report_context(load_ws(), include_secrets=include_secrets)

    @app.get("/api/report.md")
    def api_report_md(include_secrets: bool = Query(False)):
        md = build_report(load_ws(), include_secrets=include_secrets)
        return PlainTextResponse(md, headers={
            "Content-Disposition": 'attachment; filename="obol-report.md"'})

    # ── run-from-site (write) endpoints ──────────────────────────────────────
    @app.post("/api/run/action")
    def api_run_action(payload: dict = Body(...)):
        action_id = (payload or {}).get("action_id", "")
        if not action_id:
            raise HTTPException(422, "action_id is required")
        cmd_index = max(0, int((payload or {}).get("cmd_index", 1)) - 1)
        dry_run = bool((payload or {}).get("dry_run", False))
        allow_shell = bool((payload or {}).get("allow_shell", False))
        inputs = (payload or {}).get("set") or {}
        with _RUN_LOCK:
            ws = load_ws()
            for k, v in inputs.items():
                ws.set_input(str(k), str(v))
            try:
                action = find_action(action_id)
                outcome = run_action(
                    ws, action, command_index=cmd_index, dry_run=dry_run,
                    allow_shell=allow_shell, ledger_extra={"surface": "web"},
                )
            except ActionError as exc:
                raise HTTPException(404, str(exc))
            except RunnerError as exc:
                raise HTTPException(400, str(exc))
        return _outcome_view(outcome)

    @app.post("/api/run/playbook")
    def api_run_playbook(payload: dict = Body(...)):
        from .. import playbook
        name = (payload or {}).get("name", "")
        step_no = int((payload or {}).get("step", 0))
        approve = bool((payload or {}).get("approve", False))
        dry_run = bool((payload or {}).get("dry_run", False))
        allow_shell = bool((payload or {}).get("allow_shell", False))
        if not name or step_no < 1:
            raise HTTPException(422, "name and a 1-based step are required")
        with _RUN_LOCK:
            ws = load_ws()
            try:
                pb = playbook.load_playbook(name)
            except FileNotFoundError:
                raise HTTPException(404, f"no playbook named {name!r}")
            try:
                steps = playbook.resolve_steps(pb, load_packs())
            except KeyError as exc:
                raise HTTPException(500, f"playbook references unknown action {exc}")
            if not 1 <= step_no <= len(steps):
                raise HTTPException(404, f"playbook {name!r} has {len(steps)} step(s)")
            step, action = steps[step_no - 1]
            if step.require_approval and not approve and not dry_run:
                raise HTTPException(409, {
                    "reason": "require_approval",
                    "message": f"step {step_no} ({step.label}) is noisy/intrusive — "
                               "confirm to run it, or preview with dry-run",
                })
            try:
                outcome = run_action(
                    ws, action, command_index=max(0, (step.cmd or 1) - 1),
                    dry_run=dry_run, allow_shell=allow_shell, args_extra=step.args_extra,
                    ledger_extra={"surface": "web", "playbook": pb.name, "playbook_step": step_no},
                )
            except ActionError as exc:
                raise HTTPException(404, str(exc))
            except RunnerError as exc:
                raise HTTPException(400, str(exc))
        view = _outcome_view(outcome)
        view.update({"playbook": pb.name, "step": step_no,
                     "has_next": step_no < len(steps)})
        return view

    # ── real-time: SSE on state-file mtime ───────────────────────────────────
    @app.get("/api/events")
    async def api_events(request: Request):
        state_file = Path(root) / ".obol" / "state.json"

        async def gen():
            last = None
            # Prime clients so a just-opened page renders immediately.
            yield "event: hello\ndata: connected\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    mtime = state_file.stat().st_mtime_ns
                except OSError:
                    mtime = None
                if mtime != last:
                    last = mtime
                    yield f"event: state\ndata: {mtime}\n\n"
                else:
                    yield ": keep-alive\n\n"  # comment frame keeps proxies/browsers happy
                await asyncio.sleep(1.0)

        return StreamingResponse(gen(), media_type="text/event-stream", headers={
            "Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    # ── static SPA ───────────────────────────────────────────────────────────
    @app.get("/")
    def index():
        return FileResponse(STATIC_DIR / "index.html")

    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    return app


def serve(ws: Workspace, host: str = "127.0.0.1", port: int = 8765,
          token: Optional[str] = None) -> None:
    """Start the localhost web server (blocking). Prints the tokenized URL first so
    the operator can open it before uvicorn takes over the terminal."""
    try:
        import uvicorn
    except ModuleNotFoundError as exc:  # pragma: no cover - exercised via CLI
        raise _missing_dep() from exc
    token = token if token is not None else secrets.token_urlsafe(24)
    app = create_app(ws.root, token=token)
    url = f"http://{host}:{port}/?token={token}"
    print("obol web surface (localhost) — open this URL (the token gates the API):")
    print(f"    {url}")
    print("Ctrl-C to stop.")
    uvicorn.run(app, host=host, port=port, log_level="warning")

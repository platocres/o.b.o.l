"""FastAPI backend for the O.B.O.L web surface (the engagement library).

One app over an app-managed library of engagements, each holding many targets, all
sharing one runner/parser/store with the terminal:

* **Library.** `create_app(base)` serves every engagement under the base dir; create,
  list, and switch engagements from the web. Endpoints act on the *active*
  engagement; per-target endpoints take `?target=<host>`.
* **One store / one runner.** Reads load the workspace fresh; run-from-site calls
  `service.run_action(target=…)` — the same scope-checked runner/parser/ledger the
  terminal uses. The browser sends an action id + target; the server fills the
  command from that target's facts, so secrets never reach the browser.
* **Real-time.** `/api/events` (SSE) watches the active engagement's state file and
  the active-engagement pointer, pushing a tick on any change (web- or
  terminal-driven) so open pages refresh themselves.

Localhost-only, token-gated (`X-Obol-Token` header or `?token=`).
"""
from __future__ import annotations

import asyncio
import mimetypes
import secrets
import threading
from pathlib import Path
from typing import Optional

from .. import board, bloodhound, library, tools as tool_inventory
from ..graph import (
    build_engagement_graph,
    build_graph_model,
    phase_of_kind,
    target_access_level,
    target_phase,
)
from ..pack import friendly, load_packs, next_actions
from ..report import (
    build_report,
    build_report_context,
    redact_command,
    _evidence_view,
    _fact_category,
    _redact_value,
    _run_status,
    _target_open_ports,
)
from ..runner import RunnerError
from ..service import (
    ActionError,
    build_command,
    eligible_actions,
    find_action,
    run_action,
)
from ..workspace import Workspace

try:
    from fastapi import Body, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
    from fastapi.responses import (
        FileResponse,
        JSONResponse,
        PlainTextResponse,
        Response,
        StreamingResponse,
    )
    from fastapi.staticfiles import StaticFiles
    _HAVE_FASTAPI = True
except ModuleNotFoundError:  # pragma: no cover
    Body = FastAPI = File = Form = HTTPException = Query = Request = UploadFile = None
    FileResponse = JSONResponse = PlainTextResponse = Response = StreamingResponse = None
    StaticFiles = None
    _HAVE_FASTAPI = False

STATIC_DIR = Path(__file__).parent / "static"
PHASES = ["recon", "enum", "creds", "access", "escalate", "loot"]
PHASE_LABEL = {"recon": "Recon", "enum": "Enumerate", "creds": "Credentials",
               "access": "Access", "escalate": "Escalate", "loot": "Loot / domain"}

_RUN_LOCK = threading.Lock()


def _missing_dep() -> "SystemExit":
    return SystemExit('the web surface needs the "web" extra:\n    pip install "obol[web]"')


def _action_phase(action) -> str:
    return phase_of_kind(action.produces[0]) if action.produces else "recon"


def _action_view(action, ws: Workspace, target: str = "") -> dict:
    variants = []
    for i in range(len(action.commands or [{"run": action.command}])):
        try:
            cmd, tool = build_command(action, ws, command_index=i, target=target)
        except ActionError:
            continue
        note = (action.commands[i].get("note", "") if action.commands else "")
        variants.append({"index": i + 1, "command": redact_command(cmd, include_secrets=False),
                         "tool": tool, "note": note})
    return {
        "id": action.id, "title": action.title, "desc": board.action_desc(action),
        "hypothesis": action.hypothesis,
        "tools": action.tools or ([action.tool] if action.tool else []),
        "phase": _action_phase(action), "refs": action.refs,
        "produces": [friendly(k) for k in action.produces],
        "report": action.report or None, "variants": variants,
    }


def _outcome_view(outcome) -> dict:
    r = outcome.result
    return {
        "action_id": outcome.action_id, "command": redact_command(outcome.command, include_secrets=False),
        "tool": outcome.tool, "dry_run": outcome.dry_run, "returncode": r.returncode,
        "timed_out": r.timed_out, "duration_ms": r.duration_ms,
        "added": [{"kind": f.kind, "label": friendly(f.kind),
                   "value": _redact_value(f.value, include_secrets=False)} for f in outcome.added],
        "added_count": len(outcome.added),
    }


def _target_bundle(ws: Workspace, host: str) -> dict:
    """Everything a target's tabbed view needs, in one payload."""
    t = ws.get_target(host)
    if not t:
        raise KeyError(host)
    tf = ws.facts_for_target(host)
    proven_phases = {phase_of_kind(f.kind) for f in tf.facts if f.state.value == "supported"}
    cur = target_phase(tf)
    palette = eligible_actions(tf)
    nxt = next_actions(tf)

    # attack-chain bar: each phase, whether reached, and the moves available in it
    chain = []
    for ph in PHASES:
        moves = [a for a in nxt if _action_phase(a) == ph]
        chain.append({
            "phase": ph, "label": PHASE_LABEL[ph], "reached": ph in proven_phases,
            "current": ph == cur, "move_count": len(moves),
            "moves": [{"id": a.id, "title": a.title} for a in moves[:8]],
        })

    # service-aware tool palette grouped by phase
    tools_by_phase = {ph: [] for ph in PHASES}
    for a in palette:
        tools_by_phase[_action_phase(a)].append(_action_view(a, ws, target=host))
    tools = [{"phase": ph, "label": PHASE_LABEL[ph], "actions": tools_by_phase[ph]}
             for ph in PHASES if tools_by_phase[ph]]

    # static checklist: the full pack by attack chain (reference), with tick state
    ticks = ws.checklist.get(host, {})
    checklist = []
    for ph in PHASES:
        items = []
        for a in sorted(load_packs(), key=lambda x: x.priority, reverse=True):
            if _action_phase(a) != ph:
                continue
            try:
                cmd, _ = build_command(a, ws, target=host)
            except ActionError:
                cmd = a.command
            items.append({"id": a.id, "title": a.title,
                          "command": redact_command(cmd, include_secrets=False),
                          "tools": a.tools or ([a.tool] if a.tool else []),
                          "checked": bool(ticks.get(a.id))})
        if items:
            checklist.append({"phase": ph, "label": PHASE_LABEL[ph], "items": items})

    host_facts = [f for f in tf.facts if f.scope == f"host:{host}"]
    findings = [{"kind": f.kind, "label": friendly(f.kind), "category": _fact_category(f.kind),
                 "value": _redact_value(f.value, include_secrets=False),
                 "evidence": redact_command(f.source or "", include_secrets=False),
                 "state": f.state.value} for f in host_facts]

    commands = [{"tool": r.get("tool"), "command": redact_command(r.get("command", ""), include_secrets=False),
                 "status": _run_status(r), "produced": r.get("produced") or [],
                 "at": r.get("at"), "playbook": r.get("playbook")}
                for r in ws.runs if r.get("target") == host or (not r.get("target") and host == ws.target)][::-1][:60]

    return {
        "meta": {"host": host, "label": t.get("label") or host, "os": t.get("os", ""),
                 "status": t.get("status", ""), "notes": t.get("notes", ""),
                 "active": host == ws.target},
        "access": target_access_level(tf), "phase": cur,
        "open_ports": _target_open_ports(host_facts),
        "chain": chain, "next": [_action_view(a, ws, target=host) for a in nxt],
        "tools": tools, "checklist": checklist, "findings": findings,
        "commands": commands,
        "evidence": [_evidence_view(e) for e in ws.evidence_for(host)],
        "graph": build_graph_model(tf),
    }


def create_app(base, *, token: Optional[str] = None):
    if not _HAVE_FASTAPI:  # pragma: no cover
        raise _missing_dep()
    library.set_base(Path(base))
    library.engagements_dir().mkdir(parents=True, exist_ok=True)

    app = FastAPI(title="O.B.O.L", docs_url=None, redoc_url=None, openapi_url=None)
    token = token if token is not None else secrets.token_urlsafe(24)
    app.state.obol_token = token

    def active() -> Workspace:
        ws = library.resolve_active()
        if ws is None:
            raise HTTPException(404, "no active engagement — create one first")
        return ws

    def target_or_404(ws: Workspace, host: str):
        if not host or not ws.get_target(host):
            raise HTTPException(404, f"unknown target {host!r} in this engagement")
        return host

    @app.middleware("http")
    async def _require_token(request, call_next):
        if request.url.path.startswith("/api/"):
            supplied = request.headers.get("x-obol-token") or request.query_params.get("token")
            if not supplied or not secrets.compare_digest(supplied, token):
                return JSONResponse({"detail": "missing or invalid token — open the URL from `obol serve`"},
                                    status_code=401)
        return await call_next(request)

    # ── engagements ──────────────────────────────────────────────────────────
    @app.get("/api/engagements")
    def api_engagements():
        return {"engagements": library.list_engagements(), "active": library.active_slug()}

    @app.post("/api/engagements")
    def api_create_engagement(payload: dict = Body(...)):
        name = (payload or {}).get("name", "").strip()
        if not name:
            raise HTTPException(422, "name is required")
        ws = library.create_engagement(name)
        return {"ok": True, "slug": ws.root.name, "name": ws.name}

    @app.post("/api/engagements/activate")
    def api_activate_engagement(payload: dict = Body(...)):
        slug = (payload or {}).get("slug", "")
        if not library.get_engagement(slug):
            raise HTTPException(404, f"no engagement {slug!r}")
        library.set_active(slug)
        return {"ok": True, "active": slug}

    @app.get("/api/meta")
    def api_meta():
        ws = active()
        dom = ws.facts.values("ad.domain_known")
        return {"name": ws.name, "slug": ws.root.name,
                "domain": (dom[0].get("name") if dom else "") or "",
                "targets": ws.targets, "active_target": ws.target, "phases": PHASES,
                "phase_labels": PHASE_LABEL}

    # ── engagement overview + graph + report ─────────────────────────────────
    @app.get("/api/overview")
    def api_overview():
        ws = active()
        ctx = build_report_context(ws)
        activity = [{"tool": r["tool"], "command": r["command"], "status": r["status"],
                     "produced": r["produced"], "at_display": r["at_display"],
                     "playbook": r.get("playbook")} for r in ctx["timeline"][-14:][::-1]]
        return {"meta": ctx["meta"], "tiles": ctx["tiles"], "targets": ctx["targets"],
                "category_counts": ctx["category_counts"], "severity_counts": ctx["severity_counts"],
                "access_ladder": ctx["access_ladder"], "activity": activity,
                "engagement_graph": ctx["engagement_graph"], "bloodhound": ctx["bloodhound"]}

    @app.get("/api/engagement/graph")
    def api_engagement_graph():
        return build_engagement_graph(active())

    @app.get("/api/report")
    def api_report(include_secrets: bool = Query(False)):
        return build_report_context(active(), include_secrets=include_secrets)

    @app.get("/api/report.md")
    def api_report_md(include_secrets: bool = Query(False)):
        md = build_report(active(), include_secrets=include_secrets)
        return PlainTextResponse(md, headers={"Content-Disposition": 'attachment; filename="obol-report.md"'})

    # ── targets ──────────────────────────────────────────────────────────────
    @app.post("/api/targets")
    def api_add_target(payload: dict = Body(...)):
        host = (payload or {}).get("host", "").strip()
        if not host:
            raise HTTPException(422, "host is required")
        with _RUN_LOCK:
            ws = active()
            rec = ws.add_target(host, (payload or {}).get("label", "").strip())
            ws.save()
        return {"ok": True, "target": rec}

    @app.post("/api/target/activate")
    def api_activate_target(payload: dict = Body(...)):
        with _RUN_LOCK:
            ws = active()
            host = target_or_404(ws, (payload or {}).get("target", ""))
            ws.set_active_target(host)
            ws.save()
        return {"ok": True, "active_target": host}

    @app.delete("/api/target")
    def api_remove_target(target: str = Query(...)):
        with _RUN_LOCK:
            ws = active()
            if not ws.remove_target(target):
                raise HTTPException(404, f"unknown target {target!r}")
            ws.save()
        return {"ok": True}

    @app.get("/api/target")
    def api_target(target: str = Query(...)):
        ws = active()
        target_or_404(ws, target)
        return _target_bundle(ws, target)

    @app.post("/api/target/checklist")
    def api_checklist(payload: dict = Body(...)):
        with _RUN_LOCK:
            ws = active()
            host = target_or_404(ws, (payload or {}).get("target", ""))
            item = (payload or {}).get("item", "")
            checked = bool((payload or {}).get("checked", False))
            ws.checklist.setdefault(host, {})[item] = checked
            ws.save()
        return {"ok": True}

    @app.post("/api/target/notes")
    def api_notes(payload: dict = Body(...)):
        with _RUN_LOCK:
            ws = active()
            host = target_or_404(ws, (payload or {}).get("target", ""))
            ws.get_target(host)["notes"] = str((payload or {}).get("notes", ""))
            ws.save()
        return {"ok": True}

    # ── evidence ─────────────────────────────────────────────────────────────
    @app.post("/api/target/evidence")
    async def api_add_evidence(target: str = Form(...), file: UploadFile = File(...),
                               phase: str = Form(""), caption: str = Form("")):
        data = await file.read()
        with _RUN_LOCK:
            ws = active()
            target_or_404(ws, target)
            rec = ws.add_evidence(filename=file.filename or "upload", data=data,
                                  target=target, phase=phase, caption=caption)
            ws.save()
        return {"ok": True, "evidence": _evidence_view(rec)}

    @app.delete("/api/evidence/{eid}")
    def api_del_evidence(eid: str):
        with _RUN_LOCK:
            ws = active()
            if not ws.remove_evidence(eid):
                raise HTTPException(404, "no such evidence")
            ws.save()
        return {"ok": True}

    @app.get("/api/evidence/{eid}")
    def api_get_evidence(eid: str):
        ws = active()
        for e in ws.evidence:
            if e.get("id") == eid:
                path = ws.evidence_dir / e.get("stored", "")
                if not path.exists():
                    raise HTTPException(404, "evidence file missing")
                ctype = mimetypes.guess_type(e.get("filename", ""))[0] or "application/octet-stream"
                return FileResponse(str(path), media_type=ctype)
        raise HTTPException(404, "no such evidence")

    # ── BloodHound ingestion ─────────────────────────────────────────────────
    @app.post("/api/bloodhound")
    async def api_bloodhound(files: list[UploadFile] = File(...)):
        uploads = [(f.filename or "upload", await f.read()) for f in files]
        with _RUN_LOCK:
            ws = active()
            summary = bloodhound.ingest(ws, uploads)
        return {"ok": True, "domain": summary.get("domain"), "users": summary.get("users"),
                "computers": len(summary.get("computers", [])),
                "domain_admins": len(summary.get("domain_admins", [])),
                "kerberoastable": len(summary.get("kerberoastable", [])),
                "asrep_roastable": len(summary.get("asrep_roastable", [])),
                "added_facts": summary.get("added_facts", [])}

    # ── tool inventory ───────────────────────────────────────────────────────
    @app.get("/api/tools")
    def api_tools():
        return tool_inventory.scan()

    @app.post("/api/tools/add")
    def api_tools_add(payload: dict = Body(...)):
        key = (payload or {}).get("tool", "")
        path = (payload or {}).get("path", "").strip()
        try:
            d = tool_inventory.add_override(key, path)
        except KeyError:
            raise HTTPException(404, f"unknown tool {key!r}")
        except FileNotFoundError:
            raise HTTPException(400, f"no file at {path!r}")
        return {"ok": True, **d}

    @app.post("/api/tools/install")
    def api_tools_install(payload: dict = Body(...)):
        key = (payload or {}).get("tool", "")
        if key not in {t.key for t in tool_inventory.REGISTRY}:
            raise HTTPException(404, f"unknown tool {key!r}")
        return tool_inventory.install(key)

    # ── run-from-site ────────────────────────────────────────────────────────
    @app.post("/api/run/action")
    def api_run_action(payload: dict = Body(...)):
        action_id = (payload or {}).get("action_id", "")
        if not action_id:
            raise HTTPException(422, "action_id is required")
        cmd_index = max(0, int((payload or {}).get("cmd_index", 1)) - 1)
        dry_run = bool((payload or {}).get("dry_run", False))
        target = (payload or {}).get("target", "")
        with _RUN_LOCK:
            ws = active()
            if target:
                target_or_404(ws, target)
            try:
                action = find_action(action_id)
                outcome = run_action(ws, action, command_index=cmd_index, dry_run=dry_run,
                                     target=target, ledger_extra={"surface": "web", "target": target or ws.target})
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
        target = (payload or {}).get("target", "")
        if not name or step_no < 1:
            raise HTTPException(422, "name and a 1-based step are required")
        with _RUN_LOCK:
            ws = active()
            if target:
                target_or_404(ws, target)
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
                raise HTTPException(409, {"reason": "require_approval",
                                          "message": f"step {step_no} ({step.label}) is noisy/intrusive"})
            try:
                outcome = run_action(ws, action, command_index=max(0, (step.cmd or 1) - 1),
                                     dry_run=dry_run, args_extra=step.args_extra, target=target,
                                     ledger_extra={"surface": "web", "playbook": pb.name,
                                                   "playbook_step": step_no, "target": target or ws.target})
            except ActionError as exc:
                raise HTTPException(404, str(exc))
            except RunnerError as exc:
                raise HTTPException(400, str(exc))
        view = _outcome_view(outcome)
        view.update({"playbook": pb.name, "step": step_no, "has_next": step_no < len(steps)})
        return view

    @app.get("/api/playbooks")
    def api_playbooks():
        from .. import playbook
        return {"playbooks": [{"name": pb.name, "title": pb.title, "description": pb.description}
                              for pb in playbook.list_playbooks()]}

    @app.get("/api/playbook/{name}")
    def api_playbook(name: str, target: str = Query("")):
        from .. import playbook
        ws = active()
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
            try:
                cmd = board.fill_command(action, ws, max(0, (step.cmd or 1) - 1), target)
                extra = board.fill_template(step.args_extra, ws, target).strip() if step.args_extra else ""
                cmd = f"{cmd} {extra}".strip() if extra else cmd
            except Exception:
                cmd = action.command
            out.append({"step": i, "label": step.label, "action_id": action.id, "title": action.title,
                        "command": redact_command(cmd, include_secrets=False),
                        "require_approval": bool(step.require_approval),
                        "note": getattr(step, "note", "") or ""})
        return {"name": pb.name, "title": pb.title, "description": pb.description, "steps": out}

    # ── real-time ────────────────────────────────────────────────────────────
    @app.get("/api/events")
    async def api_events(request: Request):
        async def gen():
            last = None
            yield "event: hello\ndata: connected\n\n"
            while True:
                if await request.is_disconnected():
                    break
                slug = library.active_slug()
                mtime = None
                if slug:
                    sf = library.engagement_path(slug) / ".obol" / "state.json"
                    try:
                        mtime = sf.stat().st_mtime_ns
                    except OSError:
                        mtime = None
                sig = (slug, mtime)
                if sig != last:
                    last = sig
                    yield f"event: state\ndata: {slug}:{mtime}\n\n"
                else:
                    yield ": keep-alive\n\n"
                await asyncio.sleep(1.0)
        return StreamingResponse(gen(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    # ── static SPA ───────────────────────────────────────────────────────────
    @app.get("/")
    def index():
        return FileResponse(STATIC_DIR / "index.html")

    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    return app


def serve(ws: Optional[Workspace] = None, host: str = "127.0.0.1", port: int = 8765,
          token: Optional[str] = None, base: Optional[Path] = None) -> None:
    """Start the localhost server (blocking) over the engagement library. If `ws` is
    given (a directory-based engagement), it is registered into the library and made
    active so `obol serve` from an engagement dir just works."""
    try:
        import uvicorn
    except ModuleNotFoundError as exc:  # pragma: no cover
        raise _missing_dep() from exc
    token = token if token is not None else secrets.token_urlsafe(24)
    base_dir = Path(base) if base else library.base_dir()
    library.set_base(base_dir)
    library.engagements_dir().mkdir(parents=True, exist_ok=True)
    # If launched from a directory engagement that isn't in the library, link it in.
    if ws is not None and ws.exists():
        slug = ws.root.name
        target = library.engagement_path(slug)
        if ws.root.resolve() != target.resolve() and not library.get_engagement(slug):
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.symlink_to(ws.root.resolve(), target_is_directory=True)
            except OSError:
                pass
        if library.get_engagement(slug):
            library.set_active(slug)
    app = create_app(base_dir, token=token)
    url = f"http://{host}:{port}/?token={token}"
    print("O.B.O.L web surface (localhost) — open this URL (the token gates the API):")
    print(f"    {url}")
    print(f"    engagement library: {base_dir}")
    print("Ctrl-C to stop.")
    uvicorn.run(app, host=host, port=port, log_level="warning")

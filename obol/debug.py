"""Debug package — a complete, self-describing bundle for an AI agent (or human) to
review a test run of obol.

`obol debug package` writes a one-shot bundle of everything a reviewer needs:

* `manifest.json` / `README.md` — what this is, and how to read it.
* `state.json` — the full engagement export (facts, targets, runs, evidence meta).
* `events.jsonl` — the store change feed (what happened, in order).
* `facts.json` — facts grouped per target, with proof states and lineage.
* `ledger.json` + `runs/` — the run ledger and the raw stdout/stderr of every run.
* `report.md` — the OSCP report (secrets redacted unless asked).
* `tools.json` — the tool-availability scan on this box.
* `env.json` — obol / Python / platform / pack versions.
* `terminal/` — plain-text renders of the board and facts (what the terminal shows).
* `site/index.html` — the offline web-console snapshot.
* `screenshots/` — PNGs of the console and a terminal-styled view, when a headless
  browser is available (see `screenshots.py`).

`obol debug capture --interval N` records the same snapshot on a timer while a test
runs, into `timeline/<seq>/`, so the package shows the engagement evolving — useful
screenshots "at intervals during a run", exactly when the operator is heads-down.
"""
from __future__ import annotations

import contextlib
import io
import json
import platform
import re
import shutil
import sys
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from . import board, tools as tool_inventory
from .report import build_report
from .screenshots import Screenshotter
from .workspace import Workspace

SCHEMA = "obol-debug/1"
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _now_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def _capture_stdout(fn) -> str:
    """Run `fn()` capturing what it prints (the terminal board degrades to plain text
    when stdout is not a tty), stripped of any stray ANSI."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        try:
            fn()
        except Exception as exc:  # never let a render error sink the package
            print(f"[render error: {exc}]")
    return _ANSI.sub("", buf.getvalue())


def _obol_version() -> str:
    try:
        from importlib.metadata import version
        return version("obol")
    except Exception:
        return "unknown"


def _env_info() -> dict:
    extras = {}
    for mod in ("fastapi", "uvicorn", "rich", "playwright"):
        try:
            __import__(mod)
            extras[mod] = True
        except Exception:
            extras[mod] = False
    packs = []
    packs_dir = Path(__file__).parent / "packs"
    for p in sorted(packs_dir.glob("*.json")):
        try:
            data = json.loads(p.read_text())
            n = len(data if isinstance(data, list) else data.get("actions", []))
        except Exception:
            n = None
        packs.append({"file": p.name, "actions": n})
    return {
        "obol_version": _obol_version(),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "extras_installed": extras,
        "packs": packs,
    }


def _facts_by_target(ws: Workspace) -> dict:
    out: dict[str, list] = {}
    for f in ws.facts.facts:
        scope = f.scope or ""
        host = scope[5:] if scope.startswith("host:") else (scope or "engagement")
        out.setdefault(host, []).append({
            "kind": f.kind, "scope": f.scope, "state": f.state.value,
            "value": f.value, "source": f.source, "created_at": f.created_at,
        })
    by_kind: dict[str, int] = {}
    for f in ws.facts.facts:
        by_kind[f.kind] = by_kind.get(f.kind, 0) + 1
    return {"by_target": out, "by_kind": by_kind, "total": len(ws.facts.facts)}


def _terminal_html(title: str, blocks: list[tuple[str, str]]) -> str:
    """A dark, monospace 'terminal' page for screenshotting — so a captured PNG reads
    like the operator's scrollback."""
    def esc(s):
        return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
    body = "".join(
        f'<div class="w"><div class="p">$ {esc(cmd)}</div><pre>{esc(text) or "(no output)"}</pre></div>'
        for cmd, text in blocks
    )
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>{esc(title)}</title>
<style>
  body{{margin:0;background:#0b0f18;color:#c7d0e0;font:13px/1.5 ui-monospace,Menlo,Consolas,monospace;padding:20px}}
  .w{{margin-bottom:22px}} .p{{color:#38BDF8;margin-bottom:6px}}
  pre{{margin:0;white-space:pre-wrap;background:#0f1524;border:1px solid #1f2a44;border-radius:8px;padding:14px;color:#d7deee}}
  h1{{font-size:14px;color:#7f8aa3;font-weight:600;margin:0 0 16px}}
</style></head><body><h1>{esc(title)}</h1>{body}</body></html>"""


def _readme(ws: Workspace, contents: list[str]) -> str:
    return f"""# obol debug package

Generated {datetime.now(timezone.utc).isoformat(timespec="seconds")} for engagement
**{ws.name}** (active target: `{ws.target or "—"}`).

This bundle is meant to be handed to an AI agent (or teammate) to review an obol
test run. obol is an evidence-driven OSCP operator companion: it only treats
something as true when a **Fact** records it, scoped to exactly what the evidence
supports and carrying a proof state (`supported` / `refuted` / `inconclusive`) and
the command that produced it. When reviewing, respect that discipline — a port
being open is not a foothold; an AS-REP hash is crackable material, not a
credential.

## What's here

{chr(10).join("- " + c for c in contents)}

## Where to look first

1. `README.md` (this file) and `manifest.json` — orientation and counts.
2. `facts.json` — what has actually been proven, grouped per target, with lineage.
3. `events.jsonl` — the ordered change feed (facts/runs/targets as they happened).
4. `ledger.json` + `runs/` — every command run and its raw stdout/stderr.
5. `report.md` — the narrated OSCP report.
6. `terminal/` and `screenshots/` — what the operator saw.

Secrets are redacted in `report.md` unless the package was built with
`--include-secrets`. Raw run output under `runs/` is verbatim and may contain
secrets regardless — treat the whole package as sensitive.
"""


def snapshot(ws: Workspace, dest: Path, *, include_secrets: bool = False,
             shooter: Screenshotter | None = None, live_url: str = "",
             live_token: str = "") -> dict:
    """Write one full snapshot of `ws` into `dest`. Returns a summary dict. Used for
    both the one-shot package and each tick of `capture`."""
    from . import web
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    written: list[str] = []

    (dest / "state.json").write_text(ws.export_json())
    written.append("state.json — full engagement export")

    events = ws.store.read_events(0, limit=100000) if ws.store.exists() else []
    (dest / "events.jsonl").write_text("".join(json.dumps(e) + "\n" for e in events))
    written.append(f"events.jsonl — {len(events)} store change events")

    (dest / "facts.json").write_text(json.dumps(_facts_by_target(ws), indent=2, default=str))
    written.append("facts.json — facts grouped per target (kind, proof state, lineage)")

    (dest / "ledger.json").write_text(json.dumps(ws.runs, indent=2, default=str))
    written.append(f"ledger.json — {len(ws.runs)} run(s)")

    # raw run outputs
    if ws.runs_dir.exists():
        shutil.copytree(ws.runs_dir, dest / "runs", dirs_exist_ok=True)
        written.append("runs/ — raw stdout/stderr of each run")

    try:
        (dest / "report.md").write_text(build_report(ws, include_secrets=include_secrets))
        written.append("report.md — OSCP report" + (" (secrets shown)" if include_secrets else " (secrets redacted)"))
    except Exception as exc:
        (dest / "report.md").write_text(f"report generation failed: {exc}\n")

    (dest / "tools.json").write_text(json.dumps(tool_inventory.scan(), indent=2, default=str))
    written.append("tools.json — tool availability scan on this host")

    (dest / "env.json").write_text(json.dumps(_env_info(), indent=2, default=str))
    written.append("env.json — obol/python/platform/pack versions")

    # terminal renders (plain text)
    term = dest / "terminal"
    term.mkdir(exist_ok=True)
    next_txt = _capture_stdout(lambda: board.render_board(ws))
    facts_txt = _capture_stdout(lambda: _print_facts(ws))
    (term / "next.txt").write_text(next_txt)
    (term / "facts.txt").write_text(facts_txt)
    written.append("terminal/ — plain-text board + facts (terminal scrollback)")

    # offline web snapshot
    site = dest / "site"
    site.mkdir(exist_ok=True)
    (site / "index.html").write_text(web.build_page(ws))
    written.append("site/index.html — offline web-console snapshot")

    # screenshots (best effort)
    shots: dict[str, str] = {}
    if shooter and shooter.available:
        shot_dir = dest / "screenshots"
        term_html = term / "_terminal.html"
        term_html.write_text(_terminal_html(
            f"obol · {ws.name} · {ws.target}",
            [("obol next", next_txt), ("obol facts", facts_txt)]))
        if shooter.shoot(term_html, shot_dir / "terminal.png"):
            shots["terminal"] = "screenshots/terminal.png"
        term_html.unlink(missing_ok=True)
        # site: a live `obol serve` renders the real console (with charts/graph); the
        # offline snapshot is the always-available fallback.
        site_done = False
        if live_url:
            url = live_url + (("&" if "?" in live_url else "?") + "token=" + live_token if live_token else "")
            site_done = shooter.shoot_url(url, shot_dir / "site.png")
            if site_done:
                shots["site"] = "screenshots/site.png (live console)"
        if not site_done and shooter.shoot(site / "index.html", shot_dir / "site.png"):
            shots["site"] = "screenshots/site.png (offline snapshot)"
        if shots:
            written.append("screenshots/ — PNGs of the terminal view and web console")

    summary = {
        "at": time.time(),
        "at_iso": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "engagement": ws.name,
        "active_target": ws.target,
        "targets": [t.get("host") for t in ws.targets],
        "facts_total": len(ws.facts.facts),
        "runs_total": len(ws.runs),
        "events_total": len(events),
        "screenshots": shots,
        "screenshot_engine": shooter.note if shooter else "disabled",
    }
    (dest / "snapshot.json").write_text(json.dumps(summary, indent=2, default=str))
    summary["_written"] = written
    return summary


def _print_facts(ws: Workspace) -> None:
    """Plain-text fact dump for the terminal capture (mirrors `obol facts`)."""
    if not ws.facts.facts:
        print("no facts recorded yet.")
        return
    print(f"== facts · {ws.name} ==\n")
    for f in ws.facts.facts:
        val = json.dumps(f.value, default=str) if f.value else ""
        print(f"  [{f.state.value:12}] {f.kind:24} {f.scope:22} {val}")
        if f.source:
            print(f"        ↳ {f.source}")


def build_debug_package(ws: Workspace, out: Path | None = None, *,
                        include_secrets: bool = False, screenshots: bool = True,
                        live_url: str = "", live_token: str = "") -> Path:
    """One-shot debug bundle. Returns the path to the written `.zip`."""
    stamp = _now_stamp()
    base = Path(out) if out else (ws.dir / "debug")
    base.mkdir(parents=True, exist_ok=True)
    pkg_dir = base / f"obol-debug-{stamp}"
    shooter = Screenshotter() if screenshots else None
    summary = snapshot(ws, pkg_dir, include_secrets=include_secrets, shooter=shooter,
                       live_url=live_url, live_token=live_token)

    manifest = {
        "schema": SCHEMA,
        "generated_at": summary["at_iso"],
        "engagement": ws.name,
        "active_target": ws.target,
        "include_secrets": include_secrets,
        "screenshot_engine": summary["screenshot_engine"],
        "counts": {k: summary[k] for k in ("facts_total", "runs_total", "events_total")},
        "targets": summary["targets"],
        "env": _env_info(),
    }
    (pkg_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, default=str))
    (pkg_dir / "README.md").write_text(_readme(ws, summary["_written"]))

    zip_path = base / f"obol-debug-{stamp}.zip"
    _zip_dir(pkg_dir, zip_path)
    return zip_path


def capture(resolve_ws, out: Path | None = None, *, interval: int = 30,
            count: int | None = None, duration: int | None = None,
            include_secrets: bool = False, screenshots: bool = True,
            on_tick=None) -> Path:
    """Snapshot on a timer while a test runs, then bundle a `.zip`. `resolve_ws` is
    called each tick to load the current engagement state, so the timeline reflects
    the run as it evolves. Stops after `count` ticks or `duration` seconds, or on
    Ctrl-C. Returns the `.zip` path."""
    stamp = _now_stamp()
    base = Path(out) if out else (resolve_ws().dir / "debug")
    base.mkdir(parents=True, exist_ok=True)
    pkg_dir = base / f"obol-capture-{stamp}"
    timeline = pkg_dir / "timeline"
    timeline.mkdir(parents=True, exist_ok=True)
    shooter = Screenshotter() if screenshots else None

    ticks: list[dict] = []
    start = time.time()
    seq = 0
    try:
        while True:
            seq += 1
            ws = resolve_ws()
            dest = timeline / f"{seq:03d}"
            summary = snapshot(ws, dest, include_secrets=include_secrets, shooter=shooter)
            ticks.append({"seq": seq, "dir": f"timeline/{seq:03d}", **{k: summary[k] for k in
                          ("at_iso", "facts_total", "runs_total", "events_total", "active_target")}})
            if on_tick:
                on_tick(seq, summary)
            if count and seq >= count:
                break
            if duration and (time.time() - start) >= duration:
                break
            time.sleep(interval)
    except KeyboardInterrupt:
        pass

    ws = resolve_ws()
    manifest = {
        "schema": SCHEMA, "mode": "capture", "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "engagement": ws.name, "interval_seconds": interval, "ticks": ticks,
        "screenshot_engine": shooter.note if shooter else "disabled", "env": _env_info(),
    }
    (pkg_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, default=str))
    (pkg_dir / "README.md").write_text(_readme(ws, [
        f"timeline/ — {len(ticks)} snapshot(s) taken every {interval}s during the run; "
        "each folder is a full snapshot (state, facts, events, terminal, site, screenshots).",
        "manifest.json — the tick index with per-tick counts.",
    ]))
    zip_path = base / f"obol-capture-{stamp}.zip"
    _zip_dir(pkg_dir, zip_path)
    return zip_path


def _zip_dir(src: Path, zip_path: Path) -> None:
    src = Path(src)
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in sorted(src.rglob("*")):
            if f.is_file():
                zf.write(f, f.relative_to(src.parent))

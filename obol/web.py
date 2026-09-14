"""Read-only local web view: findings + the path graph.

A single self-contained page built from the current workspace state. It never
executes anything and binds to localhost only — the terminal is the sole actor;
this is just a neat mirror for eyeballing findings and the path before writing
the report. mermaid is loaded from a CDN here for the skeleton; a production
build should vendor it so the page works offline on an exam box.
"""
from __future__ import annotations

import html
from http.server import BaseHTTPRequestHandler, HTTPServer

from .board import action_desc
from .graph import build_mermaid
from .pack import next_actions
from .report import report_status_rows
from .workspace import Workspace

_TEMPLATE = """<!doctype html>
<html><head><meta charset="utf-8"><title>obol · {name}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font: 14px/1.5 system-ui, sans-serif; margin: 0; background: #0b0f14; color: #e6edf3; }}
  header {{ padding: 16px 20px; background: #111820; border-bottom: 1px solid #223; }}
  h1 {{ font-size: 16px; margin: 0; }} h1 small {{ color: #8b98a5; font-weight: 400; }}
  main {{ max-width: 1100px; margin: 0 auto; padding: 20px; }}
  section {{ margin-bottom: 28px; }}
  h2 {{ font-size: 12px; letter-spacing: .08em; text-transform: uppercase; color: #8b98a5; }}
  table {{ width: 100%; border-collapse: collapse; }}
  td, th {{ text-align: left; padding: 6px 10px; border-bottom: 1px solid #1c2530; vertical-align: top; }}
  code {{ color: #e6edf3; background: #161b22; border: 1px solid #30363d; border-radius: 4px; padding: 1px 4px; }}
  .kind {{ color: #58a6ff; font-family: ui-monospace, monospace; white-space: nowrap; }}
  .not {{ color: #d29922; }} .proves {{ color: #3fb950; }}
  .blocked {{ color: #8b98a5; }}
  .graph {{ background: #0d1117; border: 1px solid #1c2530; border-radius: 8px; padding: 12px; overflow-x: auto; }}
</style></head><body>
<header><h1>obol <small>· {name} · {target}</small></h1></header>
<main>
  <section><h2>Key findings</h2><table>{finding_rows}</table></section>
  <section><h2>Report</h2><table>{report_rows}</table></section>
  <section><h2>Path</h2><div class="graph"><pre class="mermaid">{mermaid}</pre></div></section>
  <section><h2>Next</h2><table>{next_rows}</table></section>
  <section><h2>Found so far</h2><table>{facts_rows}</table></section>
</main>
<script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
<script>mermaid.initialize({{ startOnLoad: true, theme: 'dark' }});</script>
</body></html>"""


def _open_ports(ws: Workspace) -> list[tuple[int, str, str]]:
    rows: list[tuple[int, str, str]] = []
    for fact in ws.facts.facts:
        if not fact.kind.startswith("port:"):
            continue
        try:
            port = int(fact.kind.split(":", 1)[1])
        except ValueError:
            continue
        protocol = fact.value.get("protocol", "tcp")
        service = fact.value.get("service", "")
        rows.append((port, protocol, service))
    return sorted(set(rows))


def _key_findings(ws: Workspace) -> str:
    rows: list[tuple[str, str]] = []
    ports = _open_ports(ws)
    if ports:
        rendered = ", ".join(
            f"{port}/{proto}" + (f" {service}" if service else "")
            for port, proto, service in ports[:24]
        )
        if len(ports) > 24:
            rendered += f", +{len(ports) - 24} more"
        rows.append(("Open ports", rendered))
    else:
        rows.append(("Open ports", "none parsed yet"))

    domain = ws.facts.values("ad.domain_known")
    if domain and domain[0].get("name"):
        rows.append(("Domain", domain[0]["name"]))

    if ws.facts.has("credential.available"):
        rows.append(("Credential state", "validated credential available"))
    elif ws.facts.has("credential.candidate"):
        rows.append(("Credential state", "candidate material only, not validated"))
    else:
        rows.append(("Credential state", "no validated credential"))

    if ws.facts.has("access.admin") or ws.facts.has("access.system"):
        rows.append(("Access state", "privileged access proven"))
    elif ws.facts.has("foothold.windows"):
        rows.append(("Access state", "foothold proven, privilege not proven"))
    else:
        rows.append(("Access state", "no access proven"))

    next_up = next_actions(ws.facts)
    if next_up:
        rows.append(("Recommended next", next_up[0].title))

    if ws.runs:
        last = ws.runs[-1]
        rows.append(("Last run", f"{last.get('tool', '')}: {last.get('command', '')}"))

    return _rows(rows)


def _rows(rows: list[tuple[str, str]]) -> str:
    return "".join(
        f"<tr><td class='kind'>{html.escape(label)}</td><td>{html.escape(value)}</td></tr>"
        for label, value in rows
    )


def _report_rows(ws: Workspace) -> str:
    return _rows(report_status_rows(ws))


def build_page(ws: Workspace) -> str:
    facts = ws.facts
    fact_rows = "".join(
        f"<tr><td class='kind'>{html.escape(f.kind)}</td>"
        f"<td>{html.escape(str(f.value))}</td>"
        f"<td class='blocked'>{html.escape(f.source)}</td></tr>"
        for f in sorted(facts.facts, key=lambda x: x.kind)
    ) or "<tr><td>none yet</td></tr>"

    next_rows = "".join(
        f"<tr><td>{i}</td><td>{html.escape(a.title)}</td>"
        f"<td class='blocked'>{html.escape(action_desc(a))}</td></tr>"
        for i, a in enumerate(next_actions(facts), 1)
    ) or "<tr><td>nothing queued</td></tr>"

    return _TEMPLATE.format(
        name=html.escape(ws.name), target=html.escape(ws.target),
        mermaid=html.escape(build_mermaid(facts)),
        finding_rows=_key_findings(ws),
        report_rows=_report_rows(ws),
        facts_rows=fact_rows, next_rows=next_rows,
    )


def serve(ws: Workspace, port: int = 8765) -> None:
    page = build_page  # rebuilt per request so it reflects the latest state on disk

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            fresh = Workspace(ws.root).load()
            body = page(fresh).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    httpd = HTTPServer(("127.0.0.1", port), Handler)
    print(f"obol web view (read-only) at http://127.0.0.1:{port}  ·  Ctrl-C to stop")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")

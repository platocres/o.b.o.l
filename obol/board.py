"""Terminal rendering — the board and command/explain views.

Uses rich when available; degrades to clean ASCII otherwise, so obol runs on any
box. Everything prints to scrollback (never a full-screen live layout) — the
transcript is the operator's evidence log.
"""
from __future__ import annotations

import re

from .facts import FactSet
from .pack import Action, friendly, next_actions, blocked_actions
from .workspace import Workspace

SYM_NEXT = ">>"
SYM_OK = "*"
SYM_BLOCK = "·"

try:                                # pragma: no cover - presentation only
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    _console = Console()
    _RICH = True
except Exception:                   # pragma: no cover
    _console = None
    _RICH = False


# --------------------------------------------------------------------------- #
# command templating — old-obol cards use {{placeholder}} tokens               #
# --------------------------------------------------------------------------- #
def command_context(ws: Workspace) -> dict:
    f = ws.facts
    ctx = {"target": ws.target or "<target>"}
    dom = f.values("ad.domain_known")
    if dom and dom[0].get("name"):
        name = dom[0]["name"]
        ctx["domain"] = name
        ctx["basedn"] = ",".join(f"DC={p}" for p in name.split("."))
        ctx["dc"] = name
    creds = f.values("credential.available") or f.values("credential.plaintext")
    if creds:
        ctx["user"] = creds[0].get("user", "<user>")
        ctx["password"] = creds[0].get("password", "<password>")
    return ctx


def fill_command(action: Action, ws: Workspace) -> str:
    """Substitute known {{tokens}}; leave operator-supplied placeholders visible."""
    cmd = action.command
    for key, val in command_context(ws).items():
        cmd = cmd.replace("{{" + key + "}}", str(val))
    return cmd


# --------------------------------------------------------------------------- #
# board                                                                        #
# --------------------------------------------------------------------------- #
_NOTABLE = [
    ("host.up", "host    up"),
    ("ad.domain_known", "domain  known"),
    ("ad.anonymous_bind", "ad      anonymous LDAP bind allowed"),
    ("ad.user_list", "ad      domain user list obtained"),
    ("ad.graph.collected", "ad      BloodHound graph collected"),
    ("ad.control_paths", "ad      object-control paths mapped"),
    ("hash.asrep", "cred    AS-REP hash (crackable material)"),
    ("hash.tgs", "cred    Kerberoast hash (crackable material)"),
    ("credential.candidate", "cred    candidate credentials (unvalidated)"),
    ("credential.available", "cred    validated credential"),
    ("access.admin", "access  administrative access"),
    ("access.system", "access  SYSTEM"),
    ("foothold.windows", "access  Windows foothold"),
    ("loot.ntds", "loot    NTDS secrets"),
]


def _proven_lines(facts: FactSet) -> list[str]:
    lines: list[str] = []
    for kind, label in _NOTABLE:
        if facts.has(kind):
            extra = ""
            if kind == "host.up":
                os = (facts.values(kind)[0] or {}).get("os", "")
                extra = f" · {os}" if os else ""
            if kind == "ad.domain_known":
                nm = (facts.values(kind)[0] or {}).get("name", "")
                extra = f": {nm}" if nm else ""
            lines.append(label + extra)
    if not (facts.has("credential.available") or facts.has("access.admin") or facts.has("access.system")):
        lines.append("——  no validated credential or privileged access  ——")
    return lines


def render_board(ws: Workspace) -> None:
    facts = ws.facts
    nxt = next_actions(facts)
    blk = blocked_actions(facts)

    if _RICH:
        _console.print(Panel("\n".join(_proven_lines(facts)),
                             title=f"obol · {ws.name} · {ws.target}", border_style="green"))
        t = Table(show_edge=False, expand=True)
        t.add_column("#", justify="right", style="bold cyan", width=3)
        t.add_column("action")
        t.add_column("proves / does not", style="dim")
        for i, a in enumerate(nxt, 1):
            t.add_row(str(i), a.title, f"proves: {a.proves}\nnot: {a.does_not_prove}")
        _console.print(Panel(t, title=f"{SYM_NEXT} NEXT ACTIONS", border_style="cyan"))
        if blk:
            rows = "\n".join(f"{SYM_BLOCK}  {a.title} — {a.unmet(facts)}" for a in blk[:8])
            _console.print(Panel(rows, title="blocked", border_style="grey37"))
        _console.print("[dim]run:[/dim] obol run <#>   [dim]explain:[/dim] obol explain <#>")
    else:
        print(f"\n== obol · {ws.name} · {ws.target} ==")
        print(f"\n{SYM_OK} PROVEN")
        for ln in _proven_lines(facts):
            print(f"   {ln}")
        print(f"\n{SYM_NEXT} NEXT ACTIONS")
        for i, a in enumerate(nxt, 1):
            print(f"  {i}  {a.title}")
            print(f"       proves: {a.proves}")
            print(f"       not:    {a.does_not_prove}")
        if blk:
            print("\n   blocked")
            for a in blk[:8]:
                print(f"   {SYM_BLOCK}  {a.title} — {a.unmet(facts)}")
        print("\nrun: obol run <#>   ·   explain: obol explain <#>\n")


def render_command(action: Action, ws: Workspace) -> None:
    """`explain` — the full Orange card: reasoning, every command variant, refs."""
    primary = fill_command(action, ws)
    ctx = command_context(ws)

    def _fill(run: str) -> str:
        for k, v in ctx.items():
            run = run.replace("{{" + k + "}}", str(v))
        return run

    if _RICH:
        body = [f"[dim]{action.hypothesis}[/dim]\n" if action.hypothesis else ""]
        body.append(f"[green]proves:[/green]   {action.proves}")
        body.append(f"[yellow]does NOT:[/yellow] {action.does_not_prove}\n")
        body.append("[bold]commands[/bold] (you run these):")
        for c in action.commands:
            body.append(f"  [cyan]${_fill(c['run'])}[/cyan]")
            if c.get("note"):
                body.append(f"    [dim]{c['note']}[/dim]")
        if action.refs:
            body.append("\n[dim]refs: " + " · ".join(action.refs) + "[/dim]")
        _console.print(Panel("\n".join(x for x in body if x is not None),
                             title=f"{action.title}  ·  {', '.join(action.tools) or action.tool}",
                             border_style="cyan"))
    else:
        print(f"\n{action.title}  ({', '.join(action.tools) or action.tool})")
        if action.hypothesis:
            print(f"  {action.hypothesis}")
        print(f"  proves:   {action.proves}")
        print(f"  does NOT: {action.does_not_prove}")
        print("  commands:")
        for c in action.commands:
            print(f"    $ {_fill(c['run'])}")
            if c.get("note"):
                print(f"        {c['note']}")
        if action.refs:
            print("  refs: " + " · ".join(action.refs))
        print()

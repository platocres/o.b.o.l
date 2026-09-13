"""Terminal rendering — the board and command views.

Uses rich when available for panels/tables; degrades to clean ASCII otherwise,
so obol runs on any box (the same fallback discipline Charon uses for non-UTF-8
consoles). Everything is printed to scrollback, never a full-screen live layout —
the transcript is the operator's evidence log.
"""
from __future__ import annotations

from .facts import FactSet
from .pack import Action, next_actions, blocked_actions
from .workspace import Workspace

# Semantic ASCII markers (borrowed idea from Charon's _shared symbols).
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
# command templating                                                           #
# --------------------------------------------------------------------------- #
def command_context(ws: Workspace) -> dict:
    f = ws.facts
    ctx = {"target": ws.target or "{target}"}
    domains = f.values("ad.domain")
    if domains:
        name = domains[0].get("name", "")
        ctx["domain"] = name
        ctx["basedn"] = ",".join(f"DC={p}" for p in name.split(".")) if name else "{basedn}"
    creds = f.values("cred.valid")
    if creds:
        ctx["user"] = creds[0].get("user", "{user}")
        ctx["password"] = creds[0].get("password", "{password}")
    asrep = f.values("cred.material.asrep_hash")
    if asrep:
        ctx.setdefault("user", asrep[0].get("user", "{user}"))
        ctx["hash"] = asrep[0].get("hash", "{hash}")
    nt = f.values("cred.material.nt_hash")
    if nt:
        ctx["hash"] = nt[0].get("hash", "{hash}")
    users = f.values("ad.user")
    if users and "user" not in ctx:
        ctx["user"] = users[0].get("sam", "{user}")
    return ctx


def fill_command(action: Action, ws: Workspace) -> str:
    """Best-effort substitution; unknown placeholders are left visible."""
    class _Safe(dict):
        def __missing__(self, key):
            return "{" + key + "}"
    return action.command.format_map(_Safe(command_context(ws)))


# --------------------------------------------------------------------------- #
# board                                                                        #
# --------------------------------------------------------------------------- #
def _proven_lines(facts: FactSet) -> list[str]:
    lines: list[str] = []
    if facts.has("host.up"):
        os = (facts.values("host.up")[0] or {}).get("os", "")
        lines.append(f"host    up{(' · ' + os) if os else ''}")
    if facts.has("ad.domain"):
        dn = facts.values("ad.naming_context")
        ctx = f"  (naming ctx {dn[0]['dn']})" if dn else ""
        lines.append(f"domain  {facts.values('ad.domain')[0]['name']}{ctx}")
    if facts.has("ad.anon_bind"):
        n = len(facts.values("ad.user"))
        lines.append(f"ad      anonymous LDAP bind allowed · {n} users found")
    if facts.has("cred.material.asrep_hash"):
        lines.append(f"cred    AS-REP hash for {facts.values('cred.material.asrep_hash')[0]['user']} (crackable material)")
    if facts.has("cred.valid"):
        c = facts.values("cred.valid")[0]
        lines.append(f"cred    valid: {c['user']}:{c['password']}")
    if facts.has("access.authenticated"):
        a = facts.values("access.authenticated")[0]
        adm = "ADMIN" if a.get("admin") else "user (not admin)"
        lines.append(f"access  authenticated as {a['user']} — {adm}")
    if not facts.has("cred.valid") and not facts.has("access.authenticated"):
        lines.append("——  no credentials proven  ——")
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
            _console.print(Panel("\n".join(f"{SYM_BLOCK}  {a.title} — {a.unmet(facts)}" for a in blk),
                                 title="blocked", border_style="grey37"))
        _console.print(f"[dim]run an action:[/dim] obol run <#>   ·   explain: obol explain <#>")
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
            for a in blk:
                print(f"   {SYM_BLOCK}  {a.title} — {a.unmet(facts)}")
        print("\nrun an action:  obol run <#>    ·    explain:  obol explain <#>\n")


def render_command(action: Action, ws: Workspace) -> None:
    cmd = fill_command(action, ws)
    if _RICH:
        body = f"[bold]{cmd}[/bold]\n\n[green]proves:[/green]   {action.proves}\n[yellow]does NOT:[/yellow] {action.does_not_prove}"
        _console.print(Panel(body, title=f"{action.title}  ·  {action.tool}", border_style="cyan"))
    else:
        print(f"\n{action.title}  ({action.tool})")
        print(f"  {cmd}")
        print(f"  proves:   {action.proves}")
        print(f"  does NOT: {action.does_not_prove}\n")

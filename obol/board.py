"""Terminal rendering — the board and command/explain views.

Uses rich when available; degrades to clean ASCII otherwise, so obol runs on any
box. Everything prints to scrollback (never a full-screen live layout) — the
transcript is the operator's evidence log.
"""
from __future__ import annotations

import re

from .facts import FactSet
from .graph import target_access_level, target_phase
from .pack import Action, friendly, next_actions
from .pivot import engagement_pivots
from .workspace import Workspace

SYM_NEXT = ">>"
SYM_OK = "*"


def action_desc(action: Action) -> str:
    """A short, plain 'what this does' line for the board — no proof language.

    Prefers the first sentence of the card's hypothesis (real operator guidance);
    falls back to a plain phrasing of what it turns up.
    """
    h = (action.hypothesis or "").strip()
    if h:
        first = re.split(r"(?<=[.!?])\s", h)[0].strip()
        return first if len(first) <= 150 else first[:147].rstrip() + "…"
    if action.produces:
        return "turns up " + ", ".join(friendly(k) for k in action.produces)
    return ""

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
def command_context(ws: Workspace, target: str = "", extra: dict | None = None) -> dict:
    """Template values for command rendering. `target` overrides the active host
    (and narrows ports/domain to that host's facts) so a surface can render a
    filled command preview for a specific target without changing active state.

    `extra` pins specific token values (e.g. the exact credential a session login
    chose) and wins over the facts-derived defaults, so a caller that already knows
    which credential to use is not at the mercy of whichever one sorts first."""
    tgt = target or ws.target
    f = ws.facts_for_target(tgt) if target else ws.facts
    ctx = {"target": tgt or "<target>", **ws.inputs}
    ports = _open_ports(f)
    if ports:
        ctx["nmap_ports"] = ",".join(str(p) for p in ports)
    dom = f.values("ad.domain_known")
    if dom and dom[0].get("name"):
        name = dom[0]["name"]
        ctx["domain"] = name
        ctx["basedn"] = ",".join(f"DC={p}" for p in name.split("."))
        ctx["dc"] = name
    # Flag-hunt filename set from the engagement profile (ROADMAP §7), rendered as
    # the `find -iname a -o -iname b` fragment (Linux) and the `-Include a,b` list
    # (Windows) so the flag-hunt pack searches the configured names, not a hardcoded
    # set. Names are validated to safe filename chars inside these helpers.
    try:
        flag_cfg = ws.flag_config() if hasattr(ws, "flag_config") else None
    except Exception:
        flag_cfg = None
    _flag_names = (flag_cfg or {}).get("names") if flag_cfg else None
    from . import profile as _profile
    ctx["flag_inames_linux"] = _profile.linux_iname_expr(_flag_names)
    ctx["flag_names_windows"] = _profile.windows_name_list(_flag_names)
    creds = f.values("credential.available") or f.values("credential.plaintext")
    if creds:
        ctx["user"] = creds[0].get("user", "<user>")
        ctx["password"] = creds[0].get("password", "<password>")
    # an NT hash for pass-the-hash templates ({{nthash}}), from whichever validated
    # credential carries one — a dumped/relayed hash is auth material, not a password.
    for cred in creds:
        nt = cred.get("nthash") or cred.get("hash")
        if nt:
            ctx["nthash"] = nt
            break
    if extra:
        ctx.update({k: v for k, v in extra.items() if v not in (None, "")})
    return ctx


def fill_template(text: str, ws: Workspace, target: str = "", extra: dict | None = None) -> str:
    """Substitute known {{tokens}}; leave operator-supplied placeholders visible."""
    cmd = text
    for key, val in command_context(ws, target, extra).items():
        cmd = cmd.replace("{{" + key + "}}", str(val))
    return cmd


def fill_command(action: Action, ws: Workspace, command_index: int = 0, target: str = "",
                 extra: dict | None = None) -> str:
    """Fill command variant N (zero-based); default to the action's primary command."""
    commands = action.commands or [{"run": action.command}]
    if not 0 <= command_index < len(commands):
        raise IndexError("command variant out of range")
    return fill_template(commands[command_index].get("run", action.command), ws, target, extra)


# --------------------------------------------------------------------------- #
# board                                                                        #
# --------------------------------------------------------------------------- #
_NOTABLE = [
    ("host.up", "host    up"),
    ("host.os_family", "host    OS family"),
    ("scan.nmap.quick", "scan    quick nmap complete"),
    ("scan.nmap.version", "scan    version/script nmap complete"),
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
    ("foothold.linux", "access  Linux foothold"),
    ("privesc.leads", "privesc local escalation leads"),
    ("loot.ntds", "loot    NTDS secrets"),
]


def _open_ports(facts: FactSet) -> list[int]:
    ports: set[int] = set()
    for fact in facts.facts:
        if fact.kind.startswith("port:"):
            try:
                ports.add(int(fact.kind.split(":", 1)[1]))
            except ValueError:
                continue
    return sorted(ports)


def _target_label(ws: Workspace, host: str) -> str:
    rec = ws.get_target(host)
    return (rec or {}).get("label") or host or "<no target>"


def _target_facts(ws: Workspace, host: str = "") -> FactSet:
    target = host or ws.target
    return ws.facts_for_target(target) if target else ws.facts


def _services_line(facts: FactSet, limit: int = 10) -> str:
    ports = _open_ports(facts)
    if not ports:
        return "-"
    shown = ", ".join(str(p) for p in ports[:limit])
    if len(ports) > limit:
        shown += f", +{len(ports) - limit}"
    return shown


def _proven_lines(facts: FactSet) -> list[str]:
    lines: list[str] = []
    for kind, label in _NOTABLE:
        if facts.has(kind):
            extra = ""
            if kind == "host.up":
                os = (facts.values(kind)[0] or {}).get("os", "")
                extra = f" · {os}" if os else ""
            if kind == "host.os_family":
                family = (facts.values(kind)[0] or {}).get("family", "")
                extra = f": {family}" if family else ""
            if kind == "ad.domain_known":
                nm = (facts.values(kind)[0] or {}).get("name", "")
                extra = f": {nm}" if nm else ""
            lines.append(label + extra)
    ports = _open_ports(facts)
    if ports:
        shown = ", ".join(str(p) for p in ports[:18])
        if len(ports) > 18:
            shown += f", +{len(ports) - 18} more"
        lines.append(f"ports   open: {shown}")
    if not (facts.has("credential.available") or facts.has("access.admin") or facts.has("access.system")):
        lines.append("——  no validated credential or privileged access  ——")
    return lines


def render_board(ws: Workspace) -> None:
    """Proven so far + the live actions that matter. No blocked list, no proof talk."""
    facts = _target_facts(ws)
    nxt = next_actions(facts)
    active = _target_label(ws, ws.target)

    if _RICH:
        _console.print(Panel("\n".join(_proven_lines(facts)),
                             title=f"obol · {ws.name} · {active}", border_style="green"))
        t = Table(show_edge=False, expand=True)
        t.add_column("#", justify="right", style="bold cyan", width=3)
        t.add_column("do this")
        t.add_column("", style="dim")
        for i, a in enumerate(nxt, 1):
            t.add_row(str(i), a.title, action_desc(a))
        _console.print(Panel(t, title=f"{SYM_NEXT} NEXT", border_style="cyan"))
        _console.print("[dim]run:[/dim] obol run <#>   [dim]see the command:[/dim] obol explain <#>")
    else:
        print(f"\n== obol · {ws.name} · {active} ==")
        print(f"\n{SYM_OK} PROVEN")
        for ln in _proven_lines(facts):
            print(f"   {ln}")
        print(f"\n{SYM_NEXT} NEXT")
        for i, a in enumerate(nxt, 1):
            print(f"  {i}  {a.title}")
            desc = action_desc(a)
            if desc:
                print(f"       {desc}")
        print("\nrun: obol run <#>   ·   see the command: obol explain <#>\n")


def render_overview(ws: Workspace, *, max_moves: int = 3) -> None:
    """Compact engagement-wide terminal view: scope, hosts, services, next moves."""
    if _RICH:
        scope_body = "\n".join(ws.scope) if ws.scope else "empty"
        _console.print(Panel(scope_body, title=f"scope · {ws.name}", border_style="green"))

        t = Table(show_edge=False, expand=True)
        t.add_column("", width=1)
        t.add_column("target", style="bold")
        t.add_column("identity")
        t.add_column("domain")
        t.add_column("os")
        t.add_column("state")
        t.add_column("ports", style="cyan")
        t.add_column("next")
        for rec in ws.targets:
            host = rec["host"]
            facts = _target_facts(ws, host)
            moves = " | ".join(a.title for a in next_actions(facts)[:max_moves]) or "-"
            identity = rec.get("fqdn") or rec.get("hostname") or rec.get("label") or "-"
            state = f"{target_access_level(facts)} / {target_phase(facts)}"
            t.add_row(
                "*" if host == ws.target else "",
                host,
                identity,
                rec.get("domain") or "-",
                rec.get("os") or "-",
                state,
                _services_line(facts),
                moves,
            )
        _console.print(Panel(t, title=f"{SYM_NEXT} engagement overview", border_style="cyan"))
        pivots = _pivot_lines(ws)
        if pivots:
            _console.print(Panel("\n".join(pivots), title="pivot candidates", border_style="magenta"))
        _console.print("[dim]scan scope:[/dim] obol scan   [dim]active target:[/dim] obol target use <host>   [dim]next:[/dim] obol next")
        return

    print(f"\n== obol overview - {ws.name} ==")
    print("\nSCOPE")
    if ws.scope:
        for entry in ws.scope:
            print(f"  {entry}")
    else:
        print("  empty")
    print("\nTARGETS")
    if not ws.targets:
        print("  none yet")
    for rec in ws.targets:
        host = rec["host"]
        facts = _target_facts(ws, host)
        moves = "; ".join(a.title for a in next_actions(facts)[:max_moves]) or "-"
        identity = rec.get("fqdn") or rec.get("hostname") or rec.get("label") or "-"
        mark = "*" if host == ws.target else " "
        print(f" {mark} {host:16} {identity}")
        print(f"    domain: {rec.get('domain') or '-'}   os: {rec.get('os') or '-'}   state: {target_access_level(facts)} / {target_phase(facts)}")
        print(f"    ports:  {_services_line(facts)}")
        print(f"    next:   {moves}")
    pivots = _pivot_lines(ws)
    if pivots:
        print("\nPIVOT CANDIDATES")
        for line in pivots:
            print(f"  {line}")
    print("\nscan scope: obol scan   |   active target: obol target use <host>   |   next: obol next\n")


def _pivot_lines(ws: Workspace) -> list[str]:
    """One line per host with a pivot-candidate lead — multi-homed status and the
    candidate adjacent subnets, tagged when a subnet isn't in scope yet."""
    lines: list[str] = []
    for piv in engagement_pivots(ws):
        subs = ", ".join(
            s["cidr"] + ("" if s["in_scope"] else " (not in scope)")
            for s in piv["subnets"][:6]
        ) or "-"
        tag = "multi-homed" if piv["multihomed"] else "adjacent subnet"
        lines.append(f"{piv['host']:16} {tag}: {subs}")
    return lines


def render_step_command(step, action: Action, ws: Workspace) -> str:
    """Render a playbook step's command as the runner would build it (no execution).

    Unknown {{tokens}} (e.g. ports not yet scanned) are left visible — they signal
    the step depends on evidence an earlier step gathers; the runner refuses to run
    a command that still has an unfilled token.
    """
    cmd = fill_command(action, ws, max(0, (getattr(step, "cmd", 1) or 1) - 1))
    extra = fill_template(step.args_extra, ws).strip() if getattr(step, "args_extra", "") else ""
    return f"{cmd} {extra}".strip() if extra else cmd


def render_playbook(pb, steps, ws: Workspace) -> None:
    """Plan view for a playbook: the ordered command sequence. Executes nothing.

    Stays within the product's UX guardrails — an ordered plan with the exact
    commands and a marker for the noisy steps that need `--approve`; no
    proves/blocked language.
    """
    if _RICH:
        body: list[str] = []
        if pb.description:
            body.append(f"[dim]{pb.description}[/dim]\n")
        for i, (step, action) in enumerate(steps, 1):
            tag = " [yellow](--approve)[/yellow]" if step.require_approval else ""
            body.append(f"[bold cyan]{i}.[/bold cyan] {step.label}{tag}  [dim]{action.id}[/dim]")
            body.append(f"   [cyan]$ {render_step_command(step, action, ws)}[/cyan]")
            if step.note:
                body.append(f"   [dim]{step.note}[/dim]")
        _console.print(Panel("\n".join(body), title=f"playbook · {pb.title}", border_style="cyan"))
        _console.print(f"[dim]run a step:[/dim] obol playbook {pb.name} --step <n>   "
                       f"[dim](steps marked (--approve) need it)[/dim]")
    else:
        print(f"\n== playbook · {pb.title} ==")
        if pb.description:
            print(f"  {pb.description}")
        for i, (step, action) in enumerate(steps, 1):
            tag = "  (--approve)" if step.require_approval else ""
            print(f"\n  {i}. {step.label}{tag}   [{action.id}]")
            print(f"     $ {render_step_command(step, action, ws)}")
            if step.note:
                print(f"     {step.note}")
        print(f"\nrun a step: obol playbook {pb.name} --step <n>   ·   noisy steps need --approve\n")


def render_command(action: Action, ws: Workspace) -> None:
    """`explain` — the full Orange card: reasoning, every command variant, refs."""
    ctx = command_context(ws)

    def _fill(run: str) -> str:
        for k, v in ctx.items():
            run = run.replace("{{" + k + "}}", str(v))
        return run

    if _RICH:
        body = [f"[dim]{action.hypothesis}[/dim]\n" if action.hypothesis else ""]
        body.append("[bold]commands[/bold] (you run these):")
        for i, c in enumerate(action.commands, 1):
            body.append(f"  [bold cyan]{i}.[/bold cyan] [cyan]${_fill(c['run'])}[/cyan]")
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
        print("  commands:")
        for i, c in enumerate(action.commands, 1):
            print(f"    {i}. $ {_fill(c['run'])}")
            if c.get("note"):
                print(f"        {c['note']}")
        if action.refs:
            print("  refs: " + " · ".join(action.refs))
        print()

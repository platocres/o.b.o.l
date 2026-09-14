"""obol command-line surface.

Deliberately shell subcommands (PentOS-style), not an in-process REPL: every
action is independently re-runnable and leaves an explicit command in the
scrollback, which is what OSCP documentation needs. The loop is the human
running `obol next` -> `obol run N` -> `obol next` again.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, board, discovery, library, quickstart, service, sessions
from .facts import Fact
from .pack import load_packs, next_actions
from .runner import RunnerError
from .scope import extract_ip_scope_entries, normalize_scope_entry, target_in_scope
from .seed import seed_forest
from .service import ActionError
from .sessions import SessionError
from .workspace import Workspace, find_workspace


def _load_or_exit() -> Workspace:
    """Resolve the working engagement: a `.obol` in the current directory tree, else
    the active engagement in the app-managed library."""
    ws = find_workspace() or library.resolve_active()
    if ws is None:
        print("no obol workspace here. run `obol init`, or `obol engagement new <name>`.",
              file=sys.stderr)
        raise SystemExit(1)
    return ws


def _pick(ws: Workspace, n: int):
    facts = ws.facts_for_target(ws.target) if ws.target else ws.facts
    actions = next_actions(facts)
    if not 1 <= n <= len(actions):
        print(f"no next action #{n}. `obol next` lists {len(actions)}.", file=sys.stderr)
        raise SystemExit(1)
    return actions[n - 1]


def _apply_input_overrides(ws: Workspace, values: list[str]) -> None:
    for row in values:
        if "=" not in row:
            print(f"--set expects KEY=VALUE, got {row!r}", file=sys.stderr)
            raise SystemExit(1)
        key, value = row.split("=", 1)
        key = key.strip()
        if not key:
            print("--set key cannot be empty", file=sys.stderr)
            raise SystemExit(1)
        ws.set_input(key, value.strip())


def _version_text() -> str:
    return f"obol {__version__}"


def _workspace_or_none() -> Workspace | None:
    return find_workspace() or library.resolve_active()


def _print_info() -> None:
    ws = _workspace_or_none()
    print(_version_text())
    if ws is None:
        print("workspace: none")
        print("start:     obol engagement new <name>")
        return
    print(f"workspace: {ws.root}")
    print(f"name:      {ws.name}")
    print(f"target:    {ws.target or '-'}")
    print(f"scope:     {len(ws.scope)} entr{'y' if len(ws.scope) == 1 else 'ies'}")
    print(f"targets:   {len(ws.targets)}")
    print(f"facts:     {len(ws.facts.facts)}")
    print(f"runs:      {len(ws.runs)}")
    print("web:       obol serve")


def _manual_text() -> str:
    return """obol manual

Core loop
  obol engagement new "HTB Lab"      create an engagement
  obol scope add 10.10.10.0/24       authorize a lab range
  obol scan                          sweep every scope entry, then Quick Start hosts
  obol overview                      show scope, hosts, ports, and next moves
  obol target use 10.10.10.5         switch active target
  obol next                          show next moves for the active target
  obol explain 1                     show the exact command choices
  obol run 1                         run, parse, store facts, and update next moves
  obol serve                         open the localhost web console over the same store
  obol report                        write the OSCP-style report

Scope
  obol scope list
  obol scope add 10.10.10.5 10.10.10.7 10.10.10.0/24
  obol scope paste "hosts: 10.10.10.5, bad text, 10.10.10.0/24"
  cat notes.txt | obol scope paste
  obol scope rm 10.10.10.5

Scanning
  obol scan                          scan every current scope entry
  obol scan 10.10.10.0/24            authorize and scan that range
  obol scan --extract "10.10.10.5 junk 10.10.10.0/24"
  obol scan --no-enumerate           discovery only
  obol scan --new-only               Quick Start only newly discovered targets
  obol sweep 10.10.10.0/24           sweep one range and Quick Start new hosts

Help and diagnostics
  obol --help
  obol help <command>
  obol --version
  obol info
"""


def cmd_help(args) -> None:
    parser = build_parser()
    topic = getattr(args, "topic", "")
    if topic:
        parser.parse_args([topic, "--help"])
    parser.print_help()


def cmd_manual(args) -> None:
    print(_manual_text().rstrip())


def cmd_version(args) -> None:
    print(_version_text())


def cmd_info(args) -> None:
    _print_info()


def _add_scope_values(ws: Workspace, values: list[str], *, extract_only: bool = False) -> tuple[list[str], list[str], list[str]]:
    added: list[str] = []
    existing: list[str] = []
    rejected: list[str] = []
    candidates = extract_ip_scope_entries(" ".join(values)) if extract_only else values
    for value in candidates:
        norm = normalize_scope_entry(value)
        if not norm:
            rejected.append(value)
            continue
        before = set(ws.scope)
        stored = ws.add_scope(norm)
        if stored in before:
            existing.append(stored)
        else:
            added.append(stored)
    return added, existing, rejected


def _read_scope_paste(args) -> str:
    chunks: list[str] = []
    if getattr(args, "file", None):
        chunks.append(Path(args.file).read_text())
    if getattr(args, "text", None):
        chunks.append(" ".join(args.text))
    if not chunks and not sys.stdin.isatty():
        chunks.append(sys.stdin.read())
    return "\n".join(chunks)


def _print_scope_result(added: list[str], existing: list[str], rejected: list[str]) -> None:
    for value in added:
        print(f"added scope: {value}")
    for value in existing:
        print(f"already scoped: {value}")
    for value in rejected:
        print(f"ignored: {value}")
    if not (added or existing or rejected):
        print("no valid scope entries found")


def cmd_init(args) -> None:
    cwd = Path.cwd()
    ws = Workspace(cwd)
    if ws.exists():
        print(f"workspace already initialized at {ws.dir}")
        return
    # A workspace is an engagement directory, not the code checkout. Warn (don't
    # block) if someone runs `init` inside the obol source tree.
    if (cwd / "obol" / "pack.py").exists() and (cwd / "pyproject.toml").exists():
        print("note: this looks like the obol source tree — obol keeps its state in the\n"
              "      current directory. Prefer an engagement dir: "
              "`mkdir -p ~/labs/box && cd ~/labs/box`.", file=sys.stderr)
    if args.demo:
        seed_forest(ws)
        msg = "initialized demo workspace (HTB Forest, post-nmap)."
    else:
        ws.target = args.target or ""
        if ws.target:
            ws.add_scope(ws.target)
            ws.facts.add(Fact("target.configured", f"host:{ws.target}", {"target": ws.target}, source="obol init --target"))
        msg = "initialized empty workspace."
    try:
        ws.save()
    except OSError as e:
        print(f"error: cannot create the workspace at {ws.dir}\n  {e}\n"
              "Pick a directory you can write to. If you cloned with `sudo`, the checkout\n"
              "is root-owned — re-clone without sudo (or chown it) and run obol from a\n"
              "normal directory you own.", file=sys.stderr)
        raise SystemExit(1)
    print(msg)
    print("next: obol next")


def cmd_next(args) -> None:
    ws = _load_or_exit()
    if getattr(args, "all", False):
        board.render_overview(ws)
    else:
        board.render_board(ws)


def cmd_overview(args) -> None:
    board.render_overview(_load_or_exit())


def cmd_explain(args) -> None:
    ws = _load_or_exit()
    board.render_command(_pick(ws, args.n), ws)


def _run_action(ws, action, *, command_index, timeout, dry_run, allow_shell,
                args_extra="", ledger_extra=None):
    """Terminal wrapper over the shared run service (`service.run_action`).

    The service is the one runner/parser/store path — the web run-from-site surface
    calls the same function. Here we only add scrollback output; on a bad command
    variant or a runner refusal we exit with a clear message.
    """
    try:
        cmd, _tool = service.build_command(
            action, ws, command_index=command_index, args_extra=args_extra
        )
    except ActionError as exc:
        print(f"{exc}", file=sys.stderr)
        raise SystemExit(1)
    print(f"\n$ {cmd}")
    try:
        outcome = service.run_action(
            ws, action,
            command_index=command_index, timeout=timeout,
            dry_run=dry_run, allow_shell=allow_shell,
            args_extra=args_extra, ledger_extra=ledger_extra,
        )
    except RunnerError as exc:
        print(f"\nerror: {exc}", file=sys.stderr)
        raise SystemExit(1)

    added = outcome.added
    if outcome.dry_run:
        print("\ndry run only — command was not executed and no facts were ingested.")
    elif added:
        print(f"\n{board.SYM_OK} ingested — new facts:")
        for f in added:
            detail = f.value.get("password") or f.value.get("hash") or f.value.get("sam") or f.value.get("count") or ""
            print(f"   + {f.kind}" + (f"  ({detail})" if detail else ""))
    else:
        print("\n(no new facts parsed — raw output was still saved)")
    return outcome.result, added


def cmd_run(args) -> None:
    ws = _load_or_exit()
    _apply_input_overrides(ws, args.set)
    action = _pick(ws, args.n)
    _run_action(
        ws, action,
        command_index=max(0, args.cmd - 1),
        timeout=args.timeout,
        dry_run=args.dry_run,
        allow_shell=args.allow_shell,
    )
    print("\nnext: obol next")


def cmd_playbooks(args) -> None:
    from . import playbook
    pbs = playbook.list_playbooks()
    if not pbs:
        print("no playbooks available.")
        return
    print("\nplaybooks:")
    for pb in pbs:
        print(f"  {pb.name:14} {pb.title}")
        if pb.description:
            print(f"  {'':14} {pb.description}")
    print("\nplan a playbook: obol playbook <name>")
    print("run one step:    obol playbook <name> --step N [--approve]")


def cmd_playbook(args) -> None:
    from . import playbook
    ws = _load_or_exit()
    _apply_input_overrides(ws, args.set)
    try:
        pb = playbook.load_playbook(args.name)
    except FileNotFoundError:
        names = ", ".join(p.name for p in playbook.list_playbooks()) or "(none)"
        print(f"no playbook named {args.name!r}. available: {names}", file=sys.stderr)
        raise SystemExit(1)
    try:
        steps = playbook.resolve_steps(pb, load_packs())
    except KeyError as exc:
        print(f"playbook {pb.name!r} references unknown pack action {exc}", file=sys.stderr)
        raise SystemExit(1)

    # No --step: plan view only. This never executes anything.
    if args.step is None:
        board.render_playbook(pb, steps, ws)
        return

    n = args.step
    if not 1 <= n <= len(steps):
        print(f"playbook {pb.name!r} has {len(steps)} step(s); no step #{n}.", file=sys.stderr)
        raise SystemExit(1)
    step, action = steps[n - 1]
    if step.require_approval and not args.approve and not args.dry_run:
        print(f"step {n} ({step.label}) is marked require_approval — it is noisy or intrusive.")
        print("re-run with --approve to execute it, or --dry-run to preview the command.")
        raise SystemExit(2)

    _run_action(
        ws, action,
        command_index=max(0, (step.cmd or 1) - 1),
        timeout=args.timeout,
        dry_run=args.dry_run,
        allow_shell=args.allow_shell,
        args_extra=step.args_extra,
        ledger_extra={"playbook": pb.name, "playbook_step": n},
    )
    if not args.dry_run and n < len(steps):
        print(f"\nnext: obol next   ·   continue: obol playbook {pb.name} --step {n + 1}")
    else:
        print("\nnext: obol next")


def cmd_facts(args) -> None:
    ws = _load_or_exit()
    for f in sorted(ws.facts.facts, key=lambda x: x.kind):
        print(f"  {f.state.value:12} {f.kind:28} {f.value}")


def cmd_sweep(args) -> None:
    ws = _load_or_exit()
    range_ = args.range.strip()
    if range_ not in ws.scope:
        # Typing the range at the CLI is an explicit authorization; record it in
        # scope so the runner gate (and any later web sweep) sees it.
        added = ws.add_scope(range_)
        if not added:
            print(f"not a valid host, IP, or CIDR: {range_!r}")
            return
        range_ = added
        ws.save()
        print(f"authorized scope: {range_}")
    try:
        summary = discovery.run_sweep(ws, range_, dry_run=args.dry_run, timeout=args.timeout)
    except RunnerError as exc:
        print(f"sweep refused: {exc}")
        return
    if args.dry_run:
        print(summary["command"])
        return
    hosts, created = summary["hosts"], summary["created"]
    print(f"swept {range_}: {len(hosts)} live host(s), {len(created)} new target(s)")
    for host in created:
        print(f"  + {host}")
    for host in summary["existing"]:
        print(f"    {host} (already a target)")
    if not args.no_enumerate and created:
        _quickstart_targets(ws, created, timeout=args.quick_timeout,
                            dry_run=False, allow_shell=args.allow_shell)


def _targets_in_entries(ws: Workspace, entries: list[str]) -> list[str]:
    hosts: list[str] = []
    for rec in ws.targets:
        if any(target_in_scope(rec["host"], [entry])[0] for entry in entries):
            hosts.append(rec["host"])
    return hosts


def _quickstart_targets(
    ws: Workspace,
    hosts: list[str],
    *,
    timeout: int,
    dry_run: bool,
    allow_shell: bool,
) -> list[quickstart.QuickStartResult]:
    results: list[quickstart.QuickStartResult] = []
    seen: set[str] = set()
    for host in hosts:
        if host in seen:
            continue
        seen.add(host)
        label = (ws.get_target(host) or {}).get("label") or host
        print(f"\n== Quick Start - {label} ({host}) ==")

        def on_step(step: quickstart.QuickStartStep) -> None:
            if step.status == "running":
                print(f"$ {step.command}")
            elif step.status in {"success", "failed", "timeout", "dry-run"}:
                facts = f" +{len(step.added)} fact(s)" if step.added else ""
                print(f"  {step.status}: {step.title}{facts}")
            elif step.status not in {"waiting"}:
                reason = f" ({step.reason})" if step.reason else ""
                print(f"  {step.status}: {step.title}{reason}")

        result = quickstart.run_quickstart(
            ws, host, timeout=timeout, dry_run=dry_run,
            allow_shell=allow_shell, on_step=on_step,
        )
        results.append(result)
        print(f"stored {len(result.facts)} new fact(s); skipped {len(result.skipped)} step(s)")
    return results


def cmd_scan(args) -> None:
    ws = _load_or_exit()
    if args.entries:
        added, existing, rejected = _add_scope_values(ws, args.entries, extract_only=args.extract)
        if added or existing:
            ws.save()
        _print_scope_result(added, existing, rejected)
        entries = list(dict.fromkeys(added + existing))
    else:
        entries = list(ws.scope)
    if not entries:
        print("scope is empty. add scope first: obol scope add <ip-or-cidr>")
        return

    all_created: list[str] = []
    print(f"\nscanning {len(entries)} scope entr{'y' if len(entries) == 1 else 'ies'}")
    for entry in entries:
        try:
            summary = discovery.run_sweep(ws, entry, dry_run=args.dry_run, timeout=args.timeout)
        except RunnerError as exc:
            print(f"  refused {entry}: {exc}")
            continue
        if args.dry_run:
            print(f"  {entry}: {summary['command']}")
            continue
        all_created.extend(summary["created"])
        print(
            f"  {entry}: {len(summary['hosts'])} live, "
            f"{len(summary['created'])} new, {len(summary['existing'])} existing"
        )

    if args.dry_run or args.no_enumerate:
        return

    hosts = all_created if args.new_only else _targets_in_entries(ws, entries)
    if not hosts:
        print("\nno targets to enumerate yet")
        return
    _quickstart_targets(ws, hosts, timeout=args.quick_timeout,
                        dry_run=False, allow_shell=args.allow_shell)
    print("\nnext: obol overview")


def cmd_scope(args) -> None:
    ws = _load_or_exit()
    if args.scope_cmd == "add":
        added, existing, rejected = _add_scope_values(ws, args.values)
        if added or existing:
            ws.save()
        _print_scope_result(added, existing, rejected)
        return
    if args.scope_cmd == "paste":
        text = _read_scope_paste(args)
        added, existing, rejected = _add_scope_values(ws, [text], extract_only=True)
        if added or existing:
            ws.save()
        _print_scope_result(added, existing, rejected)
        return
    if args.scope_cmd in {"rm", "remove"}:
        removed = []
        missing = []
        for value in args.values:
            if any(t.get("host") == normalize_scope_entry(value) for t in ws.targets):
                print(f"refused: {value} is a target; remove the target before removing its scope")
                continue
            if ws.remove_scope(value):
                removed.append(value)
            else:
                missing.append(value)
        if removed:
            ws.save()
        for value in removed:
            print(f"removed scope: {value}")
        for value in missing:
            print(f"not in scope: {value}")
        return
    if args.scope_cmd == "clear":
        blocked = {t.get("host") for t in ws.targets}
        removable = [entry for entry in ws.scope if normalize_scope_entry(entry) not in blocked]
        for entry in removable:
            ws.remove_scope(entry)
        if removable:
            ws.save()
        print(f"removed {len(removable)} non-target scope entr{'y' if len(removable) == 1 else 'ies'}")
        if blocked:
            print("kept target scope entries; remove targets first to clear those")
        return
    if ws.scope:
        for entry in ws.scope:
            marker = "target" if any(t.get("host") == entry for t in ws.targets) else "scope"
            print(f"{entry}  [{marker}]")
    else:
        print("scope is empty")


def cmd_serve(args) -> None:
    from . import webapp
    ws = find_workspace()   # optional: link a cwd engagement into the library
    try:
        webapp.serve(ws, host=args.host, port=args.port)
    except SystemExit:
        raise
    except OSError as exc:
        print(f"error: could not bind {args.host}:{args.port} — {exc}", file=sys.stderr)
        raise SystemExit(1)


def cmd_engagement(args) -> None:
    sub = getattr(args, "engagement_cmd", "list")
    if sub == "new":
        ws = library.create_engagement(args.name)
        print(f"created engagement {ws.name!r} (slug {ws.root.name}) and set it active")
        print("add a target: obol target add <ip>")
        return
    if sub == "use":
        if not library.get_engagement(args.slug):
            print(f"no engagement {args.slug!r}. see `obol engagement list`.", file=sys.stderr)
            raise SystemExit(1)
        library.set_active(args.slug)
        print(f"active engagement: {args.slug}")
        return
    engs = library.list_engagements()
    if not engs:
        print("no engagements yet. create one: obol engagement new <name>")
        return
    for e in engs:
        mark = "*" if e["active"] else " "
        print(f" {mark} {e['slug']:22} {e['name']}  ({e['targets']} targets, {e['facts']} facts)")


def cmd_target(args) -> None:
    ws = _load_or_exit()
    sub = getattr(args, "target_cmd", "list")
    if sub == "add":
        if args.label and len(args.hosts) != 1:
            print("--label can only be used when adding one target", file=sys.stderr)
            raise SystemExit(1)
        for host in args.hosts:
            norm = normalize_scope_entry(host)
            if not norm:
                print(f"ignored invalid target: {host}")
                continue
            rec = ws.add_target(norm, args.label or "")
            print(f"added target {rec['label']} ({rec['host']})" + ("  [active]" if ws.target == rec["host"] else ""))
        ws.save()
        return
    if sub == "use":
        if not ws.set_active_target(args.host):
            print(f"no target {args.host!r} in this engagement.", file=sys.stderr)
            raise SystemExit(1)
        ws.save()
        print(f"active target: {ws.target}")
        return
    if sub == "rm":
        if not ws.remove_target(args.host):
            print(f"no target {args.host!r}.", file=sys.stderr)
            raise SystemExit(1)
        ws.save()
        print(f"removed target {args.host}")
        return
    if not ws.targets:
        print("no targets yet. add one: obol target add <ip>")
        return
    for t in ws.targets:
        mark = "*" if t["host"] == ws.target else " "
        print(f" {mark} {t['host']:16} {t.get('label', '')}")


def cmd_web(args) -> None:
    from . import web
    ws = _load_or_exit()
    out = Path(args.out) if args.out else (ws.dir / "web" / "index.html")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(web.build_page(ws))
    print(f"wrote {out}")


def cmd_report(args) -> None:
    from .report import write_report
    ws = _load_or_exit()
    out = Path(args.out) if args.out else None
    # Show secrets by default (lab/exam notes); `--redact` opts into redaction for a
    # draft you intend to share. `--include-secrets` is kept as a harmless no-op.
    include_secrets = not args.redact
    path = write_report(ws, out=out, include_secrets=include_secrets, max_next=args.max_next)
    print(f"wrote {path}")
    if include_secrets:
        print("secrets shown — this report contains passwords/hashes; use --redact for a shareable draft")
    else:
        print("secrets redacted")


def cmd_debug(args) -> None:
    from . import debug
    ws = _load_or_exit()
    out = Path(args.out) if getattr(args, "out", None) else None
    screenshots = not getattr(args, "no_screenshots", False)
    if getattr(args, "debug_cmd", "package") == "capture":
        print(f"capturing every {args.interval}s — Ctrl-C to stop and bundle…")
        zip_path = debug.capture(
            lambda: _load_or_exit(), out=out, interval=args.interval,
            count=args.count, duration=args.duration,
            include_secrets=args.include_secrets, screenshots=screenshots,
            on_tick=lambda seq, s: print(f"  snapshot {seq}: {s['facts_total']} facts · {s['runs_total']} runs"),
        )
    else:
        zip_path = debug.build_debug_package(
            ws, out=out, include_secrets=args.include_secrets, screenshots=screenshots,
            live_url=getattr(args, "url", "") or "", live_token=getattr(args, "token", "") or "")
    print(f"wrote {zip_path}")
    if not args.include_secrets:
        print("secrets redacted in report.md — raw run output under runs/ is verbatim; treat the package as sensitive")


def _pick_login_kind(ws: Workspace, host: str, requested: str) -> str:
    """Resolve which login kind to open: the one requested, or the single ready
    offer, else print the choices and exit."""
    offers = sessions.eligible_sessions(ws, host)
    if requested:
        return requested
    ready = [o for o in offers if o["ready"]]
    if len(ready) == 1:
        return ready[0]["kind"]
    if not offers:
        print(f"no login is available for {host} yet — need a validated credential "
              f"and a reachable service (winrm/ssh/rdp).", file=sys.stderr)
        raise SystemExit(1)
    print(f"pick a login kind for {host} with --kind:")
    for o in offers:
        state = "ready" if o["ready"] else f"not ready ({o['reason']})"
        print(f"  {o['kind']:<6} {o['label']}  — {state}")
    raise SystemExit(1)


def cmd_login(args) -> None:
    ws = _load_or_exit()
    host = args.target or ws.target
    if not host:
        print("no target — pass a host or set an active target.", file=sys.stderr)
        raise SystemExit(1)
    kind = _pick_login_kind(ws, host, args.kind)
    print(f"\n$ validating {kind} access on {host} …")
    try:
        res = sessions.open_session(ws, host, kind, method=args.method,
                                    dry_run=args.dry_run, surface="cli")
    except (SessionError, ActionError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
    except RunnerError as exc:
        print(f"\nerror: {exc}", file=sys.stderr)
        raise SystemExit(1)
    if args.dry_run:
        print(f"\ndry run — would validate with:\n   $ {res['outcome'].command}")
        print(f"then hand off the interactive login:\n   $ {res['login_command']}")
        return
    if not res["ok"]:
        print(f"\n✗ {res['reason']}")
        raise SystemExit(1)
    s = res["session"]
    via = " via pass-the-hash" if res.get("method") == "pth" else ""
    print(f"\n{board.SYM_OK} access proven{via} ({s['proof_fact']}) — session {s['id']} recorded (status: {s['status']}).")
    print("\nlaunch the interactive session in your terminal:")
    print(f"   $ {res['login_command']}")
    print("\nprivesc moves for this host are now unlocked — `obol next`.")


def cmd_sessions(args) -> None:
    ws = _load_or_exit()
    if not ws.sessions:
        print("no sessions yet. establish one with `obol login <host>`.")
        return
    print(f"{'ID':<20} {'HOST':<16} {'KIND':<6} {'USER':<18} STATUS")
    for s in ws.sessions:
        print(f"{s['id']:<20} {s['host']:<16} {s['kind']:<6} {(s.get('user') or '-'):<18} {s['status']}")


def cmd_session(args) -> None:
    ws = _load_or_exit()
    cmd = getattr(args, "session_cmd", "list")
    if cmd == "close":
        if not ws.close_session(args.id):
            print(f"no session {args.id!r}", file=sys.stderr)
            raise SystemExit(1)
        ws.save()
        print(f"closed {args.id}")
    elif cmd == "rm":
        if not ws.remove_session(args.id):
            print(f"no session {args.id!r}", file=sys.stderr)
            raise SystemExit(1)
        ws.save()
        print(f"removed {args.id}")
    elif cmd == "probe":
        print(f"$ re-validating session {args.id} …")
        try:
            res = sessions.probe_session(ws, args.id)
        except (SessionError, ActionError, RunnerError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            raise SystemExit(1)
        print(f"session {args.id}: {'active' if res['alive'] else 'dead'}")
    else:
        cmd_sessions(args)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="obol",
        description="Evidence-driven OSCP operator companion.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""common flow:
  obol engagement new "HTB Lab"
  obol scope add 10.10.10.0/24
  obol scan
  obol overview
  obol next
  obol run 1

try:
  obol manual          full operator workflow
  obol help <command>  help for one command
""",
    )
    p.add_argument("-V", "-v", "--version", action="store_true", help="show the obol version and exit")
    p.add_argument("--info", action="store_true", help="show version and current workspace summary")
    sub = p.add_subparsers(dest="cmd")

    ph = sub.add_parser("help", help="show help for obol or a specific command")
    ph.add_argument("topic", nargs="?", help="command to explain")
    ph.set_defaults(func=cmd_help)

    sub.add_parser("manual", help="show the practical operator manual").set_defaults(func=cmd_manual)
    sub.add_parser("version", help="show the obol version").set_defaults(func=cmd_version)
    sub.add_parser("info", help="show version and current workspace summary").set_defaults(func=cmd_info)

    pi = sub.add_parser("init", help="initialize a workspace in the current directory")
    pi.add_argument("--target", help="target host/IP")
    pi.add_argument("--demo", action="store_true", help="seed the HTB Forest demo facts")
    pi.set_defaults(func=cmd_init)

    pn = sub.add_parser("next", help="show proven facts and ranked next actions for the active target")
    pn.add_argument("--all", action="store_true", help="show an engagement-wide next-move overview")
    pn.set_defaults(func=cmd_next)

    sub.add_parser("overview", help="show scope, targets, services, and top next moves").set_defaults(func=cmd_overview)

    pe = sub.add_parser("explain", help="show the full command card (hypothesis, commands, references) for action N")
    pe.add_argument("n", type=int)
    pe.set_defaults(func=cmd_explain)

    pr = sub.add_parser("run", help="run next action N, ingest its evidence, update facts")
    pr.add_argument("n", type=int)
    pr.add_argument("--cmd", type=int, default=1, help="command variant to run from `obol explain N` (default 1)")
    pr.add_argument("--set", action="append", default=[], metavar="KEY=VALUE", help="set command template input for this workspace")
    pr.add_argument("--timeout", type=int, default=300)
    pr.add_argument("--dry-run", action="store_true", help="print and validate the command without executing it")
    pr.add_argument("--allow-shell", action="store_true", help="allow shell metacharacters in guided handoff commands")
    pr.set_defaults(func=cmd_run)

    sub.add_parser("playbooks", help="list available playbooks (named, ordered action sequences)").set_defaults(func=cmd_playbooks)

    pp = sub.add_parser("playbook", help="show a playbook's command plan, or run one step of it")
    pp.add_argument("name", help="playbook name (see `obol playbooks`)")
    pp.add_argument("--step", type=int, help="run this step through the same runner/parser as `obol run`")
    pp.add_argument("--approve", action="store_true", help="approve a step marked require_approval (noisy/risky)")
    pp.add_argument("--set", action="append", default=[], metavar="KEY=VALUE", help="set command template input for this workspace")
    pp.add_argument("--timeout", type=int, default=300)
    pp.add_argument("--dry-run", action="store_true", help="print and validate the step's command without executing it")
    pp.add_argument("--allow-shell", action="store_true", help="allow shell metacharacters in guided handoff commands")
    pp.set_defaults(func=cmd_playbook)

    sub.add_parser("facts", help="list all proven facts").set_defaults(func=cmd_facts)

    pscan = sub.add_parser("scan", help="scan every scoped entry, then Quick Start scoped targets")
    pscan.add_argument("entries", nargs="*", help="optional IP/CIDR entries to authorize and scan now")
    pscan.add_argument("--extract", action="store_true", help="extract only IPs/CIDRs from pasted entries")
    pscan.add_argument("--no-enumerate", action="store_true", help="discovery only; do not run Quick Start")
    pscan.add_argument("--new-only", action="store_true", help="Quick Start only targets created by this scan")
    pscan.add_argument("--timeout", type=int, default=600, help="discovery sweep timeout in seconds")
    pscan.add_argument("--quick-timeout", type=int, default=300, help="per-command Quick Start timeout in seconds")
    pscan.add_argument("--dry-run", action="store_true", help="print discovery commands without running them")
    pscan.add_argument("--allow-shell", action="store_true", help="allow shell metacharacters in guided handoff commands")
    pscan.set_defaults(func=cmd_scan)

    psweep = sub.add_parser("sweep", help="discover live hosts in one range and add them as targets")
    psweep.add_argument("range", help="an authorized CIDR or host (added to scope if new)")
    psweep.add_argument("--no-enumerate", action="store_true", help="discovery only; do not Quick Start new hosts")
    psweep.add_argument("--timeout", type=int, default=600, help="discovery sweep timeout in seconds")
    psweep.add_argument("--quick-timeout", type=int, default=300, help="per-command Quick Start timeout in seconds")
    psweep.add_argument("--dry-run", action="store_true", help="print the discovery command without running it")
    psweep.add_argument("--allow-shell", action="store_true", help="allow shell metacharacters in guided handoff commands")
    psweep.set_defaults(func=cmd_sweep)

    plogin = sub.add_parser("login", help="validate access and open an interactive session (winrm/ssh/rdp)")
    plogin.add_argument("target", nargs="?", default="", help="host to log into (default: active target)")
    plogin.add_argument("--kind", default="", choices=[k.key for k in sessions.SESSION_KINDS],
                        help="login kind; inferred when only one is ready")
    plogin.add_argument("--method", default="", choices=["password", "pth"],
                        help="auth method: password or pth (pass-the-hash); "
                             "default prefers a password, else an NT hash")
    plogin.add_argument("--dry-run", action="store_true", help="show the proof + login commands without running")
    plogin.set_defaults(func=cmd_login)

    sub.add_parser("sessions", help="list interactive sessions (live login/pivot state)").set_defaults(func=cmd_sessions)
    psession = sub.add_parser("session", help="inspect or manage one session (probe/close/rm)")
    session_sub = psession.add_subparsers(dest="session_cmd")
    session_sub.add_parser("list", help="list sessions").set_defaults(func=cmd_session, session_cmd="list")
    for name, helptext in (("probe", "re-validate a session and refresh its status"),
                           ("close", "mark a session closed"),
                           ("rm", "remove a session record")):
        sp = session_sub.add_parser(name, help=helptext)
        sp.add_argument("id", help="session id (see `obol sessions`)")
        sp.set_defaults(func=cmd_session, session_cmd=name)
    psession.set_defaults(func=cmd_session, session_cmd="list")

    pscope = sub.add_parser("scope", help="list, add, paste-filter, or remove authorized scope entries")
    scope_sub = pscope.add_subparsers(dest="scope_cmd")
    scope_sub.add_parser("list", help="list scope").set_defaults(func=cmd_scope, scope_cmd="list")
    padd = scope_sub.add_parser("add", help="add IPs, hostnames, URLs, or CIDRs to scope")
    padd.add_argument("values", nargs="+")
    padd.set_defaults(func=cmd_scope, scope_cmd="add")
    ppaste = scope_sub.add_parser("paste", help="extract only valid IPs/CIDRs from pasted text")
    ppaste.add_argument("text", nargs="*", help="pasted text; stdin is used when omitted")
    ppaste.add_argument("--file", help="read pasted text from a file")
    ppaste.set_defaults(func=cmd_scope, scope_cmd="paste")
    prm = scope_sub.add_parser("rm", aliases=["remove"], help="remove scope entries")
    prm.add_argument("values", nargs="+")
    prm.set_defaults(func=cmd_scope, scope_cmd="rm")
    scope_sub.add_parser("clear", help="remove non-target scope entries").set_defaults(func=cmd_scope, scope_cmd="clear")
    pscope.set_defaults(func=cmd_scope, scope_cmd="list")

    peng = sub.add_parser("engagement", help="manage engagements in the app-managed library")
    eng_sub = peng.add_subparsers(dest="engagement_cmd")
    eng_sub.add_parser("list", help="list engagements").set_defaults(func=cmd_engagement, engagement_cmd="list")
    e_new = eng_sub.add_parser("new", help="create an engagement and make it active")
    e_new.add_argument("name")
    e_new.set_defaults(func=cmd_engagement, engagement_cmd="new")
    e_use = eng_sub.add_parser("use", help="set the active engagement")
    e_use.add_argument("slug")
    e_use.set_defaults(func=cmd_engagement, engagement_cmd="use")
    peng.set_defaults(func=cmd_engagement, engagement_cmd="list")

    ptgt = sub.add_parser("target", help="manage targets in the current/active engagement")
    tgt_sub = ptgt.add_subparsers(dest="target_cmd")
    tgt_sub.add_parser("list", help="list targets").set_defaults(func=cmd_target, target_cmd="list")
    t_add = tgt_sub.add_parser("add", help="add one or more target hosts (unlocks the nmap prelude)")
    t_add.add_argument("hosts", nargs="+")
    t_add.add_argument("--label", help="friendly label for the target")
    t_add.set_defaults(func=cmd_target, target_cmd="add")
    t_use = tgt_sub.add_parser("use", help="set the active target")
    t_use.add_argument("host")
    t_use.set_defaults(func=cmd_target, target_cmd="use")
    t_rm = tgt_sub.add_parser("rm", help="remove a target")
    t_rm.add_argument("host")
    t_rm.set_defaults(func=cmd_target, target_cmd="rm")
    ptgt.set_defaults(func=cmd_target, target_cmd="list")

    ps = sub.add_parser("serve", help="serve the live web surface on localhost (mirrors and drives the workspace)")
    ps.add_argument("--host", default="127.0.0.1", help="bind address (default 127.0.0.1; keep local — the web can launch tools)")
    ps.add_argument("--port", type=int, default=8765)
    ps.set_defaults(func=cmd_serve)

    pw = sub.add_parser("web", help="write a self-contained read-only snapshot to a static HTML file")
    pw.add_argument("--out", help="output path (default .obol/web/index.html)")
    pw.set_defaults(func=cmd_web)

    prep = sub.add_parser("report", help="write an OSCP-style markdown report from the workspace ledger and facts")
    prep.add_argument("--out", help="output path (default report.md in the workspace root)")
    prep.add_argument("--redact", action="store_true", help="redact passwords/hashes/tickets (for a shareable draft; secrets are shown by default)")
    prep.add_argument("--include-secrets", action="store_true", help="deprecated no-op — secrets are already shown by default")
    prep.add_argument("--max-next", type=int, default=8, help="maximum recommended next actions to include")
    prep.set_defaults(func=cmd_report)

    pdbg = sub.add_parser("debug", help="build a debug package for review (state, evidence, terminal/site screenshots)")
    dbg_sub = pdbg.add_subparsers(dest="debug_cmd")
    d_pkg = dbg_sub.add_parser("package", help="write a one-shot debug package (.zip)")
    d_pkg.add_argument("--out", help="output directory (default .obol/debug)")
    d_pkg.add_argument("--include-secrets", action="store_true", help="include secrets in the embedded report")
    d_pkg.add_argument("--no-screenshots", action="store_true", help="skip PNG screenshots even if a browser is available")
    d_pkg.add_argument("--url", help="live `obol serve` URL to screenshot the real console (e.g. http://127.0.0.1:8765)")
    d_pkg.add_argument("--token", help="access token for --url (from the `obol serve` banner)")
    d_pkg.set_defaults(func=cmd_debug, debug_cmd="package")
    d_cap = dbg_sub.add_parser("capture", help="snapshot on a timer during a test run, then bundle a .zip")
    d_cap.add_argument("--interval", type=int, default=30, help="seconds between snapshots (default 30)")
    d_cap.add_argument("--count", type=int, help="stop after this many snapshots")
    d_cap.add_argument("--duration", type=int, help="stop after this many seconds")
    d_cap.add_argument("--out", help="output directory (default .obol/debug)")
    d_cap.add_argument("--include-secrets", action="store_true", help="include secrets in embedded reports")
    d_cap.add_argument("--no-screenshots", action="store_true", help="skip PNG screenshots")
    d_cap.set_defaults(func=cmd_debug, debug_cmd="capture")
    pdbg.set_defaults(func=cmd_debug, debug_cmd="package")
    return p


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "version", False):
        print(_version_text())
        return
    if getattr(args, "info", False):
        _print_info()
        return
    if not getattr(args, "cmd", None):
        parser.print_help()
        return
    args.func(args)


if __name__ == "__main__":
    main()

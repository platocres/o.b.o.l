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

from . import board, library, service
from .facts import Fact
from .pack import load_packs, next_actions
from .runner import RunnerError
from .seed import seed_forest
from .service import ActionError
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
    actions = next_actions(ws.facts)
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
    board.render_board(_load_or_exit())


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


def cmd_scope(args) -> None:
    ws = _load_or_exit()
    if args.scope_cmd == "add":
        added = ws.add_scope(args.value)
        ws.save()
        print(f"added scope: {added}")
        return
    if ws.scope:
        for entry in ws.scope:
            print(entry)
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
        rec = ws.add_target(args.host, args.label or "")
        ws.save()
        print(f"added target {rec['label']} ({rec['host']})" + ("  [active]" if ws.target == rec["host"] else ""))
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
    path = write_report(ws, out=out, include_secrets=args.include_secrets, max_next=args.max_next)
    print(f"wrote {path}")
    if not args.include_secrets:
        print("secrets redacted — use --include-secrets only for private exam notes")


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


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="obol", description="Evidence-driven OSCP operator companion.")
    sub = p.add_subparsers(dest="cmd", required=True)

    pi = sub.add_parser("init", help="initialize a workspace in the current directory")
    pi.add_argument("--target", help="target host/IP")
    pi.add_argument("--demo", action="store_true", help="seed the HTB Forest demo facts")
    pi.set_defaults(func=cmd_init)

    sub.add_parser("next", help="show proven facts and the ranked next actions that matter").set_defaults(func=cmd_next)

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

    pscope = sub.add_parser("scope", help="list or add authorized scope entries")
    scope_sub = pscope.add_subparsers(dest="scope_cmd")
    scope_sub.add_parser("list", help="list scope").set_defaults(func=cmd_scope, scope_cmd="list")
    padd = scope_sub.add_parser("add", help="add an IP, hostname, or CIDR to scope")
    padd.add_argument("value")
    padd.set_defaults(func=cmd_scope, scope_cmd="add")
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
    t_add = tgt_sub.add_parser("add", help="add a target host (unlocks the nmap prelude)")
    t_add.add_argument("host")
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
    prep.add_argument("--include-secrets", action="store_true", help="include passwords, hashes, tickets, and secrets in the report")
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
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()

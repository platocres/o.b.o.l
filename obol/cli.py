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

from . import board
from .facts import Fact
from .pack import load_packs, next_actions
from .parsers import parse_action_output
from .runner import RunnerError, run_command
from .seed import seed_forest
from .workspace import Workspace, find_workspace


def _load_or_exit() -> Workspace:
    ws = find_workspace()
    if ws is None:
        print("no obol workspace here. run `obol init` first.", file=sys.stderr)
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
    """Shared run -> parse -> record path for `obol run` and playbook steps.

    There is deliberately one runner and one parser and one store: a playbook step
    is executed exactly the way `obol run` executes an action. Returns
    (RunResult, added_facts); exits with a clear message on a runner error or a
    bad command variant.
    """
    commands = action.commands or [{"tool": action.tool, "run": action.command}]
    if not 0 <= command_index < len(commands):
        print(f"action has {len(commands)} command variant(s); cannot run #{command_index + 1}.", file=sys.stderr)
        raise SystemExit(1)
    command_meta = commands[command_index]
    cmd = board.fill_command(action, ws, command_index)
    extra = board.fill_template(args_extra, ws).strip() if args_extra else ""
    if extra:
        cmd = f"{cmd} {extra}"
    tool = command_meta.get("tool") or action.tool or cmd.split()[0]
    print(f"\n$ {cmd}")
    try:
        result = run_command(
            ws, command=cmd, tool=tool, timeout=timeout,
            dry_run=dry_run, allow_shell_tokens=allow_shell,
        )
    except RunnerError as exc:
        print(f"\nerror: {exc}", file=sys.stderr)
        raise SystemExit(1)

    new = [] if result.dry_run else parse_action_output(action, ws, cmd, result.stdout, result.stderr, source=cmd)
    added = []
    for fact in new:
        if ws.facts.add(fact):
            added.append(fact)
    ws.record_run(
        tool, cmd, [f.kind for f in added],
        action_id=action.id,
        command_index=command_index + 1,
        returncode=result.returncode,
        timed_out=result.timed_out,
        dry_run=result.dry_run,
        stdout=str(result.stdout_path),
        stderr=str(result.stderr_path),
        duration_ms=result.duration_ms,
        **(ledger_extra or {}),
    )
    ws.save()
    if result.dry_run:
        print("\ndry run only — command was not executed and no facts were ingested.")
    elif added:
        print(f"\n{board.SYM_OK} ingested — new facts:")
        for f in added:
            detail = f.value.get("password") or f.value.get("hash") or f.value.get("sam") or f.value.get("count") or ""
            print(f"   + {f.kind}" + (f"  ({detail})" if detail else ""))
    else:
        print("\n(no new facts parsed — raw output was still saved)")
    return result, added


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
    from . import web
    web.serve(_load_or_exit(), port=args.port)


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

    ps = sub.add_parser("serve", help="serve the read-only web view on localhost")
    ps.add_argument("--port", type=int, default=8765)
    ps.set_defaults(func=cmd_serve)

    pw = sub.add_parser("web", help="write the read-only web view to a static HTML file")
    pw.add_argument("--out", help="output path (default .obol/web/index.html)")
    pw.set_defaults(func=cmd_web)

    prep = sub.add_parser("report", help="write an OSCP-style markdown report from the workspace ledger and facts")
    prep.add_argument("--out", help="output path (default report.md in the workspace root)")
    prep.add_argument("--include-secrets", action="store_true", help="include passwords, hashes, tickets, and secrets in the report")
    prep.add_argument("--max-next", type=int, default=8, help="maximum recommended next actions to include")
    prep.set_defaults(func=cmd_report)
    return p


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
